// Cloudflare Worker — backend das features de segurança do site (Bloco 3).
// Um só Worker, um só namespace KV (chaves com prefixo). Serve:
//   · endpoints-isco do honeypot (404 + só metadados, nunca IP)
//   · /api/honeypot, /api/map  — painel + mapa de tráfego hostil
//   · /api/scan                — self-scan de cabeçalhos (cache 6h)
//   · /api/pwned-range         — relay k-anónimo do HIBP (cache 24h por prefixo)
//   · /api/ticker              — CISA KEV + NVD (cache 1h, sanitizado)
//   · /api/csp-report (POST)   — recetor de violações CSP (report-uri/report-to)
//   · /api/csp-violations      — agregados 7d das violações (painel Segurança)
//   · /api/ct                  — vigia CT: emissões de certificados p/ o domínio (cache 6h)
//   · /api/health
// Ver README.md para deploy (routes no domínio vs. workers.dev) e secrets.

import { emptyBucket, addEvent, honeypotStats, mapData } from './lib/aggregate.js';
import {
  parseReports, normalizeViolation, emptyCspBucket, addCspEvent, cspStats,
  REPORT_CONTENT_TYPES, MAX_REPORTS_PER_REQUEST,
} from './lib/csp-report.js';
import { gradeFromHeaders, SECURITY_HEADERS } from './lib/scan.js';
import { nextState, clientHash, dailySalt } from './lib/ratelimit.js';
import { underCap } from './lib/kvcap.js';
import { fetchTicker } from './lib/feeds.js';
import { normalizePrefix, fetchRange } from './lib/pwned.js';
import { fetchCtWatch } from './lib/ct.js';
import { serverView } from './lib/mirror.js';
import { clampInt, normalizeCountry, normalizeAsn, floorToWindow } from './lib/sanitize.js';
import { techniqueForPath } from './lib/attack-map.js';
import { renderNotFoundHtml, NOT_FOUND_CSP } from './lib/notfound.js';

// Paths que só existem para apanhar scanners. Devolvem 404 como qualquer
// path inexistente — a diferença é que registamos a tentativa.
const DECOYS = new Set(['/wp-login.php', '/.env', '/admin', '/phpmyadmin/', '/.git/config']);

const HOUR_MS = 3600_000;
const DAY_MS = 86400_000;

// Anonimização: os eventos do honeypot guardam o timestamp arredondado a
// esta janela (5 min), para não permitir correlação por instante preciso.
const ANON_WINDOW_MS = 5 * 60_000;

// Cap global de escritas do honeypot por janela: limita custo/abuso se
// alguém martelar os paths-isco. Ver lib/kvcap.js. Generoso para tráfego
// legítimo de scanners, mas põe um teto duro (max eventos → ~4×max escritas
// de bucket por janela).
const HONEYPOT_WRITE_CAP = { windowMs: HOUR_MS, max: 500 };

// Timeout para fetches a montante (self-scan) — não deixar um alvo lento
// pendurar o pedido.
const UPSTREAM_TIMEOUT_MS = 5000;

// Violações CSP: corpo máximo aceite num POST (um batch reports+json legítimo
// anda nos poucos KB) e cap global de escritas por janela — uma regressão real
// gera 1 relatório × N visitantes, o teto limita o custo dessa rajada (e de
// spam deliberado) sem perder o sinal: os agregados já contados ficam.
const CSP_REPORT_MAX_BODY = 16 * 1024;
const CSP_WRITE_CAP = { windowMs: HOUR_MS, max: 300 };

// ---------- helpers de tempo/KV ----------

const hourKey = (ms) => `h:${new Date(ms).toISOString().slice(0, 13)}`; // h:2026-07-15T17
const dayKey = (ms) => `d:${new Date(ms).toISOString().slice(0, 10)}`; // d:2026-07-15

async function getJSON(env, key, dflt = null) {
  return (await env.KV.get(key, 'json')) ?? dflt;
}

/** Lê os buckets partilhados por /honeypot e /map de uma vez. */
async function readBuckets(env, now) {
  const hourKeys = Array.from({ length: 24 }, (_, i) => hourKey(now - i * HOUR_MS));
  const dayKeys = Array.from({ length: 7 }, (_, i) => dayKey(now - i * DAY_MS));
  const [hourly, days, recent, meta] = await Promise.all([
    Promise.all(hourKeys.map((k) => getJSON(env, k))),
    Promise.all(dayKeys.map((k) => getJSON(env, k))),
    getJSON(env, 'recent', []),
    getJSON(env, 'meta', {}),
  ]);
  return { hourly, days, recent, meta };
}

// ---------- honeypot: escrita ----------

async function recordHoneypot(env, request, path, now) {
  // Só metadados grosseiros, cada campo validado antes de persistir. NUNCA
  // o IP: o cf-connecting-ip não é lido aqui de todo (só a lib de rate
  // limit o vê, e apenas como hash salteado). O timestamp é arredondado a
  // ANON_WINDOW_MS para não permitir correlação por instante preciso.
  const country = normalizeCountry(request.headers.get('cf-ipcountry') || request.cf?.country);
  const asn = normalizeAsn(request.cf?.asn);
  const ts = floorToWindow(now, ANON_WINDOW_MS);
  // Lookup local (sem rede): anexa a técnica ATT&CK do path-isco ao evento,
  // para que o registo em KV já conte a que classe de ataque corresponde.
  const technique = techniqueForPath(path);
  const event = { ts, country, asn, path, technique };

  const capKey = `wcap:${hourKey(now)}`;
  const [recent, hBucket, dBucket, meta, capPrev] = await Promise.all([
    getJSON(env, 'recent', []),
    getJSON(env, hourKey(now), emptyBucket()),
    getJSON(env, dayKey(now), emptyBucket()),
    getJSON(env, 'meta', {}),
    getJSON(env, capKey),
  ]);

  // Cap de escritas por janela: passado o teto, descarta o evento (o
  // pedido já devolveu 404 na mesma) para não inflacionar o custo do KV.
  const { allowed, state: capState } = underCap(capPrev, { now, ...HONEYPOT_WRITE_CAP });
  if (!allowed) return;

  const nextRecent = [event, ...recent].slice(0, 30);
  addEvent(hBucket, event);
  addEvent(dBucket, event);

  // deployTs vem de var no deploy; firstScanTs = 1.ª tentativa alguma vez vista.
  const deployTs = meta.deployTs ?? clampInt(env.DEPLOY_TS, 0, Number.MAX_SAFE_INTEGER, ts);
  const nextMeta = { deployTs, firstScanTs: meta.firstScanTs ?? ts };

  await Promise.all([
    env.KV.put('recent', JSON.stringify(nextRecent)),
    env.KV.put(hourKey(now), JSON.stringify(hBucket), { expirationTtl: 2 * 86400 }),
    env.KV.put(dayKey(now), JSON.stringify(dBucket), { expirationTtl: 9 * 86400 }),
    env.KV.put('meta', JSON.stringify(nextMeta)),
    env.KV.put(capKey, JSON.stringify(capState), { expirationTtl: Math.ceil(HONEYPOT_WRITE_CAP.windowMs / 1000) + 60 }),
  ]);
}

// ---------- violações CSP: escrita ----------

const cspDayKey = (ms) => `cspd:${new Date(ms).toISOString().slice(0, 10)}`; // cspd:2026-07-17

/**
 * Agrega violações CSP já normalizadas no bucket diário. Só agregados — ao
 * contrário do honeypot nem sequer há lista "recent": nenhum evento
 * individual é persistido, só contadores por diretiva/categoria/origem.
 */
async function recordCspViolations(env, violations, now) {
  if (violations.length === 0) return;
  const capKey = `cspcap:${hourKey(now)}`;
  const dayK = cspDayKey(now);
  const [bucket, capPrev] = await Promise.all([
    getJSON(env, dayK, emptyCspBucket()),
    getJSON(env, capKey),
  ]);

  // Cap global de escritas por janela (mesmo padrão do honeypot): acima do
  // teto os relatórios extra descartam-se — o browser recebe 204 na mesma.
  const { allowed, state: capState } = underCap(capPrev, { now, ...CSP_WRITE_CAP });
  if (!allowed) return;

  for (const v of violations) addCspEvent(bucket, v);
  await Promise.all([
    env.KV.put(dayK, JSON.stringify(bucket), { expirationTtl: 9 * 86400 }),
    env.KV.put(capKey, JSON.stringify(capState), { expirationTtl: Math.ceil(CSP_WRITE_CAP.windowMs / 1000) + 60 }),
  ]);
}

/** Lê os 7 buckets diários de violações CSP (hoje primeiro). */
async function readCspBuckets(env, now) {
  const keys = Array.from({ length: 7 }, (_, i) => cspDayKey(now - i * DAY_MS));
  return Promise.all(keys.map((k) => getJSON(env, k)));
}

// ---------- caching de leitura ----------

// Cache de leitura com stale-while-revalidate: um valor expirado ainda é
// servido de imediato enquanto um único refresh corre em background
// (ctx.waitUntil) — evita a debandada de N fetches concorrentes ao upstream
// (NVD/KEV têm rate limit) quando a cache expira com tráfego. A cópia no KV
// vive 10 min além do exp lógico para haver "stale" que servir.
async function cached(env, ctx, key, ttlSec, producer) {
  const now = Date.now();
  const hit = await getJSON(env, key);
  if (hit && hit.exp > now) return hit.data;
  const refresh = async () => {
    const data = await producer();
    await env.KV.put(key, JSON.stringify({ data, exp: Date.now() + ttlSec * 1000 }), {
      expirationTtl: ttlSec + 600,
    });
    return data;
  };
  if (hit && ctx) {
    ctx.waitUntil(refresh().catch((err) => console.error('cache_refresh_failed', key, err?.message ?? String(err))));
    return hit.data;
  }
  return refresh();
}

// ---------- self-scan ----------

// async function runScan(env) {
  // Fetch direto ao próprio site + parsing dos seus cabeçalhos — sem
  // scraping de terceiros (securityheaders.com), portanto imune a mudanças
  // de HTML deles. Timeout para não pendurar o pedido se o alvo demorar.
//  const target = env.SCAN_TARGET || 'https://danielmala.co/';
//  const res = await fetch(target, {
//    redirect: 'follow',
//    headers: { 'user-agent': 'personal-site-worker (self-scan)' },
//    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
//  });
//  const get = (name) => res.headers.get(name);
//  const graded = gradeFromHeaders(get);
//  return { target, scannedAt: Date.now(), ...graded };
// }
async function runScan(env) {
  const target = env.SCAN_TARGET || 'https://danielmala.co/';

  const headers = {
    'user-agent': 'personal-site-worker (self-scan)',
  };

  // Autenticação Cloudflare Access (opcional).
  if (env.ACCESS_CLIENT_ID && env.ACCESS_CLIENT_SECRET) {
    headers['CF-Access-Client-Id'] = env.ACCESS_CLIENT_ID;
    headers['CF-Access-Client-Secret'] = env.ACCESS_CLIENT_SECRET;
  }

  const res = await fetch(target, {
    redirect: 'follow',
    headers,
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
  });

  const get = (name) => res.headers.get(name);
  const graded = gradeFromHeaders(get);
  return { target, scannedAt: Date.now(), ...graded };
}


// ---------- rate limiting ----------

async function rateLimit(env, request, route, { windowMs, max }) {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const salt = dailySalt(env.RATE_SALT);
  const id = await clientHash(ip, salt);
  const key = `rl:${route}:${id}`;
  const now = Date.now();
  const prev = await getJSON(env, key);
  const { allowed, state, retryAfterSec } = nextState(prev, { now, windowMs, max });
  // Bloqueado ⇒ o estado não mudou (nextState devolve a mesma contagem) —
  // não se gasta uma escrita KV por pedido recusado, senão martelar a rota
  // transformava cada 429 num put pago. O put só acontece quando conta.
  if (allowed) {
    await env.KV.put(key, JSON.stringify(state), { expirationTtl: Math.ceil(windowMs / 1000) + 1 });
  }
  return { allowed, retryAfterSec };
}

// ---------- respostas ----------

// Cabeçalhos de segurança de TODAS as respostas do Worker. O _headers do
// Pages só cobre o conteúdo estático — as rotas servidas pelo Worker (API e
// paths-isco) respondem por si e, sem isto, saíam sem nosniff nem CSP (e o
// workflow Headers, que verifica a raiz do site, nunca o apanharia). A CSP
// 'none' é a prática padrão para endpoints JSON: mesmo com tudo sanitizado,
// garante que nada executa se um browser renderizar a resposta diretamente.
const RESPONSE_SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'content-security-policy': "default-src 'none'",
};

function corsHeaders(request, env) {
  const allowed = (env.ALLOWED_ORIGINS || '').split(',').map((s) => s.trim()).filter(Boolean);
  const origin = request.headers.get('origin');
  const headers = { Vary: 'Origin' };
  if (origin && allowed.includes(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS';
  }
  return headers;
}

function json(data, request, env, { status = 200, maxAge = 0, extra = {} } = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': maxAge > 0 ? `public, max-age=${maxAge}` : 'no-store',
      ...RESPONSE_SECURITY_HEADERS,
      ...corsHeaders(request, env),
      ...extra,
    },
  });
}

// ---------- router ----------

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: { ...RESPONSE_SECURITY_HEADERS, ...corsHeaders(request, env) },
      });
    }

    // endpoints-isco: registar (em background) e devolver um 404 visualmente
    // igual ao 404 real do site (lib/notfound.js) — texto simples era um
    // "tell" mais fácil de distinguir do resto do site, não mais difícil.
    if (DECOYS.has(path)) {
      ctx.waitUntil(
        // Falha de escrita loga-se server-side (sem IP: recordHoneypot não o
        // vê) e nunca chega ao cliente — a resposta é sempre o mesmo 404.
        recordHoneypot(env, request, path, Date.now()).catch((err) =>
          console.error('honeypot_write_failed', path, err?.message ?? String(err)),
        ),
      );
      return new Response(renderNotFoundHtml(), {
        status: 404,
        headers: {
          'content-type': 'text/html; charset=utf-8',
          'x-content-type-options': 'nosniff',
          'content-security-policy': NOT_FOUND_CSP,
        },
      });
    }

    // Recetor de relatórios CSP (report-uri / Reporting API). É o único POST
    // do Worker: endpoint público por natureza (os browsers têm de lhe chegar
    // sem credenciais), por isso cada camada é defensiva — Content-Type
    // estrito, corpo limitado, rate limit por cliente, validação da origem do
    // documento na lib, e cap global de escritas. A resposta é sempre 204 nos
    // casos "aceite" e "descartado": um forjador não distingue os dois.
    if (path === '/api/csp-report' && request.method === 'POST') {
      const ctype = (request.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase();
      if (!REPORT_CONTENT_TYPES.includes(ctype)) {
        return json({ error: 'unsupported_media_type' }, request, env, { status: 415 });
      }
      const { allowed, retryAfterSec } = await rateLimit(env, request, 'cspr', {
        windowMs: 60_000,
        max: 10, // o batching nativo do browser raramente passa de 1-2/min
      });
      if (!allowed) {
        return json({ error: 'rate_limited' }, request, env, {
          status: 429,
          extra: { 'retry-after': String(retryAfterSec) },
        });
      }
      let text;
      try {
        text = await request.text();
      } catch {
        return new Response(null, { status: 204, headers: RESPONSE_SECURITY_HEADERS });
      }
      if (text.length > CSP_REPORT_MAX_BODY) {
        return json({ error: 'payload_too_large' }, request, env, { status: 413 });
      }
      const siteOrigin = new URL(env.SCAN_TARGET || 'https://danielmala.co/').origin;
      const violations = parseReports(text, ctype)
        .map((raw) => normalizeViolation(raw, siteOrigin))
        .filter(Boolean)
        .slice(0, MAX_REPORTS_PER_REQUEST);
      ctx.waitUntil(
        recordCspViolations(env, violations, Date.now()).catch((err) =>
          console.error('csp_report_write_failed', err?.message ?? String(err)),
        ),
      );
      return new Response(null, { status: 204, headers: RESPONSE_SECURITY_HEADERS });
    }

    if (request.method !== 'GET') {
      return json({ error: 'method_not_allowed' }, request, env, { status: 405 });
    }

    try {
      if (path === '/api/health') {
        return json({ ok: true, ts: Date.now() }, request, env);
      }

      if (path === '/api/honeypot') {
        const data = await cached(env, ctx, 'cache:honeypot', 60, async () =>
          honeypotStats(await readBuckets(env, Date.now())),
        );
        return json(data, request, env, { maxAge: 60 });
      }

      if (path === '/api/map') {
        const data = await cached(env, ctx, 'cache:map', 60, async () =>
          mapData(await readBuckets(env, Date.now())),
        );
        return json(data, request, env, { maxAge: 60 });
      }

      if (path === '/api/scan') {
        const refresh = url.searchParams.get('refresh') === '1';
        // o refresh manual aceita input (o botão) → rate limit apertado
        if (refresh) {
          const { allowed, retryAfterSec } = await rateLimit(env, request, 'scan', {
            windowMs: 10 * 60_000,
            max: 3,
          });
          if (!allowed) {
            return json({ error: 'rate_limited' }, request, env, {
              status: 429,
              extra: { 'retry-after': String(retryAfterSec) },
            });
          }
          const data = await runScan(env);
          await env.KV.put('cache:scan', JSON.stringify({ data, exp: Date.now() + 6 * HOUR_MS }), {
            expirationTtl: 6 * 3600 + 60,
          });
          return json(data, request, env);
        }
        const data = await cached(env, ctx, 'cache:scan', 6 * 3600, () => runScan(env));
        return json(data, request, env, { maxAge: 1800 });
      }

      // Relay k-anónimo do HIBP: o cliente só manda os 5 primeiros hex do
      // SHA-1 (a password nunca chega cá). Prefixo validado a ferro (5 hex) —
      // não é reutilizável para pedir mais nada. Rate limit por cliente (é
      // input do utilizador, não pode virar amplificador do HIBP) e cache 24h
      // por prefixo (dataset público). Nunca se regista o prefixo.
      if (path === '/api/pwned-range') {
        const prefix = normalizePrefix(url.searchParams.get('prefix'));
        if (!prefix) {
          return json({ error: 'invalid_prefix' }, request, env, { status: 400 });
        }
        const { allowed, retryAfterSec } = await rateLimit(env, request, 'pwned', {
          windowMs: 60_000,
          max: 20,
        });
        if (!allowed) {
          return json({ error: 'rate_limited' }, request, env, {
            status: 429,
            extra: { 'retry-after': String(retryAfterSec) },
          });
        }
        const data = await cached(env, ctx, `cache:pwned:${prefix}`, 86400, async () => ({
          suffixes: await fetchRange(prefix, { timeoutMs: UPSTREAM_TIMEOUT_MS }),
        }));
        return json(data, request, env, { maxAge: 3600 });
      }

      if (path === '/api/csp-violations') {
        const data = await cached(env, ctx, 'cache:cspviolations', 60, async () =>
          cspStats(await readCspBuckets(env, Date.now())),
        );
        return json(data, request, env, { maxAge: 60 });
      }

      // Vigia CT: emissões de certificados para o próprio domínio, dos logs
      // públicos de Certificate Transparency (crt.sh). Sem input de
      // visitantes (a query é fixa — não é reutilizável como proxy), por
      // isso sem rate limit próprio: a cache de 6h com SWR já garante que
      // o crt.sh só é consultado de longe em longe.
      if (path === '/api/ct') {
        const data = await cached(env, ctx, 'cache:ct', 6 * 3600, () => fetchCtWatch(env));
        return json(data, request, env, { maxAge: 1800 });
      }

      if (path === '/api/ticker') {
        const data = await cached(env, ctx, 'cache:ticker', 3600, () => fetchTicker(env));
        return json(data, request, env, { maxAge: 1800 });
      }

      // Espelho: a "vista do servidor" deste mesmo pedido. Sem input de
      // visitante (não é proxy) e sem qualquer escrita de estado — só se lê
      // o que o pedido já trouxe. O IP é visível ao Worker mas nunca é
      // devolvido (serverView não o inclui). Rate limit leve na mesma, para
      // não deixar a rota ser martelada; a resposta é per-request, logo
      // no-store (nunca em cache partilhada).
      if (path === '/api/mirror') {
        const { allowed, retryAfterSec } = await rateLimit(env, request, 'mirror', {
          windowMs: 60_000,
          max: 30,
        });
        if (!allowed) {
          return json({ error: 'rate_limited' }, request, env, {
            status: 429,
            extra: { 'retry-after': String(retryAfterSec) },
          });
        }
        const get = (name) => request.headers.get(name);
        return json(serverView(get, request.cf ?? {}), request, env);
      }
    } catch (err) {
      // Detalhe (stack) só nos logs do Worker — server-side. O cliente
      // recebe um erro genérico, sem stack, sem path interno, sem detalhes
      // do KV. `path` é seguro (não contém IP nem segredos).
      console.error('request_failed', path, err?.stack ?? err?.message ?? String(err));
      return json({ error: 'upstream_error' }, request, env, { status: 502 });
    }

    return json({ error: 'not_found' }, request, env, { status: 404 });
  },

  // Cron opcional (ver wrangler.toml): aquece as caches para que a 1.ª
  // visita após expirar não pague a latência do upstream. A agregação do
  // honeypot é on-read, por isso não precisa de cron.
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      Promise.all([
        cached(env, ctx, 'cache:ticker', 3600, () => fetchTicker(env)).catch(() => {}),
        cached(env, ctx, 'cache:scan', 6 * 3600, () => runScan(env)).catch(() => {}),
        cached(env, ctx, 'cache:ct', 6 * 3600, () => fetchCtWatch(env)).catch(() => {}),
      ]),
    );
  },
};

// reexport para uso em testes de fumo, se necessário
export { SECURITY_HEADERS };
