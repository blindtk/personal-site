// Cloudflare Worker — backend das features de segurança do site (Bloco 3).
// Um só Worker, um só namespace KV (chaves com prefixo). Serve:
//   · endpoints-isco do honeypot (404 + só metadados, nunca IP)
//   · /api/honeypot, /api/map  — painel + mapa de tráfego hostil
//   · /api/scan                — self-scan de cabeçalhos (cache 6h)
//   · /api/ticker              — CISA KEV + NVD (cache 1h, sanitizado)
//   · /api/health
// Ver README.md para deploy (routes no domínio vs. workers.dev) e secrets.

import { emptyBucket, addEvent, honeypotStats, mapData } from './lib/aggregate.js';
import { gradeFromHeaders, SECURITY_HEADERS } from './lib/scan.js';
import { nextState, clientHash, dailySalt } from './lib/ratelimit.js';
import { underCap } from './lib/kvcap.js';
import { fetchTicker } from './lib/feeds.js';
import { clampInt, normalizeCountry, normalizeAsn, floorToWindow } from './lib/sanitize.js';

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
  const event = { ts, country, asn, path };

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

// ---------- caching de leitura ----------

async function cached(env, key, ttlSec, producer) {
  const now = Date.now();
  const hit = await getJSON(env, key);
  if (hit && hit.exp > now) return hit.data;
  const data = await producer();
  await env.KV.put(key, JSON.stringify({ data, exp: now + ttlSec * 1000 }), {
    expirationTtl: ttlSec + 60,
  });
  return data;
}

// ---------- self-scan ----------

async function runScan(env) {
  // Fetch direto ao próprio site + parsing dos seus cabeçalhos — sem
  // scraping de terceiros (securityheaders.com), portanto imune a mudanças
  // de HTML deles. Timeout para não pendurar o pedido se o alvo demorar.
  const target = env.SCAN_TARGET || 'https://danielmala.co/';
  const res = await fetch(target, {
    redirect: 'follow',
    headers: { 'user-agent': 'personal-site-worker (self-scan)' },
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
  await env.KV.put(key, JSON.stringify(state), { expirationTtl: Math.ceil(windowMs / 1000) + 1 });
  return { allowed, retryAfterSec };
}

// ---------- respostas ----------

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
      return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    }

    // endpoints-isco: registar (em background) e devolver 404 seco
    if (DECOYS.has(path)) {
      ctx.waitUntil(
        // Falha de escrita loga-se server-side (sem IP: recordHoneypot não o
        // vê) e nunca chega ao cliente — a resposta é sempre o mesmo 404.
        recordHoneypot(env, request, path, Date.now()).catch((err) =>
          console.error('honeypot_write_failed', path, err?.message ?? String(err)),
        ),
      );
      return new Response('Not found', { status: 404, headers: { 'content-type': 'text/plain' } });
    }

    if (request.method !== 'GET') {
      return json({ error: 'method_not_allowed' }, request, env, { status: 405 });
    }

    try {
      if (path === '/api/health') {
        return json({ ok: true, ts: Date.now() }, request, env);
      }

      if (path === '/api/honeypot') {
        const data = await cached(env, 'cache:honeypot', 60, async () =>
          honeypotStats(await readBuckets(env, Date.now())),
        );
        return json(data, request, env, { maxAge: 60 });
      }

      if (path === '/api/map') {
        const data = await cached(env, 'cache:map', 60, async () =>
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
        const data = await cached(env, 'cache:scan', 6 * 3600, () => runScan(env));
        return json(data, request, env, { maxAge: 1800 });
      }

      if (path === '/api/ticker') {
        const data = await cached(env, 'cache:ticker', 3600, () => fetchTicker(env));
        return json(data, request, env, { maxAge: 1800 });
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
        cached(env, 'cache:ticker', 3600, () => fetchTicker(env)).catch(() => {}),
        cached(env, 'cache:scan', 6 * 3600, () => runScan(env)).catch(() => {}),
      ]),
    );
  },
};

// reexport para uso em testes de fumo, se necessário
export { SECURITY_HEADERS };
