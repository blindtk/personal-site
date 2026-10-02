// Cloudflare Worker — backend das features de segurança do site (Bloco 3).
// Um só Worker, um só namespace KV (chaves com prefixo). Serve:
//   · /api/pwned-range         — relay k-anónimo do HIBP (cache 24h por prefixo)
//   · /api/ct                  — vigia CT: emissões de certificados p/ o domínio (cache 6h)
//   · /api/cf-stats            — estado da zona Cloudflare: pedidos/cache/Worker (cache 6h)
//   · /api/threat-intel        — repartição da firewall da zona acumulada a 7d (cache 6h)
//   · /api/vitals (GET)        — Core Web Vitals p75 (RUM, 7d)
//   · /api/vitals (POST)       — beacon RUM first-party (agregados, sem PII)
//   · /api/mirror              — o que o servidor vê deste pedido (sem guardar nada)
//   · /api/health
// O honeypot (paths-isco, lista de IPs, mapa e ticker SOC) saiu deste
// Worker — ADR 0022: o sensor é agora só o honeypot externo
// (honeypot-vps-infra). `purgeLegacyHoneypotKeys` apaga do KV o que ele
// deixou. Ver README.md para deploy (routes no domínio) e secrets.

import { mergeFirewall7d } from './lib/firewall.js';
import {
  normalizeVitals, emptyVitalsBucket, addVitals, vitalsStats,
} from './lib/vitals.js';
import { nextState, clientHash, dailySalt } from './lib/ratelimit.js';
import { underCap } from './lib/kvcap.js';
import { normalizePrefix, fetchRange } from './lib/pwned.js';
import { fetchCtWatch } from './lib/ct.js';
import { fetchCfStats } from './lib/cf-analytics.js';
import { serverView } from './lib/mirror.js';
import { edgeCache, edgeKey, edgeGetJSON, edgePutJSON } from './lib/edgecache.js';

const HOUR_MS = 3600_000;
const DAY_MS = 86400_000;

// Timeout para fetches a montante (relay do HIBP em /api/pwned-range) — não
// deixar um alvo lento pendurar o pedido.
const UPSTREAM_TIMEOUT_MS = 5000;

// RUM de Core Web Vitals: corpo minúsculo (4 números), teto de escritas POR
// DIA (o plano Free tem ~1.000 escritas/dia para a conta inteira). Só agregados; ver
// lib/vitals.js. 150 amostras/dia × 2 escritas = 300/dia: o valor antigo
// (5.000/hora) media a resiliência a abuso, não o orçamento real do plano
// Free — tráfego orgânico normal já bastava para estourar o teto diário
// muito antes de qualquer flood malicioso.
const VITALS_MAX_BODY = 2 * 1024;
// Em escritas (2 por amostra: histograma + contador) — as mesmas 150
// amostras/dia de antes.
const VITALS_WRITE_CAP = { windowMs: DAY_MS, max: 300 };
const VITALS_WRITE_COST = 2;

// ---------- helpers de tempo/KV ----------

const dayKey = (ms) => `d:${new Date(ms).toISOString().slice(0, 10)}`; // d:2026-07-15

async function getJSON(env, key, dflt = null) {
  return (await env.KV.get(key, 'json')) ?? dflt;
}

/**
 * Chaves que o honeypot interno deixou no KV (ADR 0022). `iplist` tem IPs de
 * origem publicados (ADR 0020) — dados pessoais que deixam de ter razão para
 * existir; `recent`/`meta` não tinham TTL; as caches das rotas removidas
 * ficariam até ~1 dia em stale. Os buckets h:/d: e os contadores wcap: são
 * anónimos e expiram sozinhos em ≤ 9 dias.
 *
 * Corre no cron: lê primeiro (leituras são baratas) e só apaga o que ainda
 * existe — depois da 1.ª limpeza, cada tick custa só estas leituras e
 * nenhuma escrita. `cache:threatintel` só é apagada se ainda tiver o formato
 * antigo (com `ips`), senão o cron apagava a cache nova a cada 30 min.
 */
const LEGACY_HONEYPOT_KEYS = ['iplist', 'recent', 'meta', 'cache:honeypot', 'cache:map', 'cache:ticker'];

async function purgeLegacyHoneypotKeys(env) {
  const [values, threatIntel] = await Promise.all([
    Promise.all(LEGACY_HONEYPOT_KEYS.map((key) => env.KV.get(key))),
    getJSON(env, 'cache:threatintel'),
  ]);
  const stale = LEGACY_HONEYPOT_KEYS.filter((_, i) => values[i] !== null);
  if (threatIntel && threatIntel.data && 'ips' in threatIntel.data) stale.push('cache:threatintel');
  await Promise.all(stale.map((key) => env.KV.delete(key)));
}

// ---------- Core Web Vitals (RUM): escrita/leitura ----------

const vitalsDayKey = (ms) => `vit:${new Date(ms).toISOString().slice(0, 10)}`; // vit:2026-07-24

/**
 * Acumula uma amostra de Web Vitals já normalizada no histograma diário. Só
 * agregados — nenhum valor individual, IP ou UA é persistido. Cap global de
 * escritas por janela.
 */
async function recordVitals(env, sample, now) {
  const capKey = `vitcap:${dayKey(now)}`;
  const dayK = vitalsDayKey(now);
  const [bucket, capPrev] = await Promise.all([
    getJSON(env, dayK, emptyVitalsBucket()),
    getJSON(env, capKey),
  ]);
  const { allowed, state } = underCap(capPrev, { now, cost: VITALS_WRITE_COST, ...VITALS_WRITE_CAP });
  if (!allowed) return;
  addVitals(bucket, sample);
  await Promise.all([
    env.KV.put(dayK, JSON.stringify(bucket), { expirationTtl: 9 * 86400 }),
    env.KV.put(capKey, JSON.stringify(state), { expirationTtl: Math.ceil(VITALS_WRITE_CAP.windowMs / 1000) + 60 }),
  ]);
}

/** Lê os 7 histogramas diários de Web Vitals (hoje primeiro). */
async function readVitalsBuckets(env, now) {
  const keys = Array.from({ length: 7 }, (_, i) => vitalsDayKey(now - i * DAY_MS));
  return Promise.all(keys.map((k) => getJSON(env, k)));
}

// ---------- Firewall Cloudflare: acumulação diária (24h → 7d) ----------

const fwDayKey = (ms) => `fw:${new Date(ms).toISOString().slice(0, 10)}`; // fw:2026-07-24

/**
 * Fotografa a repartição de firewall das últimas 24h (já calculada em
 * `stats.zone` pelo cf-analytics) num snapshot diário no KV. Como o dataset
 * cru só tem 24h no Free, é assim que se acumula uma janela de 7 dias (a
 * "fase 2" registada no PLAN.md). Contadores por ação/origem, por país×ação
 * (ação mais comum vinda de cada país, nesse dia) e por rede (ASN, do
 * `firewallDetailBreakdown`) — nunca IP.
 */
async function snapshotFirewall(env, stats, now) {
  const zone = stats?.zone;
  if (!zone) return;
  const toMap = (list) => Object.fromEntries((Array.isArray(list) ? list : []).map((r) => [r.key, r.count]));
  const byCountry = Object.fromEntries(
    (Array.isArray(zone.firewallByCountry) ? zone.firewallByCountry : [])
      .filter((r) => r?.country && r?.action)
      .map((r) => [r.country, { action: r.action, count: r.count }]),
  );
  const snap = {
    byAction: toMap(zone.firewallByAction),
    bySource: toMap(zone.firewallBySource),
    byCountry,
    byAsn: toMap(zone.firewallByAsn),
  };
  if (
    Object.keys(snap.byAction).length === 0 &&
    Object.keys(snap.bySource).length === 0 &&
    Object.keys(snap.byCountry).length === 0 &&
    Object.keys(snap.byAsn).length === 0
  ) return;
  await env.KV.put(fwDayKey(now), JSON.stringify(snap), { expirationTtl: 8 * 86400 });
}

/**
 * Lê os snapshots de firewall dos últimos 7 dias e funde-os (`mergeFirewall7d`,
 * lib/firewall.js — pura e testável) em tops por ação/origem/rede/país MAIS
 * a série diária crua que alimenta o dashboard "Mitigação por dia".
 */
async function readFirewall7d(env, now) {
  const dates = Array.from({ length: 7 }, (_, i) => new Date(now - i * DAY_MS).toISOString().slice(0, 10));
  const snaps = await Promise.all(dates.map((date) => getJSON(env, `fw:${date}`)));
  return mergeFirewall7d(dates.map((date, i) => ({ date, snap: snaps[i] })));
}

// ---------- caching de leitura ----------

// Cache de leitura com stale-while-revalidate: um valor expirado ainda é
// servido de imediato enquanto um único refresh corre em background
// (ctx.waitUntil) — evita a debandada de N fetches concorrentes ao upstream
// (NVD/KEV têm rate limit) quando a cache expira com tráfego.
//
// Cada refresh é uma ESCRITA no KV — e as rotas públicas sem rate limit
// (na altura /api/honeypot e /api/map com TTL de 60s, hoje /api/vitals com
// 120s) deixavam o ritmo dessas escritas nas mãos de qualquer visitante
// anónimo: 3 pedidos por minuto chegavam para ~3.500 puts/dia, muito acima do teto de ~1.000/dia
// da conta (auditoria de segurança 2026-09-25, achado de severidade média).
// Por isso os refresh vindos de pedidos passam pelo orçamento diário
// CACHE_WRITE_CAP; esgotado, serve-se o valor stale (sem recalcular) ou, sem
// stale, o valor calculado sem o persistir. O cron (`scheduled`) passa
// `{ capped: false }`: o ritmo dele é fixo (a cada 30 min) e já está contado
// no orçamento. A cópia no KV vive STALE_GRACE_SEC além do exp lógico, para
// haver sempre stale que servir enquanto o orçamento do dia está esgotado.
const STALE_GRACE_SEC = 86400;

// Orçamento diário (em escritas) dos refresh de cache vindos de pedidos. Cada
// refresh aceite custa 2 (valor + contador). Soma dos orçamentos diários do
// Worker: vitals 300 + cache 80 + refresh manual 40 + cron (~16:
// ct/cfstats/fw/threatintel; a limpeza do honeypot antigo só escreve uma
// vez) ≈ 440 — abaixo das ~1.000/dia da conta, com margem para a ultrapassagem que
// pedidos concorrentes conseguem (underCap não é atómico, ver lib/kvcap.js).
// O rate limiter já não entra nesta conta: vive na Cache API (ver rateLimit).
const CACHE_WRITE_CAP = { windowMs: DAY_MS, max: 80 };

/**
 * Consome `cost` escritas do orçamento diário `prefix` (contador em
 * `<prefix>:d:<dia>`). Devolve true se cabe (e já registou o consumo — essa
 * é uma das `cost` escritas); false se o orçamento do dia está esgotado, sem
 * escrever nada.
 */
async function consumeWriteBudget(env, prefix, cap, cost, now = Date.now()) {
  const capKey = `${prefix}:${dayKey(now)}`;
  const { allowed, state } = underCap(await getJSON(env, capKey), { now, cost, ...cap });
  if (allowed) {
    await env.KV.put(capKey, JSON.stringify(state), { expirationTtl: Math.ceil(cap.windowMs / 1000) + 60 });
  }
  return allowed;
}

async function cached(env, ctx, key, ttlSec, producer, { capped = true } = {}) {
  const now = Date.now();
  const hit = await getJSON(env, key);
  if (hit && hit.exp > now) return hit.data;
  const refresh = async () => {
    if (capped && !(await consumeWriteBudget(env, 'cachecap', CACHE_WRITE_CAP, 2))) {
      console.error('cache_write_cap_exhausted', key);
      return hit ? hit.data : producer();
    }
    const data = await producer();
    await env.KV.put(key, JSON.stringify({ data, exp: Date.now() + ttlSec * 1000 }), {
      expirationTtl: ttlSec + STALE_GRACE_SEC,
    });
    return data;
  };
  if (hit && ctx) {
    ctx.waitUntil(refresh().catch((err) => console.error('cache_refresh_failed', key, err?.message ?? String(err))));
    return hit.data;
  }
  return refresh();
}

// ---------- rate limiting ----------

// Onde vive o estado por-cliente do rate limiter (auditoria de segurança
// 2026-09-25, docs/security-audit-2026-09-25/, achado de severidade baixa):
//
// No KV, cada pedido aceite custava 2 escritas (estado + contador global) e
// o teto global contava 1 — as 300 "escritas"/dia de RATE_LIMIT_WRITE_CAP
// eram na verdade 600, e um único IP, sem sair dos limites por rota,
// passava das ~1.000 escritas/dia da conta em ~16 minutos (somando a cache
// do relay HIBP, que também escrevia no KV por prefixo novo). Por isso o
// estado passou para a Cache API do data center (lib/edgecache.js): zero
// escritas no KV, e portanto nenhum teto global a esgotar — o "falhar
// fechado para TODOS os visitantes" do ADR 0003 deixa de ser alcançável por
// um só cliente. O limite fica por data center, como na prática já era no
// KV (propagação eventual de ~60s entre colos, ver ADR 0003); uma entrada
// despejada antes do fim da janela só reinicia a contagem desse cliente.
//
// O KV continua como recurso (runtime sem Cache API — Node nos testes, ou um
// Worker com Cloudflare Access à frente, onde a Cache API não existe), com
// o teto global em ESCRITAS (2 por pedido aceite) e a falha FECHADA do achado
// A1 da revisão de 2026-07-29 (docs/security-review-2026-07-29.md): com o
// orçamento esgotado a rota devolve 429 a todos, sem escrever nada, em vez
// de deixar tudo passar com a janela congelada.
const RATE_LIMIT_WRITE_CAP = { windowMs: DAY_MS, max: 300 };
const RATE_LIMIT_WRITE_COST = 2;

// Cap global de escritas dos refresh manuais (/api/cf-stats?refresh=1) —
// o rate limit por cliente desta rota (3/10min) ainda permitia até 432
// escritas/dia por IP, quase metade do teto diário da conta SÓ NESTA ROTA.
// Global (não por-rota) por desenho, para cobrir sem esforço extra qualquer
// outra rota de refresh manual que venha a existir. Descoberto numa revisão
// de segurança (2026-07, ronda 4). Em escritas: cada refresh aceite custa 2
// (contador + cache:cfstats) — os mesmos 20 refresh/dia de antes.
const REFRESH_WRITE_CAP = { windowMs: DAY_MS, max: 40 };

async function rateLimit(env, request, route, { windowMs, max }) {
  if (!env.RATE_SALT) {
    // Falha de configuração silenciosa: sem o segredo, dailySalt cai no
    // fallback de dev ('rotate-me') — o rate limit continua a "funcionar",
    // só que com um salt público e previsível. Tem de ser ruidoso nos logs
    // do Worker (ver [observability] no wrangler.toml), não uma
    // degradação silenciosa.
    console.error('rate_salt_missing', route);
  }
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const salt = dailySalt(env.RATE_SALT);
  const id = await clientHash(ip, salt);
  const key = `rl:${route}:${id}`;
  const now = Date.now();

  const cache = edgeCache();
  if (cache) {
    try {
      const url = edgeKey(request.url, key);
      const { allowed, state, retryAfterSec } = nextState(await edgeGetJSON(cache, url), { now, windowMs, max });
      // Bloqueado ⇒ o estado não mudou — nada a guardar.
      if (allowed) await edgePutJSON(cache, url, state, (state.windowStart + windowMs - now) / 1000 + 1);
      return { allowed, retryAfterSec };
    } catch (err) {
      // Cache API em falha: segue para o caminho KV abaixo (com o seu teto
      // global e a falha fechada), em vez de rebentar a rota com um 502.
      console.error('ratelimit_edge_cache_failed', route, err?.message ?? String(err));
    }
  }

  const prev = await getJSON(env, key);
  const { allowed, state, retryAfterSec } = nextState(prev, { now, windowMs, max });
  // Bloqueado ⇒ o estado não mudou (nextState devolve a mesma contagem) —
  // não se gasta uma escrita KV por pedido recusado, senão martelar a rota
  // transformava cada 429 num put pago. O put só acontece quando conta E
  // quando o cap GLOBAL diário do próprio rate limiter ainda tem margem.
  if (allowed) {
    const capKey = `rlcap:${dayKey(now)}`;
    const capPrev = await getJSON(env, capKey);
    const { allowed: capAllowed, state: capState } = underCap(capPrev, {
      now, cost: RATE_LIMIT_WRITE_COST, ...RATE_LIMIT_WRITE_CAP,
    });
    if (!capAllowed) {
      // Orçamento de escrita do dia esgotado: falhar FECHADO (ver o
      // comentário de RATE_LIMIT_WRITE_CAP acima) em vez de deixar
      // `allowed: true` passar sem persistir estado — sem escrever nada,
      // exatamente como um 429 normal.
      console.error('ratelimit_write_cap_exhausted', route);
      const capRetrySec = Math.max(1, Math.ceil((capState.windowStart + RATE_LIMIT_WRITE_CAP.windowMs - now) / 1000));
      return { allowed: false, retryAfterSec: capRetrySec };
    }
    await Promise.all([
      env.KV.put(key, JSON.stringify(state), { expirationTtl: Math.ceil(windowMs / 1000) + 1 }),
      env.KV.put(capKey, JSON.stringify(capState), {
        expirationTtl: Math.ceil(RATE_LIMIT_WRITE_CAP.windowMs / 1000) + 60,
      }),
    ]);
  }
  return { allowed, retryAfterSec };
}

/**
 * Resposta JSON calculada por `compute` e guardada na Cache API do data
 * center durante `ttlSec` — à frente do KV, para que tráfego repetido nas
 * rotas públicas não custe nem leituras nem escritas no KV. Sem Cache API
 * (Node/testes), calcula sempre.
 */
async function edgeCached(request, key, ttlSec, compute) {
  const cache = edgeCache();
  if (!cache) return compute();
  const url = edgeKey(request.url, key);
  // A Cache API é best-effort: uma falha na leitura é um miss, e uma falha
  // na escrita não pode transformar uma resposta já calculada num 502.
  let hit = null;
  try {
    hit = await edgeGetJSON(cache, url);
  } catch (err) {
    console.error('edge_cache_read_failed', key, err?.message ?? String(err));
  }
  if (hit !== null) return hit;
  const data = await compute();
  try {
    await edgePutJSON(cache, url, data, ttlSec);
  } catch (err) {
    console.error('edge_cache_write_failed', key, err?.message ?? String(err));
  }
  return data;
}

// ---------- respostas ----------

// Cabeçalhos de segurança de TODAS as respostas do Worker. O _headers do
// Pages só cobre o conteúdo estático — as rotas servidas pelo Worker (API)
// respondem por si e, sem isto, saíam sem nosniff nem CSP (e o
// workflow Headers, que verifica a raiz do site, nunca o apanharia). A CSP
// 'none' é a prática padrão para endpoints JSON: mesmo com tudo sanitizado,
// garante que nada executa se um browser renderizar a resposta diretamente.
const RESPONSE_SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'content-security-policy': "default-src 'none'",
  // O _headers do Pages cobre o conteúdo estático; sem isto, as respostas
  // da API do Worker saíam sem HSTS — inofensivo hoje (a
  // zona já força HTTPS), mas um scanner externo assinala a ausência, e
  // este é literalmente um site sobre cabeçalhos de segurança. Mesmo
  // max-age do _headers (2 anos), sem "preload" pelo mesmo motivo (ver lá).
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
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

    // Preflight CORS.
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: { ...RESPONSE_SECURITY_HEADERS, ...corsHeaders(request, env) },
      });
    }

    // Beacon de Core Web Vitals (RUM first-party). Único POST público do
    // Worker — defesa em camadas: Content-Type restrito (navigator.sendBeacon
    // envia text/plain por omissão), corpo minúsculo, rate limit por
    // cliente, cap global de escritas, e só agregados no KV. A resposta é
    // sempre 204 (aceite ou descartado — indistinguível).
    if (path === '/api/vitals' && request.method === 'POST') {
      const ctype = (request.headers.get('content-type') ?? '').split(';')[0].trim().toLowerCase();
      if (ctype !== '' && ctype !== 'application/json' && ctype !== 'text/plain') {
        return json({ error: 'unsupported_media_type' }, request, env, { status: 415 });
      }
      // Fora do try/catch do router (este POST vem antes dele): uma falha do
      // rate limiter (KV/Cache API) tem de dar a mesma resposta uniforme de
      // qualquer beacon descartado, não uma exceção por tratar.
      let limit;
      try {
        limit = await rateLimit(env, request, 'vitals', { windowMs: 60_000, max: 30 });
      } catch (err) {
        console.error('vitals_ratelimit_failed', err?.message ?? String(err));
        return new Response(null, { status: 204, headers: RESPONSE_SECURITY_HEADERS });
      }
      const { allowed, retryAfterSec } = limit;
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
      if (text.length > VITALS_MAX_BODY) {
        return json({ error: 'payload_too_large' }, request, env, { status: 413 });
      }
      let sample = null;
      try {
        sample = normalizeVitals(JSON.parse(text));
      } catch {
        sample = null;
      }
      if (sample) {
        ctx.waitUntil(
          recordVitals(env, sample, Date.now()).catch((err) =>
            console.error('vitals_write_failed', err?.message ?? String(err)),
          ),
        );
      }
      return new Response(null, { status: 204, headers: RESPONSE_SECURITY_HEADERS });
    }

    if (request.method !== 'GET') {
      return json({ error: 'method_not_allowed' }, request, env, { status: 405 });
    }

    try {
      if (path === '/api/health') {
        return json({ ok: true, ts: Date.now() }, request, env);
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
        // Cache por prefixo na Cache API, não no KV (auditoria de segurança
        // 2026-09-25): o prefixo é escolhido pelo cliente, por isso cada
        // prefixo novo era uma escrita KV fora de qualquer teto — ~300/dia
        // a partir de um só IP dentro do rate limit.
        const data = await edgeCached(request, `pwned:${prefix}`, 86400, async () => ({
          suffixes: await fetchRange(prefix, { timeoutMs: UPSTREAM_TIMEOUT_MS }),
        }));
        return json(data, request, env, { maxAge: 3600 });
      }

      // Repartição da firewall da zona, acumulada a 7 dias a partir dos
      // snapshots diários do cron (fw:<dia>) — nunca IP. O nome da rota vem
      // de quando também servia os dashboards do honeypot (ADR 0022); as
      // páginas Cloudflare e Visão Geral continuam a lê-la por este nome.
      // Cache 6h no KV (aquecida no cron) e 5 min no data center.
      if (path === '/api/threat-intel') {
        const data = await edgeCached(request, 'threatintel', 300, () =>
          cached(env, ctx, 'cache:threatintel', 6 * 3600, async () => ({
            firewall7d: await readFirewall7d(env, Date.now()),
          })),
        );
        return json(data, request, env, { maxAge: 300 });
      }

      // Core Web Vitals (RUM): p75 por métrica dos últimos 7 dias, dos
      // histogramas acumulados pelo beacon. Só agregados.
      if (path === '/api/vitals') {
        const data = await edgeCached(request, 'vitals', 120, () =>
          cached(env, ctx, 'cache:vitals', 120, async () =>
            vitalsStats(await readVitalsBuckets(env, Date.now())),
          ),
        );
        return json(data, request, env, { maxAge: 120 });
      }

      // Vigia CT: emissões de certificados para o próprio domínio, dos logs
      // públicos de Certificate Transparency (crt.sh). Sem input de
      // visitantes (a query é fixa — não é reutilizável como proxy), por
      // isso sem rate limit próprio: a cache de 6h com SWR já garante que
      // o crt.sh só é consultado de longe em longe.
      if (path === '/api/ct') {
        const data = await edgeCached(request, 'ct', 1800, () =>
          cached(env, ctx, 'cache:ct', 6 * 3600, () => fetchCtWatch(env)),
        );
        return json(data, request, env, { maxAge: 1800 });
      }

      // Estado da zona Cloudflare: pedidos/cache/ameaças da zona e
      // invocações/erros deste Worker, via GraphQL Analytics API (dados só
      // desta zona/conta — não é o Radar, que é global e anónimo). A cache
      // de 6h já limita a frequência com que se bate na API da Cloudflare;
      // o ?refresh=1 força um pedido novo antes disso — por aceitar input (o
      // parâmetro), leva rate limit apertado.
      if (path === '/api/cf-stats') {
        const refresh = url.searchParams.get('refresh') === '1';
        if (refresh) {
          const { allowed, retryAfterSec } = await rateLimit(env, request, 'cfstats', {
            windowMs: 10 * 60_000,
            max: 3,
          });
          if (!allowed) {
            return json({ error: 'rate_limited' }, request, env, {
              status: 429,
              extra: { 'retry-after': String(retryAfterSec) },
            });
          }
          // Cap global de refresh manuais (ver REFRESH_WRITE_CAP).
          if (!(await consumeWriteBudget(env, 'refreshcap', REFRESH_WRITE_CAP, 2))) {
            const data = await edgeCached(request, 'cfstats', 1800, () =>
              cached(env, ctx, 'cache:cfstats', 6 * 3600, () => fetchCfStats(env)),
            );
            return json(data, request, env, { maxAge: 1800 });
          }
          const data = await fetchCfStats(env);
          await env.KV.put('cache:cfstats', JSON.stringify({ data, exp: Date.now() + 6 * HOUR_MS }), {
            expirationTtl: 6 * 3600 + 60,
          });
          // A cópia do data center também passa a ser a fresca — senão os GET
          // normais seguintes neste colo continuavam a ver a antiga até 30 min.
          const cache = edgeCache();
          if (cache) {
            await edgePutJSON(cache, edgeKey(request.url, 'cfstats'), data, 1800).catch((err) =>
              console.error('edge_cache_write_failed', 'cfstats', err?.message ?? String(err)),
            );
          }
          return json(data, request, env);
        }
        const data = await edgeCached(request, 'cfstats', 1800, () =>
          cached(env, ctx, 'cache:cfstats', 6 * 3600, () => fetchCfStats(env)),
        );
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

  // Cron (ver wrangler.toml): aquece as caches para que a 1.ª visita após
  // expirar não pague a latência do upstream, e limpa o que o honeypot
  // interno deixou no KV (ADR 0022 — só escreve enquanto houver o que apagar).
  async scheduled(event, env, ctx) {
    ctx.waitUntil(
      (async () => {
        await purgeLegacyHoneypotKeys(env).catch((err) =>
          console.error('legacy_honeypot_purge_failed', err?.message ?? String(err)),
        );

        await Promise.all([
          cached(env, ctx, 'cache:ct', 6 * 3600, () => fetchCtWatch(env), { capped: false }).catch(() => {}),
          // Estado da Cloudflare + snapshot diário da firewall (acumula 7d).
          // O snapshot vive dentro do producer do `cached()` — corre só
          // quando o cfstats É DE FACTO REFRESCADO (~4×/dia, TTL 6h), não em
          // cada um dos 48 ticks do cron: como `cached()` devolve o mesmo
          // valor em cache nos ticks intermédios, fotografar nesses ticks só
          // reescrevia a mesma coisa em KV sem qualquer ganho de frescura (o
          // dado só muda quando o próprio fetchCfStats corre).
          cached(env, ctx, 'cache:cfstats', 6 * 3600, async () => {
            const stats = await fetchCfStats(env);
            await snapshotFirewall(env, stats, Date.now()).catch(() => {});
            return stats;
          }, { capped: false }).catch(() => {}),
          // Firewall 7d: aquece-se aqui para as visitas caírem sempre em
          // cache (TTL 6h, ver a rota /api/threat-intel).
          cached(env, ctx, 'cache:threatintel', 6 * 3600, async () => ({
            firewall7d: await readFirewall7d(env, Date.now()),
          }), { capped: false }).catch(() => {}),
        ]);
      })(),
    );
  },
};

