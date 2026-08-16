// Cloudflare Worker — backend das features de segurança do site (Bloco 3).
// Um só Worker, um só namespace KV (chaves com prefixo). Serve:
//   · endpoints-isco do honeypot (404 + metadados; o IP de origem entra
//     numa lista separada e é publicado — ADR 0020, ver comentário em
//     recordHoneypot mais abaixo. Os buckets/eventos "normais" continuam
//     sem IP, exatamente como sempre.)
//   · /api/honeypot, /api/map  — painel + mapa de tráfego hostil
//   · /api/pwned-range         — relay k-anónimo do HIBP (cache 24h por prefixo)
//   · /api/ticker              — CISA KEV + NVD (cache 1h, sanitizado)
//   · /api/ct                  — vigia CT: emissões de certificados p/ o domínio (cache 6h)
//   · /api/cf-stats            — estado da zona Cloudflare: pedidos/cache/Worker (cache 6h)
//   · /api/threat-intel        — dashboards de threat intel do honeypot + firewall 7d (cache 6h)
//   · /api/vitals (GET)        — Core Web Vitals p75 (RUM, 7d)
//   · /api/vitals (POST)       — beacon RUM first-party (agregados, sem PII)
//   · /api/health
// Ver README.md para deploy (routes no domínio vs. workers.dev) e secrets.

import {
  emptyBucket, addEvent, honeypotStats, mapData, threatIntel, THREAT_INTEL_HOURS, mergeFirewall7d,
} from './lib/aggregate.js';
import {
  normalizeVitals, emptyVitalsBucket, addVitals, vitalsStats,
} from './lib/vitals.js';
import { nextState, clientHash, dailySalt } from './lib/ratelimit.js';
import { underCap } from './lib/kvcap.js';
import { fetchTicker } from './lib/feeds.js';
import { normalizePrefix, fetchRange } from './lib/pwned.js';
import { fetchCtWatch } from './lib/ct.js';
import { fetchCfStats } from './lib/cf-analytics.js';
import { serverView } from './lib/mirror.js';
import { clampInt, normalizeCountry, normalizeAsn, floorToWindow } from './lib/sanitize.js';
import { techniqueForPath } from './lib/attack-map.js';
import { renderNotFoundHtml, NOT_FOUND_CSP } from './lib/notfound.js';
import { isDecoy } from './lib/decoys.js';
import { isPublicIp } from './lib/ipguard.js';
import {
  emptyIpList, recordIpSighting, pruneExpiredIps, ipThreatList,
} from './lib/ipthreat.js';

const HOUR_MS = 3600_000;
const DAY_MS = 86400_000;

// Anonimização: os eventos do honeypot guardam o timestamp arredondado a
// esta janela (5 min), para não permitir correlação por instante preciso.
const ANON_WINDOW_MS = 5 * 60_000;

// Cap global de escritas do honeypot por DIA (não por hora): limita
// custo/abuso se alguém martelar os paths-isco. Ver lib/kvcap.js. O plano
// Free tem um teto de ~1.000 escritas/dia PARA A CONTA INTEIRA, partilhado
// com rate-limit/vitals/cron — um cap por HORA generoso (o valor antigo,
// 500/h) deixava um único burst de scanners consumir sozinho vários dias de
// quota (500 eventos × 4-5 escritas = até 2.500 escritas numa hora, mais do
// que o teto diário inteiro). Por isso o cap passou a ser diário e mais
// apertado: 60 eventos/dia × 5 escritas (4 dos buckets anónimos + 1 da
// lista de IPs, ADR 0020) ≈ 300/dia, uma fatia do orçamento que deixa
// espaço para o resto. Trade-off consciente: sob scanning pesado
// sustentado, eventos a mais no mesmo dia são descartados (o 404 continua a
// sair) — perde-se granularidade no Threat Intel, não a proteção do core.
const HONEYPOT_WRITE_CAP = { windowMs: DAY_MS, max: 60 };

// ADR 0020 (docs/adr/0020-honeypot-public-ip.md): retenção da lista de
// IPs, mais curta que a do projeto irmão (VPS externa, 60-90 dias — ver
// docs/external-honeypot-vps.md §3). Scanners HTTP (o que este honeypot
// apanha) têm mais chance de correr em IoT/routers domésticos
// comprometidos do que os de força bruta SSH da VPS — janela mais curta
// é a postura mais conservadora das duas, de propósito.
const IP_RETENTION_MS = 30 * DAY_MS;

// Timeout para fetches a montante (relay do HIBP em /api/pwned-range) — não
// deixar um alvo lento pendurar o pedido.
const UPSTREAM_TIMEOUT_MS = 5000;

// RUM de Core Web Vitals: corpo minúsculo (4 números), teto de escritas POR
// DIA (mesmo padrão do honeypot — ver comentário acima). Só agregados; ver
// lib/vitals.js. 150 amostras/dia × 2 escritas = 300/dia: o valor antigo
// (5.000/hora) media a resiliência a abuso, não o orçamento real do plano
// Free — tráfego orgânico normal já bastava para estourar o teto diário
// muito antes de qualquer flood malicioso.
const VITALS_MAX_BODY = 2 * 1024;
const VITALS_WRITE_CAP = { windowMs: DAY_MS, max: 150 };

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
  // Os buckets anónimos (aggregate.js) continuam exatamente como sempre:
  // NUNCA o IP, timestamp arredondado a ANON_WINDOW_MS. O IP de origem só
  // entra na lista separada `iplist` (lib/ipthreat.js) — decisão explícita
  // do dono do repo (ADR 0020, docs/adr/0020-honeypot-public-ip.md), não
  // um relaxamento silencioso desta função. As duas fontes nunca se
  // misturam: `event` (abaixo) nunca ganha um campo `ip`.
  const country = normalizeCountry(request.headers.get('cf-ipcountry') || request.cf?.country);
  const asn = normalizeAsn(request.cf?.asn);
  const ts = floorToWindow(now, ANON_WINDOW_MS);
  // Lookup local (sem rede): anexa a técnica ATT&CK do path-isco ao evento,
  // para que o registo em KV já conte a que classe de ataque corresponde.
  const technique = techniqueForPath(path);
  const event = { ts, country, asn, path, technique };

  // IP: só entra na lista se for público e válido (lib/ipguard.js) —
  // gamas privadas/reservadas nunca deviam chegar aqui vindas da
  // Cloudflare, mas valida-se na mesma (defesa em profundidade).
  const ip = request.headers.get('cf-connecting-ip');
  const ipValid = isPublicIp(ip);

  const capKey = `wcap:${dayKey(now)}`;
  const [recent, hBucket, dBucket, meta, capPrev, ipList] = await Promise.all([
    getJSON(env, 'recent', []),
    getJSON(env, hourKey(now), emptyBucket()),
    getJSON(env, dayKey(now), emptyBucket()),
    getJSON(env, 'meta', {}),
    getJSON(env, capKey),
    ipValid ? getJSON(env, 'iplist', emptyIpList()) : null,
  ]);

  // Cap de escritas por janela: passado o teto, descarta o evento (o
  // pedido já devolveu 404 na mesma) para não inflacionar o custo do KV.
  const { allowed, state: capState } = underCap(capPrev, { now, ...HONEYPOT_WRITE_CAP });
  if (!allowed) return;

  // 200 (não 30): a tabela de Registo da Threat Intelligence pagina/pesquisa
  // sobre esta lista. Continua a ser só metadados por evento — nunca o IP,
  // mesmo depois do ADR 0020 (que só toca `iplist`, abaixo).
  const nextRecent = [event, ...recent].slice(0, 200);
  addEvent(hBucket, event);
  addEvent(dBucket, event);

  // deployTs vem de var no deploy; firstScanTs = 1.ª tentativa alguma vez vista.
  const deployTs = meta.deployTs ?? clampInt(env.DEPLOY_TS, 0, Number.MAX_SAFE_INTEGER, ts);
  const nextMeta = { deployTs, firstScanTs: meta.firstScanTs ?? ts };
  // meta só muda mesmo na 1.ª vez (deployTs/firstScanTs, uma vez definidos,
  // nunca voltam a mudar) — poupa 1 escrita/evento em todos os seguintes.
  const metaChanged = meta.deployTs !== nextMeta.deployTs || meta.firstScanTs !== nextMeta.firstScanTs;

  const writes = [
    env.KV.put('recent', JSON.stringify(nextRecent)),
    env.KV.put(hourKey(now), JSON.stringify(hBucket), { expirationTtl: 8 * 86400 }),
    env.KV.put(dayKey(now), JSON.stringify(dBucket), { expirationTtl: 9 * 86400 }),
    env.KV.put(capKey, JSON.stringify(capState), { expirationTtl: Math.ceil(HONEYPOT_WRITE_CAP.windowMs / 1000) + 60 }),
  ];
  if (metaChanged) writes.push(env.KV.put('meta', JSON.stringify(nextMeta)));
  if (ipValid) {
    recordIpSighting(ipList, { ip, now, country, asn, technique });
    // TTL generoso como rede de segurança (a poda real é por entrada, no
    // cron — ver pruneIpList/scheduled() abaixo): se o Worker ficar sem
    // tráfego de todo por mais tempo que isto, a chave inteira cai sozinha
    // em vez de crescer para sempre num site esquecido.
    writes.push(
      env.KV.put('iplist', JSON.stringify(ipList), { expirationTtl: Math.ceil((IP_RETENTION_MS * 2) / 1000) }),
    );
  }
  await Promise.all(writes);
}

/**
 * Poda entradas de `iplist` sem nova deteção há mais de IP_RETENTION_MS
 * (ADR 0020). Só escreve no KV quando algo foi mesmo removido — mesmo
 * princípio de `snapshotFirewall`/`cached()`: não reescrever o que não
 * mudou. Quando remove alguma coisa, invalida também `cache:threatintel`
 * (guarda `ips` por 6h) — sem isto, um IP podado continuava a ser servido
 * pela cache até 6h a mais do que a retenção promete (achado de revisão).
 * `env.KV.delete` é idempotente sobre uma chave já ausente, por isso não
 * precisa de verificar se a cache existe primeiro.
 */
async function pruneIpList(env, now) {
  const ipList = await getJSON(env, 'iplist', emptyIpList());
  const { list, prunedCount } = pruneExpiredIps(ipList, { now, maxAgeMs: IP_RETENTION_MS });
  if (prunedCount === 0) return;
  await Promise.all([
    env.KV.put('iplist', JSON.stringify(list), {
      expirationTtl: Math.ceil((IP_RETENTION_MS * 2) / 1000),
    }),
    env.KV.delete('cache:threatintel'),
  ]);
}

// ---------- Core Web Vitals (RUM): escrita/leitura ----------

const vitalsDayKey = (ms) => `vit:${new Date(ms).toISOString().slice(0, 10)}`; // vit:2026-07-24

/**
 * Acumula uma amostra de Web Vitals já normalizada no histograma diário. Só
 * agregados — nenhum valor individual, IP ou UA é persistido. Cap global de
 * escritas por janela, como o honeypot.
 */
async function recordVitals(env, sample, now) {
  const capKey = `vitcap:${dayKey(now)}`;
  const dayK = vitalsDayKey(now);
  const [bucket, capPrev] = await Promise.all([
    getJSON(env, dayK, emptyVitalsBucket()),
    getJSON(env, capKey),
  ]);
  const { allowed, state } = underCap(capPrev, { now, ...VITALS_WRITE_CAP });
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

// ---------- Threat Intelligence: leitura dos buckets acumulados ----------

/**
 * Lê os buckets horários (THREAT_INTEL_HOURS = 7d, para o heatmap/hora-do-dia)
 * + diários (7d, para os tops por país/ASN/técnica/path) + os eventos
 * recentes (Logs). Cada bucket horário vai com o `ms` do início da hora, para
 * a agregação o poder posicionar no heatmap.
 */
async function readThreatBuckets(env, now) {
  const hourStamps = Array.from({ length: THREAT_INTEL_HOURS }, (_, i) => now - i * HOUR_MS);
  const dayKeys = Array.from({ length: 7 }, (_, i) => dayKey(now - i * DAY_MS));
  const [hourlyBuckets, days, recent] = await Promise.all([
    Promise.all(hourStamps.map((ms) => getJSON(env, hourKey(ms)))),
    Promise.all(dayKeys.map((k) => getJSON(env, k))),
    getJSON(env, 'recent', []),
  ]);
  const hourlySeries = hourStamps.map((ms, i) => ({ ms, bucket: hourlyBuckets[i] }));
  return { hourlySeries, days, recent };
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
 * lib/aggregate.js — pura e testável) em tops por ação/origem/rede/país MAIS
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

// ---------- rate limiting ----------

// Teto global (não por-cliente) de escritas do PRÓPRIO rate limiter, por
// dia — mesmo padrão do honeypot/vitals (ver lib/kvcap.js). Sem isto,
// um cliente dentro do limite por rota (ex.: 30/min em /api/mirror ou
// /api/vitals) força até ~43 mil escritas/dia SÓ NESTA ROTA — muito acima
// do teto de ~1.000 escritas/dia da conta inteira no plano Free, e
// esgotá-lo apaga o orçamento de que honeypot/vitals/snapshot de
// firewall dependem (todos escrevem no mesmo KV, mesma conta — descoberto
// numa revisão de segurança, 2026-07).
//
// Passado este cap, `rateLimit()` FALHA FECHADO (achado de uma revisão de
// segurança, 2026-07-29 — docs/security-review-2026-07-29.md, achado A1):
// a versão anterior continuava a devolver `allowed: true` sem persistir o
// estado por-cliente, o que congelava a janela desse cliente para sempre —
// na prática, ~300 pedidos triviais (10 min de tráfego num único cliente
// em /api/mirror+/api/vitals, sem distribuir por IPs) desligavam o rate
// limit da rota inteira até à meia-noite UTC. Falhar fechado inverte o
// trade-off: em vez de "todos os pedidos passam", a rota devolve 429 a
// todos até o cap global re-abrir — sem gastar nenhuma escrita extra (o
// 429 continua grátis, ver o teste "sem nenhum put no KV"). Só afeta as
// rotas que aceitam input de visitante (mirror/vitals/pwned/
// refresh); as leituras públicas sem rate limit (honeypot/map/ticker/ct/
// cf-stats sem refresh) continuam servidas da cache.
const RATE_LIMIT_WRITE_CAP = { windowMs: DAY_MS, max: 300 };

// Cap global de escritas dos refresh manuais (/api/cf-stats?refresh=1) —
// mesma classe de risco da lacuna #1 (rate limiter), descoberta tarde de
// mais e aplicada só ao rate limiter na altura: o rate limit por cliente
// desta rota (3/10min) ainda permite até 432 escritas/dia por IP — quase
// metade do teto diário da conta SÓ NESTA ROTA. Global (não por-rota) por
// desenho, para cobrir sem esforço extra qualquer outra rota de refresh
// manual que venha a existir. Descoberto numa revisão de segurança (2026-07,
// ronda 4).
const REFRESH_WRITE_CAP = { windowMs: DAY_MS, max: 20 };

/**
 * Consome uma unidade do cap partilhado dos refresh manuais. Devolve
 * `true` se a escrita cabe no orçamento do dia (e já regista o consumo);
 * `false` se o cap já foi atingido — o chamador deve degradar para a cache
 * existente em vez de gastar mais orçamento.
 */
async function underRefreshCap(env, now) {
  const capKey = `refreshcap:${dayKey(now)}`;
  const capPrev = await getJSON(env, capKey);
  const { allowed, state } = underCap(capPrev, { now, ...REFRESH_WRITE_CAP });
  if (allowed) {
    await env.KV.put(capKey, JSON.stringify(state), {
      expirationTtl: Math.ceil(REFRESH_WRITE_CAP.windowMs / 1000) + 60,
    });
  }
  return allowed;
}

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
  const prev = await getJSON(env, key);
  const { allowed, state, retryAfterSec } = nextState(prev, { now, windowMs, max });
  // Bloqueado ⇒ o estado não mudou (nextState devolve a mesma contagem) —
  // não se gasta uma escrita KV por pedido recusado, senão martelar a rota
  // transformava cada 429 num put pago. O put só acontece quando conta E
  // quando o cap GLOBAL diário do próprio rate limiter ainda tem margem.
  if (allowed) {
    const capKey = `rlcap:${dayKey(now)}`;
    const capPrev = await getJSON(env, capKey);
    const { allowed: capAllowed, state: capState } = underCap(capPrev, { now, ...RATE_LIMIT_WRITE_CAP });
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
  // O _headers do Pages cobre o conteúdo estático; sem isto, as respostas
  // do Worker (API + 404 dos iscos) saíam sem HSTS — inofensivo hoje (a
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

    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: { ...RESPONSE_SECURITY_HEADERS, ...corsHeaders(request, env) },
      });
    }

    // endpoints-isco: registar (em background) e devolver um 404 visualmente
    // igual ao 404 real do site (lib/notfound.js) — texto simples era um
    // "tell" mais fácil de distinguir do resto do site, não mais difícil.
    if (isDecoy(path)) {
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
      const { allowed, retryAfterSec } = await rateLimit(env, request, 'vitals', {
        windowMs: 60_000,
        max: 30,
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

      // Threat Intelligence: dashboards próprios a partir dos buckets
      // acumulados do honeypot (heatmap, hora-do-dia, top país/ASN/técnica/
      // path, eventos p/ os Logs) + a repartição de firewall acumulada a 7d
      // + a lista de IPs vistos (ADR 0020 — só aqui o IP aparece; o resto
      // desta rota continua zero-IP). Cache 6h (aquecida no cron) — TTL a
      // 5 min dava sempre "stale" quando o cron (30 min) batia, obrigando a
      // reconstruir o fan-out de THREAT_INTEL_HOURS+7+1 leituras a cada
      // tick (~183 GETs × 48/dia). Alinhado com scan/ct/cf-stats (mesmo
      // padrão de cache já usado nesta rota) para não estourar o teto
      // diário do KV no plano Free — ver dynamic/PLAN.md.
      if (path === '/api/threat-intel') {
        const data = await cached(env, ctx, 'cache:threatintel', 6 * 3600, async () => {
          const now = Date.now();
          const [buckets, firewall7d, ipList] = await Promise.all([
            readThreatBuckets(env, now),
            readFirewall7d(env, now),
            getJSON(env, 'iplist', {}),
          ]);
          return { ...threatIntel(buckets), firewall7d, ips: ipThreatList(ipList) };
        });
        return json(data, request, env, { maxAge: 300 });
      }

      // Core Web Vitals (RUM): p75 por métrica dos últimos 7 dias, dos
      // histogramas acumulados pelo beacon. Só agregados.
      if (path === '/api/vitals') {
        const data = await cached(env, ctx, 'cache:vitals', 120, async () =>
          vitalsStats(await readVitalsBuckets(env, Date.now())),
        );
        return json(data, request, env, { maxAge: 120 });
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
          if (!(await underRefreshCap(env, Date.now()))) {
            const data = await cached(env, ctx, 'cache:cfstats', 6 * 3600, () => fetchCfStats(env));
            return json(data, request, env, { maxAge: 1800 });
          }
          const data = await fetchCfStats(env);
          await env.KV.put('cache:cfstats', JSON.stringify({ data, exp: Date.now() + 6 * HOUR_MS }), {
            expirationTtl: 6 * 3600 + 60,
          });
          return json(data, request, env);
        }
        const data = await cached(env, ctx, 'cache:cfstats', 6 * 3600, () => fetchCfStats(env));
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
      (async () => {
        // Poda da lista de IPs do honeypot (ADR 0020) — retenção de
        // IP_RETENTION_MS, aplicada aqui e não no caminho de escrita
        // (recordHoneypot) para não pagar essa leitura/escrita extra em
        // cada evento; o cron já corre a cada 30 min de qualquer forma.
        // AGUARDADA antes do resto (não dentro do Promise.all abaixo): a
        // cache de threat-intel guarda `ips` por 6h, e se corresse em
        // paralelo com o aquecimento dessa cache, uma poda que remove
        // entradas podia perder a corrida contra um refresh que ainda lê
        // o `iplist` de antes da poda — um IP expirado ficava a ser
        // servido pela cache até 6h a mais do que a retenção promete.
        // Sequenciar as duas fecha essa janela.
        await pruneIpList(env, Date.now()).catch(() => {});

        await Promise.all([
          cached(env, ctx, 'cache:ticker', 3600, () => fetchTicker(env)).catch(() => {}),
          cached(env, ctx, 'cache:ct', 6 * 3600, () => fetchCtWatch(env)).catch(() => {}),
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
          }).catch(() => {}),
          // Threat Intel é caro de ler (168 buckets horários) — aquece-se
          // aqui para as visitas caírem sempre em cache. TTL 6h (ver
          // comentário na rota /api/threat-intel) para não repetir o
          // fan-out em todos os ticks do cron.
          cached(env, ctx, 'cache:threatintel', 6 * 3600, async () => {
            const now = Date.now();
            const [buckets, firewall7d, ipList] = await Promise.all([
              readThreatBuckets(env, now),
              readFirewall7d(env, now),
              getJSON(env, 'iplist', {}),
            ]);
            return { ...threatIntel(buckets), firewall7d, ips: ipThreatList(ipList) };
          }).catch(() => {}),
        ]);
      })(),
    );
  },
};

