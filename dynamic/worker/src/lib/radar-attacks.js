// Globo "ataques na última hora" — dados GLOBAIS da Cloudflare Radar (não
// ataques a este site). Endpoint: GET /radar/attacks/layer7/top/attacks, que
// devolve os pares país de origem → país alvo dos ataques de camada 7
// mitigados pela Cloudflare, em percentagem do total (com país de faturação).
//
// Janela: o `dateRange` do Radar só aceita `<n>d`/`<n>w` (o mínimo é 1d), por
// isso a "última hora" pede-se com dateStart/dateEnd — o Radar arredonda
// ambos para baixo ao quarto de hora, por isso o pedido já vai alinhado a
// 15 min (senão uma hora "desalinhada" podia ser recusada).
//
// Layer 3 (`/radar/attacks/layer3/top/attacks`) foi avaliado e fica de fora:
// só devolve o país de ORIGEM (sem alvo), por isso não dá arcos — seria um
// ranking à parte, sem justificação para mais um pedido e mais escritas KV.
//
// Como em ct.js/cf-analytics.js: a normalização (pura, testável) está
// separada do fetch (rede). Nada da resposta chega ao cliente sem passar por
// `normalizeRadarAttacks`: códigos ISO-3166-1 alfa-2 atribuídos, percentagem
// finita em [0, 100], pares duplicados descartados, teto de pares.

export const RADAR_ATTACKS_WINDOW = '1h';
export const RADAR_ATTACKS_MAX_PAIRS = 30;
const WINDOW_MS = 3600_000;
const QUARTER_MS = 15 * 60_000;

// Códigos ISO 3166-1 alfa-2 oficialmente atribuídos (249) + XK (Kosovo,
// código de utilizador que a Cloudflare usa). Um par com "XX", "T1", "EU" ou
// "ZZ" não é um país e não tem centróide — sai.
const ISO_ALPHA2 = new Set(`
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL
BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV
CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD
GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM
IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK
LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW
MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR
PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS
ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY
UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW XK
`.trim().split(/\s+/));

/** Código alfa-2 atribuído, em maiúsculas, ou null. */
export function normalizeAlpha2(input) {
  if (typeof input !== 'string') return null;
  const code = input.trim().toUpperCase();
  return ISO_ALPHA2.has(code) ? code : null;
}

/**
 * Percentagem do Radar (vem como string, ex. "4.323214") → número finito em
 * [0, 100], arredondado a 4 casas, ou null. `Number('')` é 0 e
 * `Number(' ')` também — por isso uma string tem de ser um decimal escrito.
 */
export function normalizePct(input) {
  let value = input;
  if (typeof value === 'string') {
    if (!/^\d+(\.\d+)?([eE][-+]?\d+)?$/.test(value.trim())) return null;
    value = Number(value);
  }
  if (typeof value !== 'number' || !Number.isFinite(value)) return null;
  if (value < 0 || value > 100) return null;
  return Math.round(value * 1e4) / 1e4;
}

/** Janela pedida ao Radar: a última hora completa, alinhada a 15 min. */
export function radarWindow(now) {
  const end = Math.floor(now / QUARTER_MS) * QUARTER_MS;
  return { start: end - WINDOW_MS, end };
}

/** URL do pedido ao Radar para a janela de `radarWindow(now)`. */
export function radarAttacksUrl(now, limit = RADAR_ATTACKS_MAX_PAIRS) {
  const { start, end } = radarWindow(now);
  const params = new URLSearchParams({
    dateStart: new Date(start).toISOString(),
    dateEnd: new Date(end).toISOString(),
    limit: String(limit),
    format: 'JSON',
  });
  return `https://api.cloudflare.com/client/v4/radar/attacks/layer7/top/attacks?${params}`;
}

const isoOr = (value, fallbackMs) => {
  const ms = typeof value === 'string' ? Date.parse(value) : NaN;
  return new Date(Number.isFinite(ms) ? ms : fallbackMs).toISOString();
};

/**
 * Resposta crua do Radar → o que fica no KV e o endpoint serve:
 *   { ok: true, window, start, end, fetched, pairs: [[origem, alvo, pct], …] }
 * ou { ok: false, error } quando a resposta não serve (success:false, sem
 * pares válidos). `start`/`end` são os da resposta (meta.dateRange, já
 * ajustados pelo Radar); sem eles, os da janela pedida.
 */
export function normalizeRadarAttacks(raw, { now = Date.now(), max = RADAR_ATTACKS_MAX_PAIRS } = {}) {
  if (raw?.success !== true) return { ok: false, error: 'upstream_unsuccessful' };
  const rows = raw?.result?.top_0;
  if (!Array.isArray(rows)) return { ok: false, error: 'bad_shape' };
  const seen = new Set();
  const pairs = [];
  for (const row of rows) {
    const origin = normalizeAlpha2(row?.originCountryAlpha2);
    const target = normalizeAlpha2(row?.targetCountryAlpha2);
    const pct = normalizePct(row?.value);
    if (!origin || !target || pct === null) continue;
    const key = `${origin}>${target}`;
    if (seen.has(key)) continue;
    seen.add(key);
    pairs.push([origin, target, pct]);
  }
  if (pairs.length === 0) return { ok: false, error: 'empty' };
  pairs.sort((a, b) => b[2] - a[2]);
  const requested = radarWindow(now);
  const range = Array.isArray(raw.result.meta?.dateRange) ? raw.result.meta.dateRange[0] : null;
  return {
    ok: true,
    window: RADAR_ATTACKS_WINDOW,
    start: isoOr(range?.startTime, requested.start),
    end: isoOr(range?.endTime, requested.end),
    fetched: new Date(now).toISOString(),
    pairs: pairs.slice(0, Math.max(0, max)),
  };
}

/**
 * Pede ao Radar a última hora e normaliza. Nunca lança por resposta da API:
 * devolve `{ ok: false, error }` — `forbidden` quando o token não tem
 * Account → Radar → Read (401/403), `http_<status>` noutros casos. Só um erro
 * de rede/timeout lança. O cron decide o que gravar (ver index.js).
 */
export async function fetchRadarAttacks(env, { now = Date.now(), timeoutMs = 8000 } = {}) {
  if (!env.CF_API_TOKEN) return { ok: false, error: 'not_configured' };
  const res = await fetch(radarAttacksUrl(now), {
    headers: { authorization: `Bearer ${env.CF_API_TOKEN}`, accept: 'application/json' },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (res.status === 401 || res.status === 403) return { ok: false, error: 'forbidden' };
  if (!res.ok) return { ok: false, error: `http_${res.status}` };
  let raw;
  try {
    raw = await res.json();
  } catch {
    return { ok: false, error: 'bad_json' };
  }
  return normalizeRadarAttacks(raw, { now });
}
