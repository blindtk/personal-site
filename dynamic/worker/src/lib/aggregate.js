// Agregação dos eventos do honeypot. Puro e testável — recebe buckets já
// lidos do KV e devolve as formas que as páginas consomem. Nunca vê IPs:
// os eventos só têm país (cf-ipcountry), ASN e path.

/** Bucket vazio de contagens. */
export function emptyBucket() {
  return { total: 0, byCountry: {}, byPath: {} };
}

/** Incrementa um bucket com um evento {country, path} (usado na escrita). */
export function addEvent(bucket, { country, path }) {
  bucket.total += 1;
  if (country) bucket.byCountry[country] = (bucket.byCountry[country] ?? 0) + 1;
  if (path) bucket.byPath[path] = (bucket.byPath[path] ?? 0) + 1;
  return bucket;
}

/** Soma vários buckets num só. Ignora entradas nulas/ausentes. */
export function mergeBuckets(buckets) {
  const out = emptyBucket();
  for (const b of buckets) {
    if (!b) continue;
    out.total += b.total ?? 0;
    for (const [k, v] of Object.entries(b.byCountry ?? {})) out.byCountry[k] = (out.byCountry[k] ?? 0) + v;
    for (const [k, v] of Object.entries(b.byPath ?? {})) out.byPath[k] = (out.byPath[k] ?? 0) + v;
  }
  return out;
}

/** Chave do par com maior contagem, ou null se vazio. */
function topKey(counts) {
  let best = null;
  let bestN = -1;
  for (const [k, v] of Object.entries(counts)) {
    if (v > bestN) { best = k; bestN = v; }
  }
  return best;
}

/**
 * Stats para /api/honeypot.
 *   hourly  — buckets das últimas 24 horas (array)
 *   days    — buckets dos últimos 7 dias (array)
 *   recent  — lista dos últimos eventos {ts,country,asn,path} (para a tabela)
 *   meta    — { firstScanTs, deployTs } (epoch ms) ou {}
 */
export function honeypotStats({ hourly = [], days = [], recent = [], meta = {} }) {
  const last24 = mergeBuckets(hourly);
  const week = mergeBuckets(days);
  const timeToFirstScanSec =
    meta.firstScanTs && meta.deployTs && meta.firstScanTs >= meta.deployTs
      ? Math.round((meta.firstScanTs - meta.deployTs) / 1000)
      : null;
  return {
    attempts24h: last24.total,
    topPath: topKey(last24.byPath) ?? topKey(week.byPath),
    countryCount: Object.keys(week.byCountry).length,
    timeToFirstScanSec,
    recent: recent.slice(0, 30),
    // Contagens por path-isco na janela de 7 dias — alimenta a página
    // Deteções (contador ao vivo ao lado de cada regra Sigma).
    paths7d: Object.entries(week.byPath)
      .map(([path, count]) => ({ path, count }))
      .sort((a, b) => b.count - a.count),
  };
}

/** Ordena um mapa país→contagem numa lista decrescente. */
function toSortedList(byCountry) {
  return Object.entries(byCountry)
    .map(([country, count]) => ({ country, count }))
    .sort((a, b) => b.count - a.count);
}

/** Dados para /api/map: origens por país em duas janelas + totais. */
export function mapData({ hourly = [], days = [] }) {
  const last24 = mergeBuckets(hourly);
  const week = mergeBuckets(days);
  return {
    last24h: toSortedList(last24.byCountry),
    last7d: toSortedList(week.byCountry),
    totals: { events7d: week.total, countries7d: Object.keys(week.byCountry).length },
  };
}
