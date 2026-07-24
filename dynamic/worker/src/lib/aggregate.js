// Agregação dos eventos do honeypot. Puro e testável — recebe buckets já
// lidos do KV e devolve as formas que as páginas consomem. Nunca vê IPs:
// os eventos só têm país (cf-ipcountry), ASN e path.

/** Bucket vazio de contagens. byAsn/byTech acumulam a par de country/path
 *  para alimentar a Threat Intelligence (rede e técnica ATT&CK do atacante) —
 *  ainda só agregados, NUNCA o IP. Buckets antigos sem estes campos degradam
 *  para {} no merge (a acumulação preenche-se ao longo dos dias). */
export function emptyBucket() {
  return { total: 0, byCountry: {}, byPath: {}, byAsn: {}, byTech: {} };
}

/** Incrementa um bucket com um evento {country, path, asn, technique}. */
export function addEvent(bucket, { country, path, asn, technique }) {
  bucket.total += 1;
  if (country) bucket.byCountry[country] = (bucket.byCountry[country] ?? 0) + 1;
  if (path) bucket.byPath[path] = (bucket.byPath[path] ?? 0) + 1;
  // asn é número (ou null): a chave é "AS<n>" para casar com a tabela do
  // Perímetro. É rede, não pessoa — não é PII (já aparece nos eventos crus).
  if (asn) {
    bucket.byAsn ??= {};
    const key = `AS${asn}`;
    bucket.byAsn[key] = (bucket.byAsn[key] ?? 0) + 1;
  }
  if (technique) {
    bucket.byTech ??= {};
    bucket.byTech[technique] = (bucket.byTech[technique] ?? 0) + 1;
  }
  return bucket;
}

/** Soma um mapa chave→contagem de origem sobre o de destino (in place). */
function mergeCounts(dst, src) {
  for (const [k, v] of Object.entries(src ?? {})) dst[k] = (dst[k] ?? 0) + v;
}

/** Soma vários buckets num só. Ignora entradas nulas/ausentes. */
export function mergeBuckets(buckets) {
  const out = emptyBucket();
  for (const b of buckets) {
    if (!b) continue;
    out.total += b.total ?? 0;
    mergeCounts(out.byCountry, b.byCountry);
    mergeCounts(out.byPath, b.byPath);
    mergeCounts(out.byAsn, b.byAsn);
    mergeCounts(out.byTech, b.byTech);
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

// ---------- Threat Intelligence (dashboard dedicado) ----------

/** Quantos buckets horários ler para o heatmap/hora-do-dia (7 dias). */
export const THREAT_INTEL_HOURS = 168;

/** Ordena um mapa chave→contagem em [{key,count}] decrescente, top `limit`. */
function topN(counts, limit = 10) {
  return Object.entries(counts ?? {})
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

/**
 * Agregação para GET /api/threat-intel — dashboards próprios (não são cópia
 * da Cloudflare) a partir dos buckets JÁ acumulados do honeypot. Tudo
 * agregado, zero-PII: por rede (ASN), país, técnica ATT&CK, path-isco, hora
 * do dia e um heatmap dia×hora. Puro e defensivo — shape inesperado → listas
 * vazias, nunca lança.
 *
 *   hourlySeries — [{ ms, bucket }] das últimas THREAT_INTEL_HOURS horas
 *                  (o `ms` é o início da hora, para posicionar no heatmap)
 *   days         — buckets diários (7d), já com byAsn/byTech
 *   recent       — eventos recentes {ts,country,asn,path,technique} p/ os Logs
 */
export function threatIntel({ hourlySeries = [], days = [], recent = [] }, { limit = 10, heatmapDays = 7 } = {}) {
  const week = mergeBuckets(days);

  const byHourOfDay = Array.from({ length: 24 }, () => 0);
  const grid = new Map(); // dateISO(UTC) -> number[24]
  for (const entry of Array.isArray(hourlySeries) ? hourlySeries : []) {
    const ms = entry?.ms;
    if (typeof ms !== 'number' || !Number.isFinite(ms)) continue;
    const total = entry?.bucket?.total ?? 0;
    const dt = new Date(ms);
    const hour = dt.getUTCHours();
    const dateISO = dt.toISOString().slice(0, 10);
    byHourOfDay[hour] += total;
    if (!grid.has(dateISO)) grid.set(dateISO, Array.from({ length: 24 }, () => 0));
    grid.get(dateISO)[hour] += total;
  }

  const heatmap = [...grid.entries()]
    .sort((a, b) => (a[0] < b[0] ? -1 : 1)) // mais antigo primeiro
    .slice(-heatmapDays)
    .map(([date, hours]) => ({ date, hours }));

  const peakHour = byHourOfDay.reduce(
    (best, count, hour) => (count > best.count ? { hour, count } : best),
    { hour: 0, count: -1 },
  );

  return {
    totals: {
      events7d: week.total,
      countries7d: Object.keys(week.byCountry).length,
      asns7d: Object.keys(week.byAsn ?? {}).length,
      techniques7d: Object.keys(week.byTech ?? {}).length,
    },
    topCountries: topN(week.byCountry, limit),
    topAsns: topN(week.byAsn, limit),
    topTechniques: topN(week.byTech, limit),
    topPaths: topN(week.byPath, limit),
    byHourOfDay,
    peakHour: peakHour.count > 0 ? peakHour : null,
    heatmap,
    // Eventos para a tabela de Logs (sem IP — os eventos nunca o têm).
    events: Array.isArray(recent) ? recent.slice(0, 200) : [],
  };
}
