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
  // `deployTs` só é um marco de deploy a sério quando vem da var DEPLOY_TS.
  // Sem essa var, o Worker escreve `deployTs = ts do 1.º evento` — e então
  // `firstScanTs - deployTs` é ZERO por construção, não uma medição. Era o
  // que estava em produção (meta com os dois timestamps iguais): o cartão
  // anunciava "0s até ao 1.º scan", que se lê como um facto e não é um.
  // Igualdade = não medido → null → o painel mostra "—".
  const measurable =
    meta.firstScanTs && meta.deployTs && meta.firstScanTs > meta.deployTs;
  const timeToFirstScanSec = measurable
    ? Math.round((meta.firstScanTs - meta.deployTs) / 1000)
    : null;
  return {
    attempts24h: last24.total,
    topPath: topKey(last24.byPath) ?? topKey(week.byPath),
    countryCount: Object.keys(week.byCountry).length,
    timeToFirstScanSec,
    recent: recent.slice(0, 30),
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

  // Atacantes novos vs. recorrentes — por REDE (ASN), nunca por IP. Só com os
  // buckets diários já existentes: para cada ASN conta-se em quantos dos 7 dias
  // apareceu (days[0] = hoje). Recorrente = ≥2 dias; novo = só no dia mais
  // recente e em nenhum anterior (primeira vez visto na janela).
  const daysArr = Array.isArray(days) ? days : [];
  const asnDayCount = new Map(); // ASN -> nº de dias distintos
  const asnTotal = new Map(); // ASN -> total na janela
  for (const bucket of daysArr) {
    for (const [asn, count] of Object.entries(bucket?.byAsn ?? {})) {
      asnDayCount.set(asn, (asnDayCount.get(asn) ?? 0) + 1);
      asnTotal.set(asn, (asnTotal.get(asn) ?? 0) + count);
    }
  }
  const todayAsns = daysArr[0]?.byAsn ?? {};
  const recurringAttackers = [...asnDayCount.entries()]
    .filter(([, d]) => d >= 2)
    .map(([key, d]) => ({ key, count: asnTotal.get(key) ?? 0, days: d }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
  const newAttackers = Object.entries(todayAsns)
    .filter(([asn]) => (asnDayCount.get(asn) ?? 0) === 1)
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);

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
    recurringAttackers,
    newAttackers,
    byHourOfDay,
    peakHour: peakHour.count > 0 ? peakHour : null,
    heatmap,
    // Eventos para a tabela de Logs (sem IP — os eventos nunca o têm).
    events: Array.isArray(recent) ? recent.slice(0, 200) : [],
  };
}

/** Soma um mapa chave→contagem de origem sobre o de destino (in place). */
function mergeInto(dst, src) {
  for (const [k, v] of Object.entries(src ?? {})) dst[k] = (dst[k] ?? 0) + (Number(v) || 0);
}

/** Ordena um mapa chave→contagem em [{key,count}] decrescente, top `limit`. */
function topPairs(m, limit = 10) {
  return Object.entries(m).map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count).slice(0, limit);
}

/**
 * Funde os snapshots diários de firewall (`fw:<dia>`, já lidos do KV) numa
 * janela de 7 dias: os tops por ação/origem/rede/país que já alimentavam
 * /api/threat-intel, MAIS uma série diária crua (`daily`) — dia a dia, não
 * só o total da semana. Sem o `daily`, dois dias de natureza oposta (um de
 * ataque a sério, outro de tráfego humano a resolver desafios) ficavam
 * indistinguíveis somados (ver dashboard "Mitigação por dia").
 *
 * Puro e testável: recebe `entries` já lidos do KV pelo chamador (não faz
 * I/O), um array de `{ date, snap }` com `date` em ISO (YYYY-MM-DD) e `snap`
 * o snapshot cru ou `null` se o dia não tiver fotografia — em qualquer
 * ordem, a função reordena `daily` sozinha do mais antigo para o mais
 * recente. A classificação de cada ação em bloqueado/desafiado/passado é
 * feita pelo frontend (`firewallActionClass`, scripts/observability.js) —
 * aqui só se devolve `byAction` cru por dia, para não duplicar essa lógica
 * em duas linguagens.
 */
export function mergeFirewall7d(entries) {
  const byAction = {};
  const bySource = {};
  const byAsn = {};
  const byCountry = {}; // country -> { action -> count }
  for (const { snap } of entries) {
    if (!snap) continue;
    mergeInto(byAction, snap.byAction);
    mergeInto(bySource, snap.bySource);
    mergeInto(byAsn, snap.byAsn);
    for (const [country, entry] of Object.entries(snap.byCountry ?? {})) {
      const action = entry?.action;
      const count = Number(entry?.count) || 0;
      if (!action || count <= 0) continue;
      byCountry[country] ??= {};
      byCountry[country][action] = (byCountry[country][action] ?? 0) + count;
    }
  }
  const topCountry = Object.entries(byCountry)
    .map(([country, actions]) => {
      let bestAction = null;
      let bestCount = -1;
      let total = 0;
      for (const [action, count] of Object.entries(actions)) {
        total += count;
        if (count > bestCount) { bestAction = action; bestCount = count; }
      }
      return { country, action: bestAction, count: bestCount, total };
    })
    .sort((a, b) => b.total - a.total)
    .slice(0, 10)
    .map(({ country, action, count }) => ({ country, action, count }));
  const daily = entries
    .map(({ date, snap }) => ({ date, byAction: { ...(snap?.byAction ?? {}) } }))
    .sort((a, b) => (a.date < b.date ? -1 : 1));
  return {
    byAction: topPairs(byAction),
    bySource: topPairs(bySource),
    byAsn: topPairs(byAsn),
    byCountry: topCountry,
    daily,
  };
}
