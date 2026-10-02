// Agregação da firewall da zona Cloudflare (snapshots diários fw:<dia> →
// janela de 7 dias). Puro e testável — recebe os snapshots já lidos do KV e
// devolve a forma que as páginas Cloudflare e Visão Geral consomem. Nunca vê
// IPs: os snapshots só têm contagens por ação, origem, país e ASN.
//
// Este ficheiro era o `aggregate.js` do honeypot interno; a parte do
// honeypot saiu com ele (ADR 0022) e ficou só a firewall.

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
