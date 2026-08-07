// Estado da zona Cloudflare (ao vivo) — painel da página Provas com métricas
// reais desta zona e deste Worker, via GraphQL Analytics API da Cloudflare
// (api.cloudflare.com/client/v4/graphql).
//
// Isto NÃO é o Cloudflare Radar: o Radar é agregado global e anónimo de
// todos os clientes Cloudflare — não sabe nada sobre este domínio em
// particular. A GraphQL Analytics API, pelo contrário, só devolve dados da
// própria zona/conta autenticada com CF_API_TOKEN — é a mesma API que
// alimenta o dashboard da Cloudflare quando lá entras. Só agregados diários
// (pedidos, bytes, ameaças, invocações do Worker); nunca IPs nem dados de
// visitantes individuais.
//
// NOTA sobre o "detalhe por tipo de ameaça" (importante — houve confusão aqui):
// há DOIS datasets de eventos de firewall e no Free só um está acessível.
//   · firewallEventsAdaptive**Groups** (agregado) → Pro+; no Free responde
//     "does not have access to the path".
//   · firewallEventsAdaptive (CRU, eventos individuais) → **acessível no Free**
//     (retenção 24h), com o token a ter as permissões de Firewall/Logs Read.
// Por isso o painel usa o CRU e agrega por action/source aqui no Worker (ver
// CF_FIREWALL_QUERY + firewallBreakdown), best-effort. Duas fontes complementares:
//   · blockedByStatus — código HTTP das respostas do edge (responseStatusMap,
//     7d, do httpRequests1dGroups): o que o edge devolveu (403, 429…).
//   · firewallByAction/Source — eventos de regra de firewall (24h): managed_
//     challenge, block… de firewallCustom, ratelimit… Para 7d seria preciso
//     coletar/acumular (fase 2). Ver dynamic/PLAN.md para o historial.
//
// CORREÇÃO (2026-07): o dataset CRU já dá detalhe por URL, user-agent e ASN
// de todo o tráfego — não é preciso Pro+ para isso, ao contrário do que uma
// versão anterior do texto do painel dizia. Só o AGREGADO
// (firewallEventsAdaptiveGroups) é Pro+; o campo `clientIP` também está
// disponível no cru, mas o site nunca o pede nem mostra (zero-PII, ver
// CF_FIREWALL_DETAIL_QUERY abaixo — de propósito sem clientIP). Pedido
// SEPARADO de CF_FIREWALL_QUERY (não junta os campos na mesma query) para
// isolar o risco: se um nome de campo desviar do schema, só esta tabela
// best-effort fica vazia, nunca o painel de ação/origem/país que já
// funciona em produção.
//
// Como em ct.js: parse (puro, testável) separado de fetch (rede).

import { normalizeCountry, normalizeAsn, sanitizeText } from './sanitize.js';

const DAY_MS = 86400_000;
export const CF_STATS_WINDOW_DAYS = 7;
export const CF_STATS_TOP_COUNTRIES = 10;
// Quantas linhas de código de estado mostrar no painel (na prática são poucas;
// este teto só evita uma lista infinita).
export const CF_STATS_TOP_STATUSES = 10;

// NOTA: os nomes de campos abaixo (httpRequests1dGroups, workersInvocationsAdaptive,
// etc.) seguem o schema documentado da GraphQL Analytics API da Cloudflare
// no momento em que isto foi escrito. Convém confirmar contra o GraphQL
// schema explorer (developers.cloudflare.com/analytics/graphql-api/) ao
// ligar o CF_API_TOKEN pela primeira vez — parseCfStats degrada para 0 em
// qualquer campo em falta, por isso uma pequena deriva de schema não
// rebenta o painel, só mostra números a zero até se corrigir a query.
const CF_STATS_QUERY = `
  query CfStats($zoneTag: String!, $accountTag: String!, $scriptName: String!, $since: Date!, $until: Date!, $sinceDt: Time!, $untilDt: Time!) {
    viewer {
      zones(filter: { zoneTag: $zoneTag }) {
        httpRequests1dGroups(limit: 8, filter: { date_geq: $since, date_leq: $until }) {
          dimensions { date }
          uniq { uniques }
          sum {
            requests cachedRequests bytes threats
            countryMap { clientCountryName requests threats }
            responseStatusMap { edgeResponseStatus requests }
          }
        }
      }
      accounts(filter: { accountTag: $accountTag }) {
        workersInvocationsAdaptive(limit: 8, filter: { scriptName: $scriptName, datetime_geq: $sinceDt, datetime_leq: $untilDt }) {
          sum { requests errors }
        }
      }
    }
  }
`;

// Eventos de firewall (últimas 24h) — pedido SEPARADO e best-effort. Usa o
// dataset CRU `firewallEventsAdaptive` (eventos individuais), NÃO o
// `firewallEventsAdaptiveGroups` (agregado), porque no plano Free só o cru
// está acessível — o agregado é Pro+ ("does not have access to the path"). Por
// isso a agregação por ação/origem faz-se aqui no Worker, não na API. Retenção
// no Free: 24h; para 7d seria preciso coletar/acumular (fase 2). Pedem-se
// `action` + `source` + `clientCountryName` (país, não IP — o mesmo nível de
// detalhe já usado no `countryMap` de CF_STATS_QUERY) para poder cruzar país
// com o tipo de ação que a Cloudflare tomou — NUNCA o IP nem dados de
// visitante individual.
const CF_FIREWALL_QUERY = `
  query CfFirewall($zoneTag: String!, $since24hDt: Time!, $untilDt: Time!) {
    viewer {
      zones(filter: { zoneTag: $zoneTag }) {
        firewallEventsAdaptive(limit: 10000, filter: { datetime_geq: $since24hDt, datetime_leq: $untilDt }, orderBy: [datetime_DESC]) {
          action source sampleInterval clientCountryName
        }
      }
    }
  }
`;

// Detalhe por URL, user-agent e ASN de todo o tráfego visto pelo firewall
// (últimas 24h) — pedido SEPARADO do CF_FIREWALL_QUERY (ver nota no topo do
// ficheiro: isola o risco de deriva de schema). Mesmo dataset CRU
// `firewallEventsAdaptive`, campos diferentes. `clientIP` está disponível
// neste dataset mas NUNCA se pede — zero-PII é uma escolha do site, não uma
// limitação do plano Free.
const CF_FIREWALL_DETAIL_QUERY = `
  query CfFirewallDetail($zoneTag: String!, $since24hDt: Time!, $untilDt: Time!) {
    viewer {
      zones(filter: { zoneTag: $zoneTag }) {
        firewallEventsAdaptive(limit: 10000, filter: { datetime_geq: $since24hDt, datetime_leq: $untilDt }, orderBy: [datetime_DESC]) {
          sampleInterval clientRequestPath userAgent clientAsn
        }
      }
    }
  }
`;

function isoDate(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}

/** Soma um campo de `sum` através de várias linhas diárias. Falta → 0. */
function sumField(groups, field) {
  if (!Array.isArray(groups)) return 0;
  return groups.reduce((acc, g) => acc + (Number(g?.sum?.[field]) || 0), 0);
}

/**
 * Soma as ameaças bloqueadas por país através de várias linhas diárias
 * (cada dia traz o seu próprio `countryMap`) e devolve os `limit` países
 * com mais ameaças, do maior para o menor. País inválido (não ISO-3166-1
 * alpha-2) vira 'XX' via normalizeCountry — mas 'XX' e países sem nenhuma
 * ameaça ficam de fora do ranking (não interessa ao painel).
 */
function topCountriesByThreats(groups, limit = CF_STATS_TOP_COUNTRIES) {
  const byCountry = new Map();
  for (const g of Array.isArray(groups) ? groups : []) {
    for (const row of Array.isArray(g?.sum?.countryMap) ? g.sum.countryMap : []) {
      const country = normalizeCountry(row?.clientCountryName);
      const threats = Number(row?.threats) || 0;
      if (country === 'XX' || threats <= 0) continue;
      byCountry.set(country, (byCountry.get(country) ?? 0) + threats);
    }
  }
  return [...byCountry.entries()]
    .map(([country, threats]) => ({ country, threats }))
    .sort((a, b) => b.threats - a.threats)
    .slice(0, limit);
}

// Abaixo deste nº de pedidos, a taxa de ameaça de um país é ruído estatístico
// (1 ameaça em 3 pedidos = 33% não diz nada). Já não exclui o país do Risk
// Score (2026-07: pedido do dono do repo para ver mais países, não menos) —
// só marca `lowSample: true`, para o painel mostrar a amostra bruta a par da
// percentagem em vez de esconder o país por inteiro.
export const CF_STATS_RISK_MIN_REQUESTS = 100;

/**
 * Série temporal por dia (para as timelines Requests/Threats/Visitors e a
 * tendência semanal). Cada `httpRequests1dGroups` já traz um dia
 * (`dimensions.date`); ordena-se do mais antigo para o mais recente. Dia sem
 * data cai fora (não dá para posicionar na timeline).
 */
function dailySeries(groups) {
  return (Array.isArray(groups) ? groups : [])
    .map((g) => ({
      date: g?.dimensions?.date ?? null,
      requests: Number(g?.sum?.requests) || 0,
      threats: Number(g?.sum?.threats) || 0,
      visitors: Number(g?.uniq?.uniques) || 0,
    }))
    .filter((d) => typeof d.date === 'string' && d.date.length > 0)
    .sort((a, b) => (a.date < b.date ? -1 : 1));
}

/**
 * "Risk Score" por país — métrica PRÓPRIA que a Cloudflare não mostra: a
 * fração de pedidos de cada país que são ameaça (threats/requests). Mostra
 * TODOS os países com pelo menos 1 ameaça — nenhum é escondido. Os que não
 * atingem `minRequests` pedidos na janela vêm marcados com `lowSample: true`
 * (o rácio é pouco fiável com amostra pequena: 1 ameaça em 1 pedido dava
 * "100%" sem dizer nada) e ficam ordenados DEPOIS dos de amostra suficiente
 * — para um fluke de amostra pequena não saltar à frente de um país com
 * volume real só por sorte. Dentro de cada grupo, ordenado por taxa
 * decrescente. O chamador decide como mostrar `lowSample` (ex.: tom mais
 * discreto, contagem bruta ao lado da percentagem). Devolve rate ∈ [0,1] +
 * os brutos.
 */
function riskByCountry(groups, limit = CF_STATS_TOP_COUNTRIES, minRequests = CF_STATS_RISK_MIN_REQUESTS) {
  const acc = new Map(); // country -> { requests, threats }
  for (const g of Array.isArray(groups) ? groups : []) {
    for (const row of Array.isArray(g?.sum?.countryMap) ? g.sum.countryMap : []) {
      const country = normalizeCountry(row?.clientCountryName);
      if (country === 'XX') continue;
      const cur = acc.get(country) ?? { requests: 0, threats: 0 };
      cur.requests += Number(row?.requests) || 0;
      cur.threats += Number(row?.threats) || 0;
      acc.set(country, cur);
    }
  }
  return [...acc.entries()]
    .filter(([, v]) => v.threats > 0)
    .map(([country, v]) => ({
      country,
      requests: v.requests,
      threats: v.threats,
      rate: v.threats / v.requests,
      lowSample: v.requests < minRequests,
    }))
    .sort((a, b) => Number(a.lowSample) - Number(b.lowSample) || b.rate - a.rate)
    .slice(0, limit);
}

/**
 * Soma os pedidos por código HTTP das respostas do edge (`responseStatusMap`),
 * ficando só com os de REJEIÇÃO/ERRO (>= 400) através das várias linhas
 * diárias. É o sinal de "proteção/erros em ação" que o Free dá com números a
 * sério (ex.: 403 = bloqueado, 429 = rate limit) — os eventos de firewall com
 * action/source são Pro+ (ver nota no topo). Devolve os `limit` códigos com
 * mais pedidos, do maior para o menor; a chave é o código como string.
 */
function blockedByStatus(groups, limit = CF_STATS_TOP_STATUSES) {
  const byStatus = new Map();
  for (const g of Array.isArray(groups) ? groups : []) {
    for (const row of Array.isArray(g?.sum?.responseStatusMap) ? g.sum.responseStatusMap : []) {
      const status = Number(row?.edgeResponseStatus) || 0;
      const requests = Number(row?.requests) || 0;
      if (status < 400 || requests <= 0) continue;
      byStatus.set(status, (byStatus.get(status) ?? 0) + requests);
    }
  }
  return [...byStatus.entries()]
    .map(([status, count]) => ({ key: String(status), count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

/** Ordena um Map<chave,contagem> em [{key,count}] decrescente, top `limit`. */
function topEntries(map, limit) {
  return [...map.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

/**
 * Ordena um mapa aninhado país→(ação→contagem) numa lista [{country, action,
 * count}] — o `action` de cada país é o mais frequente nesse país (a "ameaça
 * específica" que domina a esse país), `count` é o peso desse par. Ordenado
 * pelo total do país (soma de todas as ações), do maior para o menor.
 */
function topCountryAction(byCountryAction, limit) {
  return [...byCountryAction.entries()]
    .map(([country, actions]) => {
      let bestAction = null;
      let bestCount = -1;
      let total = 0;
      for (const [action, count] of actions) {
        total += count;
        if (count > bestCount) { bestAction = action; bestCount = count; }
      }
      return { country, action: bestAction, count: bestCount, total };
    })
    .sort((a, b) => b.total - a.total)
    .slice(0, limit)
    .map(({ country, action, count }) => ({ country, action, count }));
}

/**
 * Agrega os eventos crus do `firewallEventsAdaptive` (CF_FIREWALL_QUERY) por
 * **ação** (o que a Cloudflare fez: managed_challenge, block, js_challenge…),
 * por **origem** (que sistema disparou: firewallCustom, ratelimit, bic…) e por
 * **país × ação** (qual é a ação mais comum vinda de cada país — a resposta a
 * "que ameaça específica vem de cada país", que `topCountries` sozinho não dá).
 *
 * IMPORTANTE — amostragem: o dataset é AMOSTRADO ("Sampled logs" no dashboard).
 * Cada evento traz um `sampleInterval` = quantos eventos reais aquela linha
 * representa. Somamos esse peso (não 1 por linha), para os totais aproximarem
 * os do dashboard (ex.: 143 linhas × ~5 ≈ 758 eventos reais). Falta/zero → 1.
 *
 * Função pura e defensiva: shape inesperado, `errors` ou campo em falta viram
 * listas vazias, nunca lança. Devolve o bloco que se cola em `stats.zone`.
 */
export function firewallBreakdown(raw, limit = CF_STATS_TOP_STATUSES) {
  const zones = raw?.data?.viewer?.zones;
  const events = (Array.isArray(zones) ? zones[0] : null)?.firewallEventsAdaptive ?? [];
  const byAction = new Map();
  const bySource = new Map();
  const byCountryAction = new Map(); // country -> Map<action, weight>
  for (const e of Array.isArray(events) ? events : []) {
    const action = typeof e?.action === 'string' && e.action.length > 0 ? e.action : 'unknown';
    const source = typeof e?.source === 'string' && e.source.length > 0 ? e.source : 'unknown';
    const weight = Math.max(1, Number(e?.sampleInterval) || 1);
    byAction.set(action, (byAction.get(action) ?? 0) + weight);
    bySource.set(source, (bySource.get(source) ?? 0) + weight);
    const country = normalizeCountry(e?.clientCountryName);
    if (country !== 'XX') {
      const inner = byCountryAction.get(country) ?? new Map();
      inner.set(action, (inner.get(action) ?? 0) + weight);
      byCountryAction.set(country, inner);
    }
  }
  return {
    firewallByAction: topEntries(byAction, limit),
    firewallBySource: topEntries(bySource, limit),
    firewallByCountry: topCountryAction(byCountryAction, limit),
  };
}

// Quanto do path/user-agent cru se guarda por linha antes de agregar — só
// para conter entradas absurdas (paths gigantes, UAs forjados); não é PII,
// mas mesmo assim passa por sanitizeText (remove controlo/tags, trunca).
const CF_FIREWALL_PATH_MAXLEN = 120;
const CF_FIREWALL_UA_MAXLEN = 140;

/**
 * Agrega os eventos crus do `firewallEventsAdaptive` (CF_FIREWALL_DETAIL_QUERY)
 * por **URL** (`clientRequestPath`), **user-agent** e **ASN** (`clientAsn`) —
 * o detalhe que o texto do painel dizia (incorretamente) exigir Pro+; vem do
 * mesmo dataset CRU já usado por `firewallBreakdown`, só que com campos
 * diferentes. Mesma amostragem por peso (`sampleInterval`) que `firewallBreakdown`.
 * `clientIP` não é pedido nem processado aqui — decisão de produto (zero-PII),
 * não limitação da API. Função pura e defensiva: nunca lança.
 */
export function firewallDetailBreakdown(raw, limit = CF_STATS_TOP_STATUSES) {
  const zones = raw?.data?.viewer?.zones;
  const events = (Array.isArray(zones) ? zones[0] : null)?.firewallEventsAdaptive ?? [];
  const byPath = new Map();
  const byUserAgent = new Map();
  const byAsn = new Map();
  for (const e of Array.isArray(events) ? events : []) {
    const weight = Math.max(1, Number(e?.sampleInterval) || 1);
    const path = sanitizeText(e?.clientRequestPath, CF_FIREWALL_PATH_MAXLEN);
    if (path) byPath.set(path, (byPath.get(path) ?? 0) + weight);
    const ua = sanitizeText(e?.userAgent, CF_FIREWALL_UA_MAXLEN);
    if (ua) byUserAgent.set(ua, (byUserAgent.get(ua) ?? 0) + weight);
    const asn = normalizeAsn(e?.clientAsn);
    if (asn) {
      const key = `AS${asn}`;
      byAsn.set(key, (byAsn.get(key) ?? 0) + weight);
    }
  }
  return {
    firewallByPath: topEntries(byPath, limit),
    firewallByUserAgent: topEntries(byUserAgent, limit),
    firewallByAsn: topEntries(byAsn, limit),
  };
}

/**
 * Normaliza a resposta bruta da GraphQL Analytics API num resumo estável
 * para o painel. Qualquer coisa que não bata com o shape esperado vira 0 —
 * nunca lança, para o Worker poder responder mesmo que a Cloudflare mude o
 * schema entretanto (o mesmo princípio de "degradar em silêncio" do resto
 * do projeto — ver techniquesForText em attack-map.js).
 */
export function parseCfStats(raw, { now = Date.now(), windowDays = CF_STATS_WINDOW_DAYS } = {}) {
  const zones = raw?.data?.viewer?.zones;
  const accounts = raw?.data?.viewer?.accounts;
  const zoneGroups = (Array.isArray(zones) ? zones[0] : null)?.httpRequests1dGroups ?? [];
  const workerGroups = (Array.isArray(accounts) ? accounts[0] : null)?.workersInvocationsAdaptive ?? [];

  const requests = sumField(zoneGroups, 'requests');
  const cachedRequests = sumField(zoneGroups, 'cachedRequests');
  const bytes = sumField(zoneGroups, 'bytes');
  const threats = sumField(zoneGroups, 'threats');
  // Visitantes únicos (estimativa da Cloudflare): soma os únicos diários. Como
  // o dashboard oficial, é uma soma por-dia (um visitante em 2 dias conta 2) —
  // é o que o `uniq.uniques` do 1dGroups dá no Free.
  const visitors = (Array.isArray(zoneGroups) ? zoneGroups : []).reduce(
    (acc, g) => acc + (Number(g?.uniq?.uniques) || 0), 0,
  );
  const workerRequests = sumField(workerGroups, 'requests');
  const workerErrors = sumField(workerGroups, 'errors');

  return {
    windowDays,
    zone: {
      requests,
      visitors,
      cachedRequests,
      cacheRatio: requests > 0 ? cachedRequests / requests : 0,
      bytes,
      threats,
      topCountries: topCountriesByThreats(zoneGroups),
      riskByCountry: riskByCountry(zoneGroups),
      blockedByStatus: blockedByStatus(zoneGroups),
      // Série por dia para as timelines (Requests/Threats/Visitors) e tendência.
      series: dailySeries(zoneGroups),
      // Preenchidos à parte por fetchCfStats (CF_FIREWALL_QUERY, best-effort).
      firewallByAction: [],
      firewallBySource: [],
      firewallByCountry: [],
      // Preenchidos à parte por fetchCfStats (CF_FIREWALL_DETAIL_QUERY,
      // best-effort, pedido separado — ver nota no topo do ficheiro).
      firewallByPath: [],
      firewallByUserAgent: [],
      firewallByAsn: [],
    },
    worker: {
      requests: workerRequests,
      errors: workerErrors,
      errorRatio: workerRequests > 0 ? workerErrors / workerRequests : 0,
    },
    fetchedAt: now,
  };
}

/**
 * Busca as métricas dos últimos `windowDays` dias: pedidos/cache/ameaças da
 * zona (+ repartição por país e por código HTTP) e invocações/erros deste
 * Worker. Precisa de CF_API_TOKEN (secret, scope Analytics:Read na zona e na
 * conta) e CF_ZONE_TAG / CF_ACCOUNT_ID / CF_WORKER_SCRIPT (vars, ver
 * wrangler.toml). Sem qualquer um destes, lança — a rota devolve 502 e o
 * painel mostra o fallback, tal como o vigia CT sem SCAN_TARGET configurado.
 */
export async function fetchCfStats(env, { timeoutMs = 8000, now = Date.now(), windowDays = CF_STATS_WINDOW_DAYS } = {}) {
  if (!env.CF_API_TOKEN || !env.CF_ZONE_TAG || !env.CF_ACCOUNT_ID || !env.CF_WORKER_SCRIPT) {
    throw new Error('cf_stats_not_configured');
  }
  const until = now;
  const since = now - windowDays * DAY_MS;
  const variables = {
    zoneTag: env.CF_ZONE_TAG,
    accountTag: env.CF_ACCOUNT_ID,
    scriptName: env.CF_WORKER_SCRIPT,
    since: isoDate(since),
    until: isoDate(until),
    sinceDt: new Date(since).toISOString(),
    untilDt: new Date(until).toISOString(),
    // Janela de 23h (adaptativos no Free limitam-se a 24h).
    since24hDt: new Date(now - 23 * 3600_000).toISOString(),
  };

  const post = (query) => fetch('https://api.cloudflare.com/client/v4/graphql', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${env.CF_API_TOKEN}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ query, variables }),
    signal: AbortSignal.timeout(timeoutMs),
  });

  const res = await post(CF_STATS_QUERY);
  if (!res.ok) throw new Error('cf_graphql_unavailable');
  const raw = await res.json();
  if (Array.isArray(raw?.errors) && raw.errors.length > 0) throw new Error('cf_graphql_error');
  const stats = parseCfStats(raw, { now, windowDays });

  // Eventos de firewall das últimas 24h (por ação/origem) — best-effort e
  // isolado do núcleo: se o dataset falhar (permissão de firewall em falta,
  // deriva de schema), engole-se o erro e as tabelas ficam vazias, mas o
  // painel-núcleo (pedidos/cache/ameaças/código HTTP) mantém-se sempre.
  try {
    const fwRes = await post(CF_FIREWALL_QUERY);
    if (fwRes.ok) {
      const fwRaw = await fwRes.json();
      if (Array.isArray(fwRaw?.errors) && fwRaw.errors.length > 0) {
        // "Best-effort" não pode querer dizer "invisível": uma tabela vazia
        // no painel era indistinguível de "não houve eventos". Com o
        // [observability] do wrangler.toml, isto fica retido e diz porquê.
        console.error('cf_firewall_query_errors', JSON.stringify(fwRaw.errors).slice(0, 300));
      } else {
        Object.assign(stats.zone, firewallBreakdown(fwRaw));
      }
    } else {
      console.error('cf_firewall_query_http', fwRes.status);
    }
  } catch (err) {
    console.error('cf_firewall_query_failed', err?.message ?? String(err));
  }

  // Detalhe por URL/user-agent/ASN das últimas 24h — pedido SEPARADO do de
  // cima (mesmo princípio: um desvio de schema aqui nunca deve apagar as
  // tabelas de ação/origem/país que já funcionam). Também best-effort.
  try {
    const fwDetailRes = await post(CF_FIREWALL_DETAIL_QUERY);
    if (fwDetailRes.ok) {
      const fwDetailRaw = await fwDetailRes.json();
      if (Array.isArray(fwDetailRaw?.errors) && fwDetailRaw.errors.length > 0) {
        console.error('cf_firewall_detail_query_errors', JSON.stringify(fwDetailRaw.errors).slice(0, 300));
      } else {
        Object.assign(stats.zone, firewallDetailBreakdown(fwDetailRaw));
      }
    } else {
      console.error('cf_firewall_detail_query_http', fwDetailRes.status);
    }
  } catch (err) {
    console.error('cf_firewall_detail_query_failed', err?.message ?? String(err));
  }

  return stats;
}
