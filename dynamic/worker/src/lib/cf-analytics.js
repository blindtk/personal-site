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
// Como em ct.js: parse (puro, testável) separado de fetch (rede).

import { normalizeCountry } from './sanitize.js';

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
// no Free: 24h; para 7d seria preciso coletar/acumular (fase 2). Só se pedem
// `action` + `source` — NUNCA o IP nem dados de visitante individual.
const CF_FIREWALL_QUERY = `
  query CfFirewall($zoneTag: String!, $since24hDt: Time!, $untilDt: Time!) {
    viewer {
      zones(filter: { zoneTag: $zoneTag }) {
        firewallEventsAdaptive(limit: 10000, filter: { datetime_geq: $since24hDt, datetime_leq: $untilDt }, orderBy: [datetime_DESC]) {
          action source sampleInterval
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
 * Agrega os eventos crus do `firewallEventsAdaptive` (CF_FIREWALL_QUERY) por
 * **ação** (o que a Cloudflare fez: managed_challenge, block, js_challenge…) e
 * por **origem** (que sistema disparou: firewallCustom, ratelimit, bic…).
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
  for (const e of Array.isArray(events) ? events : []) {
    const action = typeof e?.action === 'string' && e.action.length > 0 ? e.action : 'unknown';
    const source = typeof e?.source === 'string' && e.source.length > 0 ? e.source : 'unknown';
    const weight = Math.max(1, Number(e?.sampleInterval) || 1);
    byAction.set(action, (byAction.get(action) ?? 0) + weight);
    bySource.set(source, (bySource.get(source) ?? 0) + weight);
  }
  return {
    firewallByAction: topEntries(byAction, limit),
    firewallBySource: topEntries(bySource, limit),
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
  const workerRequests = sumField(workerGroups, 'requests');
  const workerErrors = sumField(workerGroups, 'errors');

  return {
    windowDays,
    zone: {
      requests,
      cachedRequests,
      cacheRatio: requests > 0 ? cachedRequests / requests : 0,
      bytes,
      threats,
      topCountries: topCountriesByThreats(zoneGroups),
      blockedByStatus: blockedByStatus(zoneGroups),
      // Preenchidos à parte por fetchCfStats (CF_FIREWALL_QUERY, best-effort).
      firewallByAction: [],
      firewallBySource: [],
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
      if (!(Array.isArray(fwRaw?.errors) && fwRaw.errors.length > 0)) {
        Object.assign(stats.zone, firewallBreakdown(fwRaw));
      }
    }
  } catch {
    // Timeout/rede/permissão: fica com as tabelas de firewall vazias.
  }

  return stats;
}
