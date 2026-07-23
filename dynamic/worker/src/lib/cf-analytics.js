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
// Como em ct.js: parse (puro, testável) separado de fetch (rede).

import { normalizeCountry } from './sanitize.js';

const DAY_MS = 86400_000;
export const CF_STATS_WINDOW_DAYS = 7;
export const CF_STATS_TOP_COUNTRIES = 10;
// Quantas linhas por tipo mostrar no painel (origens/ações são poucas na
// prática; este teto só evita uma lista infinita se a Cloudflare devolver
// muitas combinações).
export const CF_STATS_TOP_TYPES = 10;

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
          }
        }
        firewallEventsAdaptiveGroups(limit: 200, filter: { datetime_geq: $sinceDt, datetime_leq: $untilDt }) {
          count
          dimensions { action source }
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
 * Agrega os eventos de firewall (WAF/edge) por uma dimensão — `action` (o que
 * a Cloudflare fez: block, managed_challenge, jschallenge…) ou `source` (que
 * sistema apanhou: firewallManaged, rateLimit, botManagement…). É isto que
 * dá o *tipo* de ameaça/proteção que o contador cego `threats` do
 * httpRequests1dGroups não distingue.
 *
 * O `firewallEventsAdaptiveGroups` traz uma linha por combinação de dimensões
 * (aqui pedimos `action` + `source` juntas), com `count` de eventos. Somamos
 * esse `count` pela dimensão pedida. Ações `allow` ficam de fora — não são
 * uma mitigação, e o painel é sobre o que foi *travado*. Chave em falta vira
 * 'unknown' para os totais continuarem honestos. Devolve os `limit` tipos com
 * mais eventos, do maior para o menor.
 */
function breakdownByDimension(groups, dimension, limit = CF_STATS_TOP_TYPES) {
  const byKey = new Map();
  for (const g of Array.isArray(groups) ? groups : []) {
    const action = g?.dimensions?.action;
    if (action === 'allow') continue;
    const count = Number(g?.count) || 0;
    if (count <= 0) continue;
    const raw = g?.dimensions?.[dimension];
    const key = typeof raw === 'string' && raw.length > 0 ? raw : 'unknown';
    byKey.set(key, (byKey.get(key) ?? 0) + count);
  }
  return [...byKey.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
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
  const zone0 = Array.isArray(zones) ? zones[0] : null;
  const zoneGroups = zone0?.httpRequests1dGroups ?? [];
  const firewallGroups = zone0?.firewallEventsAdaptiveGroups ?? [];
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
      threatsBySource: breakdownByDimension(firewallGroups, 'source'),
      threatsByAction: breakdownByDimension(firewallGroups, 'action'),
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
 * zona + invocações/erros deste Worker. Precisa de CF_API_TOKEN (secret,
 * scope Analytics:Read na zona e na conta) e CF_ZONE_TAG / CF_ACCOUNT_ID /
 * CF_WORKER_SCRIPT (vars, ver wrangler.toml). Sem qualquer um destes,
 * lança — a rota devolve 502 e o painel mostra o fallback, tal como o
 * vigia CT sem SCAN_TARGET configurado.
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
  };

  const res = await fetch('https://api.cloudflare.com/client/v4/graphql', {
    method: 'POST',
    headers: {
      authorization: `Bearer ${env.CF_API_TOKEN}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ query: CF_STATS_QUERY, variables }),
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error('cf_graphql_unavailable');
  const raw = await res.json();
  if (Array.isArray(raw?.errors) && raw.errors.length > 0) throw new Error('cf_graphql_error');
  return parseCfStats(raw, { now, windowDays });
}
