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
      }
      accounts(filter: { accountTag: $accountTag }) {
        workersInvocationsAdaptive(limit: 8, filter: { scriptName: $scriptName, datetime_geq: $sinceDt, datetime_leq: $untilDt }) {
          sum { requests errors }
        }
      }
    }
  }
`;

// Query SEPARADA (best-effort) para o detalhe por TIPO de ameaça. Usa o
// `threatPathingMap` do httpRequests1dGroups — a taxonomia da própria
// Cloudflare de *que mecanismo* apanhou cada ameaça (nível de segurança,
// regras de firewall, rate limit, BIC…). Escolhido de propósito em vez do
// firewallEventsAdaptiveGroups: este último exige plano Pro+ (no Free devolve
// "zone does not have access to the path"), enquanto o httpRequests1dGroups —
// e portanto o threatPathingMap, irmão do countryMap que já usamos — está
// disponível no Free. Fica num pedido próprio best-effort: qualquer erro é
// engolido em fetchCfStats e o painel-núcleo nunca cai.
const CF_THREATPATHING_QUERY = `
  query CfThreatPathing($zoneTag: String!, $since: Date!, $until: Date!) {
    viewer {
      zones(filter: { zoneTag: $zoneTag }) {
        httpRequests1dGroups(limit: 8, filter: { date_geq: $since, date_leq: $until }) {
          sum {
            threatPathingMap { threatPathingName requests }
          }
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
 * Soma as ameaças por *tipo* (mecanismo) através das várias linhas diárias,
 * a partir do `threatPathingMap` — a taxonomia da Cloudflare de que sistema
 * apanhou cada ameaça (ex.: `user.securityLevel`, `firewallRules`, `bic`,
 * `hot`, `ratelimit`). É isto que dá o *tipo* que o contador cego `threats`
 * não distingue. Nome em falta vira 'unknown'; devolve os `limit` tipos com
 * mais ameaças, do maior para o menor.
 */
function threatsByPathing(groups, limit = CF_STATS_TOP_TYPES) {
  const byName = new Map();
  for (const g of Array.isArray(groups) ? groups : []) {
    for (const row of Array.isArray(g?.sum?.threatPathingMap) ? g.sum.threatPathingMap : []) {
      const requests = Number(row?.requests) || 0;
      if (requests <= 0) continue;
      const raw = row?.threatPathingName;
      const name = typeof raw === 'string' && raw.length > 0 ? raw : 'unknown';
      byName.set(name, (byName.get(name) ?? 0) + requests);
    }
  }
  return [...byName.entries()]
    .map(([key, count]) => ({ key, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

/**
 * Extrai o detalhe por tipo de ameaça da resposta da CF_THREATPATHING_QUERY
 * (pedido SEPARADO — ver fetchCfStats). Função pura e defensiva: shape
 * inesperado, `errors` ou campo em falta viram lista vazia, nunca lança.
 * Devolve o bloco que se cola em `stats.zone`.
 */
export function threatPathingBreakdown(raw) {
  const zones = raw?.data?.viewer?.zones;
  const groups = (Array.isArray(zones) ? zones[0] : null)?.httpRequests1dGroups ?? [];
  return { threatsByType: threatsByPathing(groups) };
}

/**
 * Normaliza a resposta bruta da GraphQL Analytics API num resumo estável
 * para o painel. Qualquer coisa que não bata com o shape esperado vira 0 —
 * nunca lança, para o Worker poder responder mesmo que a Cloudflare mude o
 * schema entretanto (o mesmo princípio de "degradar em silêncio" do resto
 * do projeto — ver techniquesForText em attack-map.js).
 *
 * O detalhe por tipo (threatsByType) nasce vazio aqui — é preenchido à parte
 * por fetchCfStats a partir da CF_THREATPATHING_QUERY, para que uma falha
 * nesse pedido nunca derrube este núcleo.
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
      threatsByType: [],
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
 *
 * Dois pedidos: o NÚCLEO (obrigatório — se falhar, 502) e o detalhe por
 * origem/ação (BEST-EFFORT — o dataset firewallEventsAdaptiveGroups exige
 * Logs:Read no token; sem essa permissão, ou com deriva de schema, engolimos
 * o erro e as quebras ficam vazias, mas o painel principal mantém-se).
 */
// TEMPORÁRIO (diagnóstico): corre uma query GraphQL arbitrária e devolve o
// que `pick` extrair da resposta, ou o erro (ex.: "does not have access to the
// path" quando o dataset é Pro+). Cada sonda é isolada — serve para validar,
// contra a zona real, que datasets de firewall/segurança o Free deixa buscar.
async function probeRaw(post, query, pick) {
  try {
    const res = await post(query);
    if (!res.ok) return { error: `http ${res.status}` };
    const raw = await res.json();
    if (Array.isArray(raw?.errors) && raw.errors.length > 0) {
      return { error: String(raw.errors[0]?.message ?? 'erro') };
    }
    return { ok: pick(raw) };
  } catch (e) {
    return { error: String(e?.message ?? e) };
  }
}

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
    // Janela de 23h para os datasets adaptativos: no Free têm retenção de 24h
    // e recusam intervalos > 1d ("cannot request a time range wider than 1d").
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

  // Detalhe por tipo de ameaça — best-effort, isolado do núcleo acima.
  // NOTA (TEMPORÁRIO): anexa-se um `threatDebug` à resposta para se ver, só
  // de abrir o URL, o que o threatPathingMap devolveu (status HTTP, erros
  // GraphQL, nomes crus dos mecanismos). Não expõe IPs nem dados de
  // visitantes. A remover assim que as etiquetas estiverem afinadas.
  const threatDebug = { httpStatus: null, graphqlErrors: [], pathing: [] };
  try {
    const tpRes = await post(CF_THREATPATHING_QUERY);
    threatDebug.httpStatus = tpRes.status;
    const tpRaw = tpRes.ok ? await tpRes.json() : null;
    if (Array.isArray(tpRaw?.errors)) {
      threatDebug.graphqlErrors = tpRaw.errors.map((e) => String(e?.message ?? e)).slice(0, 5);
    }
    if (tpRes.ok && threatDebug.graphqlErrors.length === 0) {
      const breakdown = threatPathingBreakdown(tpRaw);
      Object.assign(stats.zone, breakdown);
      threatDebug.pathing = breakdown.threatsByType;
    }
  } catch (e) {
    threatDebug.graphqlErrors = [String(e?.message ?? e)];
  }

  // TEMPORÁRIO: validação empírica de que datasets de firewall/segurança o
  // Free deixa buscar. (1) introspeção lista TODOS os datasets da zona cujo
  // nome cheira a firewall/segurança; (2)+(3) tentam de facto ler os dois
  // candidatos principais — a mensagem de erro (ou os dados) é a prova.
  const [zoneDatasets, firewallEventsAdaptiveGroups, httpRequestsAdaptiveGroups] = await Promise.all([
    probeRaw(
      post,
      `{ __type(name: "Zone") { fields { name } } }`,
      (raw) => (raw?.data?.__type?.fields ?? [])
        .map((f) => f?.name)
        .filter((n) => typeof n === 'string' && /fire|waf|secur|threat|attack|bot|ratelimit|ddos/i.test(n)),
    ),
    probeRaw(
      post,
      `query($zoneTag: String!, $since24hDt: Time!, $untilDt: Time!) {
        viewer { zones(filter: { zoneTag: $zoneTag }) {
          firewallEventsAdaptiveGroups(limit: 100, filter: { datetime_geq: $since24hDt, datetime_leq: $untilDt }) {
            count dimensions { action source }
          }
        } }
      }`,
      (raw) => (raw?.data?.viewer?.zones?.[0]?.firewallEventsAdaptiveGroups ?? [])
        .map((r) => ({ action: r?.dimensions?.action, source: r?.dimensions?.source, count: r?.count })),
    ),
    probeRaw(
      post,
      `query($zoneTag: String!, $since24hDt: Time!, $untilDt: Time!) {
        viewer { zones(filter: { zoneTag: $zoneTag }) {
          httpRequestsAdaptiveGroups(limit: 5, filter: { datetime_geq: $since24hDt, datetime_leq: $untilDt }) {
            count dimensions { edgeResponseStatus }
          }
        } }
      }`,
      (raw) => raw?.data?.viewer?.zones?.[0]?.httpRequestsAdaptiveGroups ?? null,
    ),
  ]);
  threatDebug.datasets = { zoneDatasets, firewallEventsAdaptiveGroups, httpRequestsAdaptiveGroups };

  stats.zone.threatDebug = threatDebug;

  return stats;
}
