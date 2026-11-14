/**
 * Resumo do honeypot externo (repo honeypot-vps-infra, ADR 0019/0022) para o
 * painel "O que o sensor viu" da página do projeto Threat Intel.
 *
 * Fonte: `history.json`, que o sensor publica a cada execução do feed em
 * intel.danielmala.co — uma linha de AGREGADOS por dia UTC, sem nenhum
 * indicador (o próprio sensor garante-o: é o arquivo que sobrevive à janela
 * de retenção). Nunca se lê `feed.json`: tem os endereços e ~18 MB.
 *
 * Só o cron vai buscar (index.js, refreshIntel); a rota /api/intel só lê o
 * KV. O que sai daqui são números, ids ATT&CK validados e nomes de campanha
 * em slug — por construção, nenhum endereço atravessa este módulo.
 */
import { readCapped } from './radar-feed.js';

// URLs fixos, por ordem. O segundo é o endereço *.pages.dev do mesmo projeto
// Pages: serve o mesmo ficheiro e fica de recurso se o WAF da zona recusar o
// sub-pedido do Worker ao domínio próprio.
export const INTEL_SOURCES = [
  'https://intel.danielmala.co/history.json',
  'https://intel-danielmalaco.pages.dev/history.json',
];

// history.json cresce uma linha (~0,7 KB) por dia e nunca encolhe: 1 MiB dá
// para cerca de quatro anos. Acima disso o JSON vem cortado e falha fechado.
export const INTEL_MAX_BYTES = 1024 * 1024;
export const INTEL_WINDOW_DAYS = 7;
export const INTEL_MAX_TECHNIQUES = 8;
export const INTEL_MAX_CAMPAIGNS = 12;
// O último dia do arquivo tem de ser recente: o sensor escreve o dia corrente
// a cada execução, por isso mais de 2 dias de atraso é um sensor parado.
export const INTEL_MAX_AGE_MS = 2 * 86_400_000;

const DAY = /^\d{4}-\d{2}-\d{2}$/;
const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/;
const CAMPAIGN = /^[a-z0-9][a-z0-9-]{0,31}$/;

const isCount = (n) => typeof n === 'number' && Number.isInteger(n) && n >= 0;
const count = (n) => (isCount(n) ? n : null);

function dayMs(day) {
  if (typeof day !== 'string' || !DAY.test(day)) return NaN;
  const ms = Date.parse(`${day}T00:00:00Z`);
  // Date.parse aceita "2026-02-31" e devolve março: só vale se der a volta.
  return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 10) === day ? ms : NaN;
}

/**
 * Reduz `history.json` ao resumo servido por /api/intel. Puro.
 *
 * `{ ok: true, day, … }` ou `{ ok: false, error }` — nunca um resumo parcial
 * com zeros inventados: sem a contagem de endereços do último dia, ou com o
 * último dia velho ou no futuro, não há resumo.
 *
 * Os campos são instantâneos da janela de publicação do sensor (o que estava
 * publicado nesse dia), exceto `sessions7d`, que soma as sessões começadas
 * em cada um dos últimos 7 dias que o arquivo tem.
 */
export function summarizeHistory(doc, now = Date.now()) {
  const rows = (Array.isArray(doc?.days) ? doc.days : [])
    .map((row) => ({ row, ms: dayMs(row?.day) }))
    .filter(({ ms }) => Number.isFinite(ms))
    .sort((a, b) => a.ms - b.ms);
  if (rows.length === 0) return { ok: false, error: 'no_days' };

  const { row: last, ms: lastMs } = rows[rows.length - 1];
  // O dia corrente começa às 00:00 UTC, por isso "no futuro" é mais de um dia
  // à frente do relógio do Worker.
  if (lastMs > now) return { ok: false, error: 'future_day' };
  if (now - lastMs > INTEL_MAX_AGE_MS + 86_400_000) return { ok: false, error: 'stale' };
  if (!isCount(last.addresses)) return { ok: false, error: 'bad_addresses' };

  const techniques = Object.entries(last.techniques && typeof last.techniques === 'object' ? last.techniques : {})
    .filter(([id, n]) => TECHNIQUE_ID.test(id) && isCount(n) && n > 0)
    .map(([id, n]) => ({ id, count: n }))
    .sort((a, b) => b.count - a.count || a.id.localeCompare(b.id))
    .slice(0, INTEL_MAX_TECHNIQUES);

  const campaigns = [...new Set(Array.isArray(last.campaigns) ? last.campaigns : [])]
    .filter((name) => typeof name === 'string' && CAMPAIGN.test(name))
    .sort()
    .slice(0, INTEL_MAX_CAMPAIGNS);

  const window = rows.filter(({ ms }) => lastMs - ms < INTEL_WINDOW_DAYS * 86_400_000);
  const withSessions = window.filter(({ row }) => isCount(row.sessions_started));
  const first = window[0];

  return {
    ok: true,
    day: last.day,
    addresses: last.addresses,
    addressesNotScanners:
      isCount(last.addresses_not_scanners) && last.addresses_not_scanners <= last.addresses
        ? last.addresses_not_scanners
        : null,
    artifacts: count(last.artifacts),
    credentialPairs: count(last.credential_pairs),
    usernames: count(last.usernames),
    sessions7d: withSessions.length > 0 ? withSessions.reduce((sum, { row }) => sum + row.sessions_started, 0) : null,
    sessionDays: withSessions.length,
    // Variação de endereços publicados face ao dia mais antigo da janela.
    addressesDelta: first.ms < lastMs && isCount(first.row.addresses) ? last.addresses - first.row.addresses : null,
    deltaDays: Math.round((lastMs - first.ms) / 86_400_000),
    techniques,
    campaigns,
  };
}

/**
 * Vai buscar `history.json` às fontes fixas, por ordem, e devolve o primeiro
 * resumo válido (com `fetched`). Redirects recusados (como no Radar): um
 * ficheiro que mudou de sítio aparece como falha em vez de ser seguido para
 * fora da lista. `{ ok: false, error }` se nenhuma fonte der um resumo.
 */
export async function fetchIntelSummary({ now = Date.now(), timeoutMs = 8000, sources = INTEL_SOURCES } = {}) {
  const errors = [];
  for (const url of sources) {
    try {
      const res = await fetch(url, {
        headers: { accept: 'application/json', 'user-agent': 'danielmala.co-intel/1.0 (+https://danielmala.co/)' },
        redirect: 'manual',
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.status !== 200) {
        errors.push(`http_${res.status}`);
        continue;
      }
      const summary = summarizeHistory(JSON.parse(await readCapped(res, INTEL_MAX_BYTES)), now);
      if (summary.ok) return { ...summary, fetched: new Date(now).toISOString() };
      errors.push(summary.error);
    } catch (err) {
      errors.push(err?.name === 'SyntaxError' ? 'bad_json' : 'fetch_failed');
    }
  }
  return { ok: false, error: errors.join(',') };
}
