/**
 * Faixa "prova ao vivo" da home — lógica pura (sem DOM), testável em Node.
 *
 * Cada função devolve um número pronto a mostrar ou `null`. `null` significa
 * "não afirmes nada": a célula fica com o texto de build, que só convida a
 * abrir o painel. Um documento malformado nunca vira um 0 — "0 certificados
 * inesperados" a partir de lixo seria uma afirmação de segurança falsa.
 */
import { firewallActionClass } from './observability.js';

const isCount = (n) => typeof n === 'number' && Number.isInteger(n) && n >= 0;

/**
 * Pedidos bloqueados ou desafiados pela firewall em 7 dias
 * (`/api/threat-intel` → `firewall7d.byAction: [{ key, count }]`).
 */
export function firewallStopped(doc) {
  const rows = doc?.firewall7d?.byAction;
  if (!Array.isArray(rows)) return null;
  let sum = 0;
  for (const row of rows) {
    if (typeof row?.key !== 'string' || !isCount(row.count)) return null;
    if (firewallActionClass(row.key) !== 'allowed') sum += row.count;
  }
  return sum;
}

/**
 * Certificados de emissor inesperado na janela da vigia de CT (`/api/ct` →
 * `summary: { total, unexpected }`). Sem nenhum certificado observado
 * (`total` 0: o crt.sh não respondeu ou a janela veio vazia) não há base
 * para dizer "0 inesperados", por isso devolve `null`.
 */
export function unexpectedCerts(doc) {
  const s = doc?.summary;
  if (!isCount(s?.total) || !isCount(s?.unexpected)) return null;
  if (s.total === 0 || s.unexpected > s.total) return null;
  return s.unexpected;
}

/** 1, 2, 5, 10, 20, 50, … — passos que se leem bem numa legenda. */
function* oneTwoFive() {
  for (let p = 1; ; p *= 10) {
    yield p;
    yield 2 * p;
    yield 5 * p;
  }
}

/** Período do pulso âmbar do hero, em segundos: legível entre estes limites. */
export const PULSE_MIN_S = 3;
export const PULSE_MAX_S = 15;

/**
 * Pedidos travados em 7 dias (`firewallStopped`) → cadência do traço âmbar do
 * hero (NetworkTopology), para que o movimento siga o ritmo real da firewall:
 *
 * - `perHour`: média por hora na janela (total / 168).
 * - Ritmo alto (um evento a cada ≤ PULSE_MAX_S s): tempo real, e cada pulso
 *   vale `eventsPerPulse` pedidos (1, 2, 5, 10, …) — o menor que dá um
 *   período ≥ PULSE_MIN_S. `speedup` = 1.
 * - Ritmo baixo: cada pulso é 1 pedido e o tempo corre `speedup` vezes mais
 *   depressa (1, 2, 5, 10, …) — o menor que dá um período ≤ PULSE_MAX_S.
 *
 * 0 pedidos → `{ perHour: 0, periodSec: null }` (o traço pára). Contagem
 * inválida → null (não se afirma nada, como em firewallStopped).
 */
export function pulseCadence(stopped7d) {
  if (!isCount(stopped7d)) return null;
  if (stopped7d === 0) return { perHour: 0, eventsPerPulse: null, speedup: null, periodSec: null };
  const perHour = stopped7d / 168;
  const secondsPerEvent = 3600 / perHour;
  const round = (s) => Math.round(s * 100) / 100;
  if (secondsPerEvent <= PULSE_MAX_S) {
    for (const n of oneTwoFive()) {
      if (n * secondsPerEvent >= PULSE_MIN_S) {
        return { perHour, eventsPerPulse: n, speedup: 1, periodSec: round(n * secondsPerEvent) };
      }
    }
  }
  for (const f of oneTwoFive()) {
    if (secondsPerEvent / f <= PULSE_MAX_S) {
      return { perHour, eventsPerPulse: 1, speedup: f, periodSec: round(secondsPerEvent / f) };
    }
  }
  return null; // inalcançável: a sequência cresce sem limite
}
