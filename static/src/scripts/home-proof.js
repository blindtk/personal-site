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
