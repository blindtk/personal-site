// Cap global de escritas ao KV por janela de tempo. Puro e testável — a
// transição de estado vive aqui; o index guarda o contador no KV.
//
// Porquê: cada tentativa no honeypot faz várias escritas (recent, bucket
// horário, bucket diário, meta). Um atacante que martele os paths-isco
// podia inflacionar o custo/quota de escrita do KV. Este contador de
// janela fixa (global, não por-IP) põe um teto duro: passado o máximo,
// os eventos extra são descartados (o pedido continua a devolver 404,
// indistinguível). É best-effort — o KV é eventualmente consistente, por
// isso pedidos concorrentes podem passar um pouco do teto; o objetivo é
// limitar a ordem de grandeza do custo, não contar ao evento exato.
//
// Unidade = ESCRITAS, não eventos (auditoria de segurança 2026-09-25,
// docs/security-audit-2026-09-25/): um evento do honeypot custa 4-5 puts, um
// pedido aceite pelo rate limiter custa 2 (estado + contador), mas os caps
// contavam 1 por evento — a soma real ultrapassava o orçamento da conta que
// os caps diziam respeitar. `cost` é o nº de puts que o evento vai fazer,
// INCLUINDO a escrita do próprio contador, e `max` passa a ser um orçamento
// de escritas por janela.

/**
 * Decide se um evento que custa `cost` escritas cabe no cap da janela.
 *   prev — { count, windowStart } | null (estado lido do KV)
 *   now  — epoch ms
 *   windowMs, max — configuração da janela (max em escritas)
 *   cost — escritas que o evento vai fazer (por omissão 1)
 * Devolve { allowed, state }. Quando allowed é false, state mantém a
 * contagem (não a incrementa) para não crescer sem limite.
 */
export function underCap(prev, { now, windowMs, max, cost = 1 }) {
  let count = prev?.count ?? 0;
  let windowStart = prev?.windowStart ?? now;
  if (now - windowStart >= windowMs) {
    count = 0;
    windowStart = now;
  }
  const allowed = count + cost <= max;
  return { allowed, state: { count: allowed ? count + cost : count, windowStart } };
}
