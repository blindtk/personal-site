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

/**
 * Decide se uma escrita cabe dentro do cap da janela atual.
 *   prev — { count, windowStart } | null (estado lido do KV)
 *   now  — epoch ms
 *   windowMs, max — configuração da janela
 * Devolve { allowed, state }. Quando allowed é false, state mantém a
 * contagem no teto (não a incrementa) para não crescer sem limite.
 */
export function underCap(prev, { now, windowMs, max }) {
  let count = prev?.count ?? 0;
  let windowStart = prev?.windowStart ?? now;
  if (now - windowStart >= windowMs) {
    count = 0;
    windowStart = now;
  }
  const allowed = count < max;
  return { allowed, state: { count: allowed ? count + 1 : count, windowStart } };
}
