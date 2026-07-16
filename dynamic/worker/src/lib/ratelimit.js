// Rate limiting de janela fixa, puro e testável. O estado (contagem +
// início da janela) é guardado no KV pelo index; aqui está só a transição.
// A chave por-cliente é um hash truncado e salteado do IP (salt roda ao
// dia) — nunca é associada aos eventos do honeypot nem persistida além da
// TTL da janela. É o único uso de qualquer valor derivado de IP.

/**
 * Calcula o próximo estado da janela.
 *   prev — { count, windowStart } | null
 *   now  — epoch ms
 *   windowMs, max — configuração da janela
 * Devolve { allowed, state, retryAfterSec }.
 */
export function nextState(prev, { now, windowMs, max }) {
  let count = prev?.count ?? 0;
  let windowStart = prev?.windowStart ?? now;
  if (now - windowStart >= windowMs) {
    count = 0;
    windowStart = now;
  }
  if (count >= max) {
    const retryAfterSec = Math.ceil((windowStart + windowMs - now) / 1000);
    return { allowed: false, state: { count, windowStart }, retryAfterSec };
  }
  return { allowed: true, state: { count: count + 1, windowStart }, retryAfterSec: 0 };
}

/**
 * Hash truncado e salteado de um identificador (IP) para chave de rate
 * limit. Usa WebCrypto (disponível no Worker e no Node moderno). O salt
 * diário deve vir de fora (env + data) para rodar. Devolve hex de 16 chars.
 */
export async function clientHash(ip, dailySalt) {
  const data = new TextEncoder().encode(`${dailySalt}:${ip ?? 'unknown'}`);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(buf)].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Salt do dia: prefixo secreto (env) + data UTC. Roda à meia-noite UTC. */
export function dailySalt(secret, now = Date.now()) {
  const day = new Date(now).toISOString().slice(0, 10);
  return `${secret ?? 'rotate-me'}:${day}`;
}
