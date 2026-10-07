// Rate limiting de janela fixa, puro e testável. O estado (contagem +
// início da janela) é guardado pelo index na Cache API (KV só como
// reserva); aqui está só a transição. A chave por-cliente é um hash
// truncado e salteado do IP (salt roda ao dia) — nunca é associada a
// nenhum evento nem persistida além da TTL da janela. É o único valor
// derivado do IP que o Worker guarda (o /api/mirror devolve o IP ao
// próprio pedido, sem o guardar — ADR 0023).

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
 * Identidade de rate limit de um IP: o próprio IPv4, ou o /64 de um IPv6.
 * Um cliente IPv6 recebe, no mínimo, um /64 inteiro (2^64 endereços) — com o
 * endereço completo como chave, rodar o sufixo dava-lhe um balde novo a cada
 * pedido e o limite por cliente deixava de limitar. Entrada que não é um IPv6
 * reconhecível (incluindo 'unknown') passa sem alteração.
 */
export function rateLimitIdentity(ip) {
  if (typeof ip !== 'string' || !ip.includes(':') || ip.includes('.') || !/^[0-9a-fA-F:]+$/.test(ip)) return ip ?? 'unknown';
  const halves = ip.toLowerCase().split('::');
  if (halves.length > 2) return ip;
  const head = halves[0] === '' ? [] : halves[0].split(':');
  const tail = halves.length === 2 ? (halves[1] === '' ? [] : halves[1].split(':')) : [];
  if (halves.length === 1 ? head.length !== 8 : head.length + tail.length > 7) return ip;
  const groups = halves.length === 1 ? head : [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail];
  if (!groups.every((g) => /^[0-9a-f]{1,4}$/.test(g))) return ip;
  return `${groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, '')).join(':')}::/64`;
}

/**
 * Hash truncado e salteado de um identificador (IP) para chave de rate
 * limit. Usa WebCrypto (disponível no Worker e no Node moderno). O salt
 * diário deve vir de fora (env + data) para rodar. Devolve hex de 16 chars.
 */
export async function clientHash(ip, dailySalt) {
  const data = new TextEncoder().encode(`${dailySalt}:${rateLimitIdentity(ip)}`);
  const buf = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(buf)].slice(0, 8).map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Salt do dia: prefixo secreto (env RATE_SALT) + data UTC. A componente de
 * data faz o salt rodar automaticamente à meia-noite UTC, o que:
 *   · impede reidentificar o mesmo IP entre dias a partir da chave de
 *     rate limit (a chave `rl:<rota>:<hash>` muda todos os dias), e
 *   · reinicia as contagens acumuladas de forma limpa.
 * Como a chave inclui a rota (ver index: `rl:${route}:${id}`), o limite é
 * por IP+rota — cada rota tem o seu próprio balde por cliente.
 *
 * Rotação do SEGREDO (RATE_SALT), separada da rotação diária automática:
 * trocar o segredo com `wrangler secret put RATE_SALT` invalida de imediato
 * TODOS os rate-limits acumulados (o hash deixa de bater). Isto é
 * intencional — é o botão de pânico se o esquema de limites for abusado.
 * Cadência recomendada: SEMANAL (ex.: cron/rotina de segurança à segunda).
 * Passos manuais no dia do deploy real (não fazer aqui): gerar string
 * longa aleatória, `wrangler secret put RATE_SALT`, e agendar o lembrete
 * semanal. O valor por omissão 'rotate-me' só serve em dev — em produção o
 * segredo TEM de estar definido.
 */
export function dailySalt(secret, now = Date.now()) {
  const day = new Date(now).toISOString().slice(0, 10);
  return `${secret ?? 'rotate-me'}:${day}`;
}
