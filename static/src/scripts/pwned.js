/**
 * Verificação de password comprometida por k-anonimato (Have I Been Pwned).
 * Toda a criptografia acontece aqui, no browser: a password é reduzida a
 * SHA-1, só os 5 primeiros hex (o "prefixo") saem para o Worker, e a
 * correspondência do resto do hash é feita localmente. A password nunca sai
 * da máquina.
 *
 * Lógica pura (sem DOM) para poder ser testada em Node — a componente
 * PwnedCheck.astro só faz a ligação ao DOM e à rede.
 */

/** SHA-1 de uma string UTF-8 → 40 hex maiúsculos. WebCrypto (browser + Node). */
export async function sha1Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest('SHA-1', bytes);
  return [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
}

/**
 * Parte um hash SHA-1 (40 hex) em { prefix (5), suffix (35) }, o corte que o
 * protocolo de range do HIBP usa. Devolve null se não for um SHA-1 válido.
 */
export function splitHash(hash) {
  if (typeof hash !== 'string' || !/^[0-9A-Fa-f]{40}$/.test(hash)) return null;
  const up = hash.toUpperCase();
  return { prefix: up.slice(0, 5), suffix: up.slice(5) };
}

/**
 * Procura o sufixo na lista devolvida pelo Worker ([sufixo, contagem]) e
 * devolve a contagem de fugas. 0 = não encontrada (ou entrada de padding com
 * contagem 0). A comparação é case-insensitive por segurança.
 */
export function matchCount(suffixes, suffix) {
  if (!Array.isArray(suffixes) || typeof suffix !== 'string') return 0;
  const target = suffix.toUpperCase();
  for (const entry of suffixes) {
    if (!Array.isArray(entry)) continue;
    const [s, c] = entry;
    if (typeof s === 'string' && s.toUpperCase() === target) {
      return Number.isInteger(c) && c > 0 ? c : 0;
    }
  }
  return 0;
}
