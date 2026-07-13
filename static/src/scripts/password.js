/**
 * Geração de passwords com CSPRNG (crypto.getRandomValues) — sem DOM.
 */

export const CHARSETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.<>?/~',
};

const AMBIGUOUS = new Set('l1IO0o|`\'"');

export function buildPool({ lower, upper, digits, symbols, noAmbiguous }) {
  let pool = '';
  if (lower) pool += CHARSETS.lower;
  if (upper) pool += CHARSETS.upper;
  if (digits) pool += CHARSETS.digits;
  if (symbols) pool += CHARSETS.symbols;
  if (noAmbiguous) pool = [...pool].filter((c) => !AMBIGUOUS.has(c)).join('');
  return pool;
}

/** Índice aleatório uniforme em [0, max) com rejection sampling (sem viés de módulo). */
function randomIndex(max) {
  const limit = Math.floor(0xffffffff / max) * max;
  const buf = new Uint32Array(1);
  let v;
  do {
    crypto.getRandomValues(buf);
    v = buf[0];
  } while (v >= limit);
  return v % max;
}

export function generatePassword(pool, length) {
  let out = '';
  for (let i = 0; i < length; i++) {
    out += pool[randomIndex(pool.length)];
  }
  return out;
}

/** Entropia teórica em bits: length × log2(|pool|). */
export function entropyBits(poolSize, length) {
  if (poolSize <= 1) return 0;
  return Math.round(length * Math.log2(poolSize));
}

/** Classifica a entropia: chaves usadas pelo dicionário i18n. */
export function strengthKey(bits) {
  if (bits < 45) return 'weak';
  if (bits < 70) return 'ok';
  if (bits < 100) return 'strong';
  return 'excellent';
}
