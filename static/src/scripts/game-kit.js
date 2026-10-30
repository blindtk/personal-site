// Peças comuns aos jogos das ferramentas («O link verdadeiro», «Phishing ou
// legítimo?»): baralhar e melhor pontuação. Sem DOM; o storage é injetado.

/** Fisher-Yates sobre uma cópia; `rng` devolve [0, 1). */
export function shuffle(items, rng = Math.random) {
  const a = [...items];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/** Só aceita um inteiro decimal 0..max; qualquer lixo no localStorage vira null. */
export function parseBest(raw, max = Number.MAX_SAFE_INTEGER) {
  if (typeof raw !== 'string' || !/^\d{1,9}$/.test(raw)) return null;
  const n = Number(raw);
  return n <= max ? n : null;
}

/** localStorage pode lançar (modo privado, bloqueado) ou nem existir: null. */
export function loadBest(storage, key, max) {
  try {
    return parseBest(storage.getItem(key), max);
  } catch {
    return null;
  }
}

/**
 * Grava `score` se for recorde (ou o primeiro). `best` é o que ficou de facto
 * guardado: se o storage falhar, o jogo continua, mas nada se anuncia como
 * recorde nem como melhor resultado.
 */
export function saveBest(storage, key, score, max) {
  const previous = loadBest(storage, key, max);
  if (previous !== null && score <= previous) return { previous, record: false, best: previous };
  try {
    storage.setItem(key, String(score));
  } catch {
    return { previous, record: false, best: previous };
  }
  return { previous, record: true, best: score };
}
