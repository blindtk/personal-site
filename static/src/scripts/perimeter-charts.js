// Lógica pura dos gráficos de CloudflarePage.astro — sem DOM, testável em
// Node (ver CLAUDE.md).

/** Classe visual (cor) de um ponto no gráfico de risco por país. */
export function riskDotClass(row) {
  if (row.lowSample) return 'sample';
  const rate = Number(row.rate) || 0;
  if (rate >= 0.5) return 'high';
  if (rate >= 0.2) return 'med';
  return 'low';
}

/**
 * Decide que pontos de um gráfico de dispersão recebem rótulo de texto sem
 * colidirem uns com os outros. `points` é `[{x, y, halfWidth}]` (halfWidth =
 * metade da largura estimada do rótulo desse ponto, em px do viewBox);
 * devolve o Set de índices aceites, por ordem de x crescente — com vários
 * países de amostra pequena (todos a 100%, apinhados no canto esquerdo da
 * escala log) uma distância fixa pequena deixava rótulos sobrepostos e
 * ilegíveis, por isso o limiar de colisão usa a largura REAL do texto, não
 * uma distância fixa.
 */
export function labelsWithoutCollision(points, { verticalTolerance = 16 } = {}) {
  const accepted = [];
  const labelled = new Set();
  const order = points
    .map((p, i) => ({ p, i }))
    .sort((a, b) => a.p.x - b.p.x);
  for (const { p, i } of order) {
    const collide = accepted.some(
      (q) => Math.abs(q.x - p.x) < (q.halfWidth + p.halfWidth) && Math.abs(q.y - p.y) < verticalTolerance,
    );
    if (!collide) {
      accepted.push(p);
      labelled.add(i);
    }
  }
  return labelled;
}
