// Lógica pura partilhada por HoneypotPage.astro e CloudflarePage.astro —
// sem DOM, testável em Node (ver CLAUDE.md). Extraído do antigo
// PerimeterPage.astro (1682 linhas, um único ficheiro) quando a página se
// dividiu em duas — ver docs/this-site-section-audit-2026-08-06.md.

/**
 * Lookup por path-isco com fallback de prefixo. Convenção dos paths-isco (a
 * mesma de dynamic/worker/src/lib/decoys.js e attack-map.js): uma chave
 * terminada em '/' cobre também tudo por baixo dela. O evento guarda o path
 * CONCRETO que o scanner pediu (`/phpmyadmin/index.php`), não a chave do
 * isco (`/phpmyadmin/`) — um lookup por igualdade exata falhava sempre
 * nesses paths.
 */
export function byDecoyPath(byKey, path) {
  if (!path) return null;
  if (Object.hasOwn(byKey, path)) return byKey[path];
  for (const key of Object.keys(byKey)) {
    if (key.endsWith('/') && path.startsWith(key)) return byKey[key];
  }
  return null;
}

/**
 * Técnica de um evento: preferir a que o Worker anexou; senão, lookup local
 * por path (mesma fonte de dados — belt and suspenders). `tech` é
 * `{ byPath, byId }`, o mesmo shape de content/honeypot-attack.json +
 * content/attack.json já resolvido no build.
 */
export function techOf(ev, tech) {
  const id = ev?.technique ?? byDecoyPath(tech.byPath, ev?.path)?.id ?? null;
  return id ? (tech.byId[id] ?? byDecoyPath(tech.byPath, ev?.path) ?? null) : null;
}

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

/**
 * Posições X de uma linha do tempo simples (fallback do heatmap quando há
 * poucos eventos na janela) — `events` com `ts` dentro de `[now-windowMs,
 * now]`, mapeados para `[xMin, xMax]`. Eventos com o mesmo instante (a
 * anonimização arredonda a 5 min) caem no mesmo x — em vez de se
 * sobreporem, cada um seguinte desloca-se ligeiramente por `bucketPx`, como
 * o cluster "AS32613 · 2 eventos" do mockup original.
 */
export function timelinePoints(events, { now = Date.now(), windowMs, xMin, xMax, bucketPx = 6 }) {
  const start = now - windowMs;
  const inWindow = events
    .filter((e) => {
      const ts = Number(e?.ts);
      return ts >= start && ts <= now;
    })
    .sort((a, b) => Number(a.ts) - Number(b.ts));
  const xOf = (ts) => xMin + ((ts - start) / windowMs) * (xMax - xMin);
  const bucketCount = new Map();
  return inWindow.map((e) => {
    const rawX = xOf(Number(e.ts));
    const bucket = Math.round(rawX / bucketPx);
    const idx = bucketCount.get(bucket) ?? 0;
    bucketCount.set(bucket, idx + 1);
    return { event: e, x: rawX + idx * bucketPx };
  });
}
