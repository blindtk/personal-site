// Globo de ataques (/este-site/mapa-de-ataques/) — matemática pura, sem DOM: máscara de
// terra, projeção ortográfica, arcos de grande círculo (Radar, mundo) e
// bolhas por país de origem (firewall deste site), com tamanho por valor.
// O desenho (canvas 2D) vive em src/components/attack-map/globe-canvas.ts.
//
// Porquê um globo próprio e não o cobe/globe.gl: o cobe 2.0.1 carrega a
// textura do mapa de um URI `data:` (bloqueado por img-src 'self' blob:) e
// injeta um <style> inline (bloqueado por style-src 'self'), e só tem uma
// espessura de arco para todos; o globe.gl arrasta o three.js (bem acima dos
// ~150 KB gz). Isto são ~3 KB gz + ~3 KB gz de dados, sem tocar na CSP.

import { firewallActionClass } from './observability.js';

const DEG = Math.PI / 180;

/**
 * Máscara de terra (bitmap de `cols`×`rows` células, linhas de norte para
 * sul, ver scripts/gen-attack-map-geo.mjs) → pontos [lat, lon] no centro de
 * cada célula de terra. Perto dos polos as células encolhem, por isso só se
 * guarda uma em cada round(1/cos(lat)) — a densidade fica uniforme na esfera.
 */
export function landDots({ land, cols, rows, step }) {
  const bytes = Uint8Array.from(atob(land), (ch) => ch.charCodeAt(0));
  const dots = [];
  for (let r = 0; r < rows; r++) {
    const lat = 90 - step / 2 - r * step;
    const every = Math.max(1, Math.round(1 / Math.cos(lat * DEG)));
    for (let c = 0; c < cols; c += every) {
      const i = r * cols + c;
      if ((bytes[i >> 3] >> (i & 7)) & 1) dots.push([lat, -180 + step / 2 + c * step]);
    }
  }
  return dots;
}

/** [lat, lon] em graus → vetor unitário: y é o eixo polar, z aponta para (0°, 0°), x para (0°, 90°E). */
export function toVec(lat, lon) {
  const la = lat * DEG;
  const lo = lon * DEG;
  return [Math.cos(la) * Math.sin(lo), Math.sin(la), Math.cos(la) * Math.cos(lo)];
}

/**
 * Roda um vetor: `phi` à volta do eixo polar (o globo a girar) e depois
 * `theta` à volta do eixo horizontal (inclinação). z > 0 = virado para nós.
 */
export function rotate([x, y, z], phi, theta) {
  const cp = Math.cos(phi);
  const sp = Math.sin(phi);
  const x1 = x * cp + z * sp;
  const z1 = -x * sp + z * cp;
  const ct = Math.cos(theta);
  const st = Math.sin(theta);
  return [x1, y * ct - z1 * st, y * st + z1 * ct];
}

/**
 * Um ponto (já rodado, raio ≥ 1) está escondido se estiver atrás do plano
 * da imagem E dentro do disco do globo — um arco alto pode passar por trás
 * e continuar visível fora do contorno.
 */
export function isHidden([x, y, z]) {
  return z < 0 && x * x + y * y < 1;
}

/**
 * Arco de grande círculo de `from` para `to` ([lat, lon]) em `n` segmentos,
 * levantado da superfície: altura máxima proporcional à distância angular
 * (pares vizinhos ficam rasos, intercontinentais sobem). Devolve n+1
 * vetores (raio 1 nos extremos).
 */
export function arcPoints(from, to, n = 32) {
  const a = toVec(...from);
  const b = toVec(...to);
  const dot = Math.min(1, Math.max(-1, a[0] * b[0] + a[1] * b[1] + a[2] * b[2]));
  const omega = Math.acos(dot);
  // Coincidentes, ou antípodas (infinitos grandes círculos — sin(ω) = 0
  // dava NaN): não há arco a desenhar, o par fica só na tabela.
  if (omega < 1e-6 || Math.PI - omega < 1e-6) return [];
  const lift = 0.08 + 0.32 * (omega / Math.PI);
  const so = Math.sin(omega);
  const pts = [];
  for (let i = 0; i <= n; i++) {
    const t = i / n;
    const ka = Math.sin((1 - t) * omega) / so;
    const kb = Math.sin(t * omega) / so;
    const h = 1 + lift * Math.sin(Math.PI * t);
    pts.push([(a[0] * ka + b[0] * kb) * h, (a[1] * ka + b[1] * kb) * h, (a[2] * ka + b[2] * kb) * h]);
  }
  return pts;
}

/**
 * Tamanho visual (px CSS) de um valor — espessura de um arco, raio de uma
 * bolha: raiz quadrada (a área percebida cresce com o valor, não a largura),
 * de `min` (valor 0) a `max` (o maior valor, `top`). Valor acima de `top`
 * fica em `max`; valor ≤ 0, NaN ou top ≤ 0 → min.
 */
export function sqrtScale(value, top, { min, max }) {
  if (!(value > 0) || !(top > 0)) return min;
  return min + (max - min) * Math.sqrt(Math.min(1, value / top));
}

/**
 * Pares [origem, alvo, pct] da API → o que o globo desenha: arcos (países
 * diferentes, ambos com centróide) e "anéis" para ataques domésticos (origem
 * = alvo). Pares sem centróide ficam só na tabela.
 */
export function globeShapes(pairs, centroids) {
  const arcs = [];
  const rings = [];
  for (const [origin, target, pct] of Array.isArray(pairs) ? pairs : []) {
    const from = centroids[origin];
    const to = centroids[target];
    if (!from || !to) continue;
    if (origin === target) rings.push({ at: from, pct, code: origin });
    else arcs.push({ from, to, pct, origin, target });
  }
  return { arcs, rings };
}

/**
 * Linhas de `firewall7d.byCountry` (/api/threat-intel — os eventos de
 * firewall deste site, por país de origem) → bolhas no centróide de cada
 * país, com o total de eventos (`total`; `count` em respostas antigas, sem
 * ele) e a classe da ação mais comum (bloqueado/desafiado/deixado passar).
 * Não há alvo: o site é servido por anycast, não tem um lugar no mapa.
 * Países sem centróide (Tor, XX) e contagens ≤ 0 ficam de fora.
 */
export function bubbleShapes(rows, centroids) {
  const out = [];
  for (const row of Array.isArray(rows) ? rows : []) {
    const code = typeof row?.country === 'string' ? row.country.toUpperCase() : '';
    const at = Object.hasOwn(centroids, code) ? centroids[code] : null;
    const count = Number(row?.total ?? row?.count);
    if (!at || !(count > 0)) continue;
    out.push({ at, count, code, cls: firewallActionClass(row.action) });
  }
  return out;
}
