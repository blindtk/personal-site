import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  landDots, toVec, rotate, isHidden, arcPoints, sqrtScale, globeShapes, bubbleShapes,
} from '../src/scripts/attack-globe.js';

const DEG = Math.PI / 180;
const close = (a, b, eps = 1e-9) => a.forEach((v, i) => assert.ok(Math.abs(v - b[i]) < eps, `${a} ≉ ${b}`));
const norm = ([x, y, z]) => Math.hypot(x, y, z);

test('toVec: (0°,0°) de frente, polo norte em cima, 90°E à direita', () => {
  close(toVec(0, 0), [0, 0, 1]);
  close(toVec(90, 0), [0, 1, 0]);
  close(toVec(0, 90), [1, 0, 0]);
});

test('rotate: phi = −lon e theta = lat põem esse ponto no centro do disco', () => {
  // Lisboa (38.7°N, 9.1°W): um sinal trocado em phi ou theta virava o globo
  close(rotate(toVec(38.7, -9.1), 9.1 * DEG, 38.7 * DEG), [0, 0, 1]);
  close(rotate(toVec(0, 90), -90 * DEG, 0), [0, 0, 1]);
});

test('isHidden: só atrás do plano E dentro do disco', () => {
  assert.equal(isHidden([0.5, 0, -0.1]), true);
  assert.equal(isHidden([0.5, 0, 0.1]), false); // à frente
  assert.equal(isHidden([1.1, 0, -0.1]), false); // atrás, mas fora do contorno (arco alto)
  assert.equal(isHidden([1, 0, -0.1]), false); // no contorno exato: visível
});

test('arcPoints: extremos nos centróides (raio 1), meio levantado, sem NaN', () => {
  const lisbon = [38.7, -9.1];
  const nyc = [40.7, -74];
  const pts = arcPoints(lisbon, nyc, 32);
  assert.equal(pts.length, 33);
  close(pts[0], toVec(...lisbon));
  close(pts[32], toVec(...nyc));
  assert.ok(norm(pts[16]) > 1.08);
  assert.ok(pts.every((p) => p.every(Number.isFinite)));
});

test('arcPoints: pontos coincidentes ou antípodas → [] (não NaN)', () => {
  assert.deepEqual(arcPoints([10, 20], [10, 20]), []);
  assert.deepEqual(arcPoints([10, 20], [-10, -160]), []);
});

test('sqrtScale: min no 0, max no maior valor, clamp acima; NaN → min', () => {
  const r = { min: 1, max: 5 };
  assert.equal(sqrtScale(0, 10, r), 1);
  assert.equal(sqrtScale(10, 10, r), 5);
  assert.equal(sqrtScale(20, 10, r), 5);
  assert.equal(sqrtScale(2.5, 10, r), 3); // raiz: 1/4 do valor → metade do caminho
  assert.equal(sqrtScale(NaN, 10, r), 1);
  assert.equal(sqrtScale(5, 0, r), 1);
});

test('landDots: ordem dos bits (LSB primeiro, linhas de norte para sul) e rarefação nos polos', () => {
  const geo = (bytes) => ({ land: Buffer.from(bytes).toString('base64'), cols: 18, rows: 9, step: 20 });
  // só o bit 1 (linha 0, coluna 1): 80°N, −180 + 10 + 20 = −150°
  assert.deepEqual(landDots(geo([0b10, ...new Array(20).fill(0)])), []); // coluna 1 é saltada a 80° (1 em cada 6)
  const one = new Array(21).fill(0);
  one[(4 * 18 + 1) >> 3] |= 1 << ((4 * 18 + 1) & 7); // linha 4 (equador), coluna 1
  assert.deepEqual(landDots(geo(one)), [[0, -150]]);
  // tudo terra: a 80° fica 1 em cada round(1/cos 80°) = 6 → 3 pontos; no equador 18
  const all = landDots(geo(new Array(21).fill(0xff)));
  assert.equal(all.filter(([lat]) => lat === 80).length, 3);
  assert.equal(all.filter(([lat]) => lat === 0).length, 18);
});

test('globeShapes: doméstico vira anel, sem centróide fica de fora', () => {
  const c = { US: [39.9, -98.8], CN: [36.6, 103.8], PT: [39.7, -8] };
  const { arcs, rings } = globeShapes([['CN', 'US', 6], ['US', 'US', 9], ['XK', 'US', 1]], c);
  assert.deepEqual(arcs, [{ from: c.CN, to: c.US, pct: 6, origin: 'CN', target: 'US' }]);
  assert.deepEqual(rings, [{ at: c.US, pct: 9, code: 'US' }]);
  assert.deepEqual(globeShapes(null, c), { arcs: [], rings: [] });
});

test('bubbleShapes: total (ou count, sem ele), classe da ação; Tor/XX, protótipo e ≤ 0 saem', () => {
  const c = { US: [39.9, -98.8], SG: [1.4, 103.8], DE: [51.1, 10.4] };
  const out = bubbleShapes([
    { country: 'US', action: 'managed_challenge', count: 500, total: 812 },
    { country: 'sg', action: 'block', count: 240 }, // resposta antiga, sem total
    { country: 'DE', action: 'skip', count: 0, total: 0 },
    { country: 'T1', action: 'block', count: 9, total: 9 },
    { country: 'constructor', action: 'block', count: 9, total: 9 },
  ], c);
  assert.deepEqual(out, [
    { at: c.US, count: 812, code: 'US', cls: 'challenged' },
    { at: c.SG, count: 240, code: 'SG', cls: 'blocked' },
  ]);
  assert.deepEqual(bubbleShapes(undefined, c), []);
});
