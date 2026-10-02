import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  riskDotClass,
  labelsWithoutCollision,
} from '../src/scripts/perimeter-charts.js';

test('riskDotClass: amostra pequena vence a taxa, senão os limiares 50%/20%', () => {
  assert.equal(riskDotClass({ lowSample: true, rate: 0.9 }), 'sample');
  assert.equal(riskDotClass({ lowSample: false, rate: 0.6 }), 'high');
  assert.equal(riskDotClass({ lowSample: false, rate: 0.3 }), 'med');
  assert.equal(riskDotClass({ lowSample: false, rate: 0.05 }), 'low');
});

test('labelsWithoutCollision: aceita pontos afastados, rejeita sobrepostos', () => {
  const points = [
    { x: 0, y: 0, halfWidth: 10 },
    { x: 5, y: 0, halfWidth: 10 }, // colide com o anterior (dx=5 < 20)
    { x: 100, y: 0, halfWidth: 10 }, // longe, aceite
  ];
  const labelled = labelsWithoutCollision(points);
  assert.ok(labelled.has(0));
  assert.ok(!labelled.has(1));
  assert.ok(labelled.has(2));
});

test('labelsWithoutCollision: mesma posição x mas y afastado não colide', () => {
  const points = [
    { x: 0, y: 0, halfWidth: 10 },
    { x: 0, y: 50, halfWidth: 10 },
  ];
  const labelled = labelsWithoutCollision(points, { verticalTolerance: 16 });
  assert.equal(labelled.size, 2);
});
