import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  byDecoyPath,
  techOf,
  riskDotClass,
  labelsWithoutCollision,
  timelinePoints,
} from '../src/scripts/perimeter-charts.js';

test('byDecoyPath: igualdade exata e fallback de prefixo', () => {
  const byKey = { '/admin': { id: 'exact' }, '/phpmyadmin/': { id: 'prefix' } };
  assert.deepEqual(byDecoyPath(byKey, '/admin'), { id: 'exact' });
  assert.deepEqual(byDecoyPath(byKey, '/phpmyadmin/index.php'), { id: 'prefix' });
  assert.equal(byDecoyPath(byKey, '/nope'), null);
  assert.equal(byDecoyPath(byKey, undefined), null);
});

test('techOf: prefere a técnica do evento, senão faz lookup por path', () => {
  const tech = {
    byPath: { '/phpmyadmin/': { id: 'T1190', name: 'Exploit', href: '#T1190' } },
    byId: { T1190: { id: 'T1190', name: 'Exploit', href: '#T1190' } },
  };
  assert.deepEqual(techOf({ technique: 'T1190', path: '/x' }, tech), tech.byId.T1190);
  assert.deepEqual(techOf({ path: '/phpmyadmin/setup.php' }, tech), tech.byPath['/phpmyadmin/']);
  assert.equal(techOf({ path: '/unknown' }, tech), null);
});

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

test('timelinePoints: filtra pela janela e desloca eventos no mesmo bucket', () => {
  const now = 1_000_000_000_000;
  const windowMs = 7 * 86400_000;
  const events = [
    { ts: now - windowMs - 1000 }, // fora da janela (demasiado antigo)
    { ts: now - 1000 },
    { ts: now - 1000 }, // mesmo instante — desloca-se
    { ts: now + 60_000 }, // futuro — fora do [now-windowMs, now] documentado
  ];
  const pts = timelinePoints(events, { now, windowMs, xMin: 0, xMax: 100, bucketPx: 6 });
  assert.equal(pts.length, 2);
  assert.notEqual(pts[0].x, pts[1].x);
  assert.ok(pts.every((p) => p.event.ts <= now));
});
