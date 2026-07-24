import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  formatNumber,
  formatBytes,
  formatPercent,
  relativeTime,
  groupBy,
  withBars,
  threatRate,
  sparkPath,
} from '../src/scripts/observability.js';

test('formatNumber: milhares e não-números', () => {
  assert.equal(formatNumber(1234567, 'en-GB'), '1,234,567');
  assert.equal(formatNumber(0, 'en-GB'), '0');
  assert.equal(formatNumber('nope'), '—');
});

test('formatBytes: base 1024 com vetores conhecidos', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(512), '512 B');
  assert.equal(formatBytes(1024, 'en-GB'), '1 KB');
  assert.equal(formatBytes(1536, 'en-GB'), '1.5 KB');
  assert.equal(formatBytes(1048576, 'en-GB'), '1 MB');
  assert.equal(formatBytes(-5), '0 B');
});

test('formatPercent: fração → percentagem', () => {
  assert.equal(formatPercent(0.1234), '12.3%');
  assert.equal(formatPercent(1), '100.0%');
  assert.equal(formatPercent(0, 0), '0%');
  assert.equal(formatPercent(NaN), '—');
});

test('relativeTime: escolhe a maior unidade', () => {
  const now = 1_000_000_000_000;
  assert.deepEqual(relativeTime(now - 30_000, now), { value: 30, unit: 'second' });
  assert.deepEqual(relativeTime(now - 5 * 60_000, now), { value: 5, unit: 'minute' });
  assert.deepEqual(relativeTime(now - 3 * 3600_000, now), { value: 3, unit: 'hour' });
  assert.deepEqual(relativeTime(now - 2 * 86400_000, now), { value: 2, unit: 'day' });
  // futuro trata-se como agora (nunca negativo)
  assert.deepEqual(relativeTime(now + 10_000, now), { value: 0, unit: 'second' });
});

test('groupBy: agrega, soma, ordena e corta', () => {
  const rows = [
    { country: 'PT', hits: 3 },
    { country: 'US', hits: 5 },
    { country: 'PT', hits: 2 },
    { country: '', hits: 9 },
  ];
  const out = groupBy(rows, (r) => r.country, (r) => r.hits, 2);
  // Empate (PT=5, US=5): ordenação estável mantém a ordem de inserção (PT
  // foi visto primeiro), por isso PT fica à frente de US.
  assert.deepEqual(out, [
    { key: 'PT', value: 5 },
    { key: 'US', value: 5 },
  ]);
  // contagem por omissão (valueFn = 1)
  assert.deepEqual(groupBy(['a', 'b', 'a'], (x) => x), [
    { key: 'a', value: 2 },
    { key: 'b', value: 1 },
  ]);
  assert.deepEqual(groupBy(null, (x) => x), []);
});

test('withBars: escala relativa ao máximo', () => {
  assert.deepEqual(withBars([{ value: 10 }, { value: 5 }, { value: 0 }]), [
    { value: 10, pct: 100 },
    { value: 5, pct: 50 },
    { value: 0, pct: 0 },
  ]);
  assert.deepEqual(withBars([{ value: 0 }]), [{ value: 0, pct: 0 }]);
});

test('sparkPath: linha/área num viewBox, vazio degrada', () => {
  assert.deepEqual(sparkPath([]), { line: '', area: '', max: 0 });
  const sp = sparkPath([0, 10], { width: 100, height: 30, pad: 2 });
  assert.equal(sp.max, 10);
  // 2 pontos: x começa no pad (2) e acaba em width-pad (98)
  assert.ok(sp.line.startsWith('M2.00 28.00')); // valor 0 → fundo (30-2)
  assert.ok(sp.line.includes('L98.00 2.00')); // valor 10 (=max) → topo (pad)
  // a área fecha até à base
  assert.ok(sp.area.endsWith('Z'));
  // um único ponto centra-se
  assert.ok(sparkPath([5]).line.startsWith('M50.00'));
});

test('threatRate: clamp e defesa', () => {
  assert.equal(threatRate(50, 1000), 0.05);
  assert.equal(threatRate(5, 0), 0);
  assert.equal(threatRate(2000, 1000), 1);
  assert.equal(threatRate('x', 10), 0);
});
