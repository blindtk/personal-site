import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeRadar, itemsFor } from '../src/scripts/radar.js';

const SOURCES = [
  { id: 'cncs', name: 'CNCS', type: 'alert', lang: 'pt', ok: true },
  { id: 'the-record', name: 'The Record', type: 'news', lang: 'en', ok: false },
];

test('normalizeRadar: um { error } (429/502) ou lixo dá listas vazias, não lança', () => {
  for (const doc of [{ error: 'rate_limited' }, null, 'x', { sources: 'x', items: {} }]) {
    assert.deepEqual(normalizeRadar(doc), { generated: null, sources: [], items: [] });
  }
});

test('normalizeRadar: itens sem fonte conhecida, sem https ou sem data não chegam ao DOM', () => {
  const { items } = normalizeRadar({
    generated: '2026-10-29T23:30:00.000Z',
    sources: SOURCES,
    items: [
      { t: 'ok', u: 'https://a.example/1', s: 'cncs', d: '2026-10-29T10:00:00.000Z' },
      { t: 'js', u: 'javascript:alert(1)', s: 'cncs', d: '2026-10-29T10:00:00.000Z' },
      { t: 'orphan', u: 'https://a.example/2', s: 'unknown', d: '2026-10-29T10:00:00.000Z' },
      { t: 'nodate', u: 'https://a.example/3', s: 'cncs', d: 'soon' },
      { t: 'newer', u: 'https://a.example/4', s: 'the-record', d: '2026-10-29T11:00:00.000Z' },
    ],
  });
  assert.deepEqual(items.map((it) => it.title), ['newer', 'ok']);
  assert.deepEqual(itemsFor(items, 'alert').map((it) => it.title), ['ok']);
  assert.deepEqual(itemsFor(items, 'news').map((it) => it.title), ['newer']);
});
