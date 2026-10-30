import { test } from 'node:test';
import assert from 'node:assert/strict';
import { shuffle, parseBest, loadBest, saveBest } from '../src/scripts/game-kit.js';

test('shuffle: é permutação, não altera o original e usa o rng', () => {
  const src = [1, 2, 3, 4, 5];
  assert.deepEqual([...shuffle(src, () => 0.999999)].sort(), src);
  assert.deepEqual(src, [1, 2, 3, 4, 5]);
  assert.notDeepEqual(shuffle(src, () => 0), src);
});

test('parseBest: só aceita um inteiro 0..max; lixo no localStorage vira null', () => {
  assert.equal(parseBest('0', 10), 0);
  assert.equal(parseBest('7', 10), 7);
  assert.equal(parseBest('10', 10), 10);
  for (const bad of ['11', '-1', '7.5', ' 7', '7 ', '1e1', 'NaN', 'Infinity', '0x7', '', '9999', '{"a":1}', null, undefined, 7]) {
    assert.equal(parseBest(bad, 10), null, String(bad));
  }
  assert.equal(parseBest('2880'), 2880, 'sem max: qualquer inteiro razoável');
});

test('loadBest/saveBest: guarda só recordes, o primeiro conta, e tolera storage a lançar', () => {
  const mem = new Map();
  const ok = { getItem: (k) => mem.get(k) ?? null, setItem: (k, v) => mem.set(k, v) };
  assert.equal(loadBest(ok, 'k'), null);
  assert.deepEqual(saveBest(ok, 'k', 0), { previous: null, record: true, best: 0 }, '0 na 1.ª partida também fica');
  assert.deepEqual(saveBest(ok, 'k', 80), { previous: 0, record: true, best: 80 });
  assert.equal(saveBest(ok, 'k', 80).record, false, 'empate não é recorde');
  assert.deepEqual(saveBest(ok, 'k', 40), { previous: 80, record: false, best: 80 });
  assert.equal(loadBest(ok, 'k'), 80);
  assert.equal(loadBest(ok, 'outra'), null, 'chaves por jogo não se misturam');
  mem.set('k', '99');
  assert.equal(loadBest(ok, 'k', 10), null, 'acima do máximo do jogo é lixo');

  const boom = { getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('QuotaExceeded'); } };
  assert.equal(loadBest(boom, 'k'), null);
  assert.equal(loadBest(null, 'k'), null, 'sem localStorage de todo');
  assert.deepEqual(saveBest(boom, 'k', 50), { previous: null, record: false, best: null }, 'falhou a escrita: nada guardado');
  const readOnly = { getItem: () => '20', setItem() { throw new Error('QuotaExceeded'); } };
  assert.deepEqual(saveBest(readOnly, 'k', 50), { previous: 20, record: false, best: 20 });
});
