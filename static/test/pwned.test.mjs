import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha1Hex, splitHash, matchCount } from '../src/scripts/pwned.js';

// Vetores de teste SHA-1 conhecidos (confirmados contra crypto.createHash
// do Node): "" e "abc" são os vetores oficiais FIPS 180; "password" é o
// exemplo clássico usado nas próprias demos do HIBP.
test('sha1Hex: vetores de teste conhecidos, 40 hex maiúsculos', async () => {
  assert.equal(await sha1Hex(''), 'DA39A3EE5E6B4B0D3255BFEF95601890AFD80709');
  assert.equal(await sha1Hex('abc'), 'A9993E364706816ABA3E25717850C26C9CD0D89D');
  assert.equal(await sha1Hex('password'), '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8');
});

test('splitHash: corta em prefixo de 5 + sufixo de 35 (protocolo de range do HIBP)', () => {
  const hash = '5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8';
  const split = splitHash(hash);
  assert.equal(split.prefix, '5BAA6');
  assert.equal(split.suffix, '1E4C9B93F3F0682250B6CF8331B7EE68FD8');
  assert.equal(split.prefix.length, 5);
  assert.equal(split.suffix.length, 35);
  // normaliza para maiúsculas mesmo com input em minúsculas
  assert.deepEqual(splitHash(hash.toLowerCase()), split);
});

test('splitHash: rejeita o que não for exatamente 40 hex', () => {
  assert.equal(splitHash('abc'), null);
  assert.equal(splitHash('g'.repeat(40)), null); // 'g' não é hex
  assert.equal(splitHash(''), null);
  assert.equal(splitHash(null), null);
});

test('matchCount: encontra o sufixo (case-insensitive) e devolve a contagem', () => {
  const suffixes = [['1E4C9B93F3F0682250B6CF8331B7EE68FD8', 9545824], ['OUTRO', 3]];
  assert.equal(matchCount(suffixes, '1E4C9B93F3F0682250B6CF8331B7EE68FD8'), 9545824);
  assert.equal(matchCount(suffixes, '1e4c9b93f3f0682250b6cf8331b7ee68fd8'), 9545824); // case-insensitive
  assert.equal(matchCount(suffixes, 'outro'), 3);
});

test('matchCount: não encontrado ou contagem inválida devolve 0', () => {
  assert.equal(matchCount([['AAAA', 5]], 'BBBB'), 0);
  assert.equal(matchCount([['AAAA', 0]], 'AAAA'), 0); // entrada de padding, contagem 0
  assert.equal(matchCount([['AAAA', -1]], 'AAAA'), 0); // negativo é inválido
  assert.equal(matchCount(null, 'AAAA'), 0);
  assert.equal(matchCount([], 'AAAA'), 0);
});
