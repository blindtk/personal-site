import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildPool, entropyBits, strengthKey, generatePassword, CHARSETS } from '../src/scripts/password.js';

test('buildPool: concatena os charsets pedidos, na ordem lower/upper/digits/symbols', () => {
  assert.equal(buildPool({}), '');
  assert.equal(buildPool({ lower: true }), CHARSETS.lower);
  assert.equal(buildPool({ lower: true, digits: true }), CHARSETS.lower + CHARSETS.digits);
  assert.equal(
    buildPool({ lower: true, upper: true, digits: true, symbols: true }),
    CHARSETS.lower + CHARSETS.upper + CHARSETS.digits + CHARSETS.symbols,
  );
});

test('buildPool: noAmbiguous remove os caracteres ambíguos de qualquer charset ativo', () => {
  const pool = buildPool({ lower: true, upper: true, digits: true, symbols: true, noAmbiguous: true });
  for (const c of "l1IO0o|`'\"") {
    assert.equal(pool.includes(c), false, `"${c}" devia ter sido removido`);
  }
  // caracteres não-ambíguos continuam presentes
  assert.ok(pool.includes('a'));
  assert.ok(pool.includes('Z'));
  assert.ok(pool.includes('9'));
});

test('entropyBits: length × log2(poolSize), arredondado', () => {
  assert.equal(entropyBits(26, 8), 38); // 8 * log2(26) ≈ 37.60
  assert.equal(entropyBits(94, 20), 131); // 20 * log2(94) ≈ 131.15
  assert.equal(entropyBits(1, 10), 0); // pool de 1 símbolo: zero entropia
  assert.equal(entropyBits(0, 10), 0);
});

test('strengthKey: fronteiras exatas de classificação', () => {
  assert.equal(strengthKey(44), 'weak');
  assert.equal(strengthKey(45), 'ok');
  assert.equal(strengthKey(69), 'ok');
  assert.equal(strengthKey(70), 'strong');
  assert.equal(strengthKey(99), 'strong');
  assert.equal(strengthKey(100), 'excellent');
});

test('generatePassword: comprimento exato e só caracteres da pool (CSPRNG)', () => {
  const pool = CHARSETS.lower + CHARSETS.digits;
  const pw = generatePassword(pool, 32);
  assert.equal(pw.length, 32);
  assert.ok([...pw].every((c) => pool.includes(c)));
});

test('generatePassword: pool de um único caractere é determinística', () => {
  assert.equal(generatePassword('x', 10), 'xxxxxxxxxx');
});
