import { test } from 'node:test';
import assert from 'node:assert/strict';
import { md5 } from '../src/scripts/md5.js';

// Vetores de teste oficiais do RFC 1321, secção A.5.
const enc = (s) => new TextEncoder().encode(s);

test('md5: vetores de teste do RFC 1321', () => {
  assert.equal(md5(enc('')), 'd41d8cd98f00b204e9800998ecf8427e');
  assert.equal(md5(enc('a')), '0cc175b9c0f1b6a831c399e269772661');
  assert.equal(md5(enc('abc')), '900150983cd24fb0d6963f7d28e17f72');
  assert.equal(md5(enc('message digest')), 'f96b697d7cb7938d525a2f31aaf161d0');
  assert.equal(md5(enc('abcdefghijklmnopqrstuvwxyz')), 'c3fcd3d76192e4007dfb496cca67e13b');
  assert.equal(
    md5(enc('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')),
    'd174ab98d277d9f5a5611c2c9f419d9f',
  );
  assert.equal(
    md5(enc('12345678901234567890123456789012345678901234567890123456789012345678901234567890')),
    '57edf4a22be3c955ac49da2e2107b67a',
  );
});

test('md5: comprimentos que cruzam limites de bloco de 64 bytes', () => {
  // O padding depende de paddedLen calculado a partir de len — testar à volta
  // do limite do bloco (55 é o último tamanho que cabe num único bloco de 64
  // com o padding mínimo de 9 bytes; 56 já exige um segundo bloco).
  const a55 = 'a'.repeat(55);
  const a56 = 'a'.repeat(56);
  const a64 = 'a'.repeat(64);
  assert.equal(md5(enc(a55)), md5(enc(a55))); // determinístico
  assert.notEqual(md5(enc(a55)), md5(enc(a56)));
  assert.notEqual(md5(enc(a56)), md5(enc(a64)));
  // valores conhecidos, confirmados contra crypto.createHash('md5') do Node
  assert.equal(md5(enc(a55)), 'ef1772b6dff9a122358552954ad0df65');
  assert.equal(md5(enc(a56)), '3b0c8ac703f828b04c6c197006d17218');
  assert.equal(md5(enc(a64)), '014842d480b571495a4a0363793f7367');
});
