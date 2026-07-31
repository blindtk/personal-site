import { test } from 'node:test';
import assert from 'node:assert/strict';
import { base64Encode, base64Decode, urlEncode, urlDecode, hexEncode, hexDecode, codecs } from '../src/scripts/encoding.js';

// Vetores de teste oficiais do RFC 4648, secção 10 ("foobar" family).
test('base64: vetores de teste do RFC 4648', () => {
  assert.equal(base64Encode(''), '');
  assert.equal(base64Encode('f'), 'Zg==');
  assert.equal(base64Encode('fo'), 'Zm8=');
  assert.equal(base64Encode('foo'), 'Zm9v');
  assert.equal(base64Encode('foob'), 'Zm9vYg==');
  assert.equal(base64Encode('fooba'), 'Zm9vYmE=');
  assert.equal(base64Encode('foobar'), 'Zm9vYmFy');
});

test('base64: round-trip UTF-8 (acentos e emoji multi-byte)', () => {
  assert.equal(base64Encode('café'), 'Y2Fmw6k=');
  assert.equal(base64Decode('Y2Fmw6k='), 'café');
  const emoji = 'round trip ok 🎉';
  assert.equal(base64Decode(base64Encode(emoji)), emoji);
});

test('base64Decode: UTF-8 inválido rejeitado (fatal: true)', () => {
  // 0xFF sozinho não é uma sequência UTF-8 válida
  assert.throws(() => base64Decode(btoa('\xFF')));
});

test('url: encode/decode via encodeURIComponent, decode trata "+" como espaço', () => {
  assert.equal(urlEncode('a b/c?d=1'), 'a%20b%2Fc%3Fd%3D1');
  assert.equal(urlDecode('a%20b%2Fc%3Fd%3D1'), 'a b/c?d=1');
  // "+" como espaço (application/x-www-form-urlencoded), não gerado por
  // encodeURIComponent mas aceite na descodificação — caso de uso real de
  // colar um URL copiado de um formulário.
  assert.equal(urlDecode('a+b'), 'a b');
});

test('hex: encode/decode ASCII e UTF-8, aceita separadores e maiúsculas', () => {
  assert.equal(hexEncode('abc'), '616263');
  assert.equal(hexDecode('616263'), 'abc');
  assert.equal(hexEncode('café'), '636166c3a9');
  assert.equal(hexDecode('636166C3A9'), 'café'); // maiúsculas
  assert.equal(hexDecode('61 62 63'), 'abc'); // espaços
  assert.equal(hexDecode('61:62:63'), 'abc'); // dois-pontos
});

test('hexDecode: hex inválido ou de comprimento ímpar lança erro', () => {
  assert.throws(() => hexDecode('zz'));
  assert.throws(() => hexDecode('abc'));
});

test('codecs: mapa expõe os 3 formatos com encode/decode', () => {
  assert.deepEqual(Object.keys(codecs), ['base64', 'url', 'hex']);
  for (const c of Object.values(codecs)) {
    assert.equal(typeof c.encode, 'function');
    assert.equal(typeof c.decode, 'function');
  }
});
