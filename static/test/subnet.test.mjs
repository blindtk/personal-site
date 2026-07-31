import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCidr, intToIp, classify, calcSubnet } from '../src/scripts/subnet.js';

test('parseCidr: aceita CIDR válido e rejeita malformado/fora de gama', () => {
  assert.deepEqual(parseCidr('192.168.1.10/24'), { ip: 0xc0a8010a, prefix: 24 });
  assert.equal(parseCidr('256.1.1.1/24'), null); // octeto > 255
  assert.equal(parseCidr('1.2.3.4/33'), null); // prefixo > 32
  assert.equal(parseCidr('1.2.3.4'), null); // sem prefixo
  assert.equal(parseCidr('não é um cidr'), null);
});

test('intToIp: converte inteiro de 32 bits para dotted-quad', () => {
  assert.equal(intToIp(0xc0a80101), '192.168.1.1');
  assert.equal(intToIp(0), '0.0.0.0');
  assert.equal(intToIp(0xffffffff), '255.255.255.255');
});

test('classify: gamas conhecidas RFC 1918/3927/6598/5771 e público', () => {
  assert.equal(classify(parseCidr('127.0.0.1/32').ip), 'loopback');
  assert.equal(classify(parseCidr('10.0.0.1/32').ip), 'private');
  assert.equal(classify(parseCidr('172.16.0.1/32').ip), 'private');
  assert.equal(classify(parseCidr('172.31.255.254/32').ip), 'private');
  assert.equal(classify(parseCidr('172.32.0.1/32').ip), 'public'); // fora da gama 172.16-31
  assert.equal(classify(parseCidr('192.168.1.1/32').ip), 'private');
  assert.equal(classify(parseCidr('169.254.1.1/32').ip), 'linkLocal');
  assert.equal(classify(parseCidr('100.64.0.1/32').ip), 'cgnat');
  assert.equal(classify(parseCidr('100.127.255.254/32').ip), 'cgnat');
  assert.equal(classify(parseCidr('224.0.0.1/32').ip), 'multicast');
  assert.equal(classify(parseCidr('8.8.8.8/32').ip), 'public');
});

test('calcSubnet: /24 — rede, broadcast e contagem de hosts standard', () => {
  const r = calcSubnet('192.168.1.10/24');
  assert.equal(intToIp(r.network), '192.168.1.0');
  assert.equal(intToIp(r.broadcast), '192.168.1.255');
  assert.equal(intToIp(r.mask), '255.255.255.0');
  assert.equal(r.hosts, 254);
  assert.equal(intToIp(r.firstHost), '192.168.1.1');
  assert.equal(intToIp(r.lastHost), '192.168.1.254');
  assert.equal(r.special, null);
  assert.equal(r.kind, 'private');
});

test('calcSubnet: /31 — ponto-a-ponto RFC 3021, sem rede/broadcast reservados', () => {
  const r = calcSubnet('192.0.2.0/31');
  assert.equal(r.special, 'p2p');
  assert.equal(r.hosts, 2);
  assert.equal(intToIp(r.firstHost), '192.0.2.0');
  assert.equal(intToIp(r.lastHost), '192.0.2.1');
});

test('calcSubnet: /32 — endereço único', () => {
  const r = calcSubnet('203.0.113.5/32');
  assert.equal(r.special, 'single');
  assert.equal(r.hosts, 1);
  assert.equal(intToIp(r.firstHost), '203.0.113.5');
  assert.equal(intToIp(r.lastHost), '203.0.113.5');
});

test('calcSubnet: /0 — toda a gama IPv4', () => {
  const r = calcSubnet('10.20.30.40/0');
  assert.equal(intToIp(r.mask), '0.0.0.0');
  assert.equal(intToIp(r.network), '0.0.0.0');
  assert.equal(intToIp(r.broadcast), '255.255.255.255');
});

test('calcSubnet: input inválido devolve null', () => {
  assert.equal(calcSubnet('999.999.999.999/24'), null);
  assert.equal(calcSubnet(''), null);
});
