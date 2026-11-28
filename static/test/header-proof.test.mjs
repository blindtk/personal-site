import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { headerLines } from '../src/scripts/header-proof.js';
import { protocolLabel } from '../src/scripts/request-path.js';

const repo = (p) => new URL(`../../${p}`, import.meta.url);
const contract = JSON.parse(readFileSync(repo('.github/expected-headers.json'), 'utf8')).headers;
const csp = readFileSync(repo('static/public/_headers'), 'utf8')
  .split('\n').find((l) => l.trim().startsWith('Content-Security-Policy:'))
  .split('Content-Security-Policy:')[1].trim();

// O que Headers#entries devolve para a página servida pelo Pages com o
// _headers atual (nomes em minúsculas, por ordem alfabética), mais os da
// Cloudflare que ficam fora do contrato.
const production = [
  ['cf-cache-status', 'HIT'],
  ['cf-ray', 'a618fea9afcb844a-ORD'],
  ['content-security-policy', csp],
  ['content-type', 'text/html; charset=utf-8'],
  ['cross-origin-embedder-policy', 'require-corp'],
  ['cross-origin-opener-policy', 'same-origin'],
  ['cross-origin-resource-policy', 'same-origin'],
  ['permissions-policy', 'geolocation=(), camera=(), microphone=(), payment=(), usb=()'],
  ['referrer-policy', 'strict-origin-when-cross-origin'],
  ['server', 'cloudflare'],
  ['strict-transport-security', 'max-age=63072000; includeSubDomains'],
  ['x-content-type-options', 'nosniff'],
  ['x-frame-options', 'DENY'],
];

test('headerLines: a produção cumpre o contrato e os cabeçalhos extra ficam sem marca', () => {
  const r = headerLines(production, contract);
  assert.equal(r.total, Object.keys(contract).length);
  assert.equal(r.present, r.total);
  assert.equal(r.lines.length, production.length);
  assert.deepEqual(r.lines.find((l) => l.name === 'server'), { name: 'server', value: 'cloudflare', status: null, missing: [] });
  assert.equal(r.lines.find((l) => l.name === 'x-frame-options').status, 'ok');
  assert.ok(r.lines.every((l, i, a) => i === 0 || a[i - 1].name < l.name), 'por ordem de nome');
});

test('headerLines: o CORP concatenado pelo Pages passa o substring, como no workflow', () => {
  // Valor inválido para o browser (a nota do _headers sobre o "!"), mas o
  // contrato só exige o substring "same-origin" — o mesmo que o
  // verify-headers aceitaria. Este teste fixa a paridade com o workflow.
  const doubled = production.map(([n, v]) => [n, n === 'cross-origin-resource-policy' ? 'same-origin, cross-origin' : v]);
  assert.equal(headerLines(doubled, contract).lines.find((l) => l.name === 'cross-origin-resource-policy').status, 'ok');
});

test('headerLines: requisito em falta marca a linha e conta um a menos', () => {
  const weak = production.map(([n, v]) => [n, n === 'content-security-policy' ? v.replace("frame-ancestors 'none'", "frame-ancestors 'self'") : v]);
  const r = headerLines(weak, contract);
  const line = r.lines.find((l) => l.name === 'content-security-policy');
  assert.equal(line.status, 'bad');
  assert.deepEqual(line.missing, ["frame-ancestors 'none'"]);
  assert.equal(r.present, r.total - 1);
});

test('headerLines: cabeçalho do contrato que não veio aparece no fim como ausente', () => {
  const r = headerLines(production.filter(([n]) => n !== 'x-frame-options'), contract);
  const last = r.lines.at(-1);
  assert.deepEqual(last, { name: 'x-frame-options', value: null, status: 'absent', missing: ['DENY'] });
  assert.equal(r.present, r.total - 1);
});

test('headerLines: nomes com maiúsculas e entradas inválidas não partem a lista', () => {
  const r = headerLines([['X-Frame-Options', 'deny'], ['x-frame-options', 'SAMEORIGIN'], ['bad'], [1, 2], null], contract);
  assert.equal(r.lines[0].name, 'x-frame-options');
  assert.equal(r.lines[0].value, 'deny');
  assert.equal(r.lines[0].status, 'ok');
  assert.equal(headerLines(null, contract).present, 0);
});

test('protocolLabel: valores ALPN reais e o resto a null', () => {
  assert.equal(protocolLabel('h3'), 'HTTP/3');
  assert.equal(protocolLabel('H2'), 'HTTP/2');
  assert.equal(protocolLabel('http/1.1'), 'HTTP/1.1');
  assert.equal(protocolLabel(''), null);
  assert.equal(protocolLabel(undefined), null);
});
