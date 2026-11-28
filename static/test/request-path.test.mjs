import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  navPhases, coloFromRay, cacheState, checkHeaders, caaIssuers, mirrorFacts,
} from '../src/scripts/request-path.js';

const repo = (p) => new URL(`../../${p}`, import.meta.url);
const contract = JSON.parse(readFileSync(repo('.github/expected-headers.json'), 'utf8')).headers;
const caa = JSON.parse(readFileSync(repo('.github/expected-dns.json'), 'utf8')).caa.expected;
// A CSP real, tal como está em public/_headers (a linha a seguir a "/*").
const productionCsp = readFileSync(repo('static/public/_headers'), 'utf8')
  .split('\n')
  .find((l) => l.trim().startsWith('Content-Security-Policy:'))
  .split('Content-Security-Policy:')[1]
  .trim();

// Navegação de primeira visita em Chrome (valores de PerformanceNavigationTiming
// copiados de uma página servida pela Cloudflare): DNS, TCP e TLS completos.
const coldVisit = {
  name: 'https://danielmala.co/este-site/',
  nextHopProtocol: 'h2',
  fetchStart: 3.2,
  domainLookupStart: 5.1,
  domainLookupEnd: 31.7,
  connectStart: 31.7,
  secureConnectionStart: 52.4,
  connectEnd: 88.9,
  requestStart: 89.3,
  responseStart: 142.6,
  activationStart: 0,
  transferSize: 6120,
  decodedBodySize: 24810,
};

test('navPhases: primeira visita mede DNS, ligação, TLS e TTFB, arredondados', () => {
  assert.deepEqual(navPhases(coldVisit), {
    protocol: 'HTTP/2',
    dnsMs: 27,
    dnsCached: false,
    connectMs: 57,
    reused: false,
    tlsMs: 37,
    ttfbMs: 53,
    prerendered: false,
    fromCache: false,
  });
});

test('navPhases: DNS e ligação a 0 exatos são "em cache" e "reaproveitada", não "sem dados"', () => {
  const warm = {
    ...coldVisit,
    nextHopProtocol: 'h3',
    domainLookupStart: 3.2, domainLookupEnd: 3.2,
    connectStart: 3.2, connectEnd: 3.2,
    // sem aperto de mão neste pedido: o browser põe 0
    secureConnectionStart: 0,
  };
  const p = navPhases(warm);
  assert.equal(p.protocol, 'HTTP/3');
  assert.equal(p.dnsMs, 0);
  assert.equal(p.dnsCached, true);
  assert.equal(p.reused, true);
  assert.equal(p.tlsMs, null);
});

test('navPhases: página pré-carregada e resposta da cache do browser são assinaladas', () => {
  assert.equal(navPhases({ ...coldVisit, activationStart: 412.5 }).prerendered, true);
  assert.equal(navPhases({ ...coldVisit, transferSize: 0 }).fromCache, true);
  // corpo vazio sem transferência não é "cache": é uma resposta vazia
  assert.equal(navPhases({ ...coldVisit, transferSize: 0, decodedBodySize: 0 }).fromCache, false);
});

test('navPhases: tempos incoerentes ou ausentes não afirmam nada', () => {
  for (const entry of [
    null,
    'x',
    {},
    { ...coldVisit, domainLookupEnd: 2 }, // fim antes do início
    { ...coldVisit, responseStart: undefined },
    { ...coldVisit, connectEnd: '88.9' },
    { ...coldVisit, requestStart: NaN },
  ]) {
    assert.equal(navPhases(entry), null, JSON.stringify(entry));
  }
});

test('navPhases: protocolo desconhecido fica null em vez de ecoar o texto', () => {
  assert.equal(navPhases({ ...coldVisit, nextHopProtocol: '' }).protocol, null);
  assert.equal(navPhases({ ...coldVisit, nextHopProtocol: 'spdy/3<script>' }).protocol, null);
});

test('coloFromRay: extrai o data center de um cf-ray real', () => {
  assert.equal(coloFromRay('a618fea9afcb844a-ORD'), 'ORD');
  assert.equal(coloFromRay(' 8f1c2a3b4d5e6f70-LIS '), 'LIS');
});

test('coloFromRay: formatos fora do padrão da Cloudflare → null', () => {
  for (const ray of [null, '', 'a618fea9afcb844a', 'a618fea9afcb844-ORD', 'a618fea9afcb844a-ord', 'a618fea9afcb844a-ORDX', 'A618FEA9AFCB844A-ORD']) {
    assert.equal(coloFromRay(ray), null, String(ray));
  }
});

test('cacheState: normaliza os estados documentados e recusa o resto', () => {
  assert.equal(cacheState('HIT'), 'HIT');
  assert.equal(cacheState(' dynamic '), 'DYNAMIC');
  assert.equal(cacheState('HIT, MISS'), null);
  assert.equal(cacheState('<b>HIT</b>'), null);
  assert.equal(cacheState(undefined), null);
});

// Headers#get é case-insensitive; o mesmo aqui.
const getter = (obj) => {
  const lower = Object.fromEntries(Object.entries(obj).map(([k, v]) => [k.toLowerCase(), v]));
  return (name) => lower[name.toLowerCase()] ?? null;
};
const production = {
  'Content-Security-Policy': productionCsp,
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'geolocation=(), camera=(), microphone=(), payment=(), usb=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
};

test('checkHeaders: os cabeçalhos de _headers cumprem o contrato inteiro', () => {
  const r = checkHeaders(getter(production), contract);
  assert.equal(r.total, Object.keys(contract).length);
  assert.equal(r.present, r.total, JSON.stringify(r.rows.filter((x) => !x.ok)));
});

test('checkHeaders: a comparação ignora maiúsculas, como o workflow verify-headers', () => {
  const r = checkHeaders(getter({ ...production, 'X-Frame-Options': 'deny' }), contract);
  assert.equal(r.rows.find((x) => x.name === 'x-frame-options').ok, true);
});

test('checkHeaders: CSP sem worker-src none falha e diz o que falta', () => {
  const weakened = productionCsp.replace("worker-src 'none'", "worker-src 'self' blob:");
  const r = checkHeaders(getter({ ...production, 'Content-Security-Policy': weakened }), contract);
  const csp = r.rows.find((x) => x.name === 'content-security-policy');
  assert.equal(csp.ok, false);
  assert.equal(csp.absent, false);
  assert.deepEqual(csp.missing, ["worker-src 'none'"]);
  assert.equal(r.present, r.total - 1);
});

test('checkHeaders: cabeçalho ausente conta como ausente, com todos os requisitos em falta', () => {
  const { 'Cross-Origin-Embedder-Policy': _drop, ...rest } = production;
  const r = checkHeaders(getter(rest), contract);
  const coep = r.rows.find((x) => x.name === 'cross-origin-embedder-policy');
  assert.equal(coep.ok, false);
  assert.equal(coep.absent, true);
  assert.deepEqual(coep.missing, ['require-corp']);
});

test('checkHeaders: contrato ou getter inválidos não inventam resultados', () => {
  assert.deepEqual(checkHeaders(null, contract), { present: 0, total: 0, rows: [] });
  assert.deepEqual(checkHeaders(getter(production), null), { present: 0, total: 0, rows: [] });
});

test('caaIssuers: as autoridades de .github/expected-dns.json, sem issuewild nem iodef', () => {
  assert.deepEqual(caaIssuers(caa), ['letsencrypt.org', 'pki.goog', 'ssl.com']);
  assert.deepEqual(caaIssuers(['0 iodef "mailto:x@y"', '0 issuewild "a.example"', 42, null]), []);
  assert.deepEqual(caaIssuers('nope'), []);
});

test('mirrorFacts: só TLS, protocolo e data center — nunca o IP', () => {
  const doc = {
    ip: '203.0.113.7', ipVersion: 4, tlsVersion: 'TLSv1.3', tlsCipher: 'AEAD-AES128-GCM-SHA256',
    httpProtocol: 'HTTP/2', country: 'PT', asn: 3243, colo: 'LIS', userAgent: 'Mozilla/5.0',
  };
  const facts = mirrorFacts(doc);
  assert.deepEqual(facts, { tlsVersion: 'TLSv1.3', httpProtocol: 'HTTP/2', colo: 'LIS' });
  assert.ok(!JSON.stringify(facts).includes('203.0.113.7'));
});

test('mirrorFacts: erro do Worker, campos vazios ou com markup → null', () => {
  assert.equal(mirrorFacts({ error: 'rate_limited' }), null);
  assert.equal(mirrorFacts({ tlsVersion: null, httpProtocol: null, colo: null }), null);
  assert.equal(mirrorFacts(null), null);
  assert.deepEqual(
    mirrorFacts({ tlsVersion: '<img src=x>', httpProtocol: 'HTTP/2', colo: 'lis' }),
    { tlsVersion: null, httpProtocol: 'HTTP/2', colo: null },
  );
});
