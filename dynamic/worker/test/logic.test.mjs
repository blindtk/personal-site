// Testes da lógica pura do Worker (node --test, sem rede nem Cloudflare).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import {
  clampInt, escapeHtml, sanitizeText, normalizeCveId, normalizeTechniques, normalizeTickerItem,
  normalizeCountry, normalizeAsn, floorToWindow,
} from '../src/lib/sanitize.js';
import {
  emptyBucket, addEvent, mergeBuckets, honeypotStats, mapData, threatIntel,
} from '../src/lib/aggregate.js';
import {
  normalizeVitals, emptyVitalsBucket, addVitals, mergeVitalsBuckets, vitalsStats,
} from '../src/lib/vitals.js';
import { gradeFromHeaders } from '../src/lib/scan.js';
import { nextState, dailySalt, clientHash } from '../src/lib/ratelimit.js';
import { underCap } from '../src/lib/kvcap.js';
import { parseKev, parseNvd, mergeFeeds } from '../src/lib/feeds.js';
import { normalizePrefix, parseRanges } from '../src/lib/pwned.js';
import {
  issuerLabel, isExpectedIssuer, parseExpectedIssuers, normalizeCtEntry, parseCtEntries, ctStats,
  DEFAULT_EXPECTED_ISSUERS,
} from '../src/lib/ct.js';
import { parseCfStats, firewallBreakdown, firewallDetailBreakdown } from '../src/lib/cf-analytics.js';
import {
  parseReports, normalizeViolation, emptyCspBucket, addCspEvent, mergeCspBuckets, cspStats,
  MAX_SOURCES_PER_BUCKET,
} from '../src/lib/csp-report.js';
import { PATH_TECHNIQUE, techniqueForPath, techniquesForText } from '../src/lib/attack-map.js';
import { serverView } from '../src/lib/mirror.js';
import { renderNotFoundHtml, NOT_FOUND_CSP } from '../src/lib/notfound.js';
import { DECOYS, isDecoy } from '../src/lib/decoys.js';
import worker from '../src/index.js';

test('clampInt', () => {
  assert.equal(clampInt('5', 1, 10, 0), 5);
  assert.equal(clampInt('50', 1, 10, 0), 10);
  assert.equal(clampInt('-3', 1, 10, 0), 1);
  assert.equal(clampInt('abc', 1, 10, 7), 7);
});

test('escapeHtml cobre os cinco caracteres', () => {
  assert.equal(escapeHtml(`<img src=x onerror="a">'&`), '&lt;img src=x onerror=&quot;a&quot;&gt;&#39;&amp;');
});

test('sanitizeText remove controlos, tags e trunca', () => {
  assert.equal(sanitizeText('hello\x00\x07 <b>world</b>'), 'hello bworld/b');
  assert.equal(sanitizeText('a'.repeat(200), 10), `${'a'.repeat(9)}…`);
  assert.equal(sanitizeText(42), '');
});

test('normalizeCveId valida o formato', () => {
  assert.equal(normalizeCveId('cve-2026-1042'), 'CVE-2026-1042');
  assert.equal(normalizeCveId('CVE-2026-1'), '');
  assert.equal(normalizeCveId('not-a-cve'), '');
});

test('normalizeTickerItem rejeita sem CVE e sanitiza', () => {
  assert.equal(normalizeTickerItem({ id: 'x' }), null);
  assert.deepEqual(
    normalizeTickerItem({
      id: 'CVE-2026-0891', source: 'nvd', severity: 'CRIT 9.8', title: 'Struts <x> RCE',
      techniques: ['T1190', 'bad', 'T1190'],
    }),
    { id: 'CVE-2026-0891', source: 'nvd', severity: 'CRIT 9.8', title: 'Struts x RCE', techniques: ['T1190'] },
  );
});

test('normalizeTechniques valida IDs e remove repetições', () => {
  assert.deepEqual(normalizeTechniques(['T1190', 'T1592', 'T1190']), ['T1190', 'T1592']);
  assert.deepEqual(normalizeTechniques(['x', 'T99999', 42, null]), []);
  assert.deepEqual(normalizeTechniques('T1190'), []);
});

test('attack-map: técnica por path-isco', () => {
  assert.equal(techniqueForPath('/wp-login.php'), 'T1110');
  assert.equal(techniqueForPath('/.env'), 'T1592');
  assert.equal(techniqueForPath('/.git/config'), 'T1592');
  assert.equal(techniqueForPath('/admin'), 'T1595');
  assert.equal(techniqueForPath('/phpmyadmin/'), 'T1190');
  assert.equal(techniqueForPath('/robots.txt'), null);
});

test('attack-map: técnica por prefixo para /phpmyadmin/* (mesma convenção do isDecoy)', () => {
  // wrangler.toml roteia danielmala.co/phpmyadmin/* — os paths que os
  // scanners reais pedem (revisão de segurança 2026-07, ronda 4, N5).
  assert.equal(techniqueForPath('/phpmyadmin/index.php'), 'T1190');
  assert.equal(techniqueForPath('/phpmyadmin/setup.php'), 'T1190');
  assert.equal(techniqueForPath('/admin/x'), null); // /admin é match exato, não glob
});

test('attack-map: técnicas por texto de CVE (heurística conservadora)', () => {
  assert.deepEqual(techniquesForText('Ivanti Connect Secure authentication bypass'), ['T1110']);
  assert.deepEqual(techniquesForText('Apache Struts remote code execution'), ['T1190']);
  assert.deepEqual(techniquesForText('Path traversal leads to information disclosure'), ['T1592']);
  assert.deepEqual(techniquesForText('A generic medium-severity bug'), []);
  assert.deepEqual(techniquesForText(null), []);
});

test('attack-map sincroniza com content/honeypot-attack.json', () => {
  const url = new URL('../../../content/honeypot-attack.json', import.meta.url);
  const content = JSON.parse(readFileSync(fileURLToPath(url), 'utf8'));
  assert.deepEqual(PATH_TECHNIQUE, content.paths);
});

test('detections.json sincroniza com os paths-isco e as técnicas', () => {
  // A página Deteções publica uma regra Sigma por path-isco — se um isco
  // novo entrar no Worker sem regra (ou vice-versa), isto rebenta.
  const url = new URL('../../../content/detections.json', import.meta.url);
  const { rules } = JSON.parse(readFileSync(fileURLToPath(url), 'utf8'));
  const byPath = Object.fromEntries(rules.map((r) => [r.path, r.technique]));
  assert.deepEqual(byPath, PATH_TECHNIQUE);
  for (const r of rules) {
    const yamlText = r.sigma.join('\n');
    // a tag ATT&CK da regra tem de bater com a técnica declarada
    assert.ok(yamlText.includes(`attack.${r.technique.toLowerCase()}`), `${r.slug}: tag ATT&CK divergente`);
    // campos essenciais de uma regra Sigma
    for (const field of ['title:', 'id:', 'logsource:', 'detection:', 'condition:', 'level:']) {
      assert.ok(yamlText.includes(field), `${r.slug}: falta ${field}`);
    }
  }
});

test('isDecoy: match exato para a maioria, prefixo para os iscos com glob no wrangler.toml', () => {
  assert.equal(isDecoy('/admin'), true);
  assert.equal(isDecoy('/admin/x'), false); // /admin é rota exata, não glob
  assert.equal(isDecoy('/phpmyadmin/'), true);
  assert.equal(isDecoy('/phpmyadmin/index.php'), true); // o que os scanners reais pedem
  assert.equal(isDecoy('/phpmyadmindiferente'), false); // não é um sub-path, não conta
  assert.equal(isDecoy('/nao-existe'), false);
});

test('decoys: DECOYS (index.js, via lib/decoys.js) bate certo com as rotas-isco do wrangler.toml', () => {
  // Achado da revisão de segurança 2026-07 (ronda 4, N5): as duas listas já
  // divergiram — /phpmyadmin/* era um glob no wrangler.toml mas string
  // exata em DECOYS, perdendo o sinal E denunciando o Worker (404 JSON em
  // vez do 404 HTML disfarçado) nos paths reais que os scanners pedem.
  const url = new URL('../wrangler.toml', import.meta.url);
  const toml = readFileSync(fileURLToPath(url), 'utf8');
  const routePaths = [...toml.matchAll(/pattern = "danielmala\.co([^"]*)"/g)]
    .map((m) => m[1])
    .filter((p) => !p.startsWith('/api/')); // /api/* é a API real, não um isco
  assert.ok(routePaths.length > 0, 'não encontrou nenhuma rota-isco em wrangler.toml — regex desatualizado?');

  // toda rota-isco do wrangler.toml tem de ser reconhecida como isco
  for (const routePath of routePaths) {
    const probe = routePath.endsWith('*') ? `${routePath.slice(0, -1)}sonda-real-de-scanner` : routePath;
    assert.ok(
      isDecoy(probe),
      `wrangler.toml roteia '${routePath}' para o Worker mas isDecoy('${probe}') é false — ` +
        'o pedido cairia no 404 JSON da API, não no 404 HTML disfarçado, e o evento perdia-se do honeypot.',
    );
  }

  // e o inverso: todo isco reconhecido em DECOYS tem de estar coberto por
  // alguma rota real — senão a Cloudflare nunca entrega esses pedidos ao
  // Worker e a entrada em DECOYS é morta.
  for (const decoy of DECOYS) {
    const covered = routePaths.some((r) => (r.endsWith('*') ? decoy.startsWith(r.slice(0, -1)) : r === decoy));
    assert.ok(covered, `DECOYS tem '${decoy}' mas nenhuma rota do wrangler.toml o cobre`);
  }
});

test('agregação: addEvent/mergeBuckets contam por país e path', () => {
  const b = emptyBucket();
  addEvent(b, { country: 'RU', path: '/.env' });
  addEvent(b, { country: 'RU', path: '/wp-login.php' });
  addEvent(b, { country: 'CN', path: '/.env' });
  assert.equal(b.total, 3);
  assert.equal(b.byCountry.RU, 2);
  assert.equal(b.byPath['/.env'], 2);
  const m = mergeBuckets([b, b]);
  assert.equal(m.total, 6);
  assert.equal(m.byCountry.RU, 4);
});

test('honeypotStats: 24h, top path, países 7d, tempo até 1.º scan', () => {
  const h = emptyBucket();
  addEvent(h, { country: 'RU', path: '/wp-login.php' });
  addEvent(h, { country: 'RU', path: '/wp-login.php' });
  addEvent(h, { country: 'US', path: '/.env' });
  const d = emptyBucket();
  addEvent(d, { country: 'BR', path: '/admin' });
  const stats = honeypotStats({
    hourly: [h],
    days: [h, d],
    recent: [{ ts: 1, country: 'RU', asn: 1, path: '/.env' }],
    meta: { deployTs: 1000, firstScanTs: 32_000 },
  });
  assert.equal(stats.attempts24h, 3);
  assert.equal(stats.topPath, '/wp-login.php');
  assert.equal(stats.countryCount, 3); // RU, US, BR nos 7 dias
  assert.equal(stats.timeToFirstScanSec, 31);
  assert.equal(stats.recent.length, 1);
  // paths7d: contagens da semana ordenadas por contagem decrescente
  assert.deepEqual(stats.paths7d, [
    { path: '/wp-login.php', count: 2 },
    { path: '/.env', count: 1 },
    { path: '/admin', count: 1 },
  ]);
});

test('mapData ordena países por contagem', () => {
  const h = emptyBucket();
  addEvent(h, { country: 'RU', path: '/a' });
  addEvent(h, { country: 'RU', path: '/a' });
  addEvent(h, { country: 'CN', path: '/a' });
  const data = mapData({ hourly: [h], days: [h] });
  assert.deepEqual(data.last24h, [{ country: 'RU', count: 2 }, { country: 'CN', count: 1 }]);
  assert.equal(data.totals.countries7d, 2);
});

test('gradeFromHeaders: A+ com tudo, F com nada', () => {
  const full = gradeFromHeaders((n) => (n === 'content-security-policy' ? "default-src 'self'" : 'x'));
  assert.equal(full.grade, 'A+');
  assert.equal(full.checklist.every((c) => c.present), true);
  const none = gradeFromHeaders(() => null);
  assert.equal(none.grade, 'F');
  assert.equal(none.checklist.some((c) => c.present), false);
});

test('gradeFromHeaders: nota intermédia sem CSP (peso 3 em falta)', () => {
  // tudo presente menos a CSP (peso 3 de 11) → 8/11 ≈ 0.727 < 0.75 → C
  const g = gradeFromHeaders((n) => (n === 'content-security-policy' ? null : 'v'));
  assert.equal(g.score, 8);
  assert.equal(g.max, 11);
  assert.equal(g.grade, 'C');
});

test('rate limit: janela fixa bloqueia ao atingir o máximo', () => {
  const cfg = { now: 1000, windowMs: 60_000, max: 2 };
  const s1 = nextState(null, cfg);
  assert.equal(s1.allowed, true);
  const s2 = nextState(s1.state, cfg);
  assert.equal(s2.allowed, true);
  const s3 = nextState(s2.state, cfg);
  assert.equal(s3.allowed, false);
  assert.ok(s3.retryAfterSec > 0);
  // nova janela liberta
  const s4 = nextState(s3.state, { ...cfg, now: 1000 + 60_001 });
  assert.equal(s4.allowed, true);
});

test('dailySalt roda por dia UTC', () => {
  const a = dailySalt('sec', Date.parse('2026-07-15T23:00:00Z'));
  const b = dailySalt('sec', Date.parse('2026-07-16T01:00:00Z'));
  assert.notEqual(a, b);
});

test('parseKev normaliza e ordena por data', () => {
  const items = parseKev({
    vulnerabilities: [
      { cveID: 'CVE-2025-9977', vendorProject: 'Fortinet', product: 'FortiOS', dateAdded: '2025-01-01' },
      { cveID: 'CVE-2026-1042', vendorProject: 'Ivanti', product: 'Connect Secure', dateAdded: '2026-02-01' },
      { cveID: 'bad-id', dateAdded: '2026-03-01' },
    ],
  });
  assert.equal(items[0].id, 'CVE-2026-1042'); // mais recente primeiro
  assert.equal(items[0].source, 'kev');
  assert.equal(items.length, 2); // o id inválido cai
});

test('parseKev anexa técnicas ATT&CK a partir da descrição da vuln', () => {
  const items = parseKev({
    vulnerabilities: [
      {
        cveID: 'CVE-2026-1042', vendorProject: 'Ivanti', product: 'Connect Secure', dateAdded: '2026-02-01',
        vulnerabilityName: 'Ivanti Connect Secure Authentication Bypass',
        shortDescription: 'Allows an attacker to bypass authentication.',
      },
      {
        cveID: 'CVE-2026-0500', vendorProject: 'Acme', product: 'Widget', dateAdded: '2026-01-01',
        vulnerabilityName: 'Acme Widget Remote Code Execution', shortDescription: 'Unauthenticated RCE.',
      },
    ],
  });
  assert.deepEqual(items[0].techniques, ['T1110']); // authentication bypass
  assert.equal(items[0].title, 'Ivanti Connect Secure'); // título continua vendor+product
  assert.deepEqual(items[1].techniques, ['T1190']); // RCE / unauthenticated
});

test('parseNvd só aceita CRITICAL', () => {
  const items = parseNvd({
    vulnerabilities: [
      { cve: { id: 'CVE-2026-0891', descriptions: [{ lang: 'en', value: 'Struts RCE' }],
        metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { baseSeverity: 'CRITICAL', baseScore: 9.8 } }] } } },
      { cve: { id: 'CVE-2026-0001', descriptions: [{ lang: 'en', value: 'medium bug' }],
        metrics: { cvssMetricV31: [{ type: 'Primary', cvssData: { baseSeverity: 'MEDIUM', baseScore: 5.0 } }] } } },
    ],
  });
  assert.equal(items.length, 1);
  assert.equal(items[0].id, 'CVE-2026-0891');
  assert.equal(items[0].severity, 'CRIT 9.8');
});

test('mergeFeeds intercala e remove duplicados', () => {
  const kev = [{ id: 'CVE-2026-1042', source: 'kev' }, { id: 'CVE-2025-9977', source: 'kev' }];
  const nvd = [{ id: 'CVE-2026-0891', source: 'nvd' }, { id: 'CVE-2026-1042', source: 'nvd' }];
  const merged = mergeFeeds(kev, nvd, 16);
  const ids = merged.map((i) => i.id);
  assert.deepEqual(ids, ['CVE-2026-1042', 'CVE-2026-0891', 'CVE-2025-9977']);
});

// ---------- pwned: k-anonimato (validação de prefixo + parse dos ranges) ----------

test('normalizePrefix: só 5 hex, em maiúsculas', () => {
  assert.equal(normalizePrefix('5baa6'), '5BAA6');
  assert.equal(normalizePrefix('ABCDE'), 'ABCDE');
  assert.equal(normalizePrefix('5BAA'), ''); // 4 dígitos
  assert.equal(normalizePrefix('5BAA61'), ''); // 6 dígitos
  assert.equal(normalizePrefix('5BAAG'), ''); // G não é hex
  assert.equal(normalizePrefix(''), '');
  assert.equal(normalizePrefix(null), '');
  assert.equal(normalizePrefix(12345), '');
});

test('parseRanges: parseia SUFIXO:CONTAGEM, mantém padding (0), descarta lixo', () => {
  const A = 'A'.repeat(35);
  const B = 'b'.repeat(35); // minúsculas → normaliza para maiúsculas
  const body = [
    `${A}:3`,
    `${B}:0`, // padding do Add-Padding — mantém-se
    'GGGG:1', // sufixo demasiado curto e não-hex → cai
    `${'C'.repeat(35)}:-4`, // contagem negativa → cai
    `${'D'.repeat(35)}:xx`, // contagem não numérica → cai
    `${'E'.repeat(34)}:5`, // 34 chars (idx do ':' ≠ 35) → cai
  ].join('\r\n');
  const out = parseRanges(body);
  assert.deepEqual(out, [[A, 3], ['B'.repeat(35), 0]]);
});

test('parseRanges: input inválido e respeito pelo limite', () => {
  assert.deepEqual(parseRanges(42), []);
  assert.deepEqual(parseRanges(''), []);
  const many = Array.from({ length: 10 }, (_, i) => `${'F'.repeat(35)}:${i + 1}`).join('\n');
  assert.equal(parseRanges(many, 3).length, 3);
});

test('pwned-range: prefixo válido relaia os sufixos parseados do HIBP', async () => {
  const env = { KV: fakeKV() };
  const A = 'A'.repeat(35);
  const orig = globalThis.fetch;
  let calledUrl = '';
  globalThis.fetch = async (url) => {
    calledUrl = String(url);
    return { ok: true, status: 200, text: async () => `${A}:7\r\n${'B'.repeat(35)}:0\r\n` };
  };
  try {
    const res = await runFetch(fakeRequest('/api/pwned-range?prefix=5baa6'), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.deepEqual(data.suffixes, [[A, 7], ['B'.repeat(35), 0]]);
    assert.match(calledUrl, /\/range\/5BAA6$/); // prefixo normalizado para maiúsculas
  } finally {
    globalThis.fetch = orig;
  }
});

test('pwned-range: prefixo inválido → 400 sem tocar no upstream', async () => {
  const env = { KV: fakeKV() };
  const orig = globalThis.fetch;
  let hit = false;
  globalThis.fetch = async () => { hit = true; return { ok: true, status: 200, text: async () => '' }; };
  try {
    const res = await runFetch(fakeRequest('/api/pwned-range?prefix=nope'), env);
    assert.equal(res.status, 400);
    assert.equal(hit, false, 'prefixo inválido não pode chegar ao HIBP');
  } finally {
    globalThis.fetch = orig;
  }
});

test('pwned-range: rate limit por cliente devolve 429', async () => {
  const env = { KV: fakeKV() };
  const ip = '203.0.113.60';
  const id = await clientHash(ip, dailySalt(undefined));
  env.KV.store.set(`rl:pwned:${id}`, JSON.stringify({ count: 20, windowStart: Date.now() }));
  const res = await runFetch(fakeRequest('/api/pwned-range?prefix=5BAA6', { ip }), env);
  assert.equal(res.status, 429);
  assert.ok(res.headers.get('retry-after'));
});

// ---------- violações CSP: parse dos formatos reais dos browsers ----------

const SITE = 'https://danielmala.co';

test('parseReports: formato legado do Chrome/Firefox (application/csp-report)', () => {
  // vetor real (Chrome 126, report-uri) — campos kebab-case
  const body = JSON.stringify({
    'csp-report': {
      'document-uri': 'https://danielmala.co/seguranca/',
      referrer: '',
      'violated-directive': 'script-src-elem',
      'effective-directive': 'script-src-elem',
      'original-policy': "default-src 'self'; script-src 'self'",
      disposition: 'enforce',
      'blocked-uri': 'https://evil.example/x.js?token=SECRET',
      'line-number': 1,
      'status-code': 200,
    },
  });
  const out = parseReports(body, 'application/csp-report');
  assert.equal(out.length, 1);
  assert.equal(out[0].documentUri, 'https://danielmala.co/seguranca/');
  assert.equal(out[0].directive, 'script-src-elem');
  assert.equal(out[0].blockedUri, 'https://evil.example/x.js?token=SECRET');
});

test('parseReports: Reporting API do Chrome (application/reports+json, batch)', () => {
  // vetor real (Chrome, report-to) — lista, campos camelCase dentro de body
  const body = JSON.stringify([
    {
      age: 10,
      type: 'csp-violation',
      url: 'https://danielmala.co/',
      user_agent: 'Mozilla/5.0 …',
      body: {
        blockedURL: 'chrome-extension://abcdefghijklmnop/inject.js',
        disposition: 'enforce',
        documentURL: 'https://danielmala.co/',
        effectiveDirective: 'script-src-elem',
        originalPolicy: "default-src 'self'",
        statusCode: 200,
      },
    },
    { age: 12, type: 'deprecation', url: 'https://danielmala.co/', body: {} },
  ]);
  const out = parseReports(body, 'application/reports+json; charset=utf-8');
  assert.equal(out.length, 1); // o relatório que não é csp-violation cai
  assert.equal(out[0].documentUri, 'https://danielmala.co/');
  assert.equal(out[0].blockedUri, 'chrome-extension://abcdefghijklmnop/inject.js');
});

test('parseReports: Safari legado com diretiva com valores e blocked-uri "data"', () => {
  const body = JSON.stringify({
    'csp-report': {
      'document-uri': 'https://danielmala.co/en/',
      'violated-directive': "img-src 'self'",
      'blocked-uri': 'data',
    },
  });
  const out = parseReports(body, 'application/csp-report');
  assert.equal(out.length, 1);
  const v = normalizeViolation(out[0], SITE);
  assert.deepEqual(v, { directive: 'img-src', category: 'other', source: 'data:' });
});

test('parseReports: corpo inválido ou formato errado devolve []', () => {
  assert.deepEqual(parseReports('not json', 'application/csp-report'), []);
  assert.deepEqual(parseReports('{"foo":1}', 'application/csp-report'), []);
  assert.deepEqual(parseReports('{"csp-report":"str"}', 'application/csp-report'), []);
  assert.deepEqual(parseReports('{}', 'application/reports+json'), []); // não é lista
  assert.deepEqual(parseReports('[]', 'application/reports+json'), []);
});

test('normalizeViolation: rejeita documentos que não são do próprio site', () => {
  const forged = { documentUri: 'https://outro-site.example/', directive: 'script-src', blockedUri: 'inline' };
  assert.equal(normalizeViolation(forged, SITE), null);
  const noDoc = { documentUri: '', directive: 'script-src', blockedUri: 'inline' };
  assert.equal(normalizeViolation(noDoc, SITE), null);
});

test('normalizeViolation: rejeita diretivas malformadas (chave de agregação limpa)', () => {
  const bad = (d) => normalizeViolation({ documentUri: `${SITE}/`, directive: d, blockedUri: 'inline' }, SITE);
  assert.equal(bad('<script>alert(1)</script>'), null);
  assert.equal(bad(''), null);
  assert.equal(bad('x'.repeat(60)), null);
  assert.ok(bad('script-src-elem')); // válida passa
});

test('normalizeViolation: extensões bucketizam por scheme, sem ID da extensão', () => {
  const v = normalizeViolation(
    { documentUri: `${SITE}/`, directive: 'script-src-elem', blockedUri: 'moz-extension://uuid-que-identifica/user.js' },
    SITE,
  );
  assert.deepEqual(v, { directive: 'script-src-elem', category: 'extension', source: 'moz-extension://' });
});

test('normalizeViolation: origem terceira guarda SÓ a origem — path/query nunca', () => {
  const v = normalizeViolation(
    { documentUri: `${SITE}/`, directive: 'connect-src', blockedUri: 'https://telemetry.example:8443/collect?token=SECRET#frag' },
    SITE,
  );
  assert.deepEqual(v, { directive: 'connect-src', category: 'external', source: 'https://telemetry.example:8443' });
  assert.equal(v.source.includes('SECRET'), false);
  assert.equal(v.source.includes('/collect'), false);
});

test('normalizeViolation: inline/eval/vazio e origem própria são categoria self', () => {
  const mk = (blockedUri) => normalizeViolation({ documentUri: `${SITE}/`, directive: 'script-src', blockedUri }, SITE);
  assert.deepEqual(mk('inline'), { directive: 'script-src', category: 'self', source: 'inline' });
  assert.deepEqual(mk('eval'), { directive: 'script-src', category: 'self', source: 'eval' });
  assert.deepEqual(mk(''), { directive: 'script-src', category: 'self', source: 'inline' });
  // DEBUG_EXPOSE_SELF_PATH ligado temporariamente — ver nota no teste
  // "DEBUG_EXPOSE_SELF_PATH" abaixo; reverter para source: 'self' depois.
  assert.deepEqual(mk(`${SITE}/js/x.js`), { directive: 'script-src', category: 'self', source: 'self:/js/x.js' });
});

test('normalizeViolation: "inline" com sourceFile de extensão é ruído, não self', () => {
  // Uma extensão que injeta um <script> diretamente (em vez de o carregar de
  // chrome-extension://) produz blocked-uri "inline" — indistinguível de uma
  // regressão real da build pelo blocked-uri sozinho. sourceFile (de onde
  // partiu a chamada) é o único sinal que sobra.
  const v = normalizeViolation(
    {
      documentUri: `${SITE}/`,
      directive: 'script-src-elem',
      blockedUri: 'inline',
      sourceFile: 'chrome-extension://abcdefghijklmnop/inject.js',
    },
    SITE,
  );
  assert.deepEqual(v, { directive: 'script-src-elem', category: 'extension', source: 'chrome-extension://' });
});

test('normalizeViolation: "inline" sem sourceFile ou com sourceFile do próprio site continua self', () => {
  const semSourceFile = normalizeViolation(
    { documentUri: `${SITE}/`, directive: 'script-src-elem', blockedUri: 'inline' },
    SITE,
  );
  assert.equal(semSourceFile.category, 'self');
  const sourceFilePropio = normalizeViolation(
    { documentUri: `${SITE}/`, directive: 'script-src-elem', blockedUri: 'inline', sourceFile: `${SITE}/js/nav.js` },
    SITE,
  );
  assert.equal(sourceFilePropio.category, 'self');
});

test('normalizeViolation: blocked-uri da própria origem com sourceFile de extensão também é ruído', () => {
  // 'self' num script-src/connect-src nunca deveria bloquear um pedido
  // genuinamente same-origin — quando o browser reporta isto mesmo assim,
  // com sourceFile a apontar para uma extensão, é ela (não o nosso código)
  // a fazer o pedido a partir do contexto da página.
  const v = normalizeViolation(
    {
      documentUri: `${SITE}/`,
      directive: 'connect-src',
      blockedUri: `${SITE}/algum-caminho`,
      sourceFile: 'moz-extension://uuid-que-identifica/content.js',
    },
    SITE,
  );
  assert.deepEqual(v, { directive: 'connect-src', category: 'extension', source: 'moz-extension://' });

  // DEBUG_EXPOSE_SELF_PATH está ligado temporariamente (ver csp-report.js) —
  // o pathname aparece no source em vez do bucket genérico 'self', só para
  // diagnosticar as violações self/self inesperadas em produção. Reverter
  // este teste (para source: 'self') quando essa flag voltar a false.
  const semExtensao = normalizeViolation(
    { documentUri: `${SITE}/`, directive: 'connect-src', blockedUri: `${SITE}/algum-caminho` },
    SITE,
  );
  assert.deepEqual(semExtensao, { directive: 'connect-src', category: 'self', source: 'self:/algum-caminho' });
});

test('normalizeViolation: DEBUG_EXPOSE_SELF_PATH nunca inclui query/fragmento, só pathname', () => {
  const v = normalizeViolation(
    { documentUri: `${SITE}/`, directive: 'script-src-elem', blockedUri: `${SITE}/cdn-cgi/challenge-platform/h/g/orchestrate/jsch/v1?token=SECRET#frag` },
    SITE,
  );
  assert.equal(v.source, 'self:/cdn-cgi/challenge-platform/h/g/orchestrate/jsch/v1');
  assert.equal(v.source.includes('SECRET'), false);
  assert.equal(v.source.includes('frag'), false);
});

test('addCspEvent: cap de cardinalidade — fontes a mais caem em ~other', () => {
  const b = emptyCspBucket();
  for (let i = 0; i < MAX_SOURCES_PER_BUCKET + 10; i += 1) {
    addCspEvent(b, { directive: 'connect-src', category: 'external', source: `https://forjado-${i}.example` });
  }
  assert.equal(b.total, MAX_SOURCES_PER_BUCKET + 10);
  assert.equal(Object.keys(b.bySource).length, MAX_SOURCES_PER_BUCKET + 1); // as N + '~other'
  assert.equal(b.bySource['~other'], 10);
  // uma fonte já conhecida continua a incrementar a sua própria chave
  addCspEvent(b, { directive: 'connect-src', category: 'external', source: 'https://forjado-0.example' });
  assert.equal(b.bySource['connect-src|external|https://forjado-0.example'], 2);
});

test('cspStats: agrega 7 dias, top diretiva, categorias e série diária', () => {
  const d0 = emptyCspBucket(); // hoje
  addCspEvent(d0, { directive: 'script-src-elem', category: 'extension', source: 'chrome-extension://' });
  addCspEvent(d0, { directive: 'script-src-elem', category: 'extension', source: 'chrome-extension://' });
  addCspEvent(d0, { directive: 'script-src-elem', category: 'self', source: 'inline' });
  const d1 = emptyCspBucket(); // ontem
  addCspEvent(d1, { directive: 'style-src-elem', category: 'extension', source: 'moz-extension://' });
  const stats = cspStats([d0, d1, null, null, null, null, null]);
  assert.equal(stats.reports7d, 4);
  assert.equal(stats.topDirective, 'script-src-elem');
  assert.equal(stats.sourceCount, 3); // chrome-ext, inline, moz-ext
  assert.deepEqual(stats.byCategory, { extension: 3, self: 1, external: 0, other: 0 });
  assert.deepEqual(stats.daily, [0, 0, 0, 0, 0, 1, 3]); // mais antigo → hoje
  assert.equal(stats.sources[0].count, 2);
  assert.deepEqual(stats.sources[0], {
    directive: 'script-src-elem', category: 'extension', source: 'chrome-extension://', count: 2,
  });
});

test('mergeCspBuckets ignora nulos e soma tudo', () => {
  const a = emptyCspBucket();
  addCspEvent(a, { directive: 'script-src', category: 'self', source: 'inline' });
  const m = mergeCspBuckets([a, null, a]);
  assert.equal(m.total, 2);
  assert.equal(m.byDirective['script-src'], 2);
  assert.equal(m.bySource['script-src|self|inline'], 2);
});

// ---------- validação de input (Sessão 6, tarefa 1/5) ----------

test('normalizeCountry: só aceita 2 letras, resto vira XX', () => {
  assert.equal(normalizeCountry('ru'), 'RU');
  assert.equal(normalizeCountry('US'), 'US');
  assert.equal(normalizeCountry('T1'), 'XX'); // Tor exit (letra+dígito)
  assert.equal(normalizeCountry('ATTACKER'), 'XX'); // cabeçalho forjado
  assert.equal(normalizeCountry(''), 'XX');
  assert.equal(normalizeCountry(null), 'XX');
  assert.equal(normalizeCountry(42), 'XX');
});

test('normalizeAsn: inteiro no espaço 32-bit ou null', () => {
  assert.equal(normalizeAsn(64512), 64512);
  assert.equal(normalizeAsn(1), 1);
  assert.equal(normalizeAsn(4_294_967_294), 4_294_967_294);
  assert.equal(normalizeAsn(0), null);
  assert.equal(normalizeAsn(-5), null);
  assert.equal(normalizeAsn(1.5), null);
  assert.equal(normalizeAsn('64512'), null); // strings não passam
  assert.equal(normalizeAsn(undefined), null);
});

test('floorToWindow arredonda ao início da janela (anonimização)', () => {
  const w = 5 * 60_000; // 5 min
  const base = Date.parse('2026-07-16T12:00:00Z');
  assert.equal(floorToWindow(base + 4 * 60_000 + 59_000, w), base); // 12:04:59 → 12:00
  assert.equal(floorToWindow(base + 5 * 60_000, w), base + 5 * 60_000); // 12:05 exato
  assert.equal(floorToWindow(base, w), base);
  // resultado é sempre múltiplo da janela (sem instante preciso)
  assert.equal(floorToWindow(base + 123_456, w) % w, 0);
});

// ---------- cap de escritas ao KV (tarefa 6) ----------

test('underCap: bloqueia ao teto e reinicia por janela', () => {
  const cfg = { now: 1000, windowMs: 60_000, max: 2 };
  const s1 = underCap(null, cfg);
  assert.equal(s1.allowed, true);
  assert.equal(s1.state.count, 1);
  const s2 = underCap(s1.state, cfg);
  assert.equal(s2.allowed, true);
  assert.equal(s2.state.count, 2);
  const s3 = underCap(s2.state, cfg);
  assert.equal(s3.allowed, false);
  assert.equal(s3.state.count, 2); // não incrementa acima do teto
  // nova janela liberta e reinicia a contagem
  const s4 = underCap(s3.state, { ...cfg, now: 1000 + 60_001 });
  assert.equal(s4.allowed, true);
  assert.equal(s4.state.count, 1);
});

// ---------- hashing do rate limit por IP+rota (tarefa 2) ----------

test('clientHash: isola por IP e por salt, hex de 16 chars', async () => {
  const salt = dailySalt('sec', Date.parse('2026-07-16T12:00:00Z'));
  const a = await clientHash('203.0.113.7', salt);
  const b = await clientHash('198.51.100.9', salt);
  const c = await clientHash('203.0.113.7', dailySalt('sec', Date.parse('2026-07-17T12:00:00Z')));
  assert.notEqual(a, b); // IPs diferentes → chaves diferentes
  assert.notEqual(a, c); // dia (salt) diferente → chave diferente
  assert.match(a, /^[0-9a-f]{16}$/);
});

// ---------- integração do honeypot: fetch() do Worker sem rede ----------

function fakeKV() {
  const store = new Map();
  return {
    store,
    async get(key, type) {
      const v = store.get(key);
      if (v === undefined) return null;
      return type === 'json' ? JSON.parse(v) : v;
    },
    async put(key, value) { store.set(key, value); },
  };
}

function fakeRequest(path, { ip, country, asn, method = 'GET' } = {}) {
  const h = new Map([
    ['cf-connecting-ip', ip],
    ['cf-ipcountry', country],
  ]);
  return {
    url: `https://danielmala.co${path}`,
    method,
    headers: { get: (k) => h.get(String(k).toLowerCase()) ?? null },
    cf: { asn, country },
  };
}

async function runFetch(request, env) {
  const tasks = [];
  const ctx = { waitUntil: (p) => tasks.push(p) };
  const res = await worker.fetch(request, env, ctx);
  await Promise.allSettled(tasks); // deixa o recordHoneypot em background terminar
  return res;
}

test('honeypot: nunca guarda nem loga o IP completo; ts arredondado; país/ASN validados', async () => {
  const IP = '203.0.113.77';
  const logs = [];
  const orig = { error: console.error, log: console.log, warn: console.warn, info: console.info };
  for (const k of Object.keys(orig)) console[k] = (...a) => logs.push(a.map(String).join(' '));
  try {
    const env = { KV: fakeKV() };
    const req = fakeRequest('/.env', { ip: IP, country: 'T1', asn: 64512 });
    const res = await runFetch(req, env);
    assert.equal(res.status, 404); // isco devolve 404 seco

    const values = [...env.KV.store.values()];
    assert.ok(values.length > 0, 'deve ter escrito buckets');
    // o IP não pode aparecer em NENHUM valor guardado no KV
    for (const v of values) assert.equal(v.includes(IP), false, `IP fugiu para o KV: ${v}`);
    // nem em NENHUMA linha de log do Worker
    for (const line of logs) assert.equal(line.includes(IP), false, `IP fugiu para os logs: ${line}`);

    const recent = JSON.parse(env.KV.store.get('recent'));
    assert.equal(recent[0].ts % (5 * 60_000), 0); // timestamp arredondado a 5 min
    assert.equal(recent[0].country, 'XX'); // 'T1' inválido → XX
    assert.equal(recent[0].asn, 64512);
    assert.equal(recent[0].path, '/.env');
    assert.equal(recent[0].technique, 'T1592'); // correlação com /attack anexada no registo
    assert.equal('ip' in recent[0], false); // o evento nem tem campo de IP
  } finally {
    Object.assign(console, orig);
  }
});

test('honeypot: cap de escritas descarta eventos acima do teto', async () => {
  const env = { KV: fakeKV() };
  const now = Date.now();
  const hourKey = `h:${new Date(now).toISOString().slice(0, 13)}`;
  const dayKey = `d:${new Date(now).toISOString().slice(0, 10)}`;
  // pré-carrega o contador da janela (diária) no teto (max=60)
  env.KV.store.set(`wcap:${dayKey}`, JSON.stringify({ count: 60, windowStart: now }));

  const req = fakeRequest('/wp-login.php', { ip: '198.51.100.5', country: 'RU', asn: 64500 });
  const res = await runFetch(req, env);
  assert.equal(res.status, 404); // continua a devolver 404 indistinguível

  // com o cap atingido, não pode ter escrito buckets nem 'recent'
  assert.equal(env.KV.store.has('recent'), false);
  assert.equal(env.KV.store.has(hourKey), false);
  assert.equal([...env.KV.store.keys()].some((k) => k.startsWith('d:')), false);
});

test('honeypot: abaixo do teto escreve normalmente', async () => {
  const env = { KV: fakeKV() };
  const req = fakeRequest('/admin', { ip: '198.51.100.6', country: 'CN', asn: 4808 });
  const res = await runFetch(req, env);
  assert.equal(res.status, 404);
  assert.ok(env.KV.store.has('recent'));
  const recent = JSON.parse(env.KV.store.get('recent'));
  assert.equal(recent[0].country, 'CN');
  // o contador de escritas foi criado e conta 1
  const capKey = [...env.KV.store.keys()].find((k) => k.startsWith('wcap:'));
  assert.ok(capKey);
  assert.equal(JSON.parse(env.KV.store.get(capKey)).count, 1);
});

// ---------- integração: POST /api/csp-report e GET /api/csp-violations ----------

function fakeCspPost(body, { ip = '203.0.113.50', contentType = 'application/csp-report' } = {}) {
  const h = new Map([
    ['cf-connecting-ip', ip],
    ['content-type', contentType],
  ]);
  return {
    url: 'https://danielmala.co/api/csp-report',
    method: 'POST',
    headers: { get: (k) => h.get(String(k).toLowerCase()) ?? null },
    cf: {},
    text: async () => body,
  };
}

const LEGACY_REPORT = JSON.stringify({
  'csp-report': {
    'document-uri': 'https://danielmala.co/seguranca/',
    'effective-directive': 'script-src-elem',
    'blocked-uri': 'https://evil.example/payload.js?tok=SECRET',
  },
});

test('csp-report: POST válido devolve 204 e agrega só a origem no bucket diário', async () => {
  const env = { KV: fakeKV() };
  const res = await runFetch(fakeCspPost(LEGACY_REPORT), env);
  assert.equal(res.status, 204);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');

  const dayK = [...env.KV.store.keys()].find((k) => k.startsWith('cspd:'));
  assert.ok(dayK, 'devia ter escrito o bucket diário');
  const bucket = JSON.parse(env.KV.store.get(dayK));
  assert.equal(bucket.total, 1);
  assert.equal(bucket.byDirective['script-src-elem'], 1);
  assert.equal(bucket.byCategory.external, 1);
  // do URL bloqueado só a origem — path e query nunca entram no KV
  for (const v of env.KV.store.values()) {
    assert.equal(v.includes('SECRET'), false, `query fugiu para o KV: ${v}`);
    assert.equal(v.includes('payload.js'), false, `path fugiu para o KV: ${v}`);
  }
});

test('csp-report: relatório forjado (documento de outro site) descarta-se com o mesmo 204', async () => {
  const env = { KV: fakeKV() };
  const forged = JSON.stringify({
    'csp-report': {
      'document-uri': 'https://site-de-terceiros.example/',
      'effective-directive': 'script-src',
      'blocked-uri': 'inline',
    },
  });
  const res = await runFetch(fakeCspPost(forged), env);
  assert.equal(res.status, 204); // indistinguível de um aceite
  assert.equal([...env.KV.store.keys()].some((k) => k.startsWith('cspd:')), false);
});

test('csp-report: Content-Type errado → 415, corpo acima do teto → 413', async () => {
  const env = { KV: fakeKV() };
  const badType = await runFetch(fakeCspPost(LEGACY_REPORT, { contentType: 'text/plain' }), env);
  assert.equal(badType.status, 415);
  const tooBig = await runFetch(fakeCspPost('x'.repeat(17 * 1024)), env);
  assert.equal(tooBig.status, 413);
  assert.equal([...env.KV.store.keys()].some((k) => k.startsWith('cspd:')), false);
});

test('csp-report: cap global de escritas descarta acima do teto (204 na mesma)', async () => {
  const env = { KV: fakeKV() };
  const now = Date.now();
  const capKey = `cspcap:d:${new Date(now).toISOString().slice(0, 10)}`;
  env.KV.store.set(capKey, JSON.stringify({ count: 50, windowStart: now }));

  const res = await runFetch(fakeCspPost(LEGACY_REPORT), env);
  assert.equal(res.status, 204);
  assert.equal([...env.KV.store.keys()].some((k) => k.startsWith('cspd:')), false);
});

test('csp-report: rate limit por cliente devolve 429', async () => {
  const env = { KV: fakeKV() };
  const ip = '203.0.113.51';
  const id = await clientHash(ip, dailySalt(undefined));
  env.KV.store.set(`rl:cspr:${id}`, JSON.stringify({ count: 10, windowStart: Date.now() }));
  const res = await runFetch(fakeCspPost(LEGACY_REPORT, { ip }), env);
  assert.equal(res.status, 429);
  assert.ok(res.headers.get('retry-after'));
});

test('csp-violations: GET devolve os agregados dos buckets diários', async () => {
  const env = { KV: fakeKV() };
  await runFetch(fakeCspPost(LEGACY_REPORT), env);
  const res = await runFetch(fakeRequest('/api/csp-violations'), env);
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.equal(data.reports7d, 1);
  assert.equal(data.topDirective, 'script-src-elem');
  assert.equal(data.byCategory.external, 1);
  assert.equal(data.sources[0].source, 'https://evil.example');
  assert.equal(data.daily.length, 7);
  assert.equal(data.daily[6], 1); // hoje é o último da série
});

// ---------- cabeçalhos de segurança das respostas do Worker ----------
// O _headers do Pages não cobre as rotas do Worker — cada resposta tem de
// trazer nosniff + CSP 'none' por si (API JSON e 404 dos iscos).

test('respostas da API trazem nosniff e CSP none', async () => {
  const env = { KV: fakeKV() };
  const res = await runFetch(fakeRequest('/api/health'), env);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('content-security-policy'), "default-src 'none'");
});

test('404 dos paths-isco traz nosniff, CSP restrita e HTML igual ao 404 real', async () => {
  const env = { KV: fakeKV() };
  const res = await runFetch(fakeRequest('/wp-login.php', { ip: '198.51.100.7', country: 'US', asn: 1 }), env);
  assert.equal(res.status, 404);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('content-security-policy'), NOT_FOUND_CSP);
  assert.equal(res.headers.get('content-type'), 'text/html; charset=utf-8');
  const body = await res.text();
  assert.equal(body, renderNotFoundHtml()); // sempre a mesma página, qualquer que seja o path-isco
});

test('renderNotFoundHtml: autocontido, sem script nem dados do pedido', () => {
  const html = renderNotFoundHtml();
  assert.ok(html.includes('<h1>404</h1>'));
  assert.ok(html.includes('cd: /404: No such file or directory')); // mesma piada do 404 real
  assert.equal(html.includes('<script'), false); // CSP da resposta não permite script-src
  assert.equal(html, renderNotFoundHtml()); // determinístico, sem input
});

// ---------- cache: stale-while-revalidate ----------

test('cache expirada serve o valor stale e renova em background', async () => {
  const env = { KV: fakeKV() };
  const now = Date.now();
  // valor logicamente expirado, mas ainda presente no KV (janela stale)
  env.KV.store.set('cache:honeypot', JSON.stringify({ data: { attempts24h: 42 }, exp: now - 1000 }));

  const res = await runFetch(fakeRequest('/api/honeypot'), env);
  const body = await res.json();
  assert.equal(body.attempts24h, 42); // resposta imediata = stale

  // depois do waitUntil, a cache foi renovada (exp no futuro, dados frescos)
  const refreshed = JSON.parse(env.KV.store.get('cache:honeypot'));
  assert.ok(refreshed.exp > now, 'refresh em background devia ter renovado o exp');
  assert.equal(refreshed.data.attempts24h, 0); // buckets vazios → 0
});

// ---------- self-scan: segue redirects só na mesma origem (N7) ----------
// Achado da revisão de segurança 2026-07 (ronda 4): CF-Access-Client-Id/
// Secret, ao contrário do Authorization, não são despidos pelo Fetch spec
// em redirects cross-origin. Com `redirect: 'follow'` normal, um 3xx do
// alvo do self-scan para outra origem reenviava as credenciais da Access
// para esse destino.

test('self-scan: NÃO segue redirect para outra origem, e não reenvia as credenciais da Access', async () => {
  const env = {
    KV: fakeKV(),
    SCAN_TARGET: 'https://danielmala.co/',
    ACCESS_CLIENT_ID: 'cid',
    ACCESS_CLIENT_SECRET: 'csecret',
  };
  const calls = [];
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    calls.push({ url: String(url), headers: opts?.headers ?? {} });
    if (String(url) === 'https://danielmala.co/') {
      return {
        status: 302,
        headers: { get: (h) => (h.toLowerCase() === 'location' ? 'https://evil.example/' : null) },
      };
    }
    return { status: 200, headers: { get: () => null } }; // não devia ser chamado
  };
  try {
    const res = await runFetch(fakeRequest('/api/scan'), env);
    assert.equal(res.status, 200); // a rota devolve sempre 200 com o grade calculado
    assert.equal(calls.length, 1, 'não deve seguir o redirect para fora da origem');
    assert.equal(calls[0].headers['CF-Access-Client-Id'], 'cid'); // o pedido same-origin inicial leva as credenciais
  } finally {
    globalThis.fetch = orig;
  }
});

test('self-scan: segue redirect same-origin e reenvia as credenciais da Access ao destino final', async () => {
  const env = {
    KV: fakeKV(),
    SCAN_TARGET: 'https://danielmala.co/',
    ACCESS_CLIENT_ID: 'cid',
    ACCESS_CLIENT_SECRET: 'csecret',
  };
  const calls = [];
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, opts) => {
    calls.push({ url: String(url), headers: opts?.headers ?? {} });
    if (String(url) === 'https://danielmala.co/') {
      return {
        status: 301,
        headers: { get: (h) => (h.toLowerCase() === 'location' ? 'https://danielmala.co/pt/' : null) },
      };
    }
    return {
      status: 200,
      headers: { get: (h) => (h.toLowerCase() === 'x-content-type-options' ? 'nosniff' : null) },
    };
  };
  try {
    const res = await runFetch(fakeRequest('/api/scan'), env);
    assert.equal(res.status, 200);
    assert.equal(calls.length, 2, 'deve seguir o redirect same-origin');
    assert.equal(calls[1].url, 'https://danielmala.co/pt/');
    assert.equal(calls[1].headers['CF-Access-Client-Id'], 'cid'); // credenciais seguem no salto same-origin
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/scan: leitura simples não é cacheável pelo browser (no-store) — só a KV controla frescura', async () => {
  // Achado: `Cache-Control: public, max-age=1800` aqui deixava o browser (e
  // qualquer cache partilhada) devolver a resposta antiga por até 30 min
  // depois de um refresh manual já ter atualizado a KV — a nota "congelava"
  // na última resposta pública que o browser tinha guardado, mesmo com a
  // KV já a refletir a nota nova.
  const env = { KV: fakeKV(), SCAN_TARGET: 'https://danielmala.co/' };
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({ status: 200, headers: { get: () => null } });
  try {
    const res = await runFetch(fakeRequest('/api/scan'), env);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('cache-control'), 'no-store');
  } finally {
    globalThis.fetch = orig;
  }
});

// ---------- rate limit: pedido bloqueado não gasta escrita KV ----------

test('rate limit bloqueado devolve 429 sem nenhum put no KV', async () => {
  const kv = fakeKV();
  let puts = 0;
  const origPut = kv.put.bind(kv);
  kv.put = async (...args) => { puts += 1; return origPut(...args); };
  const env = { KV: kv };

  // pré-carrega a janela do cliente no máximo (max=3 na rota scan)
  const ip = '203.0.113.9';
  const id = await clientHash(ip, dailySalt(undefined));
  kv.store.set(`rl:scan:${id}`, JSON.stringify({ count: 3, windowStart: Date.now() }));

  const res = await runFetch(fakeRequest('/api/scan?refresh=1', { ip }), env);
  assert.equal(res.status, 429);
  assert.ok(res.headers.get('retry-after'));
  assert.equal(puts, 0, 'um 429 não pode custar uma escrita KV');
});

// ---------- rate limit: teto global de escritas do próprio limiter ----------
// Achado da revisão de segurança de 2026-07: um cliente dentro do limite
// por rota (ex.: 30/min em /api/mirror) força uma escrita KV por pedido —
// sem este cap, ~43 mil escritas/dia SÓ NESTA ROTA, muito acima do teto de
// ~1.000/dia da conta inteira no plano Free, esgotando o orçamento que o
// honeypot/vitals/CSP também precisam.
//
// ATUALIZADO 2026-07-29 (achado A1, docs/security-review-2026-07-29.md): a
// versão original deste teste afirmava `res.status === 200` com o cap
// esgotado — ou seja, com o orçamento de escrita no teto, QUALQUER pedido
// nessa rota passava a ser aceite indefinidamente (o estado por-cliente
// nunca mais era persistido, por isso a janela ficava congelada). Bastavam
// ~300 pedidos triviais (10 min a 30/min num único IP em /api/mirror ou
// /api/vitals, sem precisar de distribuir por várias origens) para desligar
// o rate limit da rota inteira até à meia-noite UTC. Corrigido para falhar
// FECHADO: com o cap esgotado, a rota devolve 429 (sem gastar nenhuma
// escrita extra — o 429 continua "grátis") até o cap global reabrir.

test('rate limit: cap global diário no teto falha fechado (429) sem escrever nada', async () => {
  const kv = fakeKV();
  const env = { KV: kv };
  const now = Date.now();
  // rlcap:d:<dia> — o "d:" vem de dayKey() (ver honeypot/CSP: mesmo padrão)
  const capKey = `rlcap:d:${new Date(now).toISOString().slice(0, 10)}`;
  // pré-carrega o cap GLOBAL do rate limiter já no teto (max=300)
  kv.store.set(capKey, JSON.stringify({ count: 300, windowStart: now }));

  let puts = 0;
  const origPut = kv.put.bind(kv);
  kv.put = async (...args) => { puts += 1; return origPut(...args); };

  const logs = [];
  const origError = console.error;
  console.error = (...a) => logs.push(a.map(String).join(' '));
  let res;
  try {
    res = await runFetch(fakeRequest('/api/mirror', { ip: '203.0.113.99' }), env);
  } finally {
    console.error = origError;
  }
  assert.equal(res.status, 429); // A1: falhar fechado, não deixar passar tudo
  assert.ok(res.headers.get('retry-after'), 'devia trazer retry-after mesmo no caminho do cap global');
  assert.equal(puts, 0, 'com o cap global no teto, nenhuma escrita adicional (nem a do cap) deve acontecer');
  assert.ok(logs.some((l) => l.includes('ratelimit_write_cap_exhausted')), 'devia avisar ruidosamente do cap esgotado');
});

test('rate limit: cap global esgotado bloqueia TODOS os clientes da rota, não só quem o esgotou', async () => {
  // A1: o cap é global (não por-cliente) — um segundo IP, nunca antes visto
  // nesta rota, também tem de ser recusado enquanto o orçamento do dia
  // estiver esgotado. Prova que a falha fechada não depende do estado
  // (inexistente) desse cliente específico.
  const kv = fakeKV();
  const env = { KV: kv };
  const now = Date.now();
  const capKey = `rlcap:d:${new Date(now).toISOString().slice(0, 10)}`;
  kv.store.set(capKey, JSON.stringify({ count: 300, windowStart: now }));

  const res = await runFetch(fakeRequest('/api/mirror', { ip: '198.51.100.200' }), env);
  assert.equal(res.status, 429);
});

test('rate limit: abaixo do teto global escreve normalmente e o cap acumula', async () => {
  const env = { KV: fakeKV() };
  const res = await runFetch(fakeRequest('/api/mirror', { ip: '203.0.113.98' }), env);
  assert.equal(res.status, 200);
  const capKey = [...env.KV.store.keys()].find((k) => k.startsWith('rlcap:'));
  assert.ok(capKey, 'devia ter criado o contador do cap global');
  assert.equal(JSON.parse(env.KV.store.get(capKey)).count, 1);
  const rlKey = [...env.KV.store.keys()].find((k) => k.startsWith('rl:mirror:'));
  assert.ok(rlKey, 'devia ter persistido o estado por-cliente também');
});

test('RATE_SALT em falta: regista aviso ruidoso mas o pedido continua a ser servido', async () => {
  const env = { KV: fakeKV() }; // sem RATE_SALT
  const logs = [];
  const origError = console.error;
  console.error = (...a) => logs.push(a.map(String).join(' '));
  try {
    const res = await runFetch(fakeRequest('/api/mirror', { ip: '203.0.113.97' }), env);
    assert.equal(res.status, 200);
    assert.ok(logs.some((l) => l.includes('rate_salt_missing')), 'devia avisar da falta do segredo');
  } finally {
    console.error = origError;
  }
});

// ---------- vigia CT: parse do crt.sh e endpoint /api/ct ----------

// Entrada realista do JSON do crt.sh (campos que a lib usa).
function crtshEntry(over = {}) {
  return {
    issuer_ca_id: 295810,
    issuer_name: "C=US, O=Let's Encrypt, CN=R11",
    common_name: 'danielmala.co',
    name_value: 'danielmala.co\n*.danielmala.co',
    id: 130000001,
    entry_timestamp: '2026-07-02T09:00:00.123',
    not_before: '2026-07-02T08:00:00',
    not_after: '2026-09-30T08:00:00',
    serial_number: '04a1b2c3d4e5f60718293a4b5c6d7e8f9012',
    ...over,
  };
}

const CT_NOW = Date.parse('2026-07-17T12:00:00Z');
const CT_OPTS = { domain: 'danielmala.co', now: CT_NOW };

test('issuerLabel: DN do crt.sh → rótulo curto sanitizado', () => {
  assert.equal(issuerLabel("C=US, O=Let's Encrypt, CN=R11"), "Let's Encrypt R11");
  assert.equal(issuerLabel('C=US, O=Google Trust Services, CN=WE1'), 'Google Trust Services WE1');
  assert.equal(issuerLabel('CN=Só CN'), 'Só CN');
  assert.equal(issuerLabel('O=Mesmo, CN=Mesmo'.replace('Mesmo, CN=Mesmo', 'Igual, CN=Igual')), 'Igual');
  assert.equal(issuerLabel('lixo sem DN <b>'), 'lixo sem DN b'); // sanitizado, nunca markup
  assert.equal(issuerLabel(null), '');
});

test('isExpectedIssuer: substring sem caso, contra a allowlist', () => {
  assert.equal(isExpectedIssuer("let's encrypt r11", DEFAULT_EXPECTED_ISSUERS), true);
  assert.equal(isExpectedIssuer('Google Trust Services WE1', DEFAULT_EXPECTED_ISSUERS), true);
  assert.equal(isExpectedIssuer('Encryption Everywhere DV', DEFAULT_EXPECTED_ISSUERS), false);
});

test('parseExpectedIssuers: CSV do env ou a lista por omissão', () => {
  assert.deepEqual(parseExpectedIssuers("Let's Encrypt, ZeroSSL"), ["Let's Encrypt", 'ZeroSSL']);
  assert.deepEqual(parseExpectedIssuers(''), DEFAULT_EXPECTED_ISSUERS);
  assert.deepEqual(parseExpectedIssuers(undefined), DEFAULT_EXPECTED_ISSUERS);
});

test('normalizeCtEntry: só nomes do domínio, sanitizados; fora do domínio → null', () => {
  const cert = normalizeCtEntry(
    crtshEntry({ name_value: 'danielmala.co\n*.danielmala.co\nevil.com\nDANIELMALA.CO' }),
    { domain: 'danielmala.co', expectedIssuers: DEFAULT_EXPECTED_ISSUERS },
  );
  assert.deepEqual(cert.names, ['*.danielmala.co', 'danielmala.co']); // evil.com fora, sem duplicados
  assert.equal(cert.expected, true);
  // "danielmala.co.evil.com" NÃO pertence ao domínio (o sufixo é evil.com)
  const forged = normalizeCtEntry(
    crtshEntry({ name_value: 'danielmala.co.evil.com' }),
    { domain: 'danielmala.co', expectedIssuers: DEFAULT_EXPECTED_ISSUERS },
  );
  assert.equal(forged, null);
});

test('parseCtEntries: dedupe pré-cert/folha, janela de 90d, ordenação e classificação', () => {
  const entries = [
    crtshEntry(), // folha
    crtshEntry({ id: 130000002 }), // pré-certificado: mesmo serial → dedupe
    crtshEntry({
      entry_timestamp: '2026-07-16T10:00:00', not_before: '2026-07-16T09:00:00',
      serial_number: '0badc0ffee', issuer_name: 'C=US, O=DigiCert Inc, CN=Encryption Everywhere DV TLS CA',
      name_value: 'webmail.danielmala.co', common_name: 'webmail.danielmala.co',
    }),
    crtshEntry({
      entry_timestamp: '2026-01-02T09:00:00', not_before: '2026-01-02T08:00:00',
      serial_number: '00ancient',
    }), // fora da janela de 90 dias
  ];
  const certs = parseCtEntries(entries, CT_OPTS);
  assert.equal(certs.length, 2);
  // mais recente primeiro, e é o inesperado
  assert.equal(certs[0].issuer, 'DigiCert Inc Encryption Everywhere DV TLS CA');
  assert.equal(certs[0].expected, false);
  assert.deepEqual(certs[0].names, ['webmail.danielmala.co']);
  assert.equal(certs[1].expected, true);
  assert.equal('serial' in certs[0], false); // o serial não segue para o cliente

  const stats = ctStats(certs);
  assert.deepEqual(stats, { total: 2, issuerCount: 2, nameCount: 3, unexpected: 1 });
});

test('parseCtEntries: datas sem timezone parseiam como UTC (determinístico)', () => {
  const [cert] = parseCtEntries([crtshEntry()], CT_OPTS);
  assert.equal(cert.notBefore, Date.parse('2026-07-02T08:00:00Z'));
  assert.equal(cert.loggedAt, Date.parse('2026-07-02T09:00:00.123Z'));
});

test('/api/ct: junta as duas queries do crt.sh, deduplica e devolve o sumário', async () => {
  const env = { KV: fakeKV(), SCAN_TARGET: 'https://danielmala.co/' };
  const orig = globalThis.fetch;
  const urls = [];
  globalThis.fetch = async (url) => {
    urls.push(String(url));
    // as duas queries devolvem o mesmo certificado — a dedupe trata da sobreposição
    return { ok: true, status: 200, json: async () => [crtshEntry()] };
  };
  try {
    const res = await runFetch(fakeRequest('/api/ct'), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.domain, 'danielmala.co');
    assert.equal(data.certs.length, 1);
    assert.equal(data.summary.unexpected, 0);
    assert.equal(urls.length, 2);
    assert.ok(urls.some((u) => u.includes('q=danielmala.co')), 'query do apex');
    assert.ok(urls.some((u) => u.includes(encodeURIComponent('%.danielmala.co'))), 'query dos subdomínios');
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/ct: uma query falhada degrada para a outra; as duas → 502', async () => {
  const env = { KV: fakeKV(), SCAN_TARGET: 'https://danielmala.co/' };
  const orig = globalThis.fetch;
  let call = 0;
  globalThis.fetch = async () => {
    call += 1;
    if (call === 1) throw new Error('timeout');
    return { ok: true, status: 200, json: async () => [crtshEntry()] };
  };
  try {
    const res = await runFetch(fakeRequest('/api/ct'), env);
    assert.equal(res.status, 200); // parcial vale mais do que nada
    assert.equal((await res.json()).certs.length, 1);
  } finally {
    globalThis.fetch = orig;
  }

  const env2 = { KV: fakeKV(), SCAN_TARGET: 'https://danielmala.co/' };
  globalThis.fetch = async () => { throw new Error('down'); };
  try {
    const res = await runFetch(fakeRequest('/api/ct'), env2);
    assert.equal(res.status, 502); // erro genérico, painel mostra fallback
    assert.deepEqual(await res.json(), { error: 'upstream_error' });
  } finally {
    globalThis.fetch = orig;
  }
});

// ---------- Estado da Cloudflare (/api/cf-stats) ----------

function graphqlFixture({ zoneRows = [], workerRows = [] } = {}) {
  return {
    data: {
      viewer: {
        zones: [{ httpRequests1dGroups: zoneRows }],
        accounts: [{ workersInvocationsAdaptive: workerRows }],
      },
    },
  };
}

test('parseCfStats: soma vários dias e calcula os rácios', () => {
  const raw = graphqlFixture({
    zoneRows: [
      { sum: { requests: 100, cachedRequests: 60, bytes: 1_000_000, threats: 3 } },
      { sum: { requests: 200, cachedRequests: 150, bytes: 2_000_000, threats: 1 } },
    ],
    workerRows: [
      { sum: { requests: 50, errors: 2 } },
      { sum: { requests: 30, errors: 0 } },
    ],
  });
  const stats = parseCfStats(raw, { now: 1_753_200_000_000, windowDays: 7 });
  assert.deepEqual(stats.zone, {
    requests: 300, visitors: 0, cachedRequests: 210, cacheRatio: 210 / 300, bytes: 3_000_000, threats: 4,
    topCountries: [], riskByCountry: [], blockedByStatus: [], series: [],
    firewallByAction: [], firewallBySource: [], firewallByCountry: [],
    firewallByPath: [], firewallByUserAgent: [], firewallByAsn: [],
  });
  assert.deepEqual(stats.worker, { requests: 80, errors: 2, errorRatio: 2 / 80 });
  assert.equal(stats.windowDays, 7);
  assert.equal(stats.fetchedAt, 1_753_200_000_000);
});

test('parseCfStats: shape inesperado ou vazio degrada para zeros, nunca lança', () => {
  assert.deepEqual(parseCfStats({}).zone, {
    requests: 0, visitors: 0, cachedRequests: 0, cacheRatio: 0, bytes: 0, threats: 0,
    topCountries: [], riskByCountry: [], blockedByStatus: [], series: [],
    firewallByAction: [], firewallBySource: [], firewallByCountry: [],
    firewallByPath: [], firewallByUserAgent: [], firewallByAsn: [],
  });
  assert.deepEqual(parseCfStats(null).worker, { requests: 0, errors: 0, errorRatio: 0 });
  assert.deepEqual(parseCfStats({ data: { viewer: {} } }).zone.requests, 0);
  // campo `sum` em falta numa linha não rebenta a soma das outras
  const partial = graphqlFixture({ zoneRows: [{ sum: { requests: 10 } }, {}] });
  assert.equal(parseCfStats(partial).zone.requests, 10);
});

test('parseCfStats: série por dia, visitantes e risk score por país', () => {
  const raw = graphqlFixture({
    zoneRows: [
      {
        dimensions: { date: '2026-07-21' },
        uniq: { uniques: 40 },
        sum: {
          requests: 1000, cachedRequests: 700, bytes: 5_000_000, threats: 10,
          countryMap: [
            { clientCountryName: 'PT', requests: 800, threats: 1 },
            { clientCountryName: 'CN', requests: 200, threats: 90 }, // rácio alto
          ],
        },
      },
      {
        dimensions: { date: '2026-07-20' }, // ordem invertida de propósito
        uniq: { uniques: 35 },
        sum: {
          requests: 500, cachedRequests: 300, bytes: 2_000_000, threats: 4,
          countryMap: [
            { clientCountryName: 'XX', requests: 999, threats: 5 }, // XX fica sempre fora
            { clientCountryName: 'US', requests: 50, threats: 5 }, // < 100 pedidos: entra, mas lowSample
          ],
        },
      },
    ],
  });
  const zone = parseCfStats(raw).zone;
  assert.equal(zone.visitors, 75); // 40 + 35
  // série ordenada do mais antigo para o mais recente
  assert.deepEqual(zone.series.map((d) => d.date), ['2026-07-20', '2026-07-21']);
  assert.equal(zone.series[1].requests, 1000);
  assert.equal(zone.series[1].visitors, 40);
  // risk score: CN com 90/200 = 0.45 (confiante, 1.º); PT 1/800 (confiante);
  // US 5/50 = 0.1 (lowSample — < 100 pedidos), vem DEPOIS de PT apesar de ter
  // taxa mais alta: confiança ordena antes da taxa. XX nunca entra.
  assert.equal(zone.riskByCountry[0].country, 'CN');
  assert.ok(Math.abs(zone.riskByCountry[0].rate - 0.45) < 1e-9);
  assert.equal(zone.riskByCountry[0].lowSample, false);
  assert.ok(!zone.riskByCountry.some((r) => r.country === 'XX'));
  const us = zone.riskByCountry.find((r) => r.country === 'US');
  assert.ok(us, 'US já não é excluído por amostra pequena');
  assert.equal(us.lowSample, true);
  assert.ok(Math.abs(us.rate - 0.1) < 1e-9);
  const ptIndex = zone.riskByCountry.findIndex((r) => r.country === 'PT');
  const usIndex = zone.riskByCountry.findIndex((r) => r.country === 'US');
  assert.ok(ptIndex < usIndex, 'países com amostra suficiente vêm antes dos de amostra pequena');
});

test('threatIntel: atacantes novos vs recorrentes por ASN', () => {
  // day[0] = hoje. AS4837 em 3 dias (recorrente); AS9999 só hoje (novo).
  const mkDay = (asns) => { const b = emptyBucket(); b.byAsn = asns; return b; };
  const ti = threatIntel({
    days: [
      mkDay({ AS4837: 10, AS9999: 4 }), // hoje
      mkDay({ AS4837: 8 }),
      mkDay({ AS4837: 6, AS1000: 2 }),
    ],
  });
  assert.deepEqual(ti.recurringAttackers, [{ key: 'AS4837', count: 24, days: 3 }]);
  assert.deepEqual(ti.newAttackers, [{ key: 'AS9999', count: 4 }]);
});

test('parseCfStats: topCountries soma ameaças através dos dias, ordena e filtra XX/zero', () => {
  const raw = graphqlFixture({
    zoneRows: [
      {
        sum: {
          requests: 100, threats: 12,
          countryMap: [
            { clientCountryName: 'CN', requests: 40, threats: 5 },
            { clientCountryName: 'ru', requests: 20, threats: 3 }, // minúsculas normalizam
            { clientCountryName: 'PT', requests: 30, threats: 0 }, // sem ameaças → fora
            { clientCountryName: '??', requests: 5, threats: 9 }, // país inválido → XX → fora
          ],
        },
      },
      {
        sum: {
          requests: 50, threats: 6,
          countryMap: [
            { clientCountryName: 'CN', requests: 10, threats: 2 }, // acumula com o dia anterior
            { clientCountryName: 'US', requests: 40, threats: 4 },
          ],
        },
      },
    ],
  });
  const stats = parseCfStats(raw);
  assert.deepEqual(stats.zone.topCountries, [
    { country: 'CN', threats: 7 },
    { country: 'RU', threats: 3 },
    { country: 'US', threats: 4 },
  ].sort((a, b) => b.threats - a.threats));
});

test('parseCfStats: topCountries corta no limite (mais países do que o topo pedido)', () => {
  const countryMap = Array.from({ length: 15 }, (_, i) => ({
    clientCountryName: String.fromCharCode(65 + i, 65 + i), // AA, BB, CC...
    requests: 10,
    threats: 15 - i, // decrescente, para a ordenação ser previsível
  }));
  const raw = graphqlFixture({ zoneRows: [{ sum: { requests: 150, threats: 120, countryMap } }] });
  const stats = parseCfStats(raw);
  assert.equal(stats.zone.topCountries.length, 10);
  assert.equal(stats.zone.topCountries[0].country, 'AA');
  assert.equal(stats.zone.topCountries[0].threats, 15);
});

test('parseCfStats: blockedByStatus soma por código HTTP, só 4xx/5xx, ordena', () => {
  const raw = graphqlFixture({
    zoneRows: [
      {
        sum: {
          requests: 1000,
          responseStatusMap: [
            { edgeResponseStatus: 200, requests: 500 }, // < 400 → fora
            { edgeResponseStatus: 403, requests: 900 },
            { edgeResponseStatus: 503, requests: 100 },
            { edgeResponseStatus: 302, requests: 300 }, // redirect → fora
          ],
        },
      },
      {
        sum: {
          requests: 500,
          responseStatusMap: [
            { edgeResponseStatus: 403, requests: 474 }, // acumula com o dia anterior
            { edgeResponseStatus: 429, requests: 2 },
            { edgeResponseStatus: 404, requests: 0 }, // zero → fora
          ],
        },
      },
    ],
  });
  const stats = parseCfStats(raw);
  assert.deepEqual(stats.zone.blockedByStatus, [
    { key: '403', count: 1374 }, // 900 + 474
    { key: '503', count: 100 },
    { key: '429', count: 2 },
  ]);
});

test('parseCfStats: blockedByStatus corta no limite e degrada para [] sem o campo', () => {
  const responseStatusMap = Array.from({ length: 15 }, (_, i) => ({
    edgeResponseStatus: 400 + i, // 400, 401, 402… todos >= 400
    requests: 15 - i, // decrescente
  }));
  const raw = graphqlFixture({ zoneRows: [{ sum: { requests: 150, responseStatusMap } }] });
  const stats = parseCfStats(raw);
  assert.equal(stats.zone.blockedByStatus.length, 10);
  assert.deepEqual(stats.zone.blockedByStatus[0], { key: '400', count: 15 });
  // responseStatusMap ausente → []
  assert.deepEqual(parseCfStats(graphqlFixture({ zoneRows: [{ sum: { requests: 5 } }] })).zone.blockedByStatus, []);
});

// Helper: resposta da CF_FIREWALL_QUERY (firewallEventsAdaptive cru).
function firewallFixture(events) {
  return { data: { viewer: { zones: [{ firewallEventsAdaptive: events }] } } };
}

test('firewallBreakdown: agrega os eventos crus por ação e por origem, ordenado', () => {
  const raw = firewallFixture([
    { action: 'managed_challenge', source: 'firewallCustom' },
    { action: 'managed_challenge', source: 'firewallCustom' },
    { action: 'block', source: 'firewallCustom' },
    { action: 'block', source: 'ratelimit' },
    { action: 'block', source: 'ratelimit' },
    { action: 'js_challenge', source: 'bic' },
  ]);
  const fw = firewallBreakdown(raw);
  assert.deepEqual(fw.firewallByAction, [
    { key: 'block', count: 3 },
    { key: 'managed_challenge', count: 2 },
    { key: 'js_challenge', count: 1 },
  ]);
  assert.deepEqual(fw.firewallBySource, [
    { key: 'firewallCustom', count: 3 },
    { key: 'ratelimit', count: 2 },
    { key: 'bic', count: 1 },
  ]);
});

test('firewallBreakdown: pesa por sampleInterval (amostragem), falta/zero conta como 1', () => {
  const raw = firewallFixture([
    { action: 'block', source: 'firewallCustom', sampleInterval: 5 },
    { action: 'block', source: 'firewallCustom', sampleInterval: 5 },
    { action: 'managed_challenge', source: 'ratelimit' }, // sem sampleInterval → 1
    { action: 'skip', source: 'firewallCustom', sampleInterval: 0 }, // 0 → 1
  ]);
  const fw = firewallBreakdown(raw);
  assert.deepEqual(fw.firewallByAction, [
    { key: 'block', count: 10 }, // 5 + 5
    { key: 'managed_challenge', count: 1 },
    { key: 'skip', count: 1 },
  ]);
  assert.deepEqual(fw.firewallBySource, [
    { key: 'firewallCustom', count: 11 }, // 5 + 5 + 1
    { key: 'ratelimit', count: 1 },
  ]);
});

test('firewallBreakdown: campo em falta vira "unknown"; shape ausente/nulo degrada para []', () => {
  const fw = firewallBreakdown(firewallFixture([{ action: 'block' }, { source: 'ratelimit' }]));
  assert.deepEqual(fw.firewallByAction, [{ key: 'block', count: 1 }, { key: 'unknown', count: 1 }]);
  assert.deepEqual(fw.firewallBySource, [{ key: 'unknown', count: 1 }, { key: 'ratelimit', count: 1 }]);
  assert.deepEqual(firewallBreakdown({}).firewallByAction, []);
  assert.deepEqual(firewallBreakdown(null).firewallBySource, []);
});

test('firewallBreakdown: firewallByCountry cruza país com a ação dominante desse país', () => {
  const fw = firewallBreakdown(firewallFixture([
    { action: 'block', source: 'ratelimit', clientCountryName: 'NL' },
    { action: 'block', source: 'ratelimit', clientCountryName: 'NL' },
    { action: 'managed_challenge', source: 'firewallCustom', clientCountryName: 'NL' },
    { action: 'js_challenge', source: 'bic', clientCountryName: 'DE' },
    { action: 'block', source: 'ratelimit', clientCountryName: 'xx' }, // normaliza p/ 'XX' (sentinela): fora
  ]));
  assert.deepEqual(fw.firewallByCountry, [
    { country: 'NL', action: 'block', count: 2 }, // NL: block=2 domina sobre managed_challenge=1
    { country: 'DE', action: 'js_challenge', count: 1 },
  ]);
});

test('firewallDetailBreakdown: agrega por URL, user-agent e ASN, pesado por sampleInterval', () => {
  const raw = firewallFixture([
    { clientRequestPath: '/wp-login.php', userAgent: 'curl/8.0', clientAsn: 64512, sampleInterval: 5 },
    { clientRequestPath: '/wp-login.php', userAgent: 'curl/8.0', clientAsn: 64512, sampleInterval: 5 },
    { clientRequestPath: '/.env', userAgent: 'python-requests/2.31', clientAsn: 64512 }, // sem sampleInterval → 1
    { clientRequestPath: '/.env', userAgent: 'Mozilla/5.0', clientAsn: 4837 },
  ]);
  const fw = firewallDetailBreakdown(raw);
  assert.deepEqual(fw.firewallByPath, [
    { key: '/wp-login.php', count: 10 },
    { key: '/.env', count: 2 },
  ]);
  assert.deepEqual(fw.firewallByUserAgent, [
    { key: 'curl/8.0', count: 10 },
    { key: 'python-requests/2.31', count: 1 },
    { key: 'Mozilla/5.0', count: 1 },
  ]);
  assert.deepEqual(fw.firewallByAsn, [
    { key: 'AS64512', count: 11 },
    { key: 'AS4837', count: 1 },
  ]);
});

test('firewallDetailBreakdown: nunca processa clientIP (mesmo se viesse na resposta), sanitiza path/UA e ignora ASN inválido', () => {
  const fw = firewallDetailBreakdown(firewallFixture([
    { clientIP: '203.0.113.7', clientRequestPath: '/<script>x</script>', userAgent: 'a'.repeat(200), clientAsn: -1 },
    { clientRequestPath: '', userAgent: '', clientAsn: 0 },
  ]));
  assert.ok(!JSON.stringify(fw).includes('203.0.113.7'));
  assert.equal(fw.firewallByPath[0].key, '/scriptx/script'); // <> removidos por sanitizeText
  assert.equal(fw.firewallByUserAgent[0].key.length, 140); // truncado (139 + '…')
  assert.deepEqual(fw.firewallByAsn, []); // -1 e 0 são inválidos p/ normalizeAsn
});

test('firewallDetailBreakdown: shape ausente/nulo degrada para listas vazias', () => {
  assert.deepEqual(firewallDetailBreakdown({}).firewallByPath, []);
  assert.deepEqual(firewallDetailBreakdown(null).firewallByUserAgent, []);
  assert.deepEqual(firewallDetailBreakdown(firewallFixture([])).firewallByAsn, []);
});

test('/api/cf-stats: o 2.º pedido (firewall) preenche firewallByAction/Source', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const isFw = JSON.parse(init.body).query.includes('firewallEventsAdaptive');
    if (isFw) {
      return { ok: true, json: async () => firewallFixture([
        { action: 'managed_challenge', source: 'firewallCustom' },
        { action: 'managed_challenge', source: 'firewallCustom' },
        { action: 'block', source: 'ratelimit' },
      ]) };
    }
    return { ok: true, json: async () => graphqlFixture({ zoneRows: [{ sum: { requests: 10, threats: 676 } }] }) };
  };
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats'), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.zone.threats, 676);
    assert.deepEqual(data.zone.firewallByAction, [
      { key: 'managed_challenge', count: 2 },
      { key: 'block', count: 1 },
    ]);
    assert.deepEqual(data.zone.firewallBySource, [
      { key: 'firewallCustom', count: 2 },
      { key: 'ratelimit', count: 1 },
    ]);
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/cf-stats: erro só no 2.º pedido (firewall) mantém o núcleo (sem 502)', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const isFw = JSON.parse(init.body).query.includes('firewallEventsAdaptive');
    if (isFw) return { ok: true, json: async () => ({ errors: [{ message: 'does not have access to the path' }] }) };
    return { ok: true, json: async () => graphqlFixture({ zoneRows: [{ sum: { requests: 10, threats: 5 } }] }) };
  };
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats'), env);
    assert.equal(res.status, 200); // núcleo intacto — NÃO 502
    const data = await res.json();
    assert.equal(data.zone.threats, 5);
    assert.deepEqual(data.zone.firewallByAction, []);
    assert.deepEqual(data.zone.firewallBySource, []);
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/cf-stats: o 3.º pedido (firewall detail) preenche firewallByPath/UserAgent/Asn', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const query = JSON.parse(init.body).query;
    if (query.includes('CfFirewallDetail')) {
      return { ok: true, json: async () => firewallFixture([
        { clientRequestPath: '/wp-login.php', userAgent: 'curl/8.0', clientAsn: 64512 },
        { clientRequestPath: '/wp-login.php', userAgent: 'curl/8.0', clientAsn: 64512 },
      ]) };
    }
    if (query.includes('firewallEventsAdaptive')) {
      return { ok: true, json: async () => firewallFixture([{ action: 'block', source: 'ratelimit' }]) };
    }
    return { ok: true, json: async () => graphqlFixture({ zoneRows: [{ sum: { requests: 10, threats: 676 } }] }) };
  };
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats'), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.deepEqual(data.zone.firewallByPath, [{ key: '/wp-login.php', count: 2 }]);
    assert.deepEqual(data.zone.firewallByUserAgent, [{ key: 'curl/8.0', count: 2 }]);
    assert.deepEqual(data.zone.firewallByAsn, [{ key: 'AS64512', count: 2 }]);
    // O 2.º pedido continua intacto — os dois pedidos de firewall são independentes.
    assert.deepEqual(data.zone.firewallByAction, [{ key: 'block', count: 1 }]);
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/cf-stats: erro só no 3.º pedido (firewall detail) não apaga firewallByAction/Source já preenchidos', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const query = JSON.parse(init.body).query;
    if (query.includes('CfFirewallDetail')) {
      return { ok: true, json: async () => ({ errors: [{ message: 'schema drift' }] }) };
    }
    if (query.includes('firewallEventsAdaptive')) {
      return { ok: true, json: async () => firewallFixture([{ action: 'block', source: 'ratelimit' }]) };
    }
    return { ok: true, json: async () => graphqlFixture({ zoneRows: [{ sum: { requests: 10, threats: 5 } }] }) };
  };
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats'), env);
    assert.equal(res.status, 200); // núcleo E firewall-ação/origem intactos — NÃO 502
    const data = await res.json();
    assert.deepEqual(data.zone.firewallByAction, [{ key: 'block', count: 1 }]);
    assert.deepEqual(data.zone.firewallByPath, []);
    assert.deepEqual(data.zone.firewallByUserAgent, []);
    assert.deepEqual(data.zone.firewallByAsn, []);
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/threat-intel: funde snapshots fw:<dia> de vários dias em firewall7d.byCountry', async () => {
  const env = { KV: fakeKV() };
  const now = Date.now();
  const fwDayKey = (ms) => `fw:${new Date(ms).toISOString().slice(0, 10)}`;
  const DAY_MS = 86_400_000;
  // Hoje: NL domina com block=3. Ontem: NL também apareceu, mas com
  // managed_challenge=2 — a soma da semana (block=3, managed_challenge=2)
  // tem de continuar a apontar 'block' como a ação dominante de NL.
  env.KV.store.set(fwDayKey(now), JSON.stringify({
    byAction: { block: 3 }, bySource: { ratelimit: 3 },
    byCountry: { NL: { action: 'block', count: 3 }, DE: { action: 'js_challenge', count: 1 } },
    byAsn: { AS1000: 3 },
  }));
  env.KV.store.set(fwDayKey(now - DAY_MS), JSON.stringify({
    byAction: { managed_challenge: 2 }, bySource: { firewallCustom: 2 },
    byCountry: { NL: { action: 'managed_challenge', count: 2 } },
    byAsn: { AS1000: 2, AS2000: 1 },
  }));
  const res = await runFetch(fakeRequest('/api/threat-intel'), env);
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.deepEqual(data.firewall7d.byAction, [{ key: 'block', count: 3 }, { key: 'managed_challenge', count: 2 }]);
  assert.deepEqual(data.firewall7d.byCountry, [
    { country: 'NL', action: 'block', count: 3 },
    { country: 'DE', action: 'js_challenge', count: 1 },
  ]);
  // AS1000 apareceu nos dois dias (3 + 2 = 5) — a soma da semana, não só o
  // último dia, é o que decide a ordenação.
  assert.deepEqual(data.firewall7d.byAsn, [{ key: 'AS1000', count: 5 }, { key: 'AS2000', count: 1 }]);
});

test('/api/cf-stats: 200 com o resumo quando a GraphQL API responde', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const orig = globalThis.fetch;
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url: String(url), body: JSON.parse(init.body), auth: init.headers.authorization };
    return {
      ok: true,
      json: async () => graphqlFixture({
        zoneRows: [{ sum: { requests: 10, cachedRequests: 5, bytes: 1000, threats: 0 } }],
        workerRows: [{ sum: { requests: 4, errors: 0 } }],
      }),
    };
  };
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats'), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.zone.requests, 10);
    assert.equal(data.worker.requests, 4);
    assert.equal(captured.auth, 'Bearer tok');
    assert.equal(captured.body.variables.zoneTag, 'zone123');
    assert.equal(captured.body.variables.accountTag, 'acc456');
    assert.equal(captured.body.variables.scriptName, 'personal-site-worker');
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/cf-stats: sem CF_API_TOKEN/IDs configurados → 502 (painel mostra o fallback)', async () => {
  const env = { KV: fakeKV() };
  const res = await runFetch(fakeRequest('/api/cf-stats'), env);
  assert.equal(res.status, 502);
  assert.deepEqual(await res.json(), { error: 'upstream_error' });
});

test('/api/cf-stats?refresh=1: ignora a cache existente e escreve uma entrada nova', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  // cache antiga, ainda válida, sem o campo topCountries (shape pré-refresh)
  env.KV.store.set('cache:cfstats', JSON.stringify({
    data: { zone: { requests: 1 }, worker: {}, fetchedAt: 1 },
    exp: Date.now() + 3600_000,
  }));
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    json: async () => graphqlFixture({ zoneRows: [{ sum: { requests: 99, threats: 5 } }] }),
  });
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats?refresh=1', { ip: '203.0.113.10' }), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.zone.requests, 99); // veio do fetch novo, não da cache antiga
    const stored = JSON.parse(env.KV.store.get('cache:cfstats'));
    assert.equal(stored.data.zone.requests, 99); // a cache ficou atualizada
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/cf-stats: 200 devolve blockedByStatus a partir do responseStatusMap', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    json: async () => graphqlFixture({
      zoneRows: [{ sum: { requests: 10, threats: 676, responseStatusMap: [
        { edgeResponseStatus: 200, requests: 1443 },
        { edgeResponseStatus: 403, requests: 1374 },
      ] } }],
    }),
  });
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats'), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.deepEqual(data.zone.blockedByStatus, [{ key: '403', count: 1374 }]); // 200 fica de fora
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/cf-stats?refresh=1: rate limit de 3/10min, mesmo padrão do /api/scan', async () => {
  const kv = fakeKV();
  let puts = 0;
  const origPut = kv.put.bind(kv);
  kv.put = async (...args) => { puts += 1; return origPut(...args); };
  const env = {
    KV: kv,
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const ip = '203.0.113.11';
  const id = await clientHash(ip, dailySalt(undefined));
  kv.store.set(`rl:cfstats:${id}`, JSON.stringify({ count: 3, windowStart: Date.now() }));

  const res = await runFetch(fakeRequest('/api/cf-stats?refresh=1', { ip }), env);
  assert.equal(res.status, 429);
  assert.ok(res.headers.get('retry-after'));
  assert.equal(puts, 0, 'um 429 não pode custar uma escrita KV');
});

// ---------- cap partilhado dos refresh manuais (scan + cf-stats) ----------
// Achado da revisão de segurança 2026-07 (ronda 4, N2): o rate limit por
// cliente (3/10min) destas duas rotas ainda permite até 432 escritas/dia por
// rota e por IP — sem cap global, a mesma classe de risco da lacuna #1
// (rate limiter), só que aplicada tarde de mais a estes dois caminhos.

test('/api/scan?refresh=1: cap partilhado no teto degrada para a cache existente, sem novo self-scan', async () => {
  const env = { KV: fakeKV() };
  const now = Date.now();
  const capKey = `refreshcap:d:${new Date(now).toISOString().slice(0, 10)}`;
  env.KV.store.set(capKey, JSON.stringify({ count: 20, windowStart: now })); // cap já no teto (max=20)
  env.KV.store.set('cache:scan', JSON.stringify({ data: { grade: 'A', scannedAt: 1 }, exp: now + 3600_000 }));

  const orig = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = async () => { fetched = true; return { headers: { get: () => null } }; };
  try {
    const res = await runFetch(fakeRequest('/api/scan?refresh=1', { ip: '203.0.113.201' }), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.grade, 'A'); // veio da cache existente, não de um scan novo
    assert.equal(fetched, false, 'com o cap partilhado no teto, não deve repetir o self-scan');
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/cf-stats?refresh=1: cap partilhado no teto degrada para a cache existente, sem novo pedido à GraphQL API', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const now = Date.now();
  const capKey = `refreshcap:d:${new Date(now).toISOString().slice(0, 10)}`;
  env.KV.store.set(capKey, JSON.stringify({ count: 20, windowStart: now }));
  env.KV.store.set('cache:cfstats', JSON.stringify({
    data: { zone: { requests: 7 }, worker: {}, fetchedAt: 1 },
    exp: now + 3600_000,
  }));

  const orig = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = async () => { fetched = true; return { ok: true, json: async () => graphqlFixture({}) }; };
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats?refresh=1', { ip: '203.0.113.204' }), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.zone.requests, 7); // veio da cache existente
    assert.equal(fetched, false, 'com o cap partilhado no teto, não deve repetir o pedido à GraphQL API');
  } finally {
    globalThis.fetch = orig;
  }
});

test('cap dos refresh manuais: partilhado entre /api/scan e /api/cf-stats — consumir num afeta o outro', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const orig = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes('graphql')) return { ok: true, json: async () => graphqlFixture({}) };
    return { headers: { get: () => null } }; // self-scan
  };
  try {
    const r1 = await runFetch(fakeRequest('/api/scan?refresh=1', { ip: '203.0.113.202' }), env);
    assert.equal(r1.status, 200);
    const capKey = [...env.KV.store.keys()].find((k) => k.startsWith('refreshcap:'));
    assert.ok(capKey, 'devia ter criado o contador partilhado do cap de refresh');
    assert.equal(JSON.parse(env.KV.store.get(capKey)).count, 1);

    const r2 = await runFetch(fakeRequest('/api/cf-stats?refresh=1', { ip: '203.0.113.203' }), env);
    assert.equal(r2.status, 200);
    assert.equal(
      JSON.parse(env.KV.store.get(capKey)).count,
      2,
      'o mesmo contador de refresh acumula entre as duas rotas',
    );
  } finally {
    globalThis.fetch = orig;
  }
});

// ---------- Espelho (/api/mirror) ----------

test('serverView: sanitiza, valida país/ASN e NUNCA inclui o IP', () => {
  const headers = new Map([
    ['user-agent', 'Mozilla/5.0 (X11; Linux) Chrome/126'],
    ['accept-language', 'pt-PT,pt;q=0.9,en;q=0.8'],
    ['referer', 'https://danielmala.co/ferramentas/'],
    ['cf-connecting-ip', '203.0.113.9'],
  ]);
  const get = (k) => headers.get(String(k).toLowerCase()) ?? null;
  const cf = {
    tlsVersion: 'TLSv1.3', tlsCipher: 'AEAD-AES128-GCM-SHA256', httpProtocol: 'HTTP/3',
    country: 'PT', asn: 3243, asOrganization: 'MEO', colo: 'LIS',
  };
  const v = serverView(get, cf);
  assert.equal(v.tlsVersion, 'TLSv1.3');
  assert.equal(v.httpProtocol, 'HTTP/3');
  assert.equal(v.country, 'PT');
  assert.equal(v.asn, 3243);
  assert.equal(v.asOrganization, 'MEO');
  assert.equal(v.refererPresent, true);
  assert.equal(v.ipWithheld, true);
  // Garantia dura: o IP não pode aparecer em lado nenhum do objeto.
  assert.ok(!JSON.stringify(v).includes('203.0.113.9'));
});

test('serverView: país forjado vira XX; ASN inválido vira null; campos vazios null', () => {
  const v = serverView(() => null, { country: 'ZZZ', asn: -1 });
  assert.equal(v.country, 'XX');
  assert.equal(v.asn, null);
  assert.equal(v.userAgent, null);
  assert.equal(v.refererPresent, false);
});

test('serverView: dnt e sec-gpc reconhecidos', () => {
  assert.equal(serverView((k) => (k === 'dnt' ? '1' : null)).dnt, 'dnt');
  assert.equal(serverView((k) => (k === 'sec-gpc' ? '1' : null)).dnt, 'gpc');
  assert.equal(serverView(() => null).dnt, 'unset');
});

test('/api/mirror: 200 sem IP no corpo, no-store, e rate limit ao fim de 30/min', async () => {
  const env = { KV: fakeKV(), RATE_SALT: 's' };
  const mkReq = () => ({
    url: 'https://danielmala.co/api/mirror',
    method: 'GET',
    headers: { get: (k) => (String(k).toLowerCase() === 'cf-connecting-ip' ? '198.51.100.7' : String(k).toLowerCase() === 'user-agent' ? 'UA/1.0' : null) },
    cf: { tlsVersion: 'TLSv1.3', country: 'PT', asn: 3243 },
  });
  const res = await runFetch(mkReq(), env);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const body = await res.json();
  assert.equal(body.tlsVersion, 'TLSv1.3');
  assert.equal(body.ipWithheld, true);
  assert.ok(!JSON.stringify(body).includes('198.51.100.7'));

  // Esgota o balde (já gastámos 1 de 30).
  let last;
  for (let i = 0; i < 40; i++) last = await runFetch(mkReq(), env);
  assert.equal(last.status, 429);
});

// ---------- Threat Intelligence (aggregate.js) ----------

test('addEvent acumula ASN e técnica a par de país/path', () => {
  const b = emptyBucket();
  addEvent(b, { country: 'CN', path: '/.env', asn: 4837, technique: 'T1190' });
  addEvent(b, { country: 'CN', path: '/.env', asn: 4837, technique: 'T1190' });
  addEvent(b, { country: 'RU', path: '/admin', asn: 12345, technique: 'T1078' });
  assert.equal(b.total, 3);
  assert.deepEqual(b.byAsn, { AS4837: 2, AS12345: 1 });
  assert.deepEqual(b.byTech, { T1190: 2, T1078: 1 });
  // asn/técnica nulos não criam chave nova
  addEvent(b, { country: 'US', path: '/x', asn: null, technique: null });
  assert.equal(Object.keys(b.byAsn).length, 2);
  assert.equal(Object.keys(b.byTech).length, 2);
});

test('mergeBuckets funde byAsn/byTech e tolera buckets antigos sem esses campos', () => {
  const legacy = { total: 1, byCountry: { PT: 1 }, byPath: { '/a': 1 } }; // sem byAsn/byTech
  const modern = emptyBucket();
  addEvent(modern, { country: 'PT', path: '/a', asn: 1000, technique: 'T1190' });
  const merged = mergeBuckets([legacy, modern]);
  assert.equal(merged.total, 2);
  assert.deepEqual(merged.byAsn, { AS1000: 1 });
  assert.deepEqual(merged.byTech, { T1190: 1 });
});

test('threatIntel: heatmap, hora-do-dia, tops e eventos', () => {
  // dois buckets horários em horas UTC conhecidas
  const h1 = emptyBucket(); h1.total = 5;
  const h2 = emptyBucket(); h2.total = 3;
  const ms1 = Date.UTC(2026, 6, 20, 14, 0, 0); // 2026-07-20 14:00 UTC
  const ms2 = Date.UTC(2026, 6, 20, 14, 30, 0); // mesma hora/dia
  const ms3 = Date.UTC(2026, 6, 21, 9, 0, 0); // 2026-07-21 09:00 UTC
  const h3 = emptyBucket(); h3.total = 2;

  const day = emptyBucket();
  addEvent(day, { country: 'CN', path: '/.env', asn: 4837, technique: 'T1190' });
  addEvent(day, { country: 'CN', path: '/wp-login.php', asn: 4837, technique: 'T1110' });

  const ti = threatIntel({
    hourlySeries: [
      { ms: ms1, bucket: h1 },
      { ms: ms2, bucket: h2 },
      { ms: ms3, bucket: h3 },
    ],
    days: [day],
    recent: [{ ts: ms3, country: 'CN', asn: 4837, path: '/.env', technique: 'T1190' }],
  });

  // hora-do-dia: 14h = 5+3 = 8, 9h = 2
  assert.equal(ti.byHourOfDay[14], 8);
  assert.equal(ti.byHourOfDay[9], 2);
  assert.deepEqual(ti.peakHour, { hour: 14, count: 8 });
  // heatmap: dois dias distintos
  assert.equal(ti.heatmap.length, 2);
  const d20 = ti.heatmap.find((r) => r.date === '2026-07-20');
  assert.equal(d20.hours[14], 8);
  // tops do dia
  assert.deepEqual(ti.topCountries, [{ key: 'CN', count: 2 }]);
  assert.deepEqual(ti.topAsns, [{ key: 'AS4837', count: 2 }]);
  assert.equal(ti.totals.techniques7d, 2);
  assert.equal(ti.events.length, 1);
});

test('threatIntel: entrada vazia não rebenta', () => {
  const ti = threatIntel({});
  assert.equal(ti.totals.events7d, 0);
  assert.equal(ti.peakHour, null);
  assert.deepEqual(ti.heatmap, []);
  assert.deepEqual(ti.topAsns, []);
});

// ---------- Core Web Vitals (vitals.js) ----------

test('normalizeVitals: aceita válidos, rejeita lixo', () => {
  assert.deepEqual(normalizeVitals({ lcp: 1800, cls: 0.05, inp: 120, ttfb: 300 }), { lcp: 1800, cls: 0.05, inp: 120, ttfb: 300 });
  // campos fora de intervalo caem; string numérica é aceite
  assert.deepEqual(normalizeVitals({ lcp: '2000', cls: -1, inp: 999999999 }), { lcp: 2000 });
  assert.equal(normalizeVitals({ foo: 1 }), null);
  assert.equal(normalizeVitals(null), null);
});

test('vitalsStats: p75 e classificação a partir do histograma', () => {
  const b = emptyVitalsBucket();
  // 4 amostras de LCP: 1000,1000,1000,3000 → p75 (cum≥3) cai no balde 1000 = "good"
  addVitals(b, { lcp: 1000 });
  addVitals(b, { lcp: 1000 });
  addVitals(b, { lcp: 1000 });
  addVitals(b, { lcp: 3000 });
  const stats = vitalsStats([b]);
  assert.equal(stats.samples, 4);
  assert.equal(stats.metrics.lcp.p75, 1000);
  assert.equal(stats.metrics.lcp.rating, 'good');
  // métrica sem amostras → null
  assert.equal(stats.metrics.cls, null);
});

test('vitalsStats: LCP mau classifica poor; merge soma histogramas', () => {
  const b1 = emptyVitalsBucket();
  for (let i = 0; i < 3; i++) addVitals(b1, { lcp: 6000 });
  const b2 = emptyVitalsBucket();
  addVitals(b2, { lcp: 6000 });
  const merged = mergeVitalsBuckets([b1, b2]);
  assert.equal(merged.count, 4);
  const stats = vitalsStats([b1, b2]);
  assert.equal(stats.metrics.lcp.rating, 'poor');
  assert.equal(stats.metrics.lcp.samples, 4);
});
