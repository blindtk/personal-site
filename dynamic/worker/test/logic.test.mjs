// Testes da lógica pura do Worker (node --test, sem rede nem Cloudflare).
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  clampInt, escapeHtml, sanitizeText, normalizeCveId, normalizeTickerItem,
} from '../src/lib/sanitize.js';
import {
  emptyBucket, addEvent, mergeBuckets, honeypotStats, mapData,
} from '../src/lib/aggregate.js';
import { gradeFromHeaders } from '../src/lib/scan.js';
import { nextState, dailySalt } from '../src/lib/ratelimit.js';
import { parseKev, parseNvd, mergeFeeds } from '../src/lib/feeds.js';

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
    normalizeTickerItem({ id: 'CVE-2026-0891', source: 'nvd', severity: 'CRIT 9.8', title: 'Struts <x> RCE' }),
    { id: 'CVE-2026-0891', source: 'nvd', severity: 'CRIT 9.8', title: 'Struts x RCE' },
  );
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
