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
  emptyBucket, addEvent, mergeBuckets, honeypotStats, mapData,
} from '../src/lib/aggregate.js';
import { gradeFromHeaders } from '../src/lib/scan.js';
import { nextState, dailySalt, clientHash } from '../src/lib/ratelimit.js';
import { underCap } from '../src/lib/kvcap.js';
import { parseKev, parseNvd, mergeFeeds } from '../src/lib/feeds.js';
import { PATH_TECHNIQUE, techniqueForPath, techniquesForText } from '../src/lib/attack-map.js';
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
  // pré-carrega o contador da janela no teto (max=500)
  env.KV.store.set(`wcap:${hourKey}`, JSON.stringify({ count: 500, windowStart: now }));

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
