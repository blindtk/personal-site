// Testes do Radar (lib/radar-feed.js + rota /api/radar + cron), sem rede:
// só fetch, KV e o relógio são simulados. As amostras em fixtures/radar/ são
// recortes de feeds reais (2026-10-29), não feeds escritos à mão.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  parseFeed, parseKev, buildRadar, collectRadar, fetchSource, readCapped, safeHttpsUrl,
  decodeEntities, parseRfc822, parseFeedDate, RADAR_SOURCES,
  MAX_ITEMS, MAX_ITEMS_PER_SOURCE, MAX_TITLE_LEN, FUTURE_SKEW_MS,
} from '../src/lib/radar-feed.js';
import worker from '../src/index.js';

const fixture = (name) => readFileSync(new URL(`./fixtures/radar/${name}`, import.meta.url), 'utf8');
const NOW = Date.parse('2026-10-30T00:00:00Z');
const iso = (items) => items.map((it) => ({ ...it, d: new Date(it.d).toISOString() }));

/** RSS mínimo com os itens dados (título e link crus, já escapados como XML). */
function rss(items) {
  const body = items
    .map(({ title, link, date = 'Thu, 29 Oct 2026 12:00:00 +0000' }) =>
      `<item><title>${title}</title><link>${link}</link><pubDate>${date}</pubDate></item>`)
    .join('');
  return `<?xml version="1.0"?><rss version="2.0"><channel><title>x</title>${body}</channel></rss>`;
}

async function withFetch(impl, fn) {
  const orig = globalThis.fetch;
  globalThis.fetch = impl;
  try {
    return await fn();
  } finally {
    globalThis.fetch = orig;
  }
}

// ---------- formatos reais ----------

test('RSS do CERT-EU: data em "CEST" (que o Date.parse dá NaN) e link com espaços à volta', () => {
  const items = parseFeed(fixture('cert-eu.xml'), NOW);
  assert.equal(items.length, 10);
  assert.deepEqual(iso(items)[0], {
    t: '2026-018: Critical Vulnerabilities in PHP',
    u: 'https://cert.europa.eu/publications/security-advisories/2026-018/',
    d: '2026-10-23T14:36:26.000Z', // 16:36:26 CEST = UTC+2
  });
});

test('RSS do CNCS: vem do mais antigo para o mais recente — o Radar fica com os novos', () => {
  const items = parseFeed(fixture('cncs.xml'), NOW, 2);
  assert.deepEqual(iso(items).map((it) => it.d), ['2026-10-21T00:00:00.000Z', '2026-10-21T00:00:00.000Z']);
  assert.ok(items.every((it) => it.u.startsWith('https://dyn.cncs.gov.pt/pt/alerta-detalhe/')));
  // o alerta de 2016 (primeiro no documento) só entra quando cabe
  assert.equal(new Date(parseFeed(fixture('cncs.xml'), NOW, 50).at(-1).d).getUTCFullYear(), 2016);
});

test('RSS do Dark Reading: título e link em CDATA, com &amp; duplamente codificado', () => {
  const [first] = parseFeed(fixture('darkreading.xml'), NOW);
  assert.equal(first.t, 'Claude Model Builds Exploits Across Major Browsers & OSes');
  assert.equal(first.u, 'https://www.darkreading.com/application-security/claude-model-exploits-major-browsers-oses');
});

test('RSS do BleepingComputer: offset numérico (-0400) convertido para UTC', () => {
  const [first] = iso(parseFeed(fixture('bleepingcomputer.xml'), NOW));
  assert.equal(first.d, '2026-10-29T19:23:41.000Z'); // 15:23:41 -0400
});

test('Atom (Schneier): link rel="alternate" e <published>', () => {
  const items = iso(parseFeed(fixture('schneier-atom.xml'), NOW));
  assert.equal(items.length, 3);
  assert.deepEqual(items[0], {
    t: 'Studying Fraudulent North Korean IT Workers',
    u: 'https://www.schneier.com/blog/archives/2026/10/studying-fraudulent-north-korean-it-workers.html',
    d: '2026-10-28T11:05:00.000Z',
  });
});

test('Atom: <link rel="self"> antes do alternate não é o link do item', () => {
  const xml = '<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>A</title>'
    + '<link rel="self" href="https://example.org/self"/><link rel="alternate" href="https://example.org/post"/>'
    + '<updated>2026-10-29T10:00:00Z</updated></entry></feed>';
  assert.equal(parseFeed(xml, NOW)[0].u, 'https://example.org/post');
});

test('KEV da CISA: cada CVE vira item com link do NVD e a data de entrada no catálogo', () => {
  const items = iso(parseKev(fixture('cisa-kev.json'), NOW));
  assert.deepEqual(items.map((it) => it.u), [
    'https://nvd.nist.gov/vuln/detail/CVE-2026-97229',
    'https://nvd.nist.gov/vuln/detail/CVE-2026-76418',
    'https://nvd.nist.gov/vuln/detail/CVE-2026-41709',
  ]);
  assert.equal(items[2].t, 'CVE-2026-41709: Broadcom VMWare ESX Insufficient Logging Vulnerability');
  assert.equal(items[2].d, '2026-10-28T00:00:00.000Z');
});

test('KEV cortado pelo teto de bytes: ficam as entradas completas, a cortada cai', () => {
  const text = fixture('cisa-kev.json');
  const cut = text.slice(0, text.indexOf('CVE-2026-41709') + 20);
  assert.deepEqual(parseKev(cut, NOW).map((it) => it.u.slice(-14)), ['CVE-2026-97229', 'CVE-2026-76418']);
});

test('KEV: cveID fora do formato não chega a construir um link', () => {
  const text = '{"vulnerabilities":[{"cveID":"CVE-2026-1234/../../x","vulnerabilityName":"a","dateAdded":"2026-10-01"},'
    + '{"cveID":"CVE-2026-1234","vulnerabilityName":"b","dateAdded":"2026-10-01"}]}';
  assert.deepEqual(parseKev(text, NOW).map((it) => it.u), ['https://nvd.nist.gov/vuln/detail/CVE-2026-1234']);
});

// ---------- vetores maliciosos, um por modo de falha ----------

test('XSS no título: tags (escapadas ou em CDATA) saem, sobra só texto', () => {
  const items = parseFeed(rss([
    { title: '&lt;img src=x onerror=alert(1)&gt;Patch now', link: 'https://a.example/1' },
    { title: '<![CDATA[<svg onload=alert(1)>Zero-day <b>in</b> X]]>', link: 'https://a.example/2' },
    { title: '&amp;lt;script&amp;gt;', link: 'https://a.example/3' }, // duplo escape: vira texto, sem <>
    { title: 'RLO‮txt.exe\u0007', link: 'https://a.example/4' },
  ]), NOW);
  const byUrl = Object.fromEntries(items.map((it) => [it.u, it.t]));
  assert.equal(byUrl['https://a.example/1'], 'Patch now');
  assert.equal(byUrl['https://a.example/2'], 'Zero-day in X');
  assert.equal(byUrl['https://a.example/3'], 'script');
  assert.equal(byUrl['https://a.example/4'], 'RLOtxt.exe');
});

test('título: truncado em MAX_TITLE_LEN; só markup (vazio depois de limpo) → item cai', () => {
  const items = parseFeed(rss([
    { title: 'a'.repeat(MAX_TITLE_LEN), link: 'https://a.example/exact' },
    { title: 'a'.repeat(MAX_TITLE_LEN + 1), link: 'https://a.example/over' },
    { title: '&lt;b&gt;&lt;/b&gt;', link: 'https://a.example/empty' },
  ]), NOW);
  const byUrl = Object.fromEntries(items.map((it) => [it.u, it.t]));
  assert.equal(byUrl['https://a.example/exact'], 'a'.repeat(MAX_TITLE_LEN));
  assert.equal(byUrl['https://a.example/over'], `${'a'.repeat(MAX_TITLE_LEN - 1)}…`);
  assert.ok(!('https://a.example/empty' in byUrl));
});

test('links: só https: — javascript:, data:, http:, relativos e com credenciais caem', () => {
  const bad = [
    'javascript:alert(1)',
    ' JaVaScRiPt:alert(1)',
    'java&#x73;cript:alert(1)', // a entidade é descodificada antes de validar
    '<![CDATA[javascript:alert(document.domain)]]>',
    'data:text/html,&lt;script&gt;alert(1)&lt;/script&gt;',
    'http://insecure.example/post',
    '/relative/post',
    'https://user:pass@a.example/post',
  ];
  const items = parseFeed(rss([...bad.map((link) => ({ title: 'x', link })), { title: 'ok', link: 'https://a.example/ok' }]), NOW);
  assert.deepEqual(items.map((it) => it.u), ['https://a.example/ok']);
});

test('safeHttpsUrl: comprimento no limite exato (2048) passa, 2049 não', () => {
  const base = 'https://a.example/';
  assert.equal(safeHttpsUrl(base + 'x'.repeat(2048 - base.length)), base + 'x'.repeat(2048 - base.length));
  assert.equal(safeHttpsUrl(base + 'x'.repeat(2049 - base.length)), null);
});

test('XML truncado: os itens completos ficam, o cortado cai, nada lança', () => {
  const full = rss([
    { title: 'one', link: 'https://a.example/1' },
    { title: 'two', link: 'https://a.example/2' },
    { title: '<![CDATA[three]]>', link: 'https://a.example/3' },
  ]);
  const cutInItem = full.slice(0, full.indexOf('https://a.example/3'));
  assert.deepEqual(parseFeed(cutInItem, NOW).map((it) => it.t).sort(), ['one', 'two']);
  const cutInCdata = full.slice(0, full.indexOf('three') + 2);
  assert.deepEqual(parseFeed(cutInCdata, NOW).map((it) => it.t).sort(), ['one', 'two']);
  assert.deepEqual(parseFeed('<rss><channel><item><title>x', NOW), []);
  assert.deepEqual(parseFeed('', NOW), []);
  assert.deepEqual(parseFeed(null, NOW), []);
});

test('um <item> dentro de CDATA (descrição) não é um item', () => {
  const xml = '<rss><channel><item><title>real</title><link>https://a.example/r</link>'
    + '<description><![CDATA[<item><title>fake</title><link>https://evil.example/</link></item></item>]]></description>'
    + '<pubDate>Thu, 29 Oct 2026 12:00:00 GMT</pubDate></item></channel></rss>';
  assert.deepEqual(parseFeed(xml, NOW).map((it) => it.u), ['https://a.example/r']);
});

test('feed enorme: a leitura para no teto de bytes e cancela o resto do corpo', async () => {
  const chunk = new TextEncoder().encode('x'.repeat(64 * 1024));
  let pulled = 0;
  let cancelled = false;
  const body = new ReadableStream({
    pull(controller) {
      pulled++;
      controller.enqueue(chunk); // corpo infinito
    },
    cancel() { cancelled = true; },
  });
  const text = await readCapped(new Response(body), 1024 * 1024);
  assert.equal(text.length, 1024 * 1024);
  assert.ok(cancelled);
  assert.ok(pulled <= 1024 * 1024 / chunk.length + 2, `pulled ${pulled} chunks`);
});

test('feed enorme: milhares de itens válidos → só os `limit` mais recentes', () => {
  const items = Array.from({ length: 5000 }, (_, i) => ({
    title: `n${i}`,
    link: `https://a.example/${i}`,
    date: new Date(Date.parse('2026-01-01T00:00:00Z') + i * 60_000).toUTCString(),
  }));
  const out = parseFeed(rss(items), NOW);
  assert.equal(out.length, MAX_ITEMS_PER_SOURCE);
  // MAX_PARSE_ITEMS (2000) lidos: o mais recente visto é o n1999
  assert.equal(out[0].t, 'n1999');
});

test('data no futuro: até FUTURE_SKEW_MS aceita, 1 s depois o item cai', () => {
  const at = (ms) => new Date(ms).toUTCString();
  const items = parseFeed(rss([
    { title: 'edge', link: 'https://a.example/edge', date: at(NOW + FUTURE_SKEW_MS) },
    { title: 'future', link: 'https://a.example/future', date: at(NOW + FUTURE_SKEW_MS + 1000) },
    { title: 'far', link: 'https://a.example/far', date: 'Fri, 01 Jan 2100 00:00:00 GMT' },
  ]), NOW);
  assert.deepEqual(items.map((it) => it.t), ['edge']);
  assert.equal(parseFeedDate('2100-01-01T00:00:00Z', NOW), null);
});

test('datas inválidas caem: lixo, 31 de fevereiro, zona desconhecida, hora 24', () => {
  for (const s of ['yesterday', '', '31 Feb 2026 10:00:00 GMT', 'Thu, 29 Oct 2026 10:00:00 XYZ', 'Thu, 29 Oct 2026 24:00:00 GMT', '2026-02-30T00:00:00Z']) {
    assert.equal(parseFeedDate(s, NOW), null, s);
  }
  assert.equal(parseRfc822('29 Oct 2026 10:00 GMT'), Date.parse('2026-10-29T10:00:00Z')); // sem dia da semana nem segundos
  assert.equal(parseFeed(rss([{ title: 'x', link: 'https://a.example/', date: 'soon' }]), NOW).length, 0);
});

test('decodeEntities: acentos do CNCS, numéricas, e code points inválidos → U+FFFD', () => {
  assert.equal(decodeEntities('Eleva&ccedil;&atilde;o &#233;&#xE9; &bogus;'), 'Elevação éé &bogus;');
  assert.equal(decodeEntities('&#0;&#xD800;&#x110000;'), '���');
});

// ---------- agregação ----------

test('buildRadar: ordena, deduplica por URL entre fontes e corta por fonte e no total', () => {
  const sources = Array.from({ length: 10 }, (_, i) => ({ id: `s${i}`, name: `S${i}`, type: i < 5 ? 'alert' : 'news', lang: 'en' }));
  const results = sources.map((src, i) => Array.from({ length: 15 }, (_, j) => ({
    t: `${src.id}-${j}`, u: `https://a.example/${src.id}/${j}`, d: NOW - (j * 10 + i) * 60_000,
  })));
  results[1][0] = { t: 'dup', u: 'https://a.example/s0/0', d: NOW - 1 }; // mesmo URL do s0, mais antigo
  results[2] = null;
  const doc = buildRadar(sources, results, NOW);
  assert.equal(doc.generated, new Date(NOW).toISOString());
  assert.equal(doc.items.length, MAX_ITEMS);
  assert.ok(doc.items.every((it, i, a) => i === 0 || a[i - 1].d >= it.d));
  assert.equal(doc.items.filter((it) => it.u === 'https://a.example/s0/0').length, 1);
  assert.equal(doc.items.find((it) => it.u === 'https://a.example/s0/0').s, 's0'); // ficou a mais recente
  for (const src of sources) assert.ok(doc.items.filter((it) => it.s === src.id).length <= MAX_ITEMS_PER_SOURCE);
  assert.deepEqual(doc.sources[2], { id: 's2', name: 'S2', type: 'alert', lang: 'en', ok: false });
  assert.equal(doc.sources[0].ok, true);
});

test('buildRadar: fonte em baixo mantém os itens anteriores (revalidados) com ok:false', () => {
  const sources = [{ id: 'a', name: 'A', type: 'alert', lang: 'pt' }, { id: 'b', name: 'B', type: 'news', lang: 'en' }];
  const prev = {
    items: [
      { t: 'old a', u: 'https://a.example/old', s: 'a', d: '2026-10-28T00:00:00.000Z' },
      { t: 'tampered', u: 'javascript:alert(1)', s: 'a', d: '2026-10-28T00:00:00.000Z' },
      { t: 'old b', u: 'https://b.example/old', s: 'b', d: '2026-10-28T00:00:00.000Z' },
    ],
  };
  const doc = buildRadar(sources, [null, [{ t: 'new b', u: 'https://b.example/new', d: NOW - 1000 }]], NOW, prev);
  assert.deepEqual(doc.items.map((it) => it.t), ['new b', 'old a']);
  assert.deepEqual(doc.sources.map((s) => s.ok), [false, true]);
});

test('collectRadar: uma fonte com erro, outra com 500 e outra pendurada não derrubam as restantes', async () => {
  const sources = [
    { id: 'ok', name: 'OK', type: 'news', lang: 'en', format: 'xml', url: 'https://ok.example/feed' },
    { id: 'boom', name: 'Boom', type: 'news', lang: 'en', format: 'xml', url: 'https://boom.example/feed' },
    { id: 'err', name: 'Err', type: 'alert', lang: 'en', format: 'xml', url: 'https://err.example/feed' },
    { id: 'hang', name: 'Hang', type: 'alert', lang: 'en', format: 'xml', url: 'https://hang.example/feed' },
  ];
  const doc = await withFetch(async (url, init) => {
    const host = new URL(url).hostname;
    if (host === 'ok.example') return new Response(rss([{ title: 'fine', link: 'https://ok.example/1' }]));
    if (host === 'boom.example') throw new TypeError('network down');
    if (host === 'err.example') return new Response('nope', { status: 500 });
    // pendurado até o timeout da fonte abortar o pedido (o timer do
    // AbortSignal.timeout não segura o event loop do Node — este segura)
    return new Promise((_, reject) => {
      const keepAlive = setTimeout(() => {}, 5000);
      init.signal.addEventListener('abort', () => { clearTimeout(keepAlive); reject(init.signal.reason); });
    });
  }, () => collectRadar(sources, { now: NOW, timeoutMs: 20 }));
  assert.deepEqual(doc.sources.map((s) => [s.id, s.ok]), [['ok', true], ['boom', false], ['err', false], ['hang', false]]);
  assert.deepEqual(doc.items.map((it) => [it.s, it.t]), [['ok', 'fine']]);
});

test('fetchSource: não segue redirects e manda um UA honesto', async () => {
  let init;
  await withFetch(async (_url, i) => { init = i; return new Response(rss([])); },
    () => fetchSource(RADAR_SOURCES[1], { now: NOW }));
  assert.equal(init.redirect, 'error');
  assert.match(init.headers['user-agent'], /^personal-site-worker \(radar/);
});

test('RADAR_SOURCES: só https, ids únicos, tipos alert/news', () => {
  assert.equal(new Set(RADAR_SOURCES.map((s) => s.id)).size, RADAR_SOURCES.length);
  for (const s of RADAR_SOURCES) {
    assert.equal(safeHttpsUrl(s.url), s.url);
    assert.ok(s.type === 'alert' || s.type === 'news');
  }
});

// ---------- rota e cron ----------

function fakeKV() {
  const store = new Map();
  const opts = new Map();
  return {
    store,
    opts,
    async get(key, type) {
      const v = store.get(key);
      if (v === undefined) return null;
      return type === 'json' ? JSON.parse(v) : v;
    },
    async put(key, value, o) { store.set(key, value); opts.set(key, o); },
    async delete(key) { store.delete(key); },
  };
}

function fakeRequest(path) {
  return { url: `https://danielmala.co${path}`, method: 'GET', headers: { get: () => null }, cf: {} };
}

async function run(fn) {
  const tasks = [];
  const ctx = { waitUntil: (p) => tasks.push(p) };
  const out = await fn(ctx);
  await Promise.allSettled(tasks);
  return out;
}

test('/api/radar: serve o documento do KV sem nunca ir buscar feeds', async () => {
  const env = { KV: fakeKV() };
  const doc = { generated: '2026-10-29T23:30:00.000Z', sources: [], items: [{ t: 'x', u: 'https://a.example/', s: 'cncs', d: '2026-10-29T00:00:00.000Z' }] };
  env.KV.store.set('radar:feed', JSON.stringify(doc));
  let fetched = 0;
  const res = await withFetch(async () => { fetched++; throw new Error('no network'); },
    () => run((ctx) => worker.fetch(fakeRequest('/api/radar'), env, ctx)));
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), doc);
  assert.equal(res.headers.get('cache-control'), 'public, max-age=300');
  assert.equal(fetched, 0);
});

test('/api/radar: sem documento no KV (cron ainda não correu) → forma vazia, não 502', async () => {
  const res = await run((ctx) => worker.fetch(fakeRequest('/api/radar'), { KV: fakeKV() }, ctx));
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { generated: null, sources: [], items: [] });
});

test('cron: recolhe as fontes e grava radar:feed normalizado, com expiração', async () => {
  const env = { KV: fakeKV() };
  const byHost = {
    'cert.europa.eu': fixture('cert-eu.xml'),
    'www.darkreading.com': fixture('darkreading.xml'),
    'www.cisa.gov': fixture('cisa-kev.json'),
  };
  await withFetch(async (url) => {
    const body = byHost[new URL(url).hostname];
    return body ? new Response(body) : new Response('gone', { status: 404 });
  }, () => run((ctx) => worker.scheduled({}, env, ctx)));
  const doc = JSON.parse(env.KV.store.get('radar:feed'));
  assert.equal(env.KV.opts.get('radar:feed').expirationTtl, 7 * 86400);
  assert.deepEqual(Object.keys(doc).sort(), ['generated', 'items', 'sources']);
  assert.deepEqual(doc.sources.filter((s) => s.ok).map((s) => s.id).sort(), ['cert-eu', 'cisa-kev', 'darkreading']);
  assert.equal(doc.sources.length, RADAR_SOURCES.length);
  assert.ok(doc.items.length > 0 && doc.items.every((it) => it.u.startsWith('https://') && typeof it.t === 'string'));
  assert.ok(doc.items.every((it, i, a) => i === 0 || a[i - 1].d >= it.d));
});
