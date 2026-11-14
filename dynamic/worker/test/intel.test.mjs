// Testes do resumo do honeypot externo (lib/intel.js + rota /api/intel +
// cron), sem rede: só fetch, KV e o relógio são simulados. A amostra em
// fixtures/intel/ é o history.json real publicado pelo sensor em 2026-11-14
// (só agregados por dia; licença CC0).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  summarizeHistory, fetchIntelSummary, INTEL_SOURCES, INTEL_MAX_AGE_MS, INTEL_MAX_TECHNIQUES,
} from '../src/lib/intel.js';
import worker from '../src/index.js';

const HISTORY = readFileSync(new URL('./fixtures/intel/history-2026-11-14.json', import.meta.url), 'utf8');
const NOW = Date.parse('2026-11-14T13:00:00Z');
const DAY = 86_400_000;
const day = (d, extra = {}) => ({ day: d, addresses: 100, ...extra });

async function withFetch(impl, fn) {
  const orig = globalThis.fetch;
  globalThis.fetch = impl;
  try {
    return await fn();
  } finally {
    globalThis.fetch = orig;
  }
}
const jsonRes = (body, status = 200) => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status });

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
const fakeRequest = (path) => ({ url: `https://danielmala.co${path}`, method: 'GET', headers: { get: () => null }, cf: {} });
async function run(fn) {
  const tasks = [];
  const out = await fn({ waitUntil: (p) => tasks.push(p) });
  await Promise.allSettled(tasks);
  return out;
}

// ---------- summarizeHistory ----------

test('history.json real: último dia, sessões dos 7 dias e técnicas por contagem', () => {
  const s = summarizeHistory(JSON.parse(HISTORY), NOW);
  assert.equal(s.ok, true);
  assert.equal(s.day, '2026-11-14');
  assert.equal(s.addresses, 13185);
  assert.equal(s.addressesNotScanners, 9668);
  assert.equal(s.credentialPairs, 3908);
  assert.equal(s.artifacts, 83);
  assert.deepEqual(s.techniques.slice(0, 3), [
    { id: 'T1595.002', count: 8003 },
    { id: 'T1078', count: 1212 },
    { id: 'T1059.004', count: 631 },
  ]);
  assert.equal(s.techniques.length, INTEL_MAX_TECHNIQUES);
  assert.deepEqual(s.campaigns, ['bashlite', 'komari', 'mirai', 'outlaw', 'panchan', 'redtail']);
  // 10 dias no arquivo: só os 7 últimos (08 a 14) contam para a janela
  assert.equal(s.sessionDays, 7);
  assert.equal(s.deltaDays, 6);
});

test('janela de 7 dias: o dia a exatamente 7 dias do último fica de fora', () => {
  const doc = {
    days: [
      day('2026-11-07', { sessions_started: 1000, addresses: 10 }),
      day('2026-11-08', { sessions_started: 5, addresses: 40 }),
      day('2026-11-14', { sessions_started: 7, addresses: 100 }),
    ],
  };
  const s = summarizeHistory(doc, NOW);
  assert.equal(s.sessions7d, 12);
  assert.equal(s.addressesDelta, 60);
  assert.equal(s.deltaDays, 6);
});

test('sessões: linhas antigas sem sessions_started não contam como 0', () => {
  const s = summarizeHistory({ days: [day('2026-11-13'), day('2026-11-14')] }, NOW);
  assert.equal(s.sessions7d, null);
  assert.equal(s.sessionDays, 0);
});

test('um só dia: sem variação inventada', () => {
  const s = summarizeHistory({ days: [day('2026-11-14')] }, NOW);
  assert.equal(s.addressesDelta, null);
});

test('frescura: o último dia vale até 3 dias depois de começar, nem um ms mais', () => {
  const doc = { days: [day('2026-11-14')] };
  const limit = Date.parse('2026-11-14T00:00:00Z') + INTEL_MAX_AGE_MS + DAY;
  assert.equal(summarizeHistory(doc, limit).ok, true);
  assert.deepEqual(summarizeHistory(doc, limit + 1), { ok: false, error: 'stale' });
});

test('um dia no futuro (relógio do sensor adiantado) não é publicado', () => {
  const doc = { days: [day('2026-11-15')] };
  assert.deepEqual(summarizeHistory(doc, NOW), { ok: false, error: 'future_day' });
  // à meia-noite UTC em ponto o dia já começou
  assert.equal(summarizeHistory(doc, Date.parse('2026-11-15T00:00:00Z')).ok, true);
});

test('documento de erro, vazio ou sem contagem de endereços: sem resumo', () => {
  for (const doc of [null, 'x', {}, { days: 'x' }, { days: [] }, { days: [{ day: '14/11/2026', addresses: 1 }] }, { days: [{ day: '2026-02-31', addresses: 1 }] }]) {
    assert.deepEqual(summarizeHistory(doc, NOW), { ok: false, error: 'no_days' }, JSON.stringify(doc));
  }
  for (const addresses of [undefined, -1, 1.5, '13185', null]) {
    assert.deepEqual(summarizeHistory({ days: [{ day: '2026-11-14', addresses }] }, NOW), { ok: false, error: 'bad_addresses' });
  }
});

test('técnicas e campanhas: só ids ATT&CK e slugs passam — um endereço nunca sai', () => {
  const doc = {
    days: [day('2026-11-14', {
      techniques: { T1110: 5, 'T1110.001': 9, 't1110': 3, 'T11': 4, '203.0.113.7': 99, T1059: '7', T1105: 0, T1082: -2 },
      campaigns: ['mirai', 'mirai', '203.0.113.7', 'Mirai', '<script>', 'red-tail', 42, 'a'.repeat(33)],
    })],
  };
  const s = summarizeHistory(doc, NOW);
  assert.deepEqual(s.techniques, [{ id: 'T1110.001', count: 9 }, { id: 'T1110', count: 5 }]);
  assert.deepEqual(s.campaigns, ['mirai', 'red-tail']);
  assert.doesNotMatch(JSON.stringify(s), /203\.0\.113\.7/);
});

test('contagens opcionais inválidas ficam null em vez de 0', () => {
  const s = summarizeHistory({ days: [day('2026-11-14', { artifacts: '83', usernames: -1, addresses_not_scanners: 101 })] }, NOW);
  assert.equal(s.artifacts, null);
  assert.equal(s.usernames, null);
  assert.equal(s.addressesNotScanners, null); // maior que o total: incoerente
});

// ---------- fetchIntelSummary ----------

test('fetch: usa a primeira fonte; com 403 nela cai para a segunda', async () => {
  const seen = [];
  const s = await withFetch(async (url) => {
    seen.push(url);
    return url === INTEL_SOURCES[0] ? jsonRes('blocked', 403) : jsonRes(HISTORY);
  }, () => fetchIntelSummary({ now: NOW }));
  assert.deepEqual(seen, INTEL_SOURCES);
  assert.equal(s.ok, true);
  assert.equal(s.fetched, '2026-11-14T13:00:00.000Z');
});

test('fetch: um redirect não é seguido e conta como falha', async () => {
  let redirectMode;
  const s = await withFetch(async (_url, init) => {
    redirectMode = init.redirect;
    return new Response(null, { status: 302, headers: { location: 'https://example.com/history.json' } });
  }, () => fetchIntelSummary({ now: NOW }));
  assert.equal(redirectMode, 'manual');
  assert.deepEqual(s, { ok: false, error: 'http_302,http_302' });
});

test('fetch: JSON inválido e rede em baixo dão { ok: false }, não lançam', async () => {
  const s = await withFetch(async (url) => {
    if (url === INTEL_SOURCES[0]) return jsonRes('<html>challenge</html>');
    throw new TypeError('network');
  }, () => fetchIntelSummary({ now: NOW }));
  assert.deepEqual(s, { ok: false, error: 'bad_json,fetch_failed' });
});

// ---------- rota e cron ----------

test('/api/intel: serve o resumo do KV sem ir buscar nada; sem resumo dá { ok: false }', async () => {
  const env = { KV: fakeKV() };
  const noFetch = async () => { throw new Error('a rota não pode fazer fetch'); };
  const empty = await withFetch(noFetch, () => run((ctx) => worker.fetch(fakeRequest('/api/intel'), env, ctx)));
  assert.deepEqual(await empty.json(), { ok: false });

  const stored = { ok: true, day: '2026-11-14', addresses: 13185, fetched: '2026-11-14T13:00:00.000Z' };
  env.KV.store.set('intel:summary', JSON.stringify(stored));
  const res = await withFetch(noFetch, () => run((ctx) => worker.fetch(fakeRequest('/api/intel'), env, ctx)));
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), stored);
});

const TICK = { cron: '*/30 * * * *' };
const intelOnly = (calls) => async (url) => {
  if (!INTEL_SOURCES.includes(String(url))) throw new Error('offline');
  calls.push(String(url));
  return jsonRes(HISTORY);
};

test('cron: sem resumo guardado, recolhe e grava com TTL de 3 dias', async () => {
  const env = { KV: fakeKV() };
  const calls = [];
  await withFetch(intelOnly(calls), () => run((ctx) => worker.scheduled(TICK, env, ctx)));
  assert.deepEqual(calls, [INTEL_SOURCES[0]]);
  assert.equal(JSON.parse(env.KV.store.get('intel:summary')).ok, true);
  assert.deepEqual(env.KV.opts.get('intel:summary'), { expirationTtl: 3 * 86400 });
});

test('cron: resumo com menos de 6 h não é pedido de novo; às 6 h em ponto é', async () => {
  for (const [ageMs, expected] of [[6 * 3600_000 - 1000, 0], [6 * 3600_000, 1]]) {
    const env = { KV: fakeKV() };
    const fetched = new Date(Date.now() - ageMs).toISOString();
    env.KV.store.set('intel:summary', JSON.stringify({ ok: true, day: '2026-11-14', addresses: 1, fetched }));
    const calls = [];
    await withFetch(intelOnly(calls), () => run((ctx) => worker.scheduled(TICK, env, ctx)));
    assert.equal(calls.length, expected, `idade ${ageMs} ms`);
  }
});

test('cron: sensor em baixo mantém o último resumo bom', async () => {
  const env = { KV: fakeKV() };
  const prev = JSON.stringify({ ok: true, day: '2026-11-13', addresses: 9, fetched: '2026-11-13T00:00:00.000Z' });
  env.KV.store.set('intel:summary', prev);
  await withFetch(async () => jsonRes('down', 503), () => run((ctx) => worker.scheduled(TICK, env, ctx)));
  assert.equal(env.KV.store.get('intel:summary'), prev);
});
