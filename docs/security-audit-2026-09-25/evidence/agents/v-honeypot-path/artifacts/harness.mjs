import worker from '/home/user/personal-site/dynamic/worker/src/index.js';
const store = new Map(); const puts = [];
const KV = {
  async get(k, t) { const v = store.get(k); if (v == null) return null; return t === 'json' ? JSON.parse(v) : v; },
  async put(k, v, o) { store.set(k, v); puts.push([k, v.length, o?.expirationTtl ?? null]); },
  async delete(k) { store.delete(k); },
  async list() { return { keys: [...store.keys()].map((name) => ({ name })), list_complete: true }; },
};
const env = { KV, RATE_SALT: 'dummy', DEPLOY_TS: '0' };
const DAY = 86400000; const base = Date.UTC(2026, 8, 20, 1, 0, 0);
const realNow = Date.now; let fake = base; Date.now = () => fake;
const suffix = 'A'.repeat(16000);
let n = 0;
for (let d = 0; d < 4; d++) {
  for (let i = 0; i < 60; i++) {
    fake = base + d * DAY + i * 60000; const waits = [];
    const ctx = { waitUntil: (p) => waits.push(p) };
    const req = new Request(`https://danielmala.co/phpmyadmin/${n++}${suffix}`, { headers: { 'cf-connecting-ip': '203.0.113.7', 'cf-ipcountry': 'PT' } });
    const r = await worker.fetch(req, env, ctx); await Promise.all(waits);
    if (r.status !== 404) throw new Error('status ' + r.status);
  }
}
const recent = store.get('recent');
console.log('requests', n, 'recent bytes', recent.length, 'entries', JSON.parse(recent).length, 'path len', JSON.parse(recent)[0].path.length);
console.log('recent put TTL values', [...new Set(puts.filter((p) => p[0] === 'recent').map((p) => p[2]))]);
for (const [k, v] of store) if (/^\d{4}-|^d:|day/.test(k) || v.length > 100000) console.log('key', k, 'bytes', v.length);
// time one parse+stringify cycle of the stored state (Node, not Workers CPU accounting)
let t = process.hrtime.bigint(); for (let i = 0; i < 5; i++) JSON.stringify(JSON.parse(recent)); console.log('avg recent parse+stringify ms', Number(process.hrtime.bigint() - t) / 5e6);
// time one additional decoy hit end-to-end (reads + cap check; cap exhausted on day 4 => early return path)
fake = base + 4 * DAY + 5000; const waits = []; t = process.hrtime.bigint();
await worker.fetch(new Request(`https://danielmala.co/phpmyadmin/x`, { headers: { 'cf-connecting-ip': '203.0.113.7' } }), env, { waitUntil: (p) => waits.push(p) }); await Promise.all(waits);
console.log('next decoy hit (under cap, full write) ms', Number(process.hrtime.bigint() - t) / 1e6, 'recent bytes now', store.get('recent').length);
fake = base + 4 * DAY + 10000; t = process.hrtime.bigint();
const r2 = await worker.fetch(new Request('https://danielmala.co/api/threat-intel'), env, { waitUntil: (p) => waits.push(p) }); const body = await r2.text(); await Promise.all(waits);
console.log('threat-intel status', r2.status, 'body bytes', body.length, 'ms', Number(process.hrtime.bigint() - t) / 1e6);
