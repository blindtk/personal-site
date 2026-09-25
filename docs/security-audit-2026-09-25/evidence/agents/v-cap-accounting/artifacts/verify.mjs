process.on("uncaughtException", (e) => { if (String(e?.stack).includes("lazyllhttp")) return; throw e; });
const worker = (await import('/home/user/personal-site/dynamic/worker/src/index.js')).default;
function fakeKV(latency=0) {
  const store = new Map(); const stats = { puts: 0, by: {} };
  const tick = () => new Promise(r => setTimeout(r, latency));
  return { store, stats,
    async get(k, t) { if (latency) await tick(); const v = store.get(k); if (v == null) return null; return t === 'json' ? JSON.parse(v) : v; },
    async put(k, v) { if (latency) await tick(); stats.puts++; const p = k.split(':')[0]; stats.by[p] = (stats.by[p]||0)+1; store.set(k, v); },
    async delete(k) { store.delete(k); } };
}
function req(path, ip) { const h = new Map([['cf-connecting-ip', ip]]); return { url: 'https://example.test'+path, method:'GET', headers:{ get:(n)=>h.get(n.toLowerCase()) ?? null }, cf:{asn:64500,country:'PT'} }; }
async function run(env, r) { const pend=[]; const res = await worker.fetch(r, env, { waitUntil:(p)=>pend.push(p) }); await Promise.all(pend); return res; }
globalThis.fetch = async () => ({ ok:true, status:200, text: async () => '0000000000000000000000000000000000A:1\r\n' });
const T0 = Date.UTC(2026, 8, 25, 2, 0, 0); let clock = T0; Date.now = () => clock;
// A: sequential single client
{ const env = { KV: fakeKV(), RATE_SALT: 'dummy' }; const st = {}; let n = 0x10000;
  for (let m=0;m<16;m++){ for(let i=0;i<20;i++){ const r = await run(env, req('/api/pwned-range?prefix='+(n++).toString(16).toUpperCase(), '203.0.113.7')); st[r.status]=(st[r.status]||0)+1; } clock += 61000; }
  for (let i=0;i<70;i++) await run(env, req('/.env','203.0.113.7'));
  console.log('A', JSON.stringify({ statuses: st, puts: env.KV.stats.puts, by: env.KV.stats.by, rlcap: JSON.parse([...env.KV.store].find(([k])=>k.startsWith('rlcap:'))[1]).count, wcap: JSON.parse([...env.KV.store].find(([k])=>k.startsWith('wcap:'))[1]).count, minutes: (clock-T0)/60000 })); }
// B: concurrency at cap-1 (wcap 59/60), 50 concurrent decoy hits, latency fake KV
{ clock = T0; const env = { KV: fakeKV(1), RATE_SALT: 'dummy' }; const dk = new Date(clock).toISOString().slice(0,10);
  const capKey = [...(await (async()=>{ await run(env, req('/.env','203.0.113.8')); return env.KV.store.keys(); })())].find(k=>k.startsWith('wcap:'));
  env.KV.store.set(capKey, JSON.stringify({count:59, windowStart: clock})); const before = env.KV.stats.puts;
  await Promise.all(Array.from({length:50},(_, i)=>run(env, req('/.env','203.0.113.'+(10+i)))));
  console.log('B', JSON.stringify({ capKey, putsDuringBurst: env.KV.stats.puts-before, wcapAfter: JSON.parse(env.KV.store.get(capKey)).count })); }
// C: rlcap 299/300, 50 concurrent mirror from distinct IPs
{ clock = T0; const env = { KV: fakeKV(1), RATE_SALT: 'dummy' };
  await run(env, req('/api/mirror','203.0.113.99')); const capKey=[...env.KV.store.keys()].find(k=>k.startsWith('rlcap:'));
  env.KV.store.set(capKey, JSON.stringify({count:299, windowStart: clock})); const before=env.KV.stats.puts; const st={};
  const rs = await Promise.all(Array.from({length:50},(_, i)=>run(env, req('/api/mirror','198.51.100.'+(10+i)))));
  rs.forEach(r=>st[r.status]=(st[r.status]||0)+1);
  console.log('C', JSON.stringify({ statuses: st, putsDuringBurst: env.KV.stats.puts-before, rlcapAfter: JSON.parse(env.KV.store.get(capKey)).count })); }
process.exit(0);
