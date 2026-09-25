# Findings detail

This file covers the confirmed findings rated medium or higher, from `findings.json` at source ref `cb439ed`. The low-severity finding `dynamic/worker/src/index.js:rateLimit:global-write-cap-accounting-and-race` is summarised in `REPORT.md` §3.2, and its full record is in `findings.json`.

## [medium] Unauthenticated GETs to /api/honeypot, /api/map and /api/vitals trigger KV writes with no cap, which can exhaust the account's daily KV write budget

**Fingerprint:** `dynamic/worker/src/index.js:cached:uncapped-kv-write-on-public-get`

The read-cache helper cached() writes the refreshed value to KV each time the logical TTL lapses, and no global daily write cap covers that put. /api/honeypot and /api/map use a 60s TTL and GET /api/vitals uses 120s. None of these three routes is rate limited, and the Worker runs on the zone route danielmala.co/api/*, so the response's cache-control header does not stop the Worker from being invoked. An anonymous client sending about 3 requests per minute (one per route every 61s) forces about 3,500 KV writes per day. The repository sizes every other write cap around a Free-plan account ceiling of about 1,000 writes/day, and this is well above it. The stale-while-revalidate branch has no single-flight lock, so a concurrent burst against a stale entry causes one write per request. Once the account budget is exhausted, KV puts fail for the rest of the UTC day. The routes that await puts (the rate limiter, honeypot and vitals recording) stop persisting and throw into the 502 handler. Each dashboard keeps serving its stale copy until the KV copy expires (TTL+600s), and after that refresh() throws in the foreground and the route returns 502 upstream_error.

### Root cause
cached() (dynamic/worker/src/index.js:303-319) calls env.KV.put on every refresh without consulting any global daily write cap. The public, non-rate-limited GET routes /api/honeypot and /api/map (TTL 60s) and /api/vitals (TTL 120s) therefore let the request rate of anonymous visitors set the KV write rate. Each stale hit schedules its own background refresh with no single-flight guard.

### Intended behaviour (invariant)
KV writes reachable from anonymous requests should be bounded by a global daily budget, or kept out of KV entirely (for example with the Cache API or cron-only refresh). Public reads should not be able to use up the shared write quota that the honeypot, vitals, rate limiter and cron depend on.

### Trace
1. **entrypoint** `dynamic/worker/src/index.js:551` (fetch: GET /api/honeypot (also /api/map :558, GET /api/vitals :616)): An unauthenticated GET with no rate limit calls cached() with a 60s TTL (120s for /api/vitals).
2. **propagation** `dynamic/worker/src/index.js:306` (cached): The cached value is returned only while hit.exp > now. Once the TTL has passed, every request falls through to refresh.
3. **propagation** `dynamic/worker/src/index.js:315` (cached): Each stale hit schedules its own refresh() through ctx.waitUntil. There is no lock or single-flight, so concurrent stale requests each produce a write.
4. **sink** `dynamic/worker/src/index.js:309` (cached.refresh): env.KV.put(key, ...) runs with no underCap or global daily write-cap check.

### Evidence
- `dynamic/worker/src/index.js:303`: cached() has no write cap. By contrast, recordHoneypot (:139), recordVitals (:214), rateLimit (:398) and underRefreshCap (:366) all check underCap before writing.
- `dynamic/worker/src/index.js:49`: A comment documents a Free-plan ceiling of about 1,000 writes/day for the whole account, shared by rate-limit, vitals and cron.
- `dynamic/worker/src/index.js:344`: A comment assumes that public reads without a rate limit (honeypot/map/...) 'continuam servidas da cache' (are still served from cache), but each refresh of that cache is itself an uncapped KV write.
- `dynamic/worker/src/index.js:696`: The router catch block returns 502 upstream_error when a foreground refresh() or an awaited put throws.
- `dynamic/worker/wrangler.toml:28`: The Worker is bound to the zone route danielmala.co/api/*, so every /api request invokes the Worker regardless of the response's cache-control.
- `agents/v-cached-uncapped/artifacts/uncapped-cache-writes.txt:1`: Output of the independent sandboxed reproduction: 4,251 sequential GETs over one simulated day produced 3,543 uncapped cache:* puts, and 20 concurrent stale GETs produced 20 puts.

### Principal and resource
- **Attacker:** An anonymous visitor who repeatedly requests the public dashboard JSON endpoints.
- **Affected resource:** the account-wide Workers KV daily write budget, shared by the honeypot, vitals, rate limiter and cron.

### Conditions
- **authentication_level:** None: an anonymous internet client.
- **system_configuration:** The account is on the Workers KV Free plan with its ~1,000 writes/day account ceiling, as the repository states at index.js:49. On a paid plan the impact becomes billed write cost rather than an outage.
- **timing_dependency:** Requests spaced just beyond the 60s/120s TTL, or a concurrent burst while an entry is stale.

### Bounded local reproduction
The input payloads were:
- GET /api/honeypot, GET /api/map and GET /api/vitals, each once every 61 simulated seconds for 24 simulated hours
- 20 concurrent GET /api/honeypot while cache:honeypot holds {exp: now-1}

Steps:
1. Inside the no-network sandbox, import dynamic/worker/src/index.js (the real router) from Node 22. Use an in-memory fake KV whose put() counts writes per key prefix, a stubbed Date.now clock, and a ctx.waitUntil collector that is drained after each round.
2. Call worker.fetch for the three routes every 61 simulated seconds for 24 simulated hours. Record response statuses, total puts, puts per prefix and any '*cap:*' keys.
3. Seed cache:honeypot with {exp: now-1}, send 20 concurrent fetches of /api/honeypot, drain waitUntil and count the new cache puts.

The evidence harness and its output are in `evidence/agents/v-cached-uncapped/artifacts/uncapped-cache-writes.txt` and `evidence/agents/h-worker-quota/artifacts/evidence/uncapped-cache-writes.txt`. The harness imports the Worker from an absolute path, so adjust that path to run it again.

### Observed result
sequential-1-day: 4,251 requests, all 200, 3,543 KV puts (all 'cache:*'), and no cap keys created. concurrent-stale-burst: 20 requests, all 200, 20 cache:honeypot puts. Real KV exhaustion and the resulting 502s were not exercised; they follow from source (catch at :696) once puts fail.

### Severity
- **Likelihood:** high. The routes are unauthenticated and not rate limited. About 3 trivial requests per minute from one client is enough, and ordinary organic dashboard traffic produces a similar write rate.
- **Impact:** medium. The shared account KV write budget is exhausted for the rest of the UTC day. Honeypot and vitals recording stop, rate-limited routes error, and the dashboards return 502 after their stale window. The effect is availability only, recovers automatically at the daily reset, and discloses no data.
- **Confidence:** medium. The missing bound and the write counts were reproduced independently with the real router code in a sandbox. How large the outage is depends on the Free-plan KV write ceiling, which the repository documents but which cannot be observed from source. Real KV per-key write throttling could reduce the concurrent-burst multiplier, but not the sequential write rate.

### Remediation and regression case
Keep public read caches out of the KV write budget. The preferred option is to serve the short-TTL honeypot/map/vitals aggregates from the Cache API (caches.default), which consumes no KV writes. Alternatively, raise their TTLs to at least the 30-minute cron interval and refresh them only from scheduled(). If KV caching stays, route cached() puts through a global daily underCap and, once the cap is exhausted, serve stale data or compute on read without persisting. Size that cap together with the existing caps (honeypot ~300, rate limiter 300, refresh 20, vitals) so the sum stays under the account ceiling; each allowed refresh costs two writes (value plus cap counter). Add a single-flight guard so concurrent stale hits do not each write. Regression test: N sequential requests spaced beyond the TTL plus a concurrent stale burst must produce at most the configured cap of KV puts.

Sketch:

```js
const CACHE_WRITE_CAP = { windowMs: DAY_MS, max: 100 }; // each allowed refresh = 2 writes; size with the other caps
async function cached(env, ctx, key, ttlSec, producer) {
  const now = Date.now();
  const hit = await getJSON(env, key);
  if (hit && hit.exp > now) return hit.data;
  const refresh = async () => {
    const data = await producer();
    const capKey = `cachecap:${dayKey(Date.now())}`;
    const { allowed, state } = underCap(await getJSON(env, capKey), { now: Date.now(), ...CACHE_WRITE_CAP });
    if (allowed) {
      await Promise.all([
        env.KV.put(key, JSON.stringify({ data, exp: Date.now() + ttlSec * 1000 }), { expirationTtl: ttlSec + 600 }),
        env.KV.put(capKey, JSON.stringify(state), { expirationTtl: 86460 }),
      ]);
    }
    return data;
  };
  if (hit && ctx) { ctx.waitUntil(refresh().catch(() => {})); return hit.data; }
  return refresh();
}
// and raise /api/honeypot, /api/map and /api/vitals TTLs to >= 1800s (warmed in scheduled()), or move them to caches.default.
```
