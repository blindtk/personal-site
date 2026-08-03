# ADR 0003 — Rate limiting in KV (fail-closed) as a transition to a native Cloudflare rule

**Status:** accepted, with a pending migration recorded as manual.

## Context

The Worker implements per-client rate limiting in
`dynamic/worker/src/lib/ratelimit.js`: a salted, daily-rotating hash of the
IP → KV key `rl:<route>:<hash>` → fixed window (count + window start).
There's also a **global write cap** for the rate limiter itself
(`RATE_LIMIT_WRITE_CAP`, 300/day) so a single client staying within its
per-route limit can't alone exhaust the ~1,000 writes/day ceiling for the
entire account on the Free plan.

KV is eventually consistent (~60s of global propagation). That's
acceptable for the honeypot/CSP/vitals aggregated counters (they don't
need per-request accuracy), but it's a structurally wrong foundation for a
rate limiter: concurrent requests across different colos can read stale
counts.

**Finding from a security review (2026-07-29,
[docs/security-review-2026-07-29.md](../security-review-2026-07-29.md),
finding A1):** when the global write cap (300/day) was exhausted,
`rateLimit()` kept returning `allowed: true` — it just stopped persisting
per-client state. That froze that client's window indefinitely: ~300
trivial requests (10 minutes of traffic from a single IP against
`/api/mirror` or `/api/vitals`, no need to distribute across origins)
would disable the entire route's rate limit until midnight UTC.

## Decision

**Short term (done, 2026-07-29):** `rateLimit()` now fails **closed** when
the global cap is exhausted — the route returns 429 to all clients until
the budget reopens, without spending any extra write (the 429 stays
"free", as it already did for per-client rate limiting). "Everyone gets
through" is traded for "everyone waits", which is the safe side of this
trade-off.

**Medium term (pending, manual decision by the repo owner):** replace the
rate limiting with a [native Cloudflare Rate Limiting
rule](https://developers.cloudflare.com/waf/rate-limiting-rules/) (WAF,
available on the Free plan). Advantages over the current implementation:

- Applies **before** the Worker runs — zero CPU, zero KV writes.
- Doesn't depend on eventual consistency — the WAF enforces the limit correctly.
- Eliminates `ratelimit.js`, the `rl:`/`rlcap:` key space, and ~300
  writes/day from the KV budget, freeing them up for
  honeypot/CSP/vitals/firewall.

Not done in this round because it's a configuration change in the
Cloudflare dashboard (outside what a code PR can express) — see
`docs/security-review-2026-07-29.md` §9 for the rule design.

## Consequences

- Until the migration to the native rule happens, failing closed is the
  safety net: even under deliberate abuse of the global cap, the worst
  case becomes "routes with visitor input are unavailable until midnight
  UTC", never "rate limiting silently turns off".
- Public reads with no rate limit (`/api/honeypot`, `/api/map`,
  `/api/ticker`, `/api/ct`, `/api/cf-stats` without `?refresh=1`) are
  unaffected — still served from cache regardless of this cap's state.
- A regression test in `dynamic/worker/test/logic.test.mjs` ("rate limit:
  daily global cap at ceiling fails closed…") pins this behavior; any
  future change that reverts it fails the tests.
