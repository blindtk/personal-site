# ADR 0006 — Worker write caps: daily, sized to the budget, not to abuse resistance

**Status:** accepted and in production.

## Context

`HONEYPOT_WRITE_CAP`, `CSP_WRITE_CAP`, and `VITALS_WRITE_CAP` existed from
the start as an anti-abuse brake — per hour, with values "generous for
legitimate scanner traffic" (500/h, 300/h, 5000/h respectively) — but
designed with no relationship to the Free plan's real ceiling: ~1,000
writes/day for the **whole account**, shared between honeypot, CSP,
vitals, rate-limit, and cron.

Asked directly ("once this is public, are the APIs actually protected?
won't the honeypot eat the whole budget?"), the honest answer before the
fix was **no**: in the worst cases, honeypot 500×5=2,500 writes in a
single hour (2.5× the entire daily budget); vitals 5,000×2=10,000/hour
(10×). In other words, even with no attack at all, normal organic traffic
on launch day (RUM firing on every real page load) could exhaust the
day's quota by itself.

## Decision

1. All three caps move from an **hourly** window to a **daily** one
   (`windowMs: DAY_MS`), with `capKey` recalculated per day (`wcap:d:…`,
   `cspcap:d:…`, `vitcap:d:…`).
2. Much lower values, sized to the account's budget rather than to "how
   much a scanner can generate": honeypot 60/day, CSP 50/day, vitals
   150/day — ~640/day combined (counting multiple writes per event),
   leaving headroom for cron (~45/day) and rate-limiting.
3. `recordHoneypot` stops rewriting the `meta` key on every event —
   `deployTs`/`firstScanTs`, once set, never change again, so the write
   only happens the first time.

## Consequences

- **Conscious trade-off:** under sustained heavy scanning or elevated real
  traffic, extra events on the same day are dropped silently (the
  404/204 still goes out, indistinguishable) — loses granularity in
  Threat Intel/RUM, never the site's core.
- Doesn't solve everything: there's still no shared budget across the
  three keys — it's theoretically possible to exhaust the day with
  honeypot+CSP+vitals simultaneously, each within its own cap. A single,
  shared daily "circuit breaker" across all Worker writes is recorded as
  a future idea, not implemented for lack of proven urgency — see
  `dynamic/PLAN.md`.
- A regression test in `dynamic/worker/test/logic.test.mjs` pins the
  window and the per-day keys.

## Update — 2026-09-25: caps count writes, and every anonymous write path is budgeted

The [2026-09-25 security audit](../security-audit-2026-09-25/REPORT.md)
found two gaps in the arithmetic above:

1. **Caps counted events, not writes.** A decoy event costs 4–5 puts and an
   allowed rate-limited request cost 2. `underCap` now takes a `cost` (the
   event's real number of puts, counter included), and every `max` is a
   write budget: honeypot 300 (~60 events, unchanged), vitals 300 (150
   samples, unchanged), manual refresh 40 (20 refreshes, unchanged).
2. **Some anonymous write paths had no cap at all.** `cached()` rewrote KV
   on every logical expiry, so public GETs with a 60 s TTL produced
   ~3,500 puts/day. That was the medium-severity finding. Request-driven
   refreshes now draw from `CACHE_WRITE_CAP` (80 writes/day). Once it is
   exhausted, the stale copy is served, and it is kept for a day
   (`STALE_GRACE_SEC`). The cron keeps its fixed-rate refreshes outside
   that budget. The short-TTL aggregates are also cached in the
   data-center Cache API first.

The shared "circuit breaker" mentioned above is therefore implemented as a
sized set of per-path budgets. Honeypot 300 + vitals 300 + cache 80 +
refresh 40 + cron ~90 comes to about 810/day, with the remainder left as
headroom for concurrency overshoot. KV has no atomic increment, so
the counters remain best-effort. A Durable Object would be needed for an
exact counter, and the headroom is the accepted alternative.
