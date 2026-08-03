# ADR 0004 — Zero-PII in the honeypot and analytics, by choice, not plan limitation

**Status:** accepted and in production.

## Context

The honeypot (`dynamic/worker/src/index.js`, `recordHoneypot`) and the
"Cloudflare Status" panel (`cf-analytics.js`) need to aggregate hostile
traffic by country/ASN/technique/path for the Threat Intelligence
dashboards to have any content. The obvious temptation would be to store
the IP — it's the single most useful field for correlating attacks.

## Decision

**Never store the IP**, anywhere:

- `recordHoneypot` never reads `cf-connecting-ip` — only
  `lib/ratelimit.js` sees it, and even there only as a truncated, salted
  hash (`clientHash`), with the salt rotating automatically every day
  (impossible to re-identify the same IP across days from the rate-limit
  key).
- Each honeypot event's timestamp is rounded to a 5-minute window
  (`floorToWindow`) — prevents correlation by precise instant with
  third-party logs.
- In Cloudflare's raw firewall dataset (`firewallEventsAdaptive`), the
  `clientIP` field **is available** — it's literally what proved, in a
  correction documented in `dynamic/PLAN.md`, that the panel's old copy
  was wrong to say certain details required a Pro+ dataset. Even though
  available, `clientIP` is never requested or processed.

In other words: zero-PII here isn't "the Free plan doesn't allow it" —
it's a deliberate choice, made even when the data was within easy reach.

## Consequences

- The honeypot can't distinguish two events from the same attacker across
  days, nor correlate an IP with other sources — an accepted trade-off:
  the goal is to show attack *patterns* (country, ASN, technique, path,
  time of day), not build a per-attacker dossier.
- Reinforces the site's privacy posture: no visitor — hostile or
  legitimate — has their IP persisted anywhere in the Worker.
- Accepted residual risk (see `docs/security-review-2026-07-29.md`,
  finding A2): without a stable per-attacker identifier, an adversary can
  fill the honeypot's daily write budget with trivial requests and skew
  the public dashboard. A possible future mitigation (per-ASN sub-cap) is
  recorded as a *nice-to-have*, not implemented — the cost of doing it
  well (without reintroducing an IP proxy) hasn't been justified yet.
