# ADR 0020 — Honeypot events record and publish the source IP, for cross-honeypot correlation

**Status:** accepted and implemented (`dynamic/worker/src/lib/ipguard.js`,
`dynamic/worker/src/lib/ipthreat.js`, `recordHoneypot` in `src/index.js`).

## Context

The honeypot (`dynamic/worker/`, ADR 0004) has never stored the
visitor's IP, by choice: `recordHoneypot` doesn't read
`cf-connecting-ip` at all, events carry only country/ASN/path/technique,
and the timestamp is rounded to a 5-minute window specifically to block
precise cross-referencing (the comment in the code and in ADR 0004 both
say so explicitly).

Since ADR 0019 (external Cowrie honeypot + spider trap, publishing
attacker IPs on a separate VPS), the repo owner wants to correlate hits
between the two sensors and general threat intel — "the same source hit
both of my honeypots" is a materially stronger signal than "the same
network did," and ASN-level correlation (already available today, at no
extra cost, from the existing `byAsn` aggregate) was judged insufficient
for that use case.

Two designs were considered: (a) keep the honeypot's raw IP internal
only, never exposed by any public route, used solely for a private
cross-check against the VPS; (b) publish it, with the same posture as
the VPS's threat list. **The repo owner chose (b)**, explicitly, after
the trade-offs of (a) were laid out.

## Decision

Honeypot decoy-path events now record and publish the source IP,
alongside the existing fields (country, ASN, path, technique) — extended
with first/last-seen and a sighting count, the same shape as the VPS's
threat list (ADR 0019 / `docs/external-honeypot-vps.md` §3), so the two
can be compared directly. Same three controls, applied here too:

1. **Expiry.** Entries age out after a period without a repeat sighting —
   **30 days** (`IP_RETENTION_MS`, `src/index.js`), swept by the existing
   `scheduled()` cron. Shorter than the VPS's 60–90 days, and deliberately
   more conservative — HTTP-scanning botnets (the traffic hitting
   `/wp-login.php`, `/.env`, `/admin`, `/phpmyadmin/`, `/.git/config`)
   are more likely than SSH brute-forcers to run on compromised
   residential/IoT devices, not just cloud infrastructure. An IP
   recorded here has a higher chance of belonging to an actual household
   than one captured on the VPS's SSH-only surface.
2. **Dispute/removal.** `me@danielmala.co` — already the site's
   published contact (`static/src/config.ts`), same channel the VPS
   project uses.
3. **Private/reserved ranges excluded** before anything is stored or
   published.

**Scope, explicitly bounded.** This changes only the honeypot's own
decoy-path events. It does **not** touch the Cloudflare Status/firewall
analytics panel (`cf-analytics.js`), which stays governed by ADR 0004
unchanged — that panel aggregates traffic across the whole zone,
including every legitimate visitor, not just automated hits on paths no
real visitor would ever request. Reversing that would be a materially
larger decision than this one, and hasn't been asked for.

## Consequences

- **ADR 0004 is amended, not deleted or rewritten** — its Status line
  now points here for the honeypot half of its scope; the firewall-panel
  half of that decision stands exactly as originally made.
- **A currently-true, tested claim becomes false and has to be corrected
  everywhere it's stated, not only in code:**
  `dynamic/worker/test/logic.test.mjs` (the assertion that the IP never
  appears in KV or in logs is replaced with assertions for the new
  behavior — expiry respected, private ranges excluded, the dispute path
  reachable); `content/projects/{pt,en}/honeypot.md` ("Nenhum IP é
  armazenado" / "No IP is ever stored" — rewritten, with the same
  honesty about what's published and why already used for the VPS
  project); the honeypot page's copy in `static/src/i18n/ui.ts`;
  `README.md`, if it cites the honeypot's zero-IP posture as part of the
  site's privacy narrative.
- **New data shape, new write path — the existing aggregates are left
  alone.** The hourly/daily buckets and the 200-event `recent` list
  already feed the public dashboards and don't need an IP field added;
  a new IP-indexed record (first seen, last seen, count, ASN, country,
  technique) is added alongside them, not instead of them.
- **A new recurring job.** Expiry needs something to run it. The
  existing `scheduled()` cron (already firing every 30 minutes,
  `dynamic/worker/src/index.js`) is the natural place to sweep expired
  entries, rather than a new standalone mechanism.
- **New public surface on `danielmala.co` itself, not only the VPS.**
  Exact shape (page display only, vs. also a downloadable feed like the
  VPS's) is an implementation detail, not decided by this ADR.
- **Cross-honeypot correlation becomes a direct set intersection** of
  two published IP lists — the VPS reads `danielmala.co`'s public
  IP-indexed data (same one-way-read principle already established for
  the VPS project) and flags matches on its own dashboard. The
  salted-hash correlation-key workaround discussed before this decision
  is now moot.
