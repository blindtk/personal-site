# ADR 0022 — Retire the site's internal honeypot; the external sensor is the honeypot

**Status:** accepted and implemented (2026-10-02). Supersedes
[ADR 0004](0004-zero-pii-honeypot.md) and
[ADR 0007](0007-honeypot-managed-challenge.md) for the honeypot, and
[ADR 0020](0020-honeypot-public-ip.md) entirely. The zero-IP stance of the
Cloudflare/firewall panels (ADR 0004) is unchanged.

## Context

The Worker in `dynamic/worker/` served five decoy paths (`/wp-login.php`,
`/.env`, `/admin`, `/phpmyadmin/*`, `/.git/config`), aggregated what
touched them, and fed a Honeypot page, a hostile-traffic map and a
KEV/NVD ticker whose ATT&CK tagging existed to correlate with those paths.
Three things made it no longer worth its cost:

1. **It saw little of what it was for.** ADR 0007 put the decoys behind a
   Managed Challenge, so they mostly recorded whoever solved an
   interactive challenge, not the indiscriminate mass scanning that
   dominates the Internet (ADR 0019 already said so).
2. **It published personal data for a correlation that was never built.**
   ADR 0020 started storing and publishing source IPs (30-day list) so the
   site's decoys could be correlated with the external Cowrie honeypot.
   Neither side ever implemented that: `honeypot-vps-infra` does not read
   the site's IP list, and the site never fetched the external `feed.json`
   (`connect-src 'self'` would have blocked it anyway). The site was
   holding IP addresses, and offering removal on request, with no benefit
   in return.
3. **The external sensor does the job properly.** `honeypot-vps-infra`
   (ADR 0019) runs Cowrie, an HTTP maze, portlogger and endlessh on its own
   VPS with no proxy in front, maps commands to ATT&CK, enriches
   indicators, and publishes a feed, MISP/STIX exports and a report at
   `intel.danielmala.co`, under its own retention and GDPR policy.

## Decision

Remove the internal honeypot. The site's "Honeypot" is the external
sensor, presented as a project (`/projetos/threat-intel/`, "Threat Intel"), not as a layer of
this site.

- **Worker:** decoy routes (also removed from `wrangler.toml`),
  `recordHoneypot`, the IP list and its pruning, `/api/honeypot`,
  `/api/map` and `/api/ticker` are gone, with `decoys.js`, `ipguard.js`,
  `ipthreat.js`, `attack-map.js`, `feeds.js`, `notfound.js` and their
  tests. `/api/threat-intel` keeps only the 7-day firewall breakdown
  (`lib/firewall.js`, formerly `aggregate.js`) — the route name is kept so
  the Cloudflare and overview pages need no change.
- **KV cleanup:** the cron runs `purgeLegacyHoneypotKeys`, which reads
  `iplist`, `recent`, `meta` and the removed routes' caches (the old
  `cache:threatintel` included) and deletes the ones still present. Reads
  are cheap; after the first clean-up each tick costs no writes. Anonymous
  hourly/daily buckets expire on their own in ≤ 9 days.
- **New cache keys for `/api/threat-intel`** (`cache:firewall7d` in KV,
  `firewall7d` in the Cache API): an old entry, still within its TTL and
  carrying IPs, can never be served by the first request after the deploy,
  before the cron has run.
- **Site:** the Honeypot page, map and ticker are removed; the old URLs
  301 to the project page. The "This site" nav group, footer and layers
  block lose the layer; the overview keeps the three zone numbers and
  drops the honeypot + firewall tables (the firewall detail lives on the
  Cloudflare page).

## Consequences

- The Worker no longer stores any IP address. Its KV write budget drops
  by the honeypot's 300/day.
- Lost on purpose: the decoy-path dataset, the traffic map and the
  KEV/NVD ticker. If the ticker is wanted back, it has to justify itself
  without the honeypot correlation it was built for.
- **Manual steps for the owner** (outside the repository):
  - the WAF custom rule that challenged the decoy paths (ADR 0007, rule 3)
    can be deleted — harmless if left, since those paths are now plain
    404s from Pages;
  - the `NVD_API_KEY` Worker secret is unused and can be deleted
    (`npx wrangler secret delete NVD_API_KEY`);
  - after the first deploy, `/api/threat-intel` should show only
    `firewall7d`, and `iplist` should no longer exist in KV
    (`npx wrangler kv key get iplist --binding KV --remote` → not found).
