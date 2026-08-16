# personal-site-worker

Backend for the site's security features (Block 3): honeypot, hostile
traffic map, SOC ticker, and CT watch. A single Cloudflare
Worker + one KV namespace.

> **Why it lives here and not in `static/`:** the monorepo rule is that
> `static/` is 100% client, no backend. Anything that needs a server
> belongs in `dynamic/` — this is that area's first real code.

## Endpoints

| Route | What it does | Cache | Rate limit |
| --- | --- | --- | --- |
| *(decoys)* `/wp-login.php`, `/.env`, `/admin`, `/phpmyadmin/`, `/.git/config` | Records metadata (country, ASN, path, timestamp) and returns 404; the source IP is recorded separately, and published (ADR 0020 — see Privacy section below) | — | — |
| `GET /api/honeypot` | Aggregated stats + last 30 attempts (no IP — see Privacy section) | 60 s | — |
| `GET /api/map` | Origins by country (24 h / 7 d) | 60 s | — |
| `GET /api/pwned-range` | k-anonymity proxy to the Have I Been Pwned range API (the `pwned` tool) — only the 5-character hash prefix leaves the browser | — | — |
| `GET /api/ticker` | CISA KEV + critical NVD entries, sanitized | 1 h | — |
| `GET /api/threat-intel` | Heatmap, time-of-day, tops (country/ASN/technique), recent events, and the honeypot's published IP list (`ips` — ADR 0020) | 6 h | — |
| `POST /api/vitals` | Web Vitals receiver (LCP/CLS/etc.) — unauthenticated first-party beacon, the Worker's only public POST endpoint | — | 30/min per client (fails closed with 429 past this limit) + 150/day global write cap (silently dropped past the cap, still 204) |
| `GET /api/vitals` | Web Vitals aggregates (p75 + rating, per histogram) | 120 s | — |
| `GET /api/ct` | CT watcher: certificates issued for the domain (Certificate Transparency logs, 90 d) | 6 h | — |
| `GET /api/cf-stats` | Cloudflare zone status: zone requests/cache/threats (+ top countries by threats) + this Worker's invocations/errors (GraphQL Analytics API) | 6 h | `?refresh=1`: 3/10 min |
| `GET /api/mirror` | Mirror: the "server's view" of this request (TLS/ASN/country/UA, **never the IP**) | — (per-request, `no-store`) | 30/min per client |
| `GET /api/health` | Liveness | — | — |

## Privacy (honeypot)

**Two different postures, by design — not an inconsistency.**

The **Cloudflare Status/firewall panel** (`src/lib/cf-analytics.js`,
zone-wide traffic including every legitimate visitor) stays governed by
[ADR 0004](../../docs/adr/0004-zero-pii-honeypot.md), unchanged: no IP is
ever stored. The only thing derived from the IP anywhere in that path is
the rate-limit key — a truncated SHA-256 hash combining `RATE_SALT` with
the UTC date (this derived key changes daily even though the underlying
`RATE_SALT` secret itself is rotated manually on a weekly cadence, see
the secrets table below), kept only during the limit's window and never
associated with any event.

The **honeypot's own decoy-path events** are different, by an explicit,
later decision: [ADR 0020](../../docs/adr/0020-honeypot-public-ip.md)
records the source IP (`recordHoneypot`, `src/index.js`) into a
**separate** KV key (`iplist`) — never mixed into the anonymous
`recent`/hourly/daily buckets that feed `/api/honeypot`, `/api/map`, and
the "Registo" (log) table, which keep the same country/ASN/path/technique
shape and the same 5-minute-rounded timestamp they always had. Only a
public, validated IP (`src/lib/ipguard.js` — excludes RFC 1918, loopback,
link-local, CGNAT, multicast, and documentation/TEST-NET ranges) gets
recorded; entries age out after 30 days without a repeat sighting
(`IP_RETENTION_MS`, pruned by the cron in `scheduled()`) — shorter than
the sibling external-VPS project's 60–90 days
(`docs/external-honeypot-vps.md`), because HTTP-scanning botnets are more
likely than SSH brute-forcers to run on compromised residential/IoT
devices. The list is published via `/api/threat-intel`'s `ips` field, for
cross-honeypot correlation.

Covered by tests (`test/logic.test.mjs`): the anonymous buckets/`recent`
never gain an `ip` field; a private/reserved IP never reaches `iplist`;
sightings of the same IP accumulate count/techniques without duplicating.

## CT watcher (`/api/ct`)

Any TLS certificate issued for the domain gets recorded in public
Certificate Transparency logs — including one an attacker managed to
issue after a DNS/registrar takeover. The Worker queries crt.sh (two
queries: apex and `%.domain`, because a certificate issued only for a
subdomain would never show up in the apex query), deduplicates
precert/leaf by serial, and compares every issuance against the
`CT_EXPECTED_ISSUERS` allowlist — anything that doesn't match shows up as
**unexpected** on the Security page panel.

No visitor input (the query is fixed, derived from `SCAN_TARGET`) — not
reusable as a proxy and doesn't need its own rate limit. crt.sh is
unstable by nature: the 6h cache with stale-while-revalidate serves the
last good snapshot while the refresh runs in the background, the cron
warms the cache, and if one of the two queries fails, the other's
partial result is used (both failing ⇒ 502 and the panel shows the
fallback). The data is 100% public (it's in the CT logs); everything that
still reaches the client goes through `sanitizeText`, and only names
belonging to the domain are persisted (`src/lib/ct.js`, covered by a
test).

## Cloudflare Status (`/api/cf-stats`)

Panel on the Evidence page with real metrics for this zone/Worker —
requests, cache rate, threats blocked by Cloudflare's edge (with a table
of the origin countries with the most blocked threats over the last 7
days), and this Worker's own invocations and errors — via the
**GraphQL Analytics API** (`api.cloudflare.com/client/v4/graphql`).

The country table sums the `countryMap` field from each day in the
window (it's per day, not per period — the aggregation happens here, in
`topCountriesByThreats` in `src/lib/cf-analytics.js`), filters out
countries with zero threats and invalid codes, and shows the top 10 by
blocked threats. It's a broader signal than the Honeypot's "hostile
traffic map" (`/api/map`): that one only records who hit the decoy paths;
this one covers what the Cloudflare WAF/edge blocked across the
**entire** zone.

**This is not Cloudflare Radar.** Radar is a global, anonymous aggregate
across all Cloudflare customers — it knows nothing about this specific
domain, it only serves as borrowed context ("how the internet out there
is doing"). The GraphQL Analytics API, by contrast, only returns data for
**this** zone/account, authenticated with `CF_API_TOKEN` — it's the same
source that feeds the Cloudflare dashboard when you log in. Daily
aggregates only; never IPs or individual visitor data.

Needs three vars (`CF_ZONE_TAG`, `CF_ACCOUNT_ID`, `CF_WORKER_SCRIPT`, see
`wrangler.toml`) and the `CF_API_TOKEN` secret, created at
dash.cloudflare.com → My Profile → API Tokens, with the scopes:

- `Zone Analytics:Read` + `Account Analytics:Read` — zone requests/cache/
  threats and Worker invocations (`CF_STATS_QUERY`).
- `Zone Firewall Services:Read` + `Zone WAF:Read` +
  `Account Firewall Access Rules:Read` — for the separate, best-effort
  request that reads the raw `firewallEventsAdaptive` dataset (24h, the
  only one accessible on the Free plan) and aggregates by
  action/origin/country (`CF_FIREWALL_QUERY`/`firewallBreakdown` in
  `src/lib/cf-analytics.js`). A daily cron (`scheduled()` in
  `src/index.js`) snapshots that result into KV and merges 7 days
  (`snapshotFirewall`/`readFirewall7d`) — that's what feeds the
  "Firewall by action/origin/country (7d)" panel on the Analytics'
  Threat Intel tab and the "Managed challenges" card on the Overview.
  Without these three scopes, the request fails silently (it's
  *best-effort*, never takes down the core) and those panels stay stuck
  at zero — with no visible error, because that's exactly the intended
  graceful-degradation behavior. The same three scopes also feed a
  **second, separate request**
  (`CF_FIREWALL_DETAIL_QUERY`/`firewallDetailBreakdown`, same raw
  dataset, `clientRequestPath`/`userAgent`/`clientAsn` fields) that
  powers the "Most targeted URLs", "Most seen user-agents", and "Most
  seen networks" tables on the Traffic tab — no 7-day accumulation
  (stays at 24h). A separate request on purpose: a schema drift here
  should never wipe out the action/origin/country tables that already
  work. `clientIP` is available in this same dataset but is never
  requested or processed — zero-PII by the site's own choice.

Without the first group's vars/secret, the route returns 502 and the
panel shows the fallback — the same pattern as the CT watcher without
`SCAN_TARGET`.

The 6h cache already limits how often the Cloudflare API gets hit on the
normal path. `?refresh=1` forces a fresh request ahead of that — useful
so you don't have to wait 6h after changing the data's shape (e.g. when
`topCountries` was added, old KV entries lacked that field until they
expired or a manual refresh replaced them) — and, since it accepts input
(the parameter itself), it carries a tight rate limit (3/10 min).

Pure logic in `src/lib/cf-analytics.js` (parses the GraphQL response,
tested with known vectors — any missing field or schema change on
Cloudflare's side degrades to 0, never breaks the panel).

### Errors and logs

Client-facing error responses are always generic (`upstream_error`,
`rate_limited`, …) — never stack traces, internal paths, or KV detail.
The detail (the stack) stays only in the Worker's logs (server-side) via
`console.error`, and those logs never include the IP.

### KV write cap

Every attempt against the decoys triggers several writes. To limit
cost/abuse if someone hammers the decoy paths, there's a **global write
cap per DAY** (`HONEYPOT_WRITE_CAP` in `src/index.js`, defaulting to 60
events/day): past the ceiling, extra events are dropped and the request
still returns the same indistinguishable 404. See `src/lib/kvcap.js`
(best-effort — KV is eventually consistent, the goal is bounding the
order of magnitude). `VITALS_WRITE_CAP`
(150/day) follows the same pattern. Both are **daily** caps (not
hourly) on purpose: the Workers KV Free plan has a ceiling of ~1,000
writes/day for the **whole** account, shared between
honeypot/vitals/rate-limit/cron — a generous hourly cap let a single
burst of scanners or organic traffic consume several days of quota by
itself. See `dynamic/PLAN.md` for the decision and the numbers.

## Development

```bash
cd dynamic/worker
npm install
npm test          # pure logic (node --test) — no network, no Cloudflare
npx wrangler dev  # local Worker with in-memory KV
```

The modules in `src/lib/` are pure and covered by `test/logic.test.mjs`
(aggregation, sanitization, rate limiting, feed parsing, header note)
with known vectors.

## Deploy

> This section describes the manual flow via the `wrangler` CLI. In
> production, deploy runs automatically via **Workers Builds**
> (Cloudflare's Git integration) on every push to `main` — same idea, the
> commands underneath are the same (`wrangler deploy`), but configured in
> the dashboard instead of run by hand. See
> [`docs/cloudflare-deploy.md`](../../docs/cloudflare-deploy.md) for that
> process and the real problems solved (routes not taking effect because
> `routes` was misplaced in `wrangler.toml`, `workers.dev` public by
> default, etc.) — worth reading before touching this file again.

### 1. KV namespace + secrets

```bash
npx wrangler kv namespace create HONEYPOT
npx wrangler kv namespace create HONEYPOT --preview
# paste the ids into wrangler.toml (id / preview_id)

npx wrangler secret put RATE_SALT     # any long random string
npx wrangler secret put NVD_API_KEY   # optional (raises the NVD rate limit)
```

### 2a. Deploy on the real domain (what's in production)

The `routes` block in `wrangler.toml` (decoy paths + `/api/*` on
`danielmala.co`) is already active — `npx wrangler deploy` (or a push to
`main`, via Workers Builds) intercepts those paths; the rest of the site
stays served by Cloudflare Pages. Since the API ends up **same-origin**,
the frontend calls `/api/...` and the CSP's `connect-src 'self'` is
enough — nothing to change.

### 2b. Deploy on `*.workers.dev` (to test right away, without a domain)

`npx wrangler deploy` with no routes publishes to
`personal-site-worker.<account>.workers.dev`. In that case:

1. Set `PUBLIC_API_BASE` in the site's build to that URL (see
   `static/src/config.ts`).
2. Authorize the site's origin on the Worker: `ALLOWED_ORIGINS` (var)
   with the `*.pages.dev` URL.
3. Add that origin to the CSP's `connect-src` in
   `static/public/_headers` — the **only** exception to the `'self'`
   CSP, and only needed in this test mode. Not needed in mode 2a.

> Note: the decoy paths only catch real scanners when the Worker is on
> the domain's routes (2a). On `*.workers.dev` (2b), the honeypot works
> for testing, but real hostile traffic hits Pages, not the Worker.

## Variables and secrets — summary

| Name | Type | Where | For |
| --- | --- | --- | --- |
| `KV` | binding | wrangler.toml | single namespace (events, buckets, caches, rate limit) |
| `RATE_SALT` | secret, **mandatory** | `wrangler secret put` | rate-limit hash; the secret itself is rotated manually WEEKLY (invalidates accumulated limits on purpose) — the *effective* rate-limit key derived from it already changes daily (see Privacy section above). **Unresolved risk:** if unset, the Worker logs `rate_salt_missing` but doesn't fail closed — it falls back to the public, hardcoded `'rotate-me'` string (`dailySalt` in `src/lib/ratelimit.js`), so rate-limiting continues to "work" with a predictable salt instead of stopping. Fixing this (reject requests when the secret is absent) is tracked as a separate Worker change, not a docs fix. |
| `NVD_API_KEY` | secret | `wrangler secret put` | optional, NVD rate limit |
| `CF_API_TOKEN` | secret | `wrangler secret put` | Analytics:Read (zone + account) + Firewall/WAF:Read (zone + account) token, for `/api/cf-stats` — see the "Cloudflare Status" section above |
| `ALLOWED_ORIGINS` | var | wrangler.toml | CORS (mode 2b only) |
| `SCAN_TARGET` | var | wrangler.toml | own site URL — feeds the CT watch's domain |
| `DEPLOY_TS` | var | `--var` on deploy | "time to first scan" (optional) |
| `CF_ZONE_TAG` | var | wrangler.toml | zone ID, for `/api/cf-stats` |
| `CF_ACCOUNT_ID` | var | wrangler.toml | account ID, for `/api/cf-stats` |
| `CF_WORKER_SCRIPT` | var | wrangler.toml | this Worker's name on the account, for `/api/cf-stats` |
