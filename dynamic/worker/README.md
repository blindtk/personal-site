# personal-site-worker

Backend for the site's security features (Block 3): honeypot, hostile
traffic map, header self-scan, SOC ticker, and CSP violation receiver. A
single Cloudflare Worker + one KV namespace.

> **Why it lives here and not in `static/`:** the monorepo rule is that
> `static/` is 100% client, no backend. Anything that needs a server
> belongs in `dynamic/` — this is that area's first real code.

## Endpoints

| Route | What it does | Cache | Rate limit |
| --- | --- | --- | --- |
| *(decoys)* `/wp-login.php`, `/.env`, `/admin`, `/phpmyadmin/`, `/.git/config` | Records only metadata (country, ASN, path, timestamp) and returns 404 | — | — |
| `GET /api/honeypot` | Aggregated stats + last 30 attempts | 60 s | — |
| `GET /api/map` | Origins by country (24 h / 7 d) | 60 s | — |
| `GET /api/scan` | Note + checklist of the site's own headers | 6 h | `?refresh=1`: 3/10 min |
| `GET /api/pwned-range` | k-anonymity proxy to the Have I Been Pwned range API (the `pwned` tool) — only the 5-character hash prefix leaves the browser | — | — |
| `GET /api/ticker` | CISA KEV + critical NVD entries, sanitized | 1 h | — |
| `POST /api/csp-report` | CSP violation receiver — **manual** send (button on the Evidence page), not automatic `report-uri`/`report-to` (removed from the CSP in 2026-07, see `docs/security-headers.md`) | — | 10/min per client (fails closed with 429 past this limit) + 50/day global write cap (silently dropped past the cap, still 204) |
| `GET /api/csp-violations` | 7-day violation aggregates (Security page panel) | 60 s | — |
| `GET /api/threat-intel` | Heatmap, time-of-day, tops (country/ASN/technique), and recent events (Perimeter panel) | 6 h | — |
| `POST /api/vitals` | Web Vitals receiver (LCP/CLS/etc.) — unauthenticated first-party beacon | — | same pattern as `/api/csp-report` |
| `GET /api/vitals` | Web Vitals aggregates (p75 + rating, per histogram) | 120 s | — |
| `GET /api/ct` | CT watcher: certificates issued for the domain (Certificate Transparency logs, 90 d) | 6 h | — |
| `GET /api/cf-stats` | Cloudflare zone status: zone requests/cache/threats (+ top countries by threats) + this Worker's invocations/errors (GraphQL Analytics API) | 6 h | `?refresh=1`: 3/10 min |
| `GET /api/mirror` | Mirror: the "server's view" of this request (TLS/ASN/country/UA, **never the IP**) | — (per-request, `no-store`) | 30/min per client |
| `GET /api/health` | Liveness | — | — |

## Privacy (honeypot)

**No IP is ever stored.** Events only save country (`cf-ipcountry`,
validated to 2 letters — anything else becomes `XX`), ASN
(`request.cf.asn`, validated within the 32-bit space), path (only known
decoys), and a **timestamp rounded to 5 minutes**. The rounding is
anonymization: it removes the precise instant, reducing (not eliminating)
the risk of correlating ASN+path+timestamp with third-party logs. The
only thing derived from the IP is the rate-limit key: a truncated
SHA-256 hash combining `RATE_SALT` with the UTC date — this derived key
changes daily even though the underlying `RATE_SALT` secret itself is
rotated manually on a weekly cadence (see the secrets table below) — kept
only during the limit's window and never associated with the events. `recordHoneypot` doesn't even read the
IP. Covered by a test (`test/logic.test.mjs`): the IP never appears in
any KV value nor in any Worker log line.

## Privacy (CSP violations)

Since 2026-07, sending is **manual** (a button on the Evidence page, see
`static/public/js/csp-report.js` and `CspViolations.astro`) — the CSP no
longer has `report-uri`/`report-to`, so the browser no longer sends
anything on its own. The wire format and the receiver didn't change: the
body arriving at `POST /api/csp-report` can carry full URLs (with paths
and query strings, where tokens live). The Worker **never persists the
URL**: from `blocked-uri` it only saves the **origin** (scheme + host),
and browser extensions get bucketed by scheme (`chrome-extension://`),
never by extension ID — which would identify the user by what they have
installed. No IP, no User-Agent, and unlike the honeypot there isn't even
a recent-events list: only daily counters by directive/category/origin
(`src/lib/csp-report.js`, covered by a test — path and query never appear
in any KV value).

Endpoint defenses (these are the Worker's only public POST endpoints, by nature): strict
`Content-Type`, body ≤ 16 KB, per-client rate limit, validation that
`document-uri` belongs to the site itself (forged reports "from other
sites" are dropped with the same 204 — indistinguishable), a cardinality
cap on aggregation keys (`~other` past 40 distinct sources/bucket), and a
global write cap per window (`CSP_WRITE_CAP`).

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
(the parameter itself), it carries the same tight rate limit as
`/api/scan` (3/10 min).

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
order of magnitude). `CSP_WRITE_CAP` (50/day) and `VITALS_WRITE_CAP`
(150/day) follow the same pattern. All three are **daily** caps (not
hourly) on purpose: the Workers KV Free plan has a ceiling of ~1,000
writes/day for the **whole** account, shared between
honeypot/CSP/vitals/rate-limit/cron — a generous hourly cap let a single
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

# Only needed if Cloudflare Access is active in front of SCAN_TARGET
# (see docs/cloudflare-deploy.md) — without them, self-scan receives the
# Access login page instead of the site. Create the Access Service Token
# at dash.cloudflare.com → Zero Trust → Access → Service Auth.
npx wrangler secret put ACCESS_CLIENT_ID
npx wrangler secret put ACCESS_CLIENT_SECRET
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
| `RATE_SALT` | secret | `wrangler secret put` | rate-limit hash; the secret itself is rotated manually WEEKLY (invalidates accumulated limits on purpose) — the *effective* rate-limit key derived from it already changes daily (see Privacy section above) |
| `NVD_API_KEY` | secret | `wrangler secret put` | optional, NVD rate limit |
| `CF_API_TOKEN` | secret | `wrangler secret put` | Analytics:Read (zone + account) + Firewall/WAF:Read (zone + account) token, for `/api/cf-stats` — see the "Cloudflare Status" section above |
| `ACCESS_CLIENT_ID` | secret | `wrangler secret put` | optional — Access Service Token, only if Access is active in front of `SCAN_TARGET` |
| `ACCESS_CLIENT_SECRET` | secret | `wrangler secret put` | same, paired with `ACCESS_CLIENT_ID` |
| `ALLOWED_ORIGINS` | var | wrangler.toml | CORS (mode 2b only) |
| `SCAN_TARGET` | var | wrangler.toml | URL that self-scan inspects |
| `DEPLOY_TS` | var | `--var` on deploy | "time to first scan" (optional) |
| `CF_ZONE_TAG` | var | wrangler.toml | zone ID, for `/api/cf-stats` |
| `CF_ACCOUNT_ID` | var | wrangler.toml | account ID, for `/api/cf-stats` |
| `CF_WORKER_SCRIPT` | var | wrangler.toml | this Worker's name on the account, for `/api/cf-stats` |
