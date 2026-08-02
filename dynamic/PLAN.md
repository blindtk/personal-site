# dynamic/ — dynamic app ("Lab") plan

> **Status: in production.** `dynamic/worker/` (the Worker behind the
> site's security features — honeypot, hostile-traffic map, header
> self-scan, SOC ticker, and CSP-violation pipeline) is deployed on the
> `danielmala.co` domain's routes. Deploy, gotchas, and infrastructure
> (Access, WAF) are documented in `dynamic/worker/README.md` and
> `docs/cloudflare-deploy.md`.
> The network tools below (DNS/whois/…) are still to be built; the
> `/lab/` page ("under construction") will point to them once they exist.

## Recorded decisions

- **2026-07-29 — TEMPORARY: expose the pathname in self/self CSP
  violations** (direct request from the repo owner, for diagnosis): the
  "CSP Violations" panel kept showing new `script-src-elem`/`self` and
  `connect-src`/`self` violations even after the JSON-LD hash fixes and
  extension detection via `sourceFile` — `'self'` in a script-src/
  connect-src should never block a genuinely same-origin request, and
  without the path the dashboard didn't say WHERE. Main suspect:
  Cloudflare's own challenge/managed challenge (seen in the same day's KV
  `fw:` data, and in the HTML returned to an automated `curl` against the
  domain), whose injected script/fetch runs as if it were the page's
  own — it has no extension scheme for `sourceFile` to flag.
  `DEBUG_EXPOSE_SELF_PATH` (`dynamic/worker/src/lib/csp-report.js`)
  temporarily turns on the pathname (never query/fragment) in the `self`
  bucket, just for this diagnosis. Minimal exposure risk while this stays
  on: production is still behind Cloudflare Access
  (`docs/public-repo-decision.md` — "doesn't load for anyone" except the
  owner).
  **Revert (`DEBUG_EXPOSE_SELF_PATH = false` and the 2 tests that depend
  on the path) as soon as the cause of the self/self violations is
  confirmed.**

  **2026-07-30 — confirmed with the repo owner** (preparing the
  repository to go public): diagnosis still ongoing, flag stays `true`.
  Re-evaluate this point before the repository goes public, since the
  mitigation assumes production is behind Cloudflare Access — if that
  premise changes before the cause is confirmed, revert first.

  **2026-07-31 — reverted.** The repo owner confirmed that Cloudflare
  Access no longer blocks `danielmala.co`/`www.danielmala.co` — the
  accepted-risk premise changed before the cause of the self/self
  violations was confirmed, so it was reverted first, as already decided
  above: `DEBUG_EXPOSE_SELF_PATH = false` and the path-dependent tests
  updated in `dynamic/worker/test/logic.test.mjs`. Diagnosing the actual
  cause of the self/self violations is still unresolved — if they
  reappear, reopen with the flag and re-evaluate the risk now that
  production is no longer behind Access.

- **2026-07-29 — `invariants.yml` workflow: closes the detection → alert
  loop** (discussed with the repo owner after the same day's security
  review): the honeypot/threat-intel/CT/CF-stats dashboards are
  **pull-only** — they show data when someone opens the page on purpose,
  but nothing alerts anyone when something breaks (the review's
  "Observability 5/10" finding). A daily workflow
  (`.github/scripts/check-invariants.mjs`) checks `/api/health` (the only
  critical invariant — depends on no third-party upstream) and the
  Worker's read routes (informational: one failing alone is treated as an
  unstable upstream, `429` is treated as the protection working, not a
  failure; two or more at once already counts as a failure, a sign the
  Worker itself broke). On failure, it opens an Issue (label
  `automated-alert`, created at runtime) — or comments on one already
  open, instead of duplicating; once it passes again, it closes it
  itself. Uses `gh` (already installed on the runner) instead of adding
  yet another third-party action just for this. Same
  `SET-ME`/optional-Access-Service-Token convention as
  `check-headers.mjs` — while Access blocks production, this workflow
  also stays a noisily-warned no-op, instead of failing blindly.

- **2026-07-29 — Rate limit fails closed when the global write cap runs
  out** (finding from a security review, see
  `docs/security-review-2026-07-29.md` finding A1 and
  `docs/adr/0003-rate-limit-kv-vs-nativo.md`): `rateLimit()` kept
  returning `allowed: true` when `RATE_LIMIT_WRITE_CAP` (300 writes/day)
  ran out — it just stopped persisting per-client state. That froze that
  client's window indefinitely: ~300 trivial requests (10 min of traffic
  from a single IP against `/api/mirror` or `/api/vitals`) would disable
  the entire route's rate limit until midnight UTC — a cheap,
  deterministic bypass, not an accidental edge case. Fixed to fail
  **closed**: with the cap exhausted, the route returns 429 to all
  clients (without spending any extra write, as already happened for
  per-client rate limiting), until the day's budget reopens. Noisy log
  (`ratelimit_write_cap_exhausted`) along the way, same pattern as
  `rate_salt_missing`. A regression test in `test/logic.test.mjs` pins
  the new behavior (114 tests, 0 failures). **Pending (manual decision,
  outside what a code PR can express):** replace this implementation
  with a native Cloudflare Rate Limiting rule (WAF, free on the Free
  plan) — removes the dependency on KV's eventual consistency and frees
  up ~300 writes/day for the rest of the budget. See ADR 0003 for the
  full reasoning.

- **2026-07-29 — `npm ci --ignore-scripts` in `ci.yml` (static and
  worker)**: no dependency runs an arbitrary postinstall during CI's
  `npm ci` — the most common npm package-compromise vector. Verified
  before applying: neither `astro build/check/test` nor the Worker's
  `npm test` + `wrangler deploy --dry-run` need install scripts; only the
  real `wrangler dev`/`deploy` do (the workerd binary), and those stay
  manual, outside CI.

- **2026-07-29 — `supply-chain.yml` workflow (weekly + manual): `npm
  audit signatures` + SBOM (CycloneDX)**: verification of npm registry
  signatures (catches a package served without its expected signature —
  a compromised registry, a tampered mirror) and generation of a real SBOM
  of what's installed, as a workflow artifact. Runs weekly and on
  `workflow_dispatch`, not on every PR: the repository is currently over
  the GitHub Actions Free-plan minute quota (see
  `docs/security-review-2026-07-29.md` §0.2), and adding more steps to
  every PR's path would make that worse. `dynamic/worker/package.json`
  gained a `version` field (required by `npm sbom` to generate a valid
  purl — without it, `ESBOMPROBLEMS` because the root package ends up
  with type "range").

- **2026-07-29 — `check-headers.mjs` accepts an optional Access Service
  Token** (`ACCESS_CLIENT_ID`/`ACCESS_CLIENT_SECRET`, repo secrets):
  before this change, the only way for the Headers workflow to check
  production again was to turn off Cloudflare Access. Now, configuring
  the two secrets (a Service Token created in Zero Trust → Access →
  Service Auth) is enough on its own — without them, the behavior stays
  identical to today (`SET-ME`, a noisy warning, nothing checked). Follows
  the same `fetchSameOrigin` pattern as `runScan()`: only follows
  redirects within the same origin, so Access credentials never follow a
  3xx off the domain.

- **2026-07 — "This Site" section (observability) — phases 2/3**
  (approved by the repo owner, following the "This Site" request): three
  additions to the Worker to feed the new section's Threat Intelligence,
  Logs, and Performance. All **zero-PII** and **best-effort** (never take
  down the core):
    1. **Honeypot Threat Intelligence** (`/api/threat-intel`, 5-minute
       cache, warmed by the cron). The honeypot buckets now also
       accumulate **byAsn** and **byTech** (alongside country/path — see
       `aggregate.js`), and the hourly buckets now retain **8 days**
       (was 2) to give a **day×hour heatmap** and "attacks by time of
       day". Aggregates locally: top country/ASN/technique/path, peak
       hour. **Attackers grouped by ASN, NEVER by IP** — honeypot events
       never had an IP. `recent` goes from 30→200 events for the **Logs
       table** (client-side search/pagination).
    2. **7-day firewall accumulation** (the "phase 2" already anticipated
       below): the cron snapshots the last 24h's firewall breakdown into
       a daily snapshot (`fw:<day>`, TTL 8d) and `/api/threat-intel`
       merges 7 days. This is how the 24h window (the raw dataset's limit
       on Free) gets extended to 7 days, with only per-action/origin
       counters. **Cron enabled** (`*/30 * * * *`) — it used to be
       optional; now it's required to accumulate.
    3. **First-party RUM for Core Web Vitals** (`POST/GET /api/vitals`,
       `lib/vitals.js` + `static/public/js/vitals.js`). The browser
       measures LCP/CLS/INP/TTFB with `PerformanceObserver` and sends
       **once** via `sendBeacon`; the Worker accumulates **daily
       histograms** and returns the **p75** (Google's percentile) per
       metric. **Aggregates only**: never the individual sample, nor IP,
       UA, or URL — the same layered defense as the CSP receiver
       (restricted Content-Type, body ≤2KB, rate limit, write cap). Why
       first-party and not Cloudflare's RUM: theirs is a **third-party
       script**, incompatible with the strict CSP and with the site's
       "no trackers" stance. **To disable**: remove
       `<script src="/js/vitals.js">` from `BaseLayout.astro` (the rest
       of the site doesn't depend on it).

- **2026-07 — Detail by HTTP status code in the "Cloudflare Status"
  panel** (approved by the repo owner): the "threats blocked (WAF/edge)"
  card showed only a blind counter (`threats` from
  `httpRequests1dGroups`), without saying *what* the protection did.
  Added a **"requests rejected by HTTP status code · 7d"** table (only
  4xx/5xx: 403 blocked, 429 rate limited, 503 challenge/unavailable…),
  from the `httpRequests1dGroups`'s **`responseStatusMap`** — a sibling
  field to the `countryMap` already in use. Aggregates only, never IPs.
  Lives in the **core request** (not a separate best-effort one): it's a
  field as stable as `countryMap`. Pure logic in `cf-analytics.js`
  (`blockedByStatus`), tested; UI (`CfAnalytics.astro`) + i18n
  (`statusLabels`, with a fallback to the raw code).

  **Why the HTTP status code and not the WAF rule's "origin/action" (the
  obvious choice):** the real detail —
  `firewallEventsAdaptiveGroups` (action `block`/`skip`, source
  `firewallCustom`/`ratelimit`…) — is **Pro+**. Proven by elimination
  against the real zone (Free), not by documentation:
    - permissions: the token has `Account Analytics:Read` + `Zone
      Analytics:Read` + `Zone Logs:Read` and the dataset still returns
      `"does not have access to the path"`;
    - window: on Free the adaptive datasets are capped at 24h
      (`httpRequestsAdaptiveGroups` literally returned *"cannot request
      a time range wider than 1d"*); the firewall query was reduced to
      24h, and it's **still** blocked, while `httpRequestsAdaptiveGroups`
      — same token, same window — **does** return data. So: it's neither
      permissions nor the window, it's the **plan**.
    - `threatPathingMap` (Free, per-threat mechanism) was tested and is
      sparse to the point of useless (1 in ~676), so it was dropped too.

  **Cost of this decision:** it took many iterations and several PRs
  (the firewall dataset was tried and reverted). The outcome is recorded
  here: on the Free plan, the honest, rich path for "what the protection
  does" is the **edge response HTTP status code**; per-WAF-rule detail
  requires Pro+. If the zone ever moves to Pro,
  `firewallEventsAdaptiveGroups` can be reopened (with a window ≤ the
  plan's retention).

- **2026-07 — CORRECTION: firewall events ARE accessible on Free (raw
  dataset)** (phase 1 approved by the repo owner): the earlier conclusion
  ("firewall is Pro-only") was **wrong** — it confused the two datasets.
  `firewallEventsAdaptive**Groups**` (aggregated) is Pro+, but
  `firewallEventsAdaptive` (**raw**, individual events) **works on
  Free** (24h retention), with the token holding firewall read
  permissions (Zone Firewall Services:Read, Zone WAF:Read, Account
  Firewall Access Rules:Read). Proven in production: the raw dataset
  returned real events (`managed_challenge` from `firewallCustom`), while
  the aggregated one kept saying "no access". Since the aggregated one is
  Pro, **action/origin aggregation happens in the Worker** from the raw
  data (`firewallBreakdown`). A separate, **best-effort** request (never
  takes down the core panel). The panel now has two tables — **by
  action** and **by origin · 24h** — alongside the "by HTTP code · 7d"
  one (which stays, it's a complementary signal). i18n labels
  (`actionLabels`/`sourceLabels`) with a fallback to the raw value; the IP
  is never requested or stored. **Phase 2 (planned, not done yet):**
  since the raw dataset only has 24h on Free, a **daily cron** collects
  the day's aggregate into KV and accumulates a **7-day** window — the
  repo owner's "collect and keep" idea, which makes complete sense here.

- **2026-07 — CORRECTION 2: the "Traffic" panel's copy about IP/URL/
  user-agent/ASN was wrong; added detail by URL, user-agent, and ASN**
  (direct request from the repo owner): the Traffic tab's `planNote`
  said "detail by IP, URL, user-agent, and ASN for all traffic requires
  the `firewallEventsAdaptiveGroups` dataset (Pro+)". That confused the
  two datasets from the point above again — only the AGGREGATED one is
  Pro+; the RAW one (already in use for action/origin/country since the
  previous correction) always had the `clientRequestPath`, `userAgent`,
  and `clientAsn` fields available on Free. Fixed the copy and added what
  it said was missing: three new tables on the Traffic tab — **most
  targeted URLs**, **most seen user-agents**, and **most seen networks
  (ASN)**, all from the firewall data over the last 24h (the raw
  dataset's retention limit). Implementation:
    - `CF_FIREWALL_DETAIL_QUERY` — a GraphQL request **separate** from
      `CF_FIREWALL_QUERY` (same dataset, different fields), to isolate
      the risk: a schema drift in these three new fields never wipes out
      the action/origin/country tables already working in production
      (same best-effort principle as always).
    - `firewallDetailBreakdown` in `cf-analytics.js` — weights by
      `sampleInterval` (same sampling as `firewallBreakdown`), sanitizes
      path/user-agent with `sanitizeText`, and validates the ASN with
      `normalizeAsn`.
    - **`clientIP` stays out** — it's available in this dataset (it's
      literally what proves the old copy was wrong), but it's never
      requested or processed. Zero-PII is the site's choice, not a Free
      limitation — the corrected `planNote` says this explicitly.
    - No 7-day accumulation for these three tables (they stay at 24h,
      unlike action/origin/country, which already have the phase-2 daily
      snapshot above) — keeping `KV`/`snapshotFirewall` accumulating
      path/user-agent would increase the retained-data footprint without
      an explicit request for it; revisit only if the repo owner asks.

- **2026-07 — Dependabot security-only alongside Renovate** (repo owner's
  decision): Renovate handles all *version updates* (grouped routine +
  majors), but **Dependabot security updates** also stays enabled — for
  vulnerabilities only. This doesn't contradict the config's "replaces
  Dependabot": Renovate, by design, only opens security PRs for
  **direct** dependencies (the ones in `package.json`); **transitive**
  ones (deep in `package-lock.json`) aren't reached by it — not even with
  `osvVulnerabilityAlerts`. Dependabot security-only covers that gap
  because it scans the entire lock file. The case that prompted the
  decision: `sharp`/`libvips` (High, CVE-2026-33327/33328/35590/35591), a
  transitive dependency pulled in by `wrangler` (a devDependency) in
  `dynamic/worker/` — Renovate would never have listed it. What's
  **not** enabled: Dependabot *version updates* (would collide with
  Renovate) and Dependabot's auto-dismiss rules (the "dismiss low-impact
  dev-scoped" rule would dismiss alerts like the sharp one and defeat the
  security update itself; malware never self-dismisses). Renovate's
  config tags CVEs with the `security` label (`vulnerabilityAlerts`).

- **2026-07 — Compromised-password checker (k-anonymity)** (approved by
  the repo owner): an educational tool that checks whether a password
  appears in known breaches via Have I Been Pwned's *range API*,
  **without the password ever leaving the browser**. The client computes
  the SHA-1 locally (WebCrypto), sends only the first 5 hex characters of
  the hash to the Worker (`GET /api/pwned-range?prefix=XXXXX`), receives
  ~800 suffixes sharing that prefix, and matches locally — neither the
  Worker nor HIBP ever knows which password was tested. The Worker acts
  as an anonymizing *relay* (HIBP sees Cloudflare's egress IP, not the
  visitor's) and sends `Add-Padding: true` to normalize response sizes.
  Pure logic in `dynamic/worker/src/lib/pwned.js` (parsing) and
  `static/src/scripts/pwned.js` (split/match), both tested with known
  vectors. Principles: strict prefix validation (`^[0-9A-F]{5}$` — not
  reusable as an open proxy), rate limiting from day one, 24h cache per
  prefix (a public dataset), zero prefix logs. The UI, styled like a
  terminal log, makes the k-anonymity protocol *visible* — that's the
  product, not the lookup result. **2026-07 update (see entry below):
  no longer lives only on the Security page — has its own page at
  `/ferramentas/pwned/`.**

- **2026-07 — CSP violation pipeline** (approved by the repo owner):
  `report-uri`/`report-to` at the CSP header layer → `POST
  /api/csp-report` on the Worker (strict validation, rate limit,
  anonymous aggregates only — never the full URL) → "CSP Violations"
  panel on the Security page. Dual role: CSP regression canary (zero
  inline, script-src/style-src `'self'`) + observatory for the noise a
  strict CSP catches. Rollout: calibrate the noise buckets with real data
  before giving the panel prominence.

- **2026-07 — CT watcher (Certificate Transparency monitor for the
  domain itself)** (approved by the repo owner): the Worker queries
  public CT logs via crt.sh (two queries — apex and `%.domain`, because a
  certificate issued only for a subdomain would never show up in the apex
  query), deduplicates precert/leaf by serial, and compares every
  issuance from the last 90 days against the `CT_EXPECTED_ISSUERS`
  allowlist (defaults to Let's Encrypt + Google Trust Services,
  Cloudflare's primary/backup pair). Issuances outside the allowlist show
  up as "unexpected" — the first signal of a DNS/registrar takeover.
  Panel on the Security page (same pattern as CspViolations: fallback
  without the Worker, stats + banner + table), `GET /api/ct` endpoint
  with a 6h cache + stale-while-revalidate, warmed by the cron.
  **Distinct from the roadmap's "TLS certificate check"** (that one is
  for arbitrary hosts with user input; this is defensive observability of
  the site's own asset, with no visitor input at all — not reusable as a
  proxy and doesn't need its own rate limit). Pure logic in
  `dynamic/worker/src/lib/ct.js`, tested with realistic crt.sh vectors.

- **2026-07 — Reversal: tools with a backend now live under
  `/ferramentas/`** (repo owner's decision): the two entries above said
  the password checker and self-scan lived only on the Security page
  "because the `/ferramentas/` index is 100% client-side". That's no
  longer true — both now have their own page (`/ferramentas/pwned/`,
  `/ferramentas/self-scan/`) and appear in the index with a "requires
  server" badge (green "client-side" for the rest), instead of
  client-side being an implicit, absolute contract of the index. The
  Security page keeps the narrative (why each tool exists) and now links
  to the tool instead of embedding it — the same pattern already used
  there for the ATT&CK heatmap and Evidence. The **Evidence page still
  embeds self-scan directly** (that's the whole point of that page: live
  proof, not a link).

- **2026-07 — Three new tools** (approved by the repo owner, after a
  proposal with mockups):

  - **CSP Analyzer** (`/ferramentas/csp/`, **100% client-side**): paste a
    `Content-Security-Policy` and get a critical, directive-by-directive
    read — `unsafe-inline`/`unsafe-eval`, bypassable wildcards (a host
    with `*.`, JSONP/CDN), bare schemes, and missing directives
    (`base-uri`, `object-src`, `frame-ancestors`, `form-action`).
    Deterministic letter grade. Pure logic in
    `static/src/scripts/csp-lint.js` (parsing + CSP L3 heuristics + known
    public bypasses), tested with vectors
    (`static/test/csp-lint.test.mjs`); messages are i18n-translated IDs.
    No network, no abuse surface; complements self-scan (which says *if*
    the header exists; this says *if the value is any good*).

  - **Mirror** (`/ferramentas/mirror/`, **requires a server**): the
    honeypot's mirror image — shows the visitor themselves what any
    server learns about them from the handshake (TLS/cipher, HTTP,
    country/ASN, User-Agent, Accept-Language) in one panel, and what the
    browser reveals locally (screen, timezone, cores, theme) in the
    other. `GET /api/mirror` endpoint **with no visitor input** (not a
    proxy), **with no state writes at all** (only rate limiting touches
    KV), and that **never returns the IP** (visible to the Worker, but
    never echoed or stored). Pure logic in
    `dynamic/worker/src/lib/mirror.js` (`serverView`), tested — including
    a hard guarantee that the IP never appears in the body. Rate limit
    30/min per client; per-request response (`no-store`).

  - **Passkey Lab** (`/ferramentas/passkeys/`, **100% client-side**):
    creates a real demo passkey (WebAuthn), dissects `authenticatorData`
    byte by byte (rpIdHash, UP/UV/BE/BS/ED flags, signCount, identified
    AAGUID, COSE public key via `getPublicKey`), and verifies the
    assertion's signature with WebCrypto — showing, by repeating it
    against a decoy domain, why the browser refuses (phishing resistance
    = the authenticator signs the origin the browser actually saw). Pure
    logic in `static/src/scripts/passkeys.js` (binary parsing, flags,
    AAGUID, DER→raw ECDSA signature conversion), tested with vectors. No
    network, no server-side state; the passkey created is real and stays
    in the user's manager (cleanup warning shown).

- **2026-07 — Cron cache aligned to the interval (avoids rebuilding
  threat-intel on every tick)** (direct request from the repo owner —
  "do whatever you think is best to reduce API consumption", Free plan):
  the same "50% of your daily Workers KV operation limit reached" alert
  as the entry below (CSP reporting), but this time with the site **still
  unpublished** and only the owner accessing it via Zero Trust Access —
  Access covers all of `danielmala.co` (including `/api/*` and the decoy
  paths), so no real visitor or scanner could reach it. The source had to
  be something that runs without HTTP requests: the **cron**
  (`*/30 * * * *`, `scheduled()` in `src/index.js`), which fires directly
  from the Cloudflare runtime, outside Access's reach. Two causes
  identified by inspecting the code (without access to the dashboard's
  exact breakdown):
    1. `cache:threatintel` had a 5-minute TTL — shorter than the cron's
       interval (30 min). Each of the 48 ticks/day found the cache always
       "stale" and rebuilt the full fan-out of `readThreatBuckets`
       (`THREAT_INTEL_HOURS`=168 + 7 days + `recent` = ~176 GETs) +
       `readFirewall7d` (7 GETs) — **~183 reads + 1 write per tick, 48×/day
       (~8,800 reads/day)**, for a value that in practice never stayed
       cached from the cron's point of view. Fixed: TTL raised to 6h,
       aligned with scan/ct/cf-stats (the same pattern already used on
       this route).
    2. `snapshotFirewall` ran chained right after **all** of
       `cached('cache:cfstats', ...)`, not only when the cache actually
       refreshed — on ticks where `cached()` returned the already-cached
       value (most of them, TTL 6h), the daily snapshot (`fw:<day>`) got
       rewritten with the same data, with no freshness gain (cf-stats
       only changes when `fetchCfStats` actually runs, ~4×/day). Fixed:
       the snapshot moved inside `cached()`'s producer, so it only runs
       when the data is actually new — from 48 writes/day down to ~4/day
       on that key.
  Nothing changed in what visitors see (same 6h TTL already used by
  scan/ct/cf-stats) — it just stopped paying KV to rebuild the same value
  on ticks where nothing had changed. `npm test` (pure logic) still
  passes; there's no automated test for `scheduled()`/the router itself
  (best-effort, graceful degradation by design). If the alert persists
  after this, the next step is to look at the dashboard (Storage &
  Databases → KV → Metrics) for the real read/write breakdown — without
  those numbers, this fix starts from the most obvious fan-out in the
  code, not a direct measurement.

- **2026-07 — Honeypot/CSP/vitals write caps: from per-HOUR to per-DAY,
  and much lower values** (direct request from the repo owner — "once
  this is public in the future, are the APIs well protected? won't the
  honeypot eat up everything?"): the honest answer before the fix was
  **no** — the existing caps (`HONEYPOT_WRITE_CAP` 500/h, `CSP_WRITE_CAP`
  300/h, `VITALS_WRITE_CAP` 5000/h) were designed only as an anti-abuse
  brake ("generous for legitimate scanner traffic"), with no relationship
  to the Free plan's real ceiling (~1,000 writes/day **for the whole
  account**, shared between honeypot, CSP, vitals, rate-limit, and cron).
  Worst cases: honeypot 500×5=2,500 writes **in a single hour** (2.5× the
  entire daily budget); vitals 5,000×2=10,000/hour (10×). In other words:
  even with no attack at all, normal organic traffic on launch day (RUM
  firing on every real page load) could exhaust the day's quota by
  itself. Fixed:
    1. The three caps moved from an HOURLY window to a DAILY one
       (`windowMs: DAY_MS`), with `capKey` also recalculated per day
       (`wcap:d:…`, `cspcap:d:…`, `vitcap:d:…` — they used to be `h:…`,
       which incidentally meant the counter never actually accumulated
       across different-hour ticks).
    2. Much lower values, sized to the budget rather than to "how much a
       scanner can generate": honeypot 60/day (×4 writes ≈ 240/day), CSP
       50/day (×2 ≈ 100/day), vitals 150/day (×2 ≈ 300/day) — ~640/day
       combined, leaving headroom for cron (~45/day, see entry above) and
       rate-limiting.
    3. `recordHoneypot` stopped rewriting the `meta` key on every event —
       `deployTs`/`firstScanTs`, once set, never change again, so the
       write only happens the first time (saves 1 of 5 writes/event,
       hence "×4" above instead of "×5").
  **Conscious trade-off:** under sustained heavy scanning or elevated
  real traffic, extra events on the same day are dropped silently (the
  404/204 still goes out, indistinguishable) — loses granularity in
  Threat Intel/RUM, never the site's core. `README.md` (the "KV write
  cap" section) and `test/logic.test.mjs` (two tests that assumed an
  hourly key/ceiling) updated alongside. This **doesn't** solve
  everything: there's still no shared budget across the three keys (it's
  theoretically possible to exhaust the day with honeypot+CSP+vitals
  simultaneously, each within its own cap) — a single, shared daily
  "circuit breaker" across all Worker writes is left for later, if it's
  still a problem after launch; not implemented now since it's a bigger
  architectural change with no proven urgency.

- **2026-07 — CSP reporting: from automatic (`report-uri`/`report-to`) to
  manual (button)** (direct request from the repo owner, prompted by a
  real Cloudflare alert — "50% of your daily Workers KV operation limit
  reached" on the Free plan): automatic reporting sent a POST to
  `/api/csp-report` on every violation from ANY visitor — in practice,
  mostly noise from browser extensions (see the "CSP Violations" panel,
  the `extension noise` stat), and every accepted POST costs KV writes
  (rate-limit + bucket + cap, ~3 writes/POST), shared with
  honeypot/vitals/cron under the same daily ceiling. Removed
  `report-uri`, `report-to`, and the `Reporting-Endpoints` header from
  `static/public/_headers` (+ the nginx/Caddy mirrors in
  `docs/security-headers.md`, + `.github/expected-headers.json`).
  Replaced with 100% local capture — `static/public/js/csp-report.js`,
  the first resource in `<head>` (deliberately without `defer`: attaches
  the `securitypolicyviolation` listener before any script/link that
  could violate the CSP, so the build's own regression signal isn't
  lost) — stores in `sessionStorage` (deduped by directive+origin, capped
  at 20). Nothing leaves without a click: `CspViolations.astro` (the
  Evidence page) reads the queue and offers a "Report" button that sends
  everything in a single POST in the batch format
  `application/reports+json`, already supported by `parseReports()` —
  zero change to the Worker beyond comments. **Consciously accepted
  trade-off:** loses automatic detection of real production regressions —
  you only find out if someone (typically the owner, testing after a
  deploy) visits the Evidence page and clicks. Revisit if the KV ceiling
  stops being a problem (plan upgrade, or sampling instead of a total
  cutoff).

- **2026-07 — Validating `wrangler.toml` against the real Cloudflare
  account** (via Cloudflare's MCP connectors, `.mcp.json` at the repo
  root): confirmed that the KV IDs (`id`/`preview_id` on the `KV`
  binding) and the Worker's name (`personal-site-worker`, `name` at the
  top of the file and `CF_WORKER_SCRIPT` in `[vars]`) match what actually
  exists in the account — the `HONEYPOT`/`HONEYPOT_PREVIEW` namespaces
  and the deployed Worker, with no divergence. `CF_ZONE_TAG`/
  `CF_ACCOUNT_ID` and the deployed Worker's routes/bindings state were
  **not** validated live — the available connector (Cloudflare Developer
  Platform, connected via Settings → Connectors in the app) doesn't
  expose zone listing or route detail; the other `.mcp.json` servers
  (`cloudflare-dns-analytics`, `cloudflare-graphql-analytics`,
  `cloudflare-builds`, `cloudflare-observability`, `cloudflare-audit-logs`,
  `cloudflare-docs`) don't show up in the app's connector directory and
  can only be authorized in an interactive Claude Code CLI session
  (`/mcp`).

- **2026-07 — Cloudflare MCP servers in `.mcp.json` (repo root): finding
  to confirm** (2026-07 security review, round 4, N6): `.mcp.json` was
  added in PR #127 to validate `wrangler.toml` against the real account
  (see the entry above, "Validating wrangler.toml…"), but it landed
  **without** going through the same decision discipline this file
  imposes on everything else — it's not mentioned anywhere in the
  original security review nor in the threat model.

  It registers seven remote MCP servers, **at project scope** (versioned
  in the repo, therefore proposed to any session — human or agent — that
  opens it): `cloudflare-audit-logs`, `cloudflare-graphql-analytics`,
  `cloudflare-dns-analytics`, `cloudflare-observability`,
  `cloudflare-bindings`, `cloudflare-builds`, `cloudflare-docs`. All
  require interactive OAuth before any call — `.mcp.json` by itself
  grants no access, it only proposes it.

  **What deserves attention, in order of risk:**
  1. `cloudflare-bindings` — the only **write** one: creates and deletes
     KV namespaces, D1 databases, and R2 buckets. It's a write path into
     the Cloudflare account from the repository's context, via OAuth,
     alongside the "no Cloudflare token exists in GitHub secrets" fact
     the review praised as the detail "almost nobody gets right". The
     GitHub Actions token still doesn't exist (that stays correct) — but
     there's now a second path, outside CI, that the original threat
     model didn't account for.
  2. `cloudflare-audit-logs` — reads the account's audit log
     (administrative action history). Not destructive, but it's
     sensitive information about the account itself.
  3. The remaining five (`graphql-analytics`, `dns-analytics`,
     `observability`, `builds`, `docs`) are read-only and low risk — the
     same kind of data already read manually in the dashboard.

  **Not removed in this entry**: there's no visibility, from the repo,
  into which of these seven are actually used in real sessions (the
  "Validating wrangler.toml" entry above used a different *personal*
  connector — "Cloudflare Developer Platform", connected via Settings →
  Connectors in the app — not the ones in `.mcp.json`). Repo owner's
  decision: keep all seven, cut down to the read-only ones, or move
  `cloudflare-bindings` to a personal connector (outside the repo, not
  proposed to everyone who clones it) if write access is still needed.

  **Resolved (2026-07-30, preparing the repository to go public):** the
  owner's decision was to cut down to the read-only ones.
  `cloudflare-bindings` (the only write one) was removed from
  `.mcp.json`; the remaining six (`cloudflare-audit-logs`,
  `cloudflare-graphql-analytics`, `cloudflare-dns-analytics`,
  `cloudflare-observability`, `cloudflare-builds`, `cloudflare-docs`)
  stay, confirmed as read-only by the analysis above.

## Shelved ideas (presented, **not approved** for implementation)

2026-07 proposals that stayed in the drawer by the repo owner's
decision — recorded so they aren't lost, not to be built without a new
decision:

- **Link Unpacker (phishing URL triage)** — 100% client-side in
  `static/`: paste a suspicious URL and the tool takes it apart *without
  ever visiting it* — the true registrable domain vs. a decoy subdomain
  (`paypal.com.conta-segura.xyz`), punycode/homoglyphs, redirects
  embedded in parameters, the `@` trick in the authority, frequently
  abused TLDs. A verdict by "signals", never a binary safe/unsafe. No
  network, no abuse risk; small-to-medium effort (heuristics + an
  embedded Public Suffix List subset).

- **Sigma Playground** — client-side in `static/`: the visitor pastes an
  nginx/apache log line and a mini Sigma engine (declared subset:
  `selection`, `contains/startswith/endswith`, `condition` AND/OR/NOT)
  runs the same rules published on /detections, showing field by field
  what fired, with a link to the ATT&CK technique. Closes the "honeypot →
  rules → try it yourself" loop; rules shared with /detections via
  `content/` (single source of truth). Logs never leave the browser;
  medium effort.

## What it's going to be

The part of the site that needs a backend: network and security tools
that can't run in the browser alone (because they require server-side
queries, access to arbitrary ports, or private API keys).

## Planned tools

| Priority | Tool | Why it needs a backend |
| --- | --- | --- |
| 1 | **DNS lookup** (A, AAAA, MX, TXT, NS, CNAME, SOA) | direct DNS queries to arbitrary resolvers; the browser's DoH doesn't cover every type/resolver |
| 2 | **Whois** for domains and IPs | the whois protocol (port 43) isn't accessible from the browser |
| 3 | **HTTP security header analysis** | CORS prevents the browser from inspecting third-party sites' headers |
| 4 | **IP blacklist check** (DNSBL) | requires reverse DNS queries against lists like Spamhaus |
| — | (future ideas) visual traceroute, TLS certificate check, port check | raw network access |

## Planned architecture

- **Runtime:** Cloudflare Workers (fits the Cloudflare Pages deploy — the
  same account, free up to 100k requests/day) **or** a small service on a
  VPS (Node/Hono or Go) behind the Cloudflare proxy. Decide when work
  starts.
- **Shape:** JSON API (`/api/dns?name=…&type=MX`, `/api/whois?q=…`) +
  frontend living in the same design system as the static site (reuse
  `static/src/styles/global.css`).
- **URL:** `lab.<domain>` or `<domain>/lab/` via Cloudflare routing —
  decide once the domain exists.

## Principles (for whenever this gets built)

1. **Rate limiting from day one** — these are tools that make requests to
   third parties; they can't turn into an open proxy.
2. **No personal state/logs** — user queries aren't stored.
3. **Strict input validation** on the server (hostnames, IPs) before any
   external query.
4. **Same look** as the static site: share design tokens and, where
   possible, components.

## Roadmap

- [ ] Decide on runtime (Workers vs. VPS) — depends on where the site ends up hosted
- [ ] Project skeleton + deploy of an `/api/health`
- [ ] DNS lookup (API + page)
- [ ] Whois (API + page)
- [ ] Security headers (API + page)
- [ ] DNSBL check
- [ ] Replace `/lab/`'s "under construction" page with real links
