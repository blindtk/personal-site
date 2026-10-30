# dynamic/ — backend decisions and plan

> **Status: in production.** `dynamic/worker/` (the Worker behind the
> site's security features — Cloudflare/firewall panels, CT watch, Web
> Vitals, the HIBP relay and the mirror) is deployed on the `danielmala.co`
> domain's routes. Deploy, gotchas, and infrastructure (Access, WAF) are
> documented in `dynamic/worker/README.md` and `docs/cloudflare-deploy.md`.
> The network tools under [Next tools](#next-tools) are still to be built.

This file is the decision log for `dynamic/` — newest first — plus the
plan for what comes next. Decisions with lasting trade-offs also have an
ADR in `docs/adr/`; features that have since been removed are listed
under [Removed](#removed-features-and-reverted-decisions) in one line
each, with the full original entries kept in this file's git history.

## Recorded decisions

- **2026-10-30 — Attack map: this site's firewall and Cloudflare Radar on
  a globe** (approved by the repo owner). A new page, PT `/mapa-de-ataques/`
  and EN `/en/attack-map/` (kept clear of `/attack/`, the MITRE ATT&CK
  matrix; the two pages link to each other), with a "requires server"
  badge and two tabs, one globe each:
    1. **This site · 7 days** (default; the owner's original idea): this
       zone's firewall events by origin country, from `/api/threat-intel`.
       **Bubbles, not arcs**: size = events, colour = the most common action
       (blocked `--danger`, challenged `--accent-2`, let through
       `--accent`). An arc needs a target, and the site has no place on the
       map (anycast) — arcs converging on Portugal would have suggested
       something untrue. `firewall7d.byCountry` gained a `total` per country
       for the bubble size (a lower bound: each daily snapshot keeps only
       that day's dominant action).
    2. **World · last hour** (context, and never empty): global Radar data,
       not attacks on this site — the tab says so, with attribution to
       Cloudflare Radar (CC BY-NC 4.0). Details below. Unrelated to the
       `/radar/` page (RSS alerts and news, `radar:feed`), despite the name.
    - **Source:** `GET /radar/attacks/layer7/top/attacks`, origin → target
      country pairs as a % of mitigated layer 7 attacks. `dateRange` only
      takes `<n>d`/`<n>w` (1 day minimum), so the last hour is asked for with
      `dateStart`/`dateEnd`, aligned to 15 minutes (Radar floors both to the
      quarter hour), `limit=30`. Layer 3 (`/radar/attacks/layer3/top/attacks`)
      was evaluated and left out: it only returns the origin country, so
      it can't draw arcs.
    - **Backend:** the existing `*/30` cron fetches it with `CF_API_TOKEN`
      (needs **Account → Radar → Read**) and stores
      `{ ok, window, start, end, fetched, pairs: [[origin, target, pct], …] }`
      in KV (`radar:attacks`, TTL 3 h). `GET /api/radar-attacks` only reads
      that key (5 min data-center Cache API): no visitor input, no upstream
      call, no KV write, no rate limit needed. On 401/403 the cron logs
      `radar_attacks_forbidden`, writes `{ ok: false }` once, and the page
      shows a message; transient errors keep the last good value. It runs
      isolated from the other cron jobs, so it never stops them. Pure
      validation in `src/lib/radar-attacks.js` (assigned ISO 3166-1 alpha-2
      codes + XK, finite % in [0, 100], duplicates and junk dropped, 30-pair
      cap), tested. **Write budget:** +48/day (one per tick), ≈ 190/day
      in total with the RSS Radar's 4.
    - **Frontend:** a small canvas-2D globe of our own
      (`static/src/scripts/attack-globe.js`, pure and tested;
      `components/attack-map/globe-canvas.ts`, loaded lazily), not cobe or
      globe.gl. cobe 2.0.1 loads its map texture from a `data:` URI (blocked
      by `img-src 'self' blob:`), injects an inline `<style>` (blocked by
      `style-src 'self'`) and has one arc width for all arcs; globe.gl pulls
      in three.js, well past the ~150 KB gz limit. The page's JS is ~2 KB gz
      up front plus ~5 KB gz lazy (renderer + country centroids and land
      mask from Natural Earth, `static/scripts/gen-attack-map-geo.mjs`), and
      the CSP is unchanged. Arc width follows the %, colours come from
      `--accent-2` (origin) and `--accent` (target), rotation starts paused
      under `prefers-reduced-motion` and has a pause button, and an
      accessible "most active pairs" table is the text alternative.
      Country names come from `Intl.DisplayNames`.
    - Each tab has its own globe and an accessible table (countries and
      events; or origin → target pairs). A globe only loads and animates
      once its tab is shown.
- **2026-10-30 — Radar: cybersecurity alerts and news aggregated from RSS**
  (decision by the repo owner). A new page (`/radar/`, `/en/radar/`, with
  the "requires server" badge) lists alerts and news from fixed sources.
  The Worker collects them on a schedule and `GET /api/radar` serves them
  from KV.
    - **Sources** (URLs confirmed 2026-10-29). Alerts: CNCS (PT), CERT-EU
      security advisories, NCSC UK (all-content feed), CISA KEV (JSON).
      News: The Record, BleepingComputer, SecurityWeek, Dark Reading.
      **ENISA dropped**: its new website discontinued RSS feeds and the old
      URLs return 404.
    - **Every 6 hours, on its own cron trigger** (`13 */6 * * *`, chosen
      by Claude under the owner's "do it the best way" after the owner
      asked whether once a day would do). RSS has no "only what's new"
      request, so every collection downloads each feed whole. Every 6 h
      means 4 KV writes/day instead of 48 at `*/30`. Items reach the page
      at most 6 h late, which is fine for a radar. A separate trigger is a
      separate invocation with its own 10 ms of Free-plan CPU, so the CNCS
      feed (the Worker's heaviest job, ~4–5 ms in Node) doesn't share a
      budget with the cache warm-up. Once a day was rejected because news
      up to 24 h old turns the page into a daily digest. The `*/30` tick
      only reads `radar:feed`: if the key is missing (first deploy, or 7
      days without a collection), it collects right away instead of
      leaving the page empty for up to 6 h.
    - **Collection, never on request.** All sources are fetched in
      parallel, each with its own timeout (8 s) and byte cap (1 MiB; 4 MiB
      for CNCS, whose feed is ~1.7 MB and oldest-first; 64 KiB for KEV,
      which is newest-first, so the start of the ~1.8 MB catalog is
      enough). Redirects are refused (`redirect: 'manual'` + any 3xx is
      a failure; workerd rejects `'error'`): a moved feed
      shows up as down instead of being followed off the fixed list. A
      source that fails is `ok: false` and keeps its items from the
      previous run; it never takes the others down. The route only reads
      `radar:feed`, behind the data-center Cache API (30 min) and a 60/min
      per-client rate limit.
    - **Pure parsing, no dependencies** (`src/lib/radar-feed.js`): a minimal
      RSS 2.0/Atom reader that skips CDATA and comments, decodes entities,
      strips HTML, truncates titles (160), keeps only `https:` links with no
      credentials, and drops items with an invalid date or one more than
      1 h in the future. Titles go through `sanitizeText`. Items are sorted
      by date, deduplicated by URL, capped at 10 per source and 80 in total.
      Stored shape: `{generated, sources:[{id,name,type,lang,ok}],
      items:[{t,u,s,d}]}`.
    - **Budgets.** KV: 4 writes/day, so the Worker's total goes from ~440
      to ~445/day. CPU: the parser reads dates first and only cleans the
      newest items. If the Radar's own invocation still hits the limit,
      drop CNCS's full-history feed.

- **2026-10-02 — Remove two tools** (decision by the repo owner): the
  passkey lab and the encoder/decoder. They are generic utilities that
  other tools do better (CyberChef, for one). The password generator was
  removed in the same pass and restored on 2026-10-03 at the owner's
  request. The old URLs 301 to the tools index. `encoding.js` stays,
  because the Lab terminal's `encode`/`decode` commands use it.

- **2026-10-02 — Retire the internal honeypot** (decision by the repo
  owner; [ADR 0022](../docs/adr/0022-retire-internal-honeypot.md)). The
  decoy paths sat behind a Managed Challenge and saw little mass scanning,
  and the IP list from ADR 0020 existed for a correlation with the
  external Cowrie honeypot that was never built. Removed: decoy routes,
  `recordHoneypot`, `iplist`, `/api/honeypot`, `/api/map`, `/api/ticker`
  (its ATT&CK tagging only served the decoy correlation) and the site's
  Honeypot page. `/api/threat-intel` keeps only `firewall7d`. The cron's
  `purgeLegacyHoneypotKeys` deletes the leftover KV keys, reading first so
  later ticks write nothing. Write budget: ~810 → ~440/day. Owner-side
  follow-ups: delete WAF rule 3 and the `NVD_API_KEY` secret.

- **2026-09-25 — Fixes for the security audit run with Cloudflare's
  `security-audit` skill** (requested by the repo owner; the report is
  not published). All four findings were addressed in one PR:
    1. *(medium, confirmed)* Uncapped KV writes from public GETs via
       `cached()`. Request-driven refreshes now draw from a
       `CACHE_WRITE_CAP` budget (80 writes/day) and serve stale copies
       past it. The cron is exempt, and the short-TTL routes are
       cached in the data-center Cache API first.
    2. *(low, confirmed)* The caps counted events, not writes, and the
       HIBP cache was uncounted. `underCap` now takes a `cost`. The
       per-client rate-limit state and the HIBP cache moved to the Cache
       API, which uses no KV writes. See ADR 0003 and ADR 0006 updates.
    3. *(needs validation)* An unbounded decoy path in `recent` — moot
       since the honeypot's retirement (ADR 0022).
    4. *(needs validation)* `verify-headers.yml` on `deployment_status` ran with
       `CI_WAF_TOKEN`. The token is now withheld from `deployment_status`
       runs and only ever sent to the production origin
       (`isProductionTarget`), including by `verify-tls.yml`. The part
       source cannot close is a workflow file modified in a fork commit.
       That needs the owner to keep Pages from building fork PRs and to
       move the secrets to an Environment restricted to `main`
       (`docs/cloudflare-deploy.md` §6–§7).
  Hardening from the same report still in place: a rate-limiter failure
  on `POST /api/vitals` returns the uniform 204, and the EXIF map link
  requires finite coordinates.

- **2026-07-29 — `verify-worker.yml` workflow: closes the detection → alert
  loop** (discussed with the repo owner after the same day's security
  review): the Worker-backed panels are **pull-only** — they show data
  when someone opens the page on purpose, but nothing alerts anyone when
  something breaks. A daily workflow
  (`.github/scripts/check-invariants.mjs`) checks `/api/health` (the only
  critical invariant — depends on no third-party upstream) and the
  Worker's read routes (informational: one failing alone is treated as an
  unstable upstream, `429` is treated as the protection working, not a
  failure; two or more at once counts as a failure, a sign the Worker
  itself broke). On failure, it opens an Issue (label `automated-alert`,
  created at runtime) — or comments on one already open, instead of
  duplicating; once it passes again, it closes it itself. Uses `gh`
  instead of a third-party action
  ([ADR 0017](../docs/adr/0017-gh-cli-em-vez-de-actions-terceiras.md)).

- **2026-07-29 — Rate limit fails closed when the global write cap runs
  out** (finding A1 of the 2026-07-29 security review, not published;
  [ADR 0003](../docs/adr/0003-rate-limit-kv-vs-nativo.md)): `rateLimit()`
  kept returning `allowed: true` when `RATE_LIMIT_WRITE_CAP` (300
  writes/day) ran out — ~300 trivial requests would disable the route's
  rate limit until midnight UTC. Fixed to fail **closed**: with the cap
  exhausted, the route returns 429 to all clients until the day's budget
  reopens, with a noisy `ratelimit_write_cap_exhausted` log. A regression
  test in `test/logic.test.mjs` pins the behavior. **Pending (manual
  decision, outside what a code PR can express):** replace this with a
  native Cloudflare Rate Limiting rule (WAF, free on the Free plan).

- **2026-07-29 — `npm ci --ignore-scripts` in `ci.yml` (static and
  worker)**: no dependency runs an arbitrary postinstall during CI's
  `npm ci` — the most common npm package-compromise vector. Verified
  before applying: neither `astro build/check/test` nor the Worker's
  `npm test` + `wrangler deploy --dry-run` need install scripts; only the
  real `wrangler dev`/`deploy` do (the workerd binary), and those stay
  outside CI.

- **2026-07-29 — `security-supply-chain.yml` workflow (weekly + manual): `npm
  audit signatures` + SBOM (CycloneDX)**: verification of npm registry
  signatures (catches a package served without its expected signature —
  a compromised registry, a tampered mirror) and a real SBOM of what's
  installed, as a workflow artifact. Weekly rather than per-PR (cadence
  reasoning in `docs/ci-cd.md`). `dynamic/worker/package.json` gained a
  `version` field (required by `npm sbom` to generate a valid purl).

- **2026-07-29 — `check-headers.mjs` accepts an optional Access Service
  Token** (`ACCESS_CLIENT_ID`/`ACCESS_CLIENT_SECRET`, repo secrets), so
  the production checks can pass Cloudflare Access where it still
  applies. It only follows redirects within the same origin, so Access
  credentials never follow a 3xx off the domain. Without the secrets, the
  check behaves as before.

- **2026-07 — "This Site" section (observability)** (approved by the repo
  owner). Two additions to the Worker, both **zero-PII** and
  **best-effort** (never take down the core):
    1. **7-day firewall accumulation:** the cron snapshots the last 24h's
       firewall breakdown into a daily snapshot (`fw:<day>`, TTL 8d) and
       `/api/threat-intel` merges 7 days. This is how the 24h window (the
       raw dataset's limit on Free) gets extended to 7 days, with only
       per-action/origin/country counters. The cron (`*/30 * * * *`) is
       required for this.
    2. **First-party RUM for Core Web Vitals** (`POST/GET /api/vitals`,
       `lib/vitals.js` + `static/public/js/vitals.js`). The browser
       measures LCP/CLS/INP/TTFB with `PerformanceObserver` and sends
       **once** via `sendBeacon`; the Worker accumulates **daily
       histograms** and returns the **p75** per metric. **Aggregates
       only**: never the individual sample, nor IP, UA, or URL
       (restricted Content-Type, body ≤2KB, rate limit, write cap). Why
       first-party and not Cloudflare's RUM: theirs is a **third-party
       script**, incompatible with the strict CSP and with the site's
       "no trackers" stance. **To disable**: remove
       `<script src="/js/vitals.js">` from `BaseLayout.astro`.

- **2026-07 — Detail by HTTP status code in the "Cloudflare Status"
  panel** (approved by the repo owner): a **"requests rejected by HTTP
  status code · 7d"** table (4xx/5xx only) from
  `httpRequests1dGroups.responseStatusMap`, a sibling of the `countryMap`
  already in use. Lives in the core request (as stable as `countryMap`).
  Pure logic in `cf-analytics.js` (`blockedByStatus`), tested.
  `threatPathingMap` was tested and dropped (sparse to the point of
  useless). It stays alongside the firewall tables below as a
  complementary signal.

- **2026-07 — Firewall events on the Free plan: the raw dataset works**
  (two corrections of an earlier wrong conclusion, approved by the repo
  owner): `firewallEventsAdaptive**Groups**` (aggregated) is Pro+ and
  answers "does not have access to the path" on Free, but
  `firewallEventsAdaptive` (**raw**, 24h retention) works on Free with the
  firewall read scopes (Zone Firewall Services:Read, Zone WAF:Read,
  Account Firewall Access Rules:Read). Aggregation therefore happens in
  the Worker:
    - `CF_FIREWALL_QUERY` → `firewallBreakdown`: by action, origin and
      country (accumulated to 7 days by the snapshot above).
    - `CF_FIREWALL_DETAIL_QUERY` → `firewallDetailBreakdown`: most
      targeted URLs, user-agents and networks (ASN), 24h only. A
      **separate** request so a schema drift in these fields never wipes
      out the action/origin/country tables. Weighted by `sampleInterval`,
      path/UA through `sanitizeText`, ASN through `normalizeAsn`.
    - **`clientIP` stays out** — it's in the dataset, but never requested
      or processed. Zero-PII is the site's choice, not a Free limitation.
    - No 7-day accumulation for the detail tables — it would grow the
      retained-data footprint without an explicit request for it.

- **2026-07 — Dependabot security-only alongside Renovate** (repo owner's
  decision; [ADR 0002](../docs/adr/0002-renovate-dependabot-split.md)):
  Renovate handles all *version updates*, but **Dependabot security
  updates** stays enabled because Renovate only opens security PRs for
  **direct** dependencies; transitive ones deep in `package-lock.json`
  aren't reached by it, not even with `osvVulnerabilityAlerts`. The case
  that prompted it: `sharp`/`libvips` (High,
  CVE-2026-33327/33328/35590/35591), pulled in by `wrangler` in
  `dynamic/worker/`. Not enabled: Dependabot *version updates* (would
  collide with Renovate) and its auto-dismiss rules (the "low-impact
  dev-scoped" rule would have dismissed that very alert).

- **2026-07 — Compromised-password checker (k-anonymity)** (approved by
  the repo owner): checks whether a password appears in known breaches
  via Have I Been Pwned's *range API*, **without the password ever
  leaving the browser**. The client computes the SHA-1 locally
  (WebCrypto), sends only the first 5 hex characters to the Worker
  (`GET /api/pwned-range?prefix=XXXXX`), receives ~800 suffixes sharing
  that prefix, and matches locally. The Worker is an anonymizing *relay*
  (HIBP sees Cloudflare's egress IP, not the visitor's) and sends
  `Add-Padding: true`. Pure logic in `dynamic/worker/src/lib/pwned.js`
  and `static/src/scripts/pwned.js`, tested with known vectors. Strict
  prefix validation (`^[0-9A-F]{5}$` — not an open proxy), rate limiting
  from day one, 24h cache per prefix, zero prefix logs. Lives at
  `/ferramentas/pwned/`.

- **2026-07 — CT watcher (Certificate Transparency monitor for the
  domain itself)** (approved by the repo owner): the Worker queries
  public CT logs via crt.sh (two queries — apex and `%.domain`),
  deduplicates precert/leaf by serial, and compares every issuance from
  the last 90 days against the `CT_EXPECTED_ISSUERS` allowlist (default:
  Let's Encrypt + Google Trust Services). Anything outside it shows up as
  "unexpected" — the first signal of a DNS/registrar takeover. Panel on
  the Evidence page (`/este-site/provas/`), `GET /api/ct` with a 6h cache
  + stale-while-revalidate, warmed by the cron. No visitor input — not
  reusable as a proxy, no rate limit needed. Pure logic in
  `dynamic/worker/src/lib/ct.js`, tested with realistic crt.sh vectors.

- **2026-07 — Tools with a backend live under `/ferramentas/`** (repo
  owner's decision): server-backed tools get their own page and appear in
  the index with a "requires server" badge (green "client-side" for the
  rest), instead of client-side being an implicit contract of the index.
  The Security page keeps the narrative and links to the tool instead of
  embedding it. Today that's `pwned` and `mirror`.

- **2026-07 — New tools** (approved by the repo owner, after a proposal
  with mockups):
  - **CSP Analyzer** (`/ferramentas/csp/`, **100% client-side**): paste a
    `Content-Security-Policy` and get a directive-by-directive read —
    `unsafe-inline`/`unsafe-eval`, bypassable wildcards, JSONP/CDN hosts,
    bare schemes, and missing directives (`base-uri`, `object-src`,
    `frame-ancestors`, `form-action`), with a deterministic letter grade.
    Pure logic in `static/src/scripts/csp-lint.js`, tested with vectors
    (`static/test/csp-lint.test.mjs`); messages are i18n IDs.
  - **Mirror** (`/ferramentas/mirror/`, **requires a server**): shows the
    visitor what any server learns about them from the handshake
    (TLS/cipher, HTTP, country/ASN, User-Agent, Accept-Language) next to
    what the browser reveals locally (screen, timezone, cores, theme).
    `GET /api/mirror` takes **no visitor input** and writes **no state**
    (only rate limiting). It **returns the visitor's own IP to the
    visitor only** (owner decision 2026-10-05,
    [ADR 0023](../docs/adr/0023-mirror-echoes-client-ip.md)), validated
    fail-closed (`normalizeIp`), **never stored or logged**, hidden on the
    page until the visitor clicks "show". Pure logic in
    `dynamic/worker/src/lib/mirror.js` (`serverView`, `normalizeIp`),
    tested — including that nothing in KV ever contains the IP. Rate limit
    30/min per client; `no-store`, so no shared cache can serve one
    visitor's IP to another.

- **2026-07 — Cron cache aligned to the interval** (direct request from
  the repo owner after a real "50% of your daily Workers KV operation
  limit reached" alert, with the site still unpublished): the source was
  the cron (`*/30 * * * *`), not traffic. Two fixes: (1) cache TTLs
  shorter than the cron interval meant every tick found the cache stale
  and rebuilt it — TTLs of threat-intel/cf-stats/ct are now 6h; (2) the
  firewall snapshot ran on every tick, not only when cf-stats actually
  refreshed — it moved inside `cached()`'s producer (48 → ~4 writes/day on
  that key). The same reasoning is in the `[triggers]` comment in
  `wrangler.toml`.

- **2026-10 — k threshold on the firewall URL/user-agent tables, and a
  Durable Object for Web Vitals** (both left open by the 2026-10 security
  audit; decided and requested by the repo owner):
  1. `/api/cf-stats` only publishes a firewall URL or user-agent seen at
     least `CF_FIREWALL_MIN_COUNT` = 5 times in the 24h window (weighted by
     `sampleInterval`; the cut is inclusive). A rare path/UA can identify a
     single visitor (an exact-version UA, a token in a URL) and the panel is
     public. Actions, origins, countries and ASNs are coarse aggregates and
     have no threshold. The page says so (`firewallMinNote`, intro).
  2. `/api/vitals` keeps its histograms and the per-day sample cap in a
     **Durable Object** (`VITALS`, class `VitalsCounter`, SQLite storage —
     the only kind the Free plan allows). The KV read-modify-write lost
     concurrent samples and its cap overshot (`underCap` is not atomic);
     the DO serialises both, so each accepted sample counts exactly once and
     the cap (1000 samples/day, per UTC day) is exact. Side effect: vitals no
     longer spend the KV write budget (the 300/day line is gone). It is the
     Worker's only new product surface: one object (`idFromName('global')`),
     no public route, reachable only through the binding. Reads fall back to
     the legacy `vit:<day>` KV keys (they expire in 9 days) if the DO is
     down or lacks a day; that fallback can be deleted after the transition.

## Removed features and reverted decisions

One line each; the full entries are in this file's git history.

| Date | What | Why / where |
| --- | --- | --- |
| 2026-10-02 | Internal honeypot (decoys, IP list, map, KEV/NVD ticker, Honeypot page), and its write caps | [ADR 0022](../docs/adr/0022-retire-internal-honeypot.md); supersedes ADR 0007, ADR 0020 |
| 2026-10-02 | Passkey Lab and encoder/decoder tools | Generic utilities others do better (entry above) |
| 2026-09-26 | `.mcp.json` (project-scoped Cloudflare MCP servers) | Loaded on every turn for little use; [ADR 0008](../docs/adr/0008-mcp-cloudflare-so-leitura.md) |
| 2026-08-16 | "Sigma Playground" idea and `content/detections.json` | The rules were only the path→technique mapping in another notation |
| 2026-08-06 | CSP violation reporting (automatic, then manual button; `/api/csp-report`, `/api/csp-violations`, `csp_report_fuzz.js`) | `self`/`self` alerts were suspected to come from Cloudflare's challenge page, so the control couldn't tell noise from a regression; [ADR 0005](../docs/adr/0005-csp-report-manual.md). The CSP is still enforced |
| 2026-08-06 | Header self-scan (`/api/scan`, `/ferramentas/self-scan/`) | Bot Fight Mode/WAF served the Worker's own `fetch()` a challenge page, so it graded that page. External scanners cover it (`docs/ci-cd.md`) |
| 2026-07-31 | `DEBUG_EXPOSE_SELF_PATH` (pathname in self/self CSP reports) | Temporary diagnostic, reverted when Access stopped covering production |

## Shelved ideas (presented, **not approved** for implementation)

Recorded so they aren't lost, not to be built without a new decision:

- **Link Unpacker (phishing URL triage)** — 100% client-side in
  `static/`: paste a suspicious URL and the tool takes it apart *without
  ever visiting it* — the true registrable domain vs. a decoy subdomain
  (`paypal.com.conta-segura.xyz`), punycode/homoglyphs, redirects
  embedded in parameters, the `@` trick in the authority, frequently
  abused TLDs. A verdict by "signals", never a binary safe/unsafe. No
  network, no abuse risk; small-to-medium effort (heuristics + an
  embedded Public Suffix List subset).

## Next tools

Network and security tools that can't run in the browser alone (they
need server-side queries, ports the browser can't reach, or private API
keys). Each needs an explicit go-ahead from the repo owner before work
starts, and would be served by the existing Worker under `/api/*` and
listed under `/ferramentas/` (and in the Lab) with the "requires server"
badge.

| Priority | Tool | Why it needs a backend |
| --- | --- | --- |
| 1 | **DNS lookup** (A, AAAA, MX, TXT, NS, CNAME, SOA) | direct DNS queries to arbitrary resolvers; the browser's DoH doesn't cover every type/resolver |
| 2 | **Whois** for domains and IPs | the whois protocol (port 43) isn't reachable from the browser |
| 3 | **HTTP security header analysis** for any site | CORS prevents the browser from reading third-party sites' headers |
| 4 | **IP blacklist check** (DNSBL) | requires reverse DNS queries against lists like Spamhaus |
| — | (future ideas) TLS certificate check, port check | raw network access |

Principles, from day one:

1. **Rate limiting** — these tools query third parties on a visitor's
   behalf; they can't turn into an open proxy.
2. **No personal state or logs** — queries aren't stored.
3. **Strict input validation** on the server (hostnames, IPs) before any
   external query.
4. **KV write budget** — any new write path draws from a sized daily
   budget (ADR 0006), or stays in the Cache API.
5. **Same look** as the rest of the site: `static/src/styles/global.css`
   tokens and shared components.
