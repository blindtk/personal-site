# Architecture — blindtk/personal-site @ cb439ed

## Product, principals, protected resources
Bilingual (PT/EN) personal security portfolio site for `danielmala.co`. Principals:
- **Anonymous internet visitor / scanner** (lowest trust): browses static pages, calls the Worker's public JSON API, hits honeypot decoy paths, runs client-side tools in their own browser.
- **Third-party upstreams** (semi-trusted data sources): CISA KEV + NVD (ticker), crt.sh (CT watch), Cloudflare GraphQL Analytics (cf-stats), HIBP range API (pwned relay).
- **Repo owner / CI**: GitHub Actions workflows, Renovate/Dependabot PRs, external PR authors (repo is public per ADR 0009).
Protected resources: the Worker's KV namespace (shared daily write budget ~1,000/day on Free plan; honeypot buckets, rate-limit state, caches, `iplist`), secrets `RATE_SALT`, `CF_API_TOKEN`, `NVD_API_KEY` (Worker) and GitHub repo secrets/tokens, integrity of the rendered site (no script injection into other visitors' browsers), availability of the dashboards, visitor privacy (zero-PII except ADR 0020 honeypot IP list).

## Stack and deployment
- `static/`: Astro static site, deployed on Cloudflare Pages; headers from `static/public/_headers` (strict CSP `script-src 'self'` + one JSON-LD hash, `require-trusted-types-for 'script'; trusted-types 'none'`, COOP/COEP/CORP). Client JS in `static/src/scripts/*.js` (pure logic) + `static/src/components/**/*.astro` `<script>` DOM wiring, `static/public/js/{nav,vitals}.js`.
- `dynamic/worker/`: one Cloudflare Worker (`src/index.js`) on zone routes `danielmala.co/api/*` + 5 decoy paths (`wrangler.toml`), `workers_dev=false`. One KV binding. Cron `*/30` warms caches, prunes iplist, snapshots firewall.
- CI: `.github/workflows/*.yml` (CI, CodeQL, semgrep/gitleaks/zizmor security, supply chain, release, labeler, scheduled prod checks via `.github/scripts/*.mjs`). ClusterFuzzLite fuzzes `sanitize.js`.
- Offline test: `dynamic/worker` `node --test test/` and `static` `node --test test/` import pure modules only (no node_modules present; Astro build not runnable offline).

## Entry surfaces and key paths
1. Worker HTTP router `dynamic/worker/src/index.js:464` — OPTIONS/CORS (`corsHeaders` :437, `ALLOWED_ORIGINS` empty), decoys (`isDecoy` → `recordHoneypot` :106 → KV buckets/`recent`/`iplist`), `POST /api/vitals` (:501, content-type check, rateLimit, 2 KiB body, `normalizeVitals`, `recordVitals` with daily cap), GET `/api/honeypot|map|threat-intel|vitals|ct|cf-stats[?refresh=1]|ticker|mirror|pwned-range?prefix=`.
2. Rate limiting `rateLimit` :375 (KV `rl:<route>:<sha256(ip+dailySalt)>`, `lib/ratelimit.js`), global caps `lib/kvcap.js` (`rlcap`, `wcap`, `vitcap`, `refreshcap`). `cf-connecting-ip` header trusted as client identity.
3. Stored/second-order data: decoy request → `country`/`asn`/`path`/`technique` (normalized in `lib/sanitize.js`) → aggregate (`lib/aggregate.js`) → `/api/threat-intel`/`/api/honeypot`/`/api/map` → browser dashboards (`HoneypotPage.astro`, `SiteOverviewPage.astro`, `HostMap.astro`, `static/src/scripts/observability.js`).
4. Upstream data: `lib/feeds.js`, `lib/ct.js`, `lib/cf-analytics.js`, `lib/pwned.js` → sanitize → KV cache → `Ticker.astro`, `CtWatch.astro`, `CloudflarePage.astro`, `PwnedCheck.astro`.
5. `/api/mirror` → `lib/mirror.js serverView` reflects request headers/cf metadata → `Mirror.astro`.
6. Client-only tools (`static/src/scripts/{exif,email-headers,csp-lint,encoding,md5,passkeys,password,subnet,lab-terminal}.js` + `components/tools/*.astro`) process visitor-supplied files/text inside the visitor's own browser (self-impact unless a URL/share parameter injects input).
7. CI: workflow triggers (`pull_request`, `schedule`, `deployment_status`, `workflow_dispatch`, `release`), `permissions: {}` defaults, scripts consuming external content (`github.event.deployment_status.environment_url` in `headers.yml:37`).

## Trust boundaries and strongest visible controls
- Visitor → Worker KV budget: per-client KV rate limit + global daily caps failing closed (`index.js:395-414`).
- Visitor/decoy request → stored dashboard → other visitors' DOM: `sanitize.js` normalization + CSP/Trusted Types `'none'` (no HTML sinks permitted).
- Upstream feed → other visitors' DOM: same (sanitize + textContent + Trusted Types).
- Visitor → HIBP relay: 5-hex prefix validation `lib/pwned.js normalizePrefix`.
- Public internet → Worker: zone routes only (`workers_dev=false`); WAF/Access state is deployment-only (not source-visible).
- External PR author → CI secrets/tokens: `permissions: {}`, no `pull_request_target` found, pinned actions (zizmor in `security.yml`).

## Starting paths
`dynamic/worker/src/index.js`, `dynamic/worker/src/lib/*.js`, `static/src/components/**`, `static/src/scripts/*.js`, `static/public/js/*.js`, `static/public/_headers`, `.github/workflows/*.yml`, `.github/scripts/*.mjs`.

## Prior coverage
No compatible prior `coverage-ledger.json`/`findings.json`. A prose review exists (`docs/security-review-2026-07-29.md`, finding A1 rate-limit fail-open — fixed in source); used only as context, not as coverage.

## Companion selection
- `WEB-PROTOCOL-AND-AUTH.md` (HTTP framing and cache): Worker sets cache-control/CORS on public JSON routes behind a CDN.
- `CLIENT-SIDE.md` (DOM and object-state): stored/upstream data rendered into other visitors' DOM; client tools parse untrusted files.
- `RESOURCE-EXHAUSTION-AND-AVAILABILITY.md` (Quota and scheduling): shared KV daily write budget reachable by anonymous visitors.
- `SUPPLY-CHAIN-AND-RELEASE.md` (CI and automation): public repo with GitHub Actions.
- Excluded: AI-AND-LLM (no model/tool surface in runtime code), MEMORY-SAFETY (JS only), DESKTOP-MOBILE, PROTOCOLS-RPC, DATA-ISOLATION (single-tenant, no user accounts), CLOUD-AND-DEPLOYMENT (IAM/infra not in source beyond wrangler.toml; covered by Worker units as needs_validation where decisive).
