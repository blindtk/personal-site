# Security audit — blindtk/personal-site

**Method:** [cloudflare/security-audit-skill](https://github.com/cloudflare/security-audit-skill), full-audit workflow, `quick` profile.
**Source ref:** `cb439ed1f8915a0cb7f7b09325f7fb62d515579c` (branch `claude/security-audit-personal-site-hixdg8`, clean worktree).
**Date:** 2026-09-25.

## 1. Run summary and limits

- **Profile:** `quick`. This was one hunter wave followed by one final coverage-critic pass, with one fresh independent verifier per candidate (in `quick`, Phase 3 and Phase 5 are merged). **It is a partial pass, not a claim of exhaustive coverage.**
- **Scope:** `dynamic/worker`, `static/src`, `static/public`, `static/astro.config.mjs`, `.github`, `.mcp.json`, `.clusterfuzzlite`. `content/` (markdown/JSON only) was not treated as a separate surface.
- **Budget:** 12 agent invocations were planned and 10 were spent: 0 for reconnaissance, 5 hunters, 1 final critic and 4 candidate verifiers.
- **Deviation from the skill:** Phase 1 reconnaissance was done by the parent directly rather than by four delegated `research` agents, because the target is small (~8k LOC of code). The architecture summary is in `architecture.md`.
- **Execution:** only sandboxed source review and local runs. Target code ran only inside an OS-enforced sandbox: user, mount and network namespaces with no network; the whole filesystem read-only except the agent's own scratch directory; `env -i` with an allowlist; and `prlimit` CPU, memory, process and file-size limits plus a wall-clock timeout. Evidence files were promoted with a no-follow, `O_EXCL`, size-bounded procedure. **No deployed endpoint, GitHub API or Cloudflare API was contacted.**
- **Prior runs:** there is no compatible prior ledger. `docs/security-review-2026-07-29.md` was read as context only. Its finding A1 (rate-limit fail-open) is fixed in the current source and was not re-reported.
- **Deferred / out-of-scope units:** none. The final critic returned no missing units and no reassignments (`stop: true`).

## 2. Security posture

The site's injection surface is very well contained. Every piece of runtime data (honeypot records, upstream feeds, the mirror reflection) reaches the DOM only through `textContent` or `setAttribute` with numeric or constant values. That is backed by a CSP of `script-src 'self'` with Trusted Types `'none'`. The CI uses least-privilege `permissions: {}`, actions pinned by SHA, and no `pull_request_target`. The weak spot is **availability of the Worker's shared KV write budget**. Several anonymous paths write to KV outside the global daily caps, or cost more writes than the caps count. A single client can therefore exhaust the Free plan's ~1,000 writes/day and stop honeypot and vitals recording, and eventually the dashboards, until the UTC reset. One CI lead depends on hosted configuration and needs owner validation.

## 3. Confirmed findings

| Severity | Title | Affected boundary | Observed result (local, fake KV) |
|---|---|---|---|
| **Medium** | Uncapped KV writes from public GETs via `cached()` | Anonymous visitor → account-wide KV daily write budget | 3 GETs/min for a simulated day → 3,543 uncapped `cache:*` puts; 20 concurrent stale requests → 20 puts |
| **Low** | Global write caps count events, not writes; pwned cache writes uncounted; caps race | Anonymous visitor → account-wide KV daily write budget | One IP, ~16 simulated min, only capped paths → 1,141 puts; 50 concurrent requests at cap−1 all pass |

### 3.1 [Medium] Unauthenticated GETs to `/api/honeypot`, `/api/map` and `/api/vitals` trigger uncapped KV writes

- **Fingerprint:** `dynamic/worker/src/index.js:cached:uncapped-kv-write-on-public-get`
- **Source:** `dynamic/worker/src/index.js:303-319` (`cached()`, which calls `KV.put` at :309). It is reached from :551 (`/api/honeypot`, TTL 60s), :558 (`/api/map`, TTL 60s) and :616 (`GET /api/vitals`, TTL 120s).
- **Lower-trust principal:** an anonymous internet client. These routes have no rate limit, and the zone route `danielmala.co/api/*` invokes the Worker on every request.
- **Reproduction:** the real router (`worker.fetch`) was imported into the sandbox with an in-memory KV that counts puts and a simulated clock. Each route was requested every 61s for 24h. Separately, 20 concurrent requests were sent while the cache entry was stale.
- **Result:** 4,251 requests, all 200; 3,543 KV puts, all `cache:*`, with no cap key involved. The concurrent burst produced 20 puts, because stale-while-revalidate has no single-flight guard.
- **Conditions:** the Workers KV Free plan (~1,000 writes/day for the whole account, as documented at `index.js:49` and ADR 0006). On a paid plan the effect becomes billed cost rather than an outage.
- **Impact:** the shared daily write budget runs out. Honeypot, vitals and firewall-snapshot recording stop. Rate-limited routes fail. Dashboards return 502 once their stale copy (TTL+600s) expires. Recovery is automatic at the UTC reset. No data is disclosed.
- **Priority rationale:** high likelihood, because ordinary dashboard traffic alone produces this write rate; medium impact (availability only, self-healing).
- **Smallest fix:** move the short-TTL read caches out of KV (use `caches.default`, the Cache API), or raise the TTLs to at least the 30-minute cron interval and refresh only from `scheduled()`. If they stay in KV, put `cached()` behind a global daily `underCap` and add single-flight. Regression test: N sequential requests spaced past the TTL, plus a concurrent stale burst, must produce no more puts than the cap.

### 3.2 [Low] Global daily write caps count events instead of writes; pwned cache writes uncounted; caps race under concurrency

- **Fingerprint:** `dynamic/worker/src/index.js:rateLimit:global-write-cap-accounting-and-race`
- **Source:** `dynamic/worker/src/lib/kvcap.js:21-29` (a non-atomic read-then-increment). `dynamic/worker/src/index.js:395-413` makes two puts per rate-limit cap unit. `index.js:584` makes an uncapped `cache:pwned:<prefix>` put for each new prefix.
- **Lower-trust principal:** an anonymous client using one IP, staying within every per-IP limit.
- **Reproduction:** 20 `GET /api/pwned-range?prefix=<new 5-hex>` requests per simulated minute for 16 minutes, followed by 70 decoy hits. Separately, 50 concurrent decoy requests at `wcap` 59/60, and 50 concurrent `/api/mirror` requests at `rlcap` 299/300. HIBP was stubbed; there was no network.
- **Result:** 1,141 puts in total (rl 300, rlcap 300, cache:pwned 300, honeypot 241). The decoy burst produced 200 puts where 1 cap unit remained. All 50 mirror requests returned 200.
- **Impact:** the ADR 0006 budget arithmetic does not hold. One client can exhaust the account's daily writes through "capped" paths alone. The effect and recovery are the same as in 3.1.
- **Priority rationale:** medium likelihood (about 390 requests in about 16 minutes, no race needed); low impact (daily-reset availability only).
- **Smallest fix:** keep HIBP ranges in the Cache API instead of KV. Charge `rlcap` for 2 writes per allowed request, or move per-client rate limiting to the Workers Rate Limiting binding or a WAF rule (already noted as pending in `dynamic/PLAN.md`). Size all caps together so their sum plus cron stays under the ceiling, leaving margin for concurrency overshoot. Add a regression test that asserts total fake-KV puts from one client stay within budget.

Full traces are in `FINDINGS-DETAIL.md`.

## 4. Needs validation (leads, no severity)

| Title | Trace | Blocker | Local next step | Owner-observed check |
|---|---|---|---|---|
| `headers.yml` on `deployment_status` runs code from the deployment commit with `ACCESS_CLIENT_*` / `CI_WAF_TOKEN` | `.github/workflows/headers.yml:9 → :29 → :41 → :47` | Whether Cloudflare Pages builds fork PRs and creates GitHub deployments for them, and whether GitHub then gives those runs secrets | none (hosted config) | Pages → Settings → Builds (preview/fork builds); past Headers runs' head SHA/ref; Actions fork-PR approval setting; environment protection |
| Unbounded `/phpmyadmin/*` decoy path persisted in `recent` (no TTL) and buckets | `decoys.js:23 → index.js:119 → aggregate.js:17 → index.js:145 → :157` | Edge max URL length for the zone; Workers Free-plan CPU accounting for multi-MB JSON parsing | Run the fixture under `wrangler dev --local` and measure CPU per invocation | Size of KV key `recent`; `exceededCpu` / `honeypot_write_failed` in Workers logs |

Details and exact plans are in `NEEDS-VALIDATION.md`. Both leads have small source-side hardening fixes whatever the deployment answer turns out to be (see §5).

## 5. Hardening notes (not findings)

- **Worker:**
  - Cap and sanitize the stored decoy path, e.g. `sanitizeText(path, 128)` or collapsing it to the matched decoy prefix (`index.js:119`).
  - Check `wcap` before reading `recent`, the buckets and `iplist` in `recordHoneypot`, so capped-out hits cost no reads.
  - Wrap `rateLimit()` in `POST /api/vitals` (`index.js:506`) in `try/catch` like the GET routes.
  - Add `cache-control: no-store` and HSTS to the decoy 404.
  - OPTIONS is handled before `isDecoy`, so decoys answer preflight requests with a 204 (a small honeypot tell).
  - The `cf-connecting-ip` fallback to `'unknown'` is safe only while `workers_dev=false` and `preview_urls=false`.
  - The rate limiter's fail-closed trade-off means one IP can cause a global 429 until UTC midnight; a WAF rate-limit rule would remove this.
- **CI:**
  - Gate `headers.yml` on `github.event.deployment.environment == 'Production'` and `deployment.ref == 'main'`, or scope the secrets to a protected environment.
  - Narrow `target.mjs` so that it no longer trusts every `*.personal-site-4fm.pages.dev` alias.
  - `tls-check.yml` sends `CI_WAF_TOKEN` to the host given in the `workflow_dispatch` input without calling `isTrustedTarget`. Only users with write access can dispatch, but the check should match the other workflows.
  - Semgrep registry rulesets are unpinned. This is already documented in ADR 0015.
- **Client:**
  - `perimeter-charts.js` `techOf` should use `Object.hasOwn`, as `byDecoyPath` does.
  - Assert `Number.isFinite` for lat/lon before building the EXIF map link (`ExifTool.astro:170`).

**Positive patterns observed:**
- There are no HTML sinks for runtime data anywhere, and Trusted Types is set to `'none'`.
- `sanitize.js` normalization is strict: CVE, technique, country and ASN are regex- or number-bound.
- The CORS allowlist is exact-match and empty, with `Vary: Origin`.
- Per-request `/api/mirror` responses are `no-store`, and the IP is withheld.
- The HIBP relay accepts only a strict 5-hex prefix.
- Every workflow uses `permissions: {}`, `persist-credentials: false`, SHA pins and `npm ci --ignore-scripts`.
- The `target.mjs` host allowlist resisted userinfo, suffix, trailing-dot and port tricks in local tests.

## 6. Coverage (from `coverage-ledger.json`)

| Status | Count |
|---|---|
| covered | 4 (client tools/DOM; Worker CORS, cache and mirror; stored honeypot data → DOM; upstream feeds → DOM) |
| candidate | 3 (rate-limited routes and caps; decoy and public GET write paths; CI workflows) |
| blocked | 0 |
| deferred / out_of_scope | 0 |

- **Excluded companion domains** (reasons recorded per unit): AI/LLM, memory safety, data isolation, desktop/mobile/IPC, RPC/messaging, and cloud IAM. Cloud and deployment facts appear as needs-validation blockers instead.
- **Final critic:** no missing units, no reassignments (`stop: true`).
- **Validators:** `validate-findings.cjs` PASS (4 records); `validate-coverage-ledger.cjs` PASS (7 units).
