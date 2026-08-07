# CI/CD — build and security pipeline

The single source for the detail behind every check that runs on push/PR
or against production. `README.md` keeps only a summary with a link here —
this table is the full version.

## Checks on every push/PR

| Check | Where | What it guarantees |
| --- | --- | --- |
| **Build + `npm audit`** | `ci.yml` | The site builds with no errors, no high/critical advisories in dependencies. |
| **CodeRabbit** | GitHub App (`.coderabbit.yaml`), not a workflow | AI-assisted PR review, free on a public repo. Not a blocking gate — a comment, not pass/fail. Calibrated with per-folder `path_instructions` (e.g. reminds it of the KV write budget in `dynamic/worker/`, PT/EN parity in `i18n/`, thin routes in `pages/`) instead of generic. |
| **Dependency Review** | `dependency-review.yml` | Blocks PRs that introduce a new dependency with a known vulnerability, scoped to the PR's diff (GitHub Dependency Graph) — the fast gate, complementary to the full-lockfile OSV-Scanner sweep below. |
| **OSV-Scanner** | `security.yml` | `package-lock.json` has no known vulnerabilities ([OSV.dev](https://osv.dev), includes GHSA); fails CI on any known advisory. |
| **gitleaks** | `security.yml` + local hook | Scans for secrets (Cloudflare tokens, keys) matching its configured rules — detection, not a guarantee against every possible secret. Locally: `pipx install pre-commit && pre-commit install`. |
| **CodeQL** | `codeql.yml` | Semantic SAST for JavaScript/TypeScript — a different analysis class from Semgrep's pattern-matching, run separately. |
| **Semgrep** | `security.yml` | SAST via `p/typescript`/`p/javascript` plus custom rules for DOM-XSS sinks in `.astro` components (`.semgrep/`) — public rulesets don't parse that file type. |
| **zizmor** | `security.yml` | Audits the workflows themselves: missing pins, excessive permissions, template injection, persisted credentials. |
| **Headers in production** | `headers.yml` | After every deploy (and a daily cron), production is checked against `.github/expected-headers.json` — a missing or regressed security header fails the workflow. |
| **`npm audit signatures` + SBOM** | `supply-chain.yml` (weekly + manual) | Verifies npm registry signatures (catches a package served without its expected signature) and generates a CycloneDX SBOM for both lockfiles, as an artifact. |
| **Production invariants** | `invariants.yml` (daily + manual) | Checks `/api/health` and the Worker's read routes; opens an Issue if something is genuinely broken (self-closes when it recovers). Closes the loop the honeypot/threat-intel dashboards otherwise leave open — they're pull-only, so nothing used to alert anyone without someone looking. |
| **TLS/cipher/vuln scan in production** | `tls-check.yml` (monthly + manual) | Runs [testssl.sh](https://testssl.sh) against production; findings are classified by testssl.sh's own severity — CRITICAL/HIGH (weak protocols, known vulnerabilities like Heartbleed/POODLE, an invalid/expired cert) fail the workflow, MEDIUM/LOW only warn. |
| **DNS hygiene in production** | `dns-check.yml` (weekly + manual) | Checks SPF, DMARC, CAA, and the DNSSEC trust chain (`AD` flag from two independent resolvers) against what [`docs/dns-tls.md`](dns-tls.md) documents as already correct — a regression fails the workflow; a still-missing CAA record (a known, documented gap) only warns. |
| **Mozilla Observatory grade in production** | `observatory-check.yml` (weekly + manual) | Calls the free [Mozilla HTTP Observatory](https://github.com/mdn/mdn-http-observatory) API — a second, independent grading rubric (cookies, redirect chain, cross-origin isolation) on top of the exact-header checks in `headers.yml`. Grade D/F fails the workflow, B/C only warns. |
| **Fuzzing** ([ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) + Jazzer.js) | `fuzzing.yml` (manual only — see note below) | Two harnesses fuzz the three Worker functions that parse untrusted network input — `parseReports()` (CSP-report parsing) and the output sanitizers `sanitizeText()`/`escapeHtml()` — since those, unlike the client-side tools, are a real trust boundary. |
| **Signed releases** | `release.yml` (on `v*` tag + manual) | Builds `static/dist` and a dry-run Worker bundle, generates a CycloneDX SBOM for both, and signs their provenance with Sigstore ([`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)) before attaching everything to a GitHub Release. Doesn't touch the real deploy — that's automatic via Cloudflare (Pages + Workers Builds on push to `main`), outside this workflow; see [`docs/cloudflare-deploy.md`](cloudflare-deploy.md). |

## Cross-cutting practices

Every action **pinned to a commit SHA** ([Renovate](../renovate.json5)
keeps the digests current and batches updates into a weekly PR),
`permissions: {}` by default with least-privilege per job,
`persist-credentials: false` on every checkout, and
`npm ci --ignore-scripts` in `ci.yml` (no dependency runs an arbitrary
postinstall in CI). The CSP is one static line in
`static/public/_headers` — no hashes, because there's no inline
`<script>`/`<style>` on the site (see
[`docs/security-headers.md`](security-headers.md) and
[ADR 0001](adr/0001-csp-sem-inline.md)). The DNS/TLS plan (CAA, HSTS
preload, DNSSEC) lives in [`docs/dns-tls.md`](dns-tls.md). The Cloudflare
deploy process (domain, Pages, Worker, Access, WAF) and the real
incidents hit along the way are in
[`docs/cloudflare-deploy.md`](cloudflare-deploy.md).

## Cadence

**SBOM/signature verification — weekly, not per-PR.** This cadence
predates the repository going public, when Actions minutes were metered
against the private-repo free tier (2,000 min/month). Public repos get
unlimited Actions minutes, but the weekly cadence stayed — SBOM drift and
signature checks don't need per-PR granularity, and there was no reason
to change a schedule that was already working. Full context in
[`docs/security-review-2026-07-29.md`](security-review-2026-07-29.md) §0.

**Fuzzing has no cron.** `fuzzing.yml` has no cron for now — `language:
javascript` + `sanitizer: coverage` (the only `SANITIZER` value accepted
by both the OSS-Fuzz compile script and the ClusterFuzzLite action's own
validator for JS) makes `google/clusterfuzzlite/actions/build_fuzzers`
compile unrelated honggfuzz/AFL compiler-wrapper binaries alongside the
real JS targets, and `run_fuzzers` treats them as fuzz targets, failing
instantly. Confirmed independent of the pinned commit — it and the
action's current `main` both resolve to the same floating
`gcr.io/oss-fuzz-base/clusterfuzzlite-build-fuzzers:v1` Docker image, so
the bug lives there, not in this repo. The workflow stays
`workflow_dispatch`-only until upstream fixes it. That floating tag is an
accepted residual risk, not an oversight: it's resolved entirely inside
Google's own action (this repo has no way to pin it to a digest without
forking the action), the workflow only runs on manual dispatch (never
automatically on untrusted input), and it's revisited whenever upstream
changes the tag's behavior enough to unblock the JS sanitizer bug above.

## External scans (manual)

Beyond the automated checks above, these third-party scanners run
manually against production, not wired into CI — either because they have
no API, the API is redundant with a check this repo already runs, or the
free tier doesn't fit a recurring cron (tool-by-tool reasoning in
[PR #155](https://github.com/blindtk/personal-site/pull/155)). Each link
below is a live report for `danielmala.co`, not a static snapshot — the
grade column is a point-in-time reading (last checked 2026-08-07) and
will drift as the site or the tool's rubric changes; `—` means the tool
doesn't produce a single comparable grade (categorical/diagnostic report,
or genuinely ad-hoc):

| Scanner | What it checks | Grade | Report |
| --- | --- | --- | --- |
| ImmuniWeb | Full website security test — HTTP security headers (including CSP directive-by-directive), GDPR/PCI DSS compliance signals, cookie privacy, external content and CMS/component fingerprinting, AI-crawler/bot-scraping protection (`robots.txt` + Cloudflare AI Crawl Control), and DNSSEC chain validation | A | [immuniweb.com](https://www.immuniweb.com/websec/danielmala.co/) |
| Qualys SSL Labs | TLS/cipher/certificate grade | A+ | [ssllabs.com/ssltest](https://www.ssllabs.com/ssltest/analyze.html?d=danielmala.co) |
| Security Headers | HTTP security header grade (A+–F) — an independent scorecard on the same headers `headers.yml` already pins to an exact expected set | A+ | [securityheaders.com](https://securityheaders.com/?q=danielmala.co&followRedirects=on) |
| Mozilla HTTP Observatory | Headers, cookies, redirects, cross-origin isolation — see `observatory-check.yml` above for the automated half | A+ | [developer.mozilla.org/observatory](https://developer.mozilla.org/en-US/observatory/analyze?host=danielmala.co) |
| Hardenize | DNS/TLS/email configuration monitoring | — | [hardenize.com](https://www.hardenize.com/report/danielmala.co/1785606965) |
| DNSViz | Independent DNSSEC chain validation and visualization | — | [dnsviz.net](https://dnsviz.net/d/danielmala.co/dnssec/) |
| Cloudflare Agent Readiness | AI-agent/LLM discoverability — canonical/hreflang signals exposed via HTTP `Link` headers, for agents that skip HTML parsing | — | [isitagentready.com](https://isitagentready.com/danielmala.co) |
| MXToolbox | Ad-hoc DNS/email lookups (blacklists, SPF/DMARC syntax) | — | [mxtoolbox.com](https://mxtoolbox.com/) |
