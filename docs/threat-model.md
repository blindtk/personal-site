# Threat model

Living document — review every quarter or whenever a relevant architecture
decision is made (record the review date at the bottom of this file).
Origin: initial analysis in
[`docs/security-review-2026-07-29.md`](security-review-2026-07-29.md) §8.

## Assets

1. **The Cloudflare account** — by far the highest-value one; a compromise
   gives DNS control, certificate issuance, and traffic interception for
   the domain.
2. **The GitHub repository and its Actions secrets.**
3. **Domain and published-content reputation/integrity.**
4. **Visitor privacy** — the site explicitly promises zero-PII (see
   [ADR 0004](adr/0004-zero-pii-honeypot.md)); it's a breakable
   reputational asset.
5. **The Free-plan quota budget** (KV writes/day, Worker invocations) —
   unusually, a *budget* is an asset here: exhausting it degrades real
   protections (see Attack A1 below).
6. **The site's own security claims** — a site that documents its
   controls takes greater reputational damage if one of them turns out to
   be false.

## Trust boundaries

Internet → Cloudflare edge (WAF/Access) → Worker → upstream KV/APIs.
Developer laptop → GitHub → Cloudflare Workers Builds (automatic deploy,
no verifiable provenance nor reviewer gate — *real gap, see H3*) →
production (see `docs/architecture.md`). npm registry → lockfile → build →
deployed artifact. Upstream feeds (NVD, CISA KEV, crt.sh, HIBP) → Worker →
browser DOM. Browser → POST endpoints → KV.

## Attack surfaces

11 GET endpoints (most with no input); 2 unauthenticated POST endpoints
(`/api/csp-report`, `/api/vitals`); 5 decoy routes; the static site; the
client-side tools (all local except `pwned`, `mirror`); the
GitHub Actions supply chain; the npm dependency tree; the Cloudflare
dashboard/API credentials.

## Most likely attacks

### A1 — Rate limit disablement via write-budget exhaustion
**Status: fixed on 2026-07-29** (see [ADR 0003](adr/0003-rate-limit-kv-vs-nativo.md)).
Original finding: with the global write cap (300/day) exhausted,
`rateLimit()` kept returning `allowed: true` without persisting state —
~300 trivial requests would disable the entire route's rate limit until
midnight UTC. Fixed to fail closed; migration to a native Cloudflare Rate
Limiting rule remains pending (manual dashboard decision).

### A2 — Honeypot dashboard poisoning
**Status: accepted residual risk.** The honeypot's 60-events/day cap means
an attacker can fill the day's budget with trivial requests from a chosen
ASN, making the Threat Intelligence dashboard show attacker-chosen data and
hiding genuine scanning. Low impact (no security control depends on this
data); a possible mitigation (per-ASN sub-cap) is recorded as a
*nice-to-have*.

### A3 — Metric poisoning (Vitals/CSP)
**Status: accepted residual risk, out of necessity.** Both POST endpoints
are unauthenticated by nature (that's what makes them useful). An attacker
can submit fabricated LCP/CLS values or fake CSP violations within the
caps. Impact: cosmetic/reputational — mitigation: be explicit on the page
that these are unauthenticated first-party beacons.

### A4 — Dependency compromise via npm
**Status: mitigated in depth.** `minimumReleaseAge: 3 days`, OSV-Scanner,
`npm audit`, `npm audit signatures` (verifies registry signatures),
`npm ci --ignore-scripts` (no arbitrary postinstall runs in CI). Residual
risk: a compromised package with only scripts *required* to function (no
known case in this repo today).

## Highest-impact attacks

### B1 — Cloudflare account compromise
Catastrophic and with no technical mitigation possible from this
repository — DNS control implies certificate issuance and full traffic
interception. **Controls to confirm outside the code:** hardware-key MFA
on the Cloudflare account, minimally-scoped and rotated API tokens,
account audit log review. This is the highest-impact risk and the least
discussed in the repository — deserves explicit confirmation, not
assumption.

### B2 — GitHub account/Actions compromise
Well mitigated for the *pipeline* (SHA pins, `permissions: {}`,
`persist-credentials: false`, zizmor). Residual risk: account-level MFA.
Production deploy runs through Workers Builds, entirely outside GitHub
Actions (see B3, [ADR 0011](adr/0011-sem-token-cloudflare-no-github-actions.md))
— finding H3 is the missing provenance and reviewer gate on that path,
not a deploy token, since no deploy credential lives on the GitHub side
at all. A deploy token would only become relevant if H3's remediation
moved production deployment into GitHub Actions instead.

### B3 — Developer laptop compromise
The normal path to Worker production is automatic (Workers Builds, on
push to `main` — see `docs/architecture.md`), not the laptop. But a
secondary manual path still exists (`npx wrangler deploy` from the laptop,
used to test a branch before merging, `CLAUDE.md`) that points at the same
production Worker — a compromised laptop can still publish directly,
without going through GitHub. See finding H3 in
`docs/security-review-2026-07-29.md`: the real gap isn't "manual deploy",
it's the absence of verifiable provenance and a reviewer gate on either
path.

## Abuse cases

- **Quota exhaustion** (A1) is the dominant one.
- `/api/pwned-range` as an HIBP proxy: contained — `normalizePrefix`
  restricts input to exactly 5 hex characters, rate limiting applies,
  results are cached for 24h.

## Supply-chain risks

Semgrep's `p/*` packages aren't pinnable (documented, mitigated by local
rules + retry). npm lifecycle scripts (mitigated: `--ignore-scripts` in
CI). **No provenance between CI and production on the Worker** — the
largest gap (finding H3).

## GitHub risks

The repository is public (since 2026-07-31, see `docs/cloudflare-deploy.md`
§6) — native secret scanning and push protection are available on the Free
plan for public repos; whether they're actually turned on has **not been
verified from within this session** (no access to the repository's GitHub
settings). Until confirmed, treat gitleaks as the only *verified* secret
control. Actions quota pressure — a real constraint while the repo was
private — no longer applies (public repos get unlimited Actions minutes).
Branch protection status to be confirmed.

## Cloudflare risks

Free-plan quota exhaustion as a denial-of-service vector against
protections (A1). KV's eventual consistency undermining security logic
(partially mitigated by fail-closed). No Logpush — incident reconstruction
depends on the Observability retention window.

## Explicitly accepted residual risks

Public-dashboard poisoning (A2/A3) — unavoidable without authentication,
which would cost more than it's worth. Fidelity limits of the firewall
panels on the Free plan. Availability of crt.sh as the CT watcher's single
source. Zero-day in Astro or workerd. Cloudflare as a single point of
failure — accepted deliberately, the right call for a personal site.

---

**Last review:** 2026-07-29 (creation of this document, from the same
day's security review). **2026-07-30:** corrected attack-surface counts
(12 GET endpoints, not 11; 5 decoy routes, not 6) and the Worker deploy
description (it's automatic via Cloudflare Workers Builds, not manual —
finding H3 remains open due to the lack of provenance/reviewer gate, not
the lack of automation), as part of preparing the repository for going
public. **2026-08-02 (translation pass):** corrected the "GitHub risks"
section, which still described the repository as private — it went public
on 2026-07-31 (`docs/cloudflare-deploy.md` §6); whether secret
scanning/push protection are actually enabled is unverified from this
session, noted explicitly rather than assumed. **2026-08-06:** self-scan
(`/api/scan`) removed — Cloudflare Bot Fight Mode/WAF was intercepting the
Worker's own same-zone `fetch()` and grading its managed-challenge page
instead of the real site (see `dynamic/PLAN.md`, 2026-08-06 entry).
Corrected attack-surface count (11 GET endpoints, not 12) and dropped the
now-removed `/api/scan`/`fetchSameOrigin` abuse-case entry; CSP violation
tracking was kept, unaffected.
