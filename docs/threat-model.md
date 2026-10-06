# Threat model

Living document — review every quarter or whenever a relevant architecture
decision is made (record the review date at the bottom of this file).
Origin: initial analysis in
§8 of the 2026-07-29 security review (not published).

## Assets

1. **The Cloudflare account** — by far the highest-value one; a compromise
   gives DNS control, certificate issuance, and traffic interception for
   the domain.
2. **The GitHub repository and its Actions secrets.**
3. **Domain and published-content reputation/integrity.**
4. **Visitor privacy** — the site explicitly promises zero-PII (see
   [ADR 0004](adr/0004-zero-pii-honeypot.md); since
   [ADR 0022](adr/0022-retire-internal-honeypot.md) the Worker stores no IP
   address at all); it's a breakable reputational asset.
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
deployed artifact. Upstream APIs (crt.sh, HIBP, Cloudflare GraphQL) →
Worker → browser DOM. Browser → POST endpoint → KV.

## Attack surfaces

7 GET endpoints (most with no input); 1 unauthenticated POST endpoint
(`/api/vitals`); the static site; the
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
**Status: retired on 2026-10-02 with the internal honeypot
([ADR 0022](adr/0022-retire-internal-honeypot.md)).** Kept as the record: The honeypot's 60-events/day cap means
an attacker can fill the day's budget with trivial requests from a chosen
ASN, making the Threat Intelligence dashboard show attacker-chosen data and
hiding genuine scanning. Low impact (no security control depends on this
data); a possible mitigation (per-ASN sub-cap) is recorded as a
*nice-to-have*.

### A3 — Metric poisoning (Vitals)
**Status: accepted residual risk, out of necessity.** The POST endpoint
is unauthenticated by nature (that's what makes it useful). An attacker
can submit fabricated LCP/CLS values within the cap. Impact:
cosmetic/reputational — mitigation: be explicit on the page that this is
an unauthenticated first-party beacon.

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
the 2026-07-29 security review (not published): the real gap isn't "manual deploy",
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
plan for public repos, but whether they're turned on lives in GitHub's
settings and is **not yet recorded as confirmed** (open item in
`docs/cloudflare-deploy.md` §7). Until it is, treat gitleaks as the only
*verified* secret control. Actions quota pressure — a real constraint while the repo was
private — no longer applies (public repos get unlimited Actions minutes).
Branch protection: `main` is behind a ruleset (PR + Code Owners review, required checks — see `docs/catalog-sync.md`).

## Cloudflare risks

Free-plan quota exhaustion as a denial-of-service vector against
protections (A1). KV's eventual consistency undermining security logic
(partially mitigated by fail-closed). No Logpush — incident reconstruction
depends on the Observability retention window.

## Explicitly accepted residual risks

Public-dashboard poisoning (A3) — unavoidable without authentication,
which would cost more than it's worth. Fidelity limits of the firewall
panels on the Free plan. Availability of crt.sh as the CT watcher's single
source. Zero-day in Astro or workerd. Cloudflare as a single point of
failure — accepted deliberately, the right call for a personal site.

---

## Review log

Next scheduled review: **2026-10-29** (quarterly).

| Date | Change |
| --- | --- |
| 2026-07-29 | Created, from the same day's security review (not published). |
| 2026-07-30 | Attack-surface counts corrected; Worker deploy described as automatic (Workers Builds), with H3 open for missing provenance/reviewer gate, not for lack of automation. |
| 2026-08-02 | "GitHub risks" updated: repository public since 2026-07-31; secret scanning/push protection noted as unconfirmed. |
| 2026-08-06 | Self-scan (`/api/scan`) removed — Cloudflare's challenge page was being graded instead of the site. Later the same day CSP violation reporting (`/api/csp-report`, `/api/csp-violations`) removed too, for a suspected false-signal problem of the same kind; the CSP itself is still enforced. A3 lost its CSP half. |
| 2026-10-02 | Internal honeypot retired ([ADR 0022](adr/0022-retire-internal-honeypot.md)): no decoy routes, IP list, `/api/honeypot`/`/api/map`/`/api/ticker`; 7 GET endpoints; NVD/CISA KEV no longer upstream; A2 retired. |
| 2026-10-06 | GitHub risks: branch protection recorded (ruleset on `main`); remaining settings checks tracked in `docs/cloudflare-deploy.md` §7. |
