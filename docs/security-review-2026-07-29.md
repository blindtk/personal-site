# Security & engineering review — 2026-07-29

> **Relation to the other security review.** This is the current snapshot,
> linked from `README.md`. An earlier, round-by-round working log in
> Portuguese existed alongside it (the findings here were partly drawn from
> it) but was removed 2026-07-31 as part of trimming `docs/` down to what a
> first-time reader needs — its content lives on in git history.

Reviewer posture: Principal AppSec Engineer / Cloud Security Architect /
DevSecOps Lead / Staff Engineer. Scope: the repository as it stands at
`9ee07d0`, the Worker in `dynamic/worker/`, the Astro site in `static/`, and the
CI/CD in `.github/`.

**Headline: the engineering here is already top-decile for a personal project.
The binding constraint on this repository is not a missing scanner — it is that
the repository is private and the site is behind Cloudflare Access. Those two
facts cap the portfolio value near zero, invalidate the free tier of half the
tools under consideration, and make several existing controls unverifiable. Fix
those two things before adding a single new tool.**

---

## 0. Two findings that reframe everything

### 0.1 The repository is private

Verified via the GitHub API: `"private": true`, `"visibility": "private"`.

This is consistent with the comment in `security.yml` explaining that SARIF
upload to Security → Code scanning "exige o GitHub Advanced Security —
indisponível neste repo". That is correct — but the reason is the visibility,
not an inherent limitation. Consequences, all of which disappear the moment the
repo is public:

| Capability | Private (today) | Public |
| --- | --- | --- |
| **Actions minutes** | 2,000/month, metered | **Unlimited, free** |
| **CodeQL / code scanning / SARIF** | Requires GHAS (paid) | **Free** |
| **Secret scanning + push protection** | Requires GHAS (paid) | **Free** |
| **Dependency Review action** | Requires GHAS (paid) | **Free** |
| **Artifact attestations** (`attest-build-provenance`) | Team/Enterprise | **Free** |
| **OpenSSF Scorecard** | Not meaningfully usable | **Free, badge** |
| **CodeRabbit** | ~$12–24/user/month | **Free (OSS plan)** |
| **Portfolio value** | **Zero — nobody can read it** | The entire point |

Every single tool the review asks about is either free or unnecessary on a
public repo. On a private repo, most of them cost money. **Going public is the
highest-ROI action available and it costs €0.**

The usual objection is "my code will be exposed". Read the repo honestly: there
are no secrets in it (gitleaks in CI and pre-commit, `wrangler secret put` for
everything sensitive), the KV namespace IDs and zone/account tags in
`wrangler.toml` are identifiers not credentials (correctly documented as such),
and the whole architecture is designed to be inspectable — the site literally
has a page explaining its own security controls. This repo was *built* to be
public. It just isn't.

Before flipping the switch, do one pass:
1. `gitleaks detect --no-git` and `gitleaks detect` over full history (already
   clean per CI, but confirm locally).
2. Rotate `CF_API_TOKEN` and `RATE_SALT` on the day you flip — cheap insurance
   against anything that ever transited a laptop.
3. Confirm `CF_ZONE_TAG` / `CF_ACCOUNT_ID` exposure is acceptable to you. It is
   — they are not credentials — but decide deliberately rather than by default.

### 0.2 You are over the Actions free quota

59 merge commits in 17 days ≈ **104 PRs/month**. Each PR event fans out to 7
jobs (`build`, `worker`, `osv-scanner`, `gitleaks`, `semgrep`, `zizmor`,
`labeler`), and merging fires all of them again on `push: main`. GitHub bills
each job rounded up to the whole minute.

Conservative arithmetic: ~11 billed minutes per event × 2 events per PR × 104
PRs ≈ **2,300 minutes/month**, before review iterations (each push to a PR
branch re-fires everything) and before the daily `headers.yml` cron. Realistic
figure with 2–3 pushes per PR: **3,000–4,500 minutes/month against a 2,000
minute quota.**

Check Settings → Billing → Actions to confirm. If you are not seeing overage
charges, it is because runs are being queued or cancelled, which means your
security gates are silently not running on some PRs — which is worse.

Going public makes this line item disappear entirely. That is the second reason
it dominates every other recommendation.

### 0.3 (corollary) The site is not publicly reachable

`expected-headers.json` is deliberately reverted to `SET-ME` because Cloudflare
Access still blocks unauthenticated requests (`docs/cloudflare-deploy.md` §3).
The team handled this well — `check-headers.mjs` emits a `::warning::` and a
step summary rather than passing silently, which is exactly the right call and
was itself the product of an earlier review round.

But the consequence stands: **the `headers.yml` workflow verifies nothing, the
honeypot receives no real traffic, `/api/scan` grades a login page, the CT
watcher and the Threat Intel dashboards have no signal, and every runtime
control in this repo is untested in production.** The Cloudflare Free plan's
WAF, the rate limiting, the decoy routes — none of it has met an adversary.

Two ways out, and I recommend the first:
- **Launch.** Turn Access off, let the site be public. This is Phase 3 in
  `docs/cloudflare-deploy.md` and everything is ready for it.
- **Access Service Token for CI.** Already scaffolded — `runScan()` reads
  `ACCESS_CLIENT_ID`/`ACCESS_CLIENT_SECRET`, and `fetchSameOrigin()` exists
  specifically so those headers do not leak across a redirect. Add the same
  pair to `headers.yml` as repo secrets. This unblocks the header check without
  launching, but leaves the honeypot and dashboards dark.

---

## 1. Maturity assessment

| Domain | Score | One-line justification |
| --- | :---: | --- |
| Secrets management | **8/10** | gitleaks in CI *and* pre-commit, everything sensitive via `wrangler secret`, documented rotation for `RATE_SALT`. |
| Dependency security | **8/10** | OSV + `npm audit` with a justified allowlist, Renovate/Dependabot split correctly, `minimumReleaseAge: 3 days`. |
| Supply-chain security | **6/10** | Actions SHA-pinned and audited — but the deployed artefact has no provenance link to CI. |
| Static analysis | **7/10** | Semgrep at ERROR+WARNING with bespoke `.astro` rules, plus `astro check`. No dataflow-grade analysis. |
| CI/CD security | **9/10** | Genuinely excellent. See §3. |
| Cloudflare security | **7/10** | Correct hardening of the obvious things; architectural weakness in KV-based rate limiting; no environment separation. |
| Runtime security | **6/10** | Good response hygiene and zero-PII discipline; rate limiting fails open under budget exhaustion; nothing watches the logs. |
| API security | **6/10** | Input validation is strong. Unauthenticated POSTs can exhaust the daily write budget. |
| Business logic security | **6/10** | The cost-control caps are themselves the attack surface. See §8. |
| Observability | **5/10** | Rich dashboards, zero alerting. Detection without response. |
| **Overall engineering maturity** | **9/10** | Comment quality, decision records, honest reversals, tested pure logic. Top decile. |
| **Overall security maturity** | **7/10** | Strong build-time posture, thin runtime posture, unproven in production. |

### Notes on the scores

**Secrets management (8).** `.pre-commit-config.yaml` + the CI job is real
defence in depth, and `wrangler.toml` documents every secret it does *not*
contain. Deductions: no rotation cadence for `CF_API_TOKEN` (only `RATE_SALT`
has one), and no GitHub-native secret scanning or push protection — which is a
GHAS feature you cannot have while private. Note that gitleaks is doing work
here that GitHub would do for free on a public repo.

**Dependency security (8).** The Renovate/Dependabot division of labour —
Renovate for version updates, Dependabot for security updates only, because
Renovate by design won't PR transitive lockfile vulns — is a genuinely
sophisticated call that most professional teams get wrong. `osv-scanner.toml`
requires a justification *and* an expiry per exception. `minimumReleaseAge: 3
days` is real protection against the npm-compromise pattern. Deduction: no SBOM,
and `npm ci` runs lifecycle scripts (see §2).

**Supply-chain security (6).** This is the largest gap in an otherwise strong
posture, and it is invisible because everything upstream of it is so good. CI
proves the Worker builds (`wrangler deploy --dry-run`), tests pass, and no
advisories exist. Then a human runs `npx wrangler deploy` from a laptop. **There
is no cryptographic or procedural link between the code CI blessed and the code
serving traffic.** A compromised laptop, a dirty working tree, or an
accidentally-stale branch deploys silently. Everything else — SHA-pinned
actions, `persist-credentials: false`, zizmor — protects a pipeline that is not
actually the path to production.

**Static analysis (7).** Running Semgrep at both ERROR *and* WARNING after an
evidence-based triage (16 findings → 0, documented in the original
round-by-round log — see git history) is better practice than most commercial
setups. The custom `.semgrep/astro-dom.yml` rules targeting DOM XSS sinks in
`.astro` `<script>` blocks — a file type public rulesets don't parse — is
exactly the right instinct. The retry loop distinguishing exit 1 (real finding,
fail immediately) from exit 2 (network/config, retry) is the kind of detail that
separates engineers from tool-installers. Deduction: Semgrep OSS is
pattern-matching; it does not do interprocedural dataflow. CodeQL would, and is
free on a public repo.

**CI/CD security (9).** `permissions: {}` at workflow level with per-job
minimums, every action pinned by commit SHA with Renovate maintaining digests,
`persist-credentials: false` on every checkout, no `pull_request_target`
anywhere, external values passed via `env:` rather than interpolated into `run:`
(explicitly to defeat template injection, and audited by zizmor). The zizmor
comment recording that version 1.27.0 was pulled from PyPI under
GHSA-f42p-wjw5-97qh, caught while reproducing the job locally, is the sort of
thing that makes a reviewer trust the rest of the repo. Deduction only for the
deploy gap and unverified branch protection.

**Cloudflare security (7).** `workers_dev = false` and `preview_urls = false`
with the reasoning recorded (a `*.workers.dev` subdomain bypasses the zone's
Access application and WAF) is a control most people miss entirely. `[limits]
cpu_ms = 10` making the platform ceiling explicit is good defensive
documentation. Deductions in §6.

**Runtime security (6) / API security (6) / Business logic (6).** Grouped,
because they share one root cause: the KV write caps that protect the Free plan
budget are reachable by unauthenticated attackers, and the failure mode is
degradation of the security controls themselves. Detailed in §8.

**Observability (5).** `[observability] enabled = true` with
`head_sampling_rate = 1`, structured `console.error` keys
(`honeypot_write_failed`, `rate_salt_missing`, `request_failed`), first-party
RUM, CSP violation aggregation, CF Analytics dashboards. The instrumentation is
genuinely good. **Nothing reads any of it.** `rate_salt_missing` fires into a log
nobody tails. There is no uptime check, no alert, no error-budget notion. The
one automated production check that exists (`headers.yml`) is a no-op by design
right now. This is the biggest gap between "looks mature" and "is mature".

---

## 2. Gap analysis

### High priority

**H1 — Repository is private.** *Why it matters:* nullifies portfolio value,
costs Actions minutes, blocks the free tier of CodeQL/Dependency
Review/Scorecard/attestations/secret scanning/CodeRabbit. *Realistic?* It is the
single most realistic action here. *Effort:* 30 minutes including a history
audit and token rotation. *Maintenance:* zero.

**H2 — Site not publicly reachable; `headers.yml` verifies nothing.** *Why:*
every runtime control is unproven; the honeypot and all dashboards have no
signal; a green CI badge overstates reality. *Realistic?* Yes — it is the
documented Phase 3. *Effort:* hours (launch) or ~1 hour (Access Service Token
for CI). *Maintenance:* zero.

**H3 — No provenance between CI and production.** *Why:* the deployed artefact
is unverified; this is the classic supply-chain gap and the one a security
reviewer will ask about first. *Realistic?* Yes. *Effort:* ~2 hours for a
deploy workflow using a scoped Cloudflare API token in a GitHub Environment with
required reviewers. *Maintenance:* low. Add `attest-build-provenance` once
public (free) for the full story.

**H4 — Rate limiting fails open under write-budget exhaustion.** *Why:* an
attacker can cheaply disable rate limiting globally for the rest of the UTC day.
See §8 A1. *Realistic?* Yes, and the fix reduces complexity. *Effort:* ~2 hours
to move to a Cloudflare native Rate Limiting rule. *Maintenance:* negative —
deletes code.

### Medium priority

**M1 — No environment separation.** One Worker, one KV namespace, no staging.
`preview_id` exists in `wrangler.toml` but no `[env.staging]` block. *Why:* you
cannot rehearse a deploy; a bad push hits production directly. *Effort:* ~1
hour. *Maintenance:* low.

**M2 — No alerting on any signal.** *Why:* see Observability. *Effort:* ~2 hours
for a scheduled workflow hitting `/api/health` and asserting invariants, opening
a GitHub Issue on failure. *Maintenance:* low.

**M3 — No SBOM.** *Why:* it is the lingua franca of supply-chain conversations,
and cheap. `npm sbom --sbom-format cyclonedx` is built into npm 10+ — no new
tool. *Effort:* 30 minutes. *Maintenance:* zero.

**M4 — `npm ci` runs lifecycle scripts.** *Why:* postinstall scripts are the
primary npm compromise vector, and `minimumReleaseAge` only narrows the window.
*Effort:* try `npm ci --ignore-scripts` in CI; Astro/sharp may need an
exception, in which case document why. *Maintenance:* low.

**M5 — Honeypot data poisoning.** The 60 events/day cap makes the Threat Intel
dashboard cheap to skew. See §8 A2. *Effort:* ~2 hours. *Maintenance:* low.

**M6 — Branch protection unverified.** Rulesets on private Free repos are
limited; on public repos they are full-featured. Fold into H1. *Effort:* 20
minutes post-H1.

### Low priority

**L1 — No signed commits.** Cheap, visible, good hygiene (`git config
commit.gpgsign true` + SSH signing key). ~20 min.
**L2 — CT watcher single-sourced on crt.sh**, which is frequently slow or down.
Failure is graceful but the panel goes blank. Consider a second CT log source or
a "last known good" fallback in KV.
**L3 — `CF_API_TOKEN` has no documented rotation cadence**, unlike `RATE_SALT`.
Add a line to `wrangler.toml`'s secret block.
**L4 — `/api/vitals` accepts an empty `Content-Type`.** Deliberate
(`sendBeacon`), but tightening to explicit types only is trivial.
**L5 — No ESLint.** Semgrep covers the security-relevant subset; `astro check`
covers types. Genuinely optional — I would not bother.

### Nice to have

- ADRs as first-class files. `dynamic/PLAN.md` already *is* a decision log of
  unusual quality (including two documented self-corrections about Cloudflare
  datasets). Promoting the pattern to `docs/adr/NNNN-*.md` costs little and
  reads far better to a Staff-level reviewer.
- An architecture diagram (Mermaid, in-repo, renders on GitHub).
- A public status/security dashboard page — you have the data already.
- `--ignore-scripts` + `npm audit signatures` for registry signature verification.

---

## 3. Review of existing tooling

### gitleaks — **keep**
*Protects:* credentials entering git history; runs both pre-commit and in CI
over full history (`fetch-depth: 0`), so a secret in any commit of a PR is
caught, not just the tip. *Misses:* secrets already live in Cloudflare, secrets
in build output, high-entropy values it has no rule for. *Overlap:* would be
substantially redundant with GitHub secret scanning + push protection — but you
cannot have those while private. Today it is your only secret control.
*False positives:* low; `.gitleaksignore` exists and is empty of noise.
*Maintenance:* near-zero (Renovate tracks the pre-commit `rev`).

### OSV-Scanner — **keep**
*Protects:* known vulns in both lockfiles, from OSV.dev (which includes GHSA).
The decision to call the action directly rather than the reusable workflow — to
avoid transitive `upload-sarif`/`download-artifact` dependencies that the repo's
SHA-pinning allowlist would reject — is well-reasoned and well-documented.
*Misses:* unknown vulns, malicious-but-unreported packages, anything outside the
lockfiles. *Overlap:* meaningful overlap with `npm audit` (both consume GHSA),
but OSV has broader sources and `npm audit` gives you the allowlist mechanism
OSV's `IgnoredVulns` also gives you. Keeping both is defensible; if you wanted to
cut CI minutes, `npm audit` is the more droppable of the two.
*False positives:* one live example — MAL-2026-10726 against Astro 7.1.0, which
the repo correctly identified as a bad advisory and documented with an upstream
PR link and an expiry. That is exemplary exception handling.
*Maintenance:* low.

### Semgrep — **keep**
*Protects:* JS/TS patterns plus custom rules for DOM XSS sinks inside `.astro`
`<script>` blocks. *Misses:* interprocedural dataflow (this is the OSS
engine's real limit), and it cannot fully parse `.astro` — hence the `generic`
mode workaround. *Overlap:* would overlap CodeQL substantially, but CodeQL is
strictly stronger on dataflow. *False positives:* measured — 16 findings triaged
to 0, with `nosemgrep` used sparingly and each instance carrying a written
justification (see `sanitize.js`, `notfound.js`). This is the correct way to use
suppressions. *Maintenance:* moderate — the unpinnable `p/*` registry packs mean
rule drift can appear without a code change. The retry logic mitigates
availability, not drift. Accept it.

### zizmor — **keep**
*Protects:* the workflows themselves — missing pins, excessive permissions,
template injection, credential persistence, impostor commits. *Misses:*
everything outside `.github/workflows/`. *Overlap:* none. Nothing else you run
does this. *False positives:* very low at `--min-severity medium`.
*Maintenance:* near-zero. **This is the highest signal-to-noise tool in your
stack** and the one most reviewers won't have heard of — keep it visible.

### Dependabot (security updates only) + Renovate (version updates) — **keep both**
The split is correct and deliberately documented. Renovate does not open PRs for
transitive lockfile vulns; Dependabot does. Turning on Dependabot *version*
updates would collide with Renovate — the config explicitly warns against this.
*False positives:* low. *Maintenance:* the `prConcurrentLimit: 3` and weekly
grouped schedule keep the noise manageable — important at your PR velocity.

### `astro check` + `node --test` (113 tests, all passing) — **keep**
Verified locally: 113/113 pass in 644ms. The story behind these — both existed
but neither ran in CI until a review found that the PR template was asking a
human to confirm by hand — is worth keeping in the README. "A control that
depends on discipline is not a control" is the correct lesson.

### `headers.yml` — **keep, but fix**
Right idea, currently inert (see §0.3). The `::warning::` + step-summary
treatment of the `SET-ME` path is the correct interim behaviour.

**Verdict: your existing stack has no redundancy worth cutting and no obvious
hole that another scanner of the same class would fill.** The gaps are
structural (provenance, runtime verification, alerting), not detectional.

---

## 4. Evaluation of proposed tools

Costs and free tiers below assume **public repo after H1**. Where private
changes the answer, it is stated.

### CodeQL — **Recommended** (Essential once public)
*Purpose:* semantic, interprocedural dataflow analysis; results in the Security
tab as SARIF. *Advantages:* genuinely finds things Semgrep OSS structurally
cannot — taint from source to sink across functions and files. First-class
JS/TS. Zero-config `javascript-typescript` pack. *Disadvantages:* slow (3–8 min
here), and its `.astro` support is no better than Semgrep's — it will analyse
your `src/scripts/*.js`, `src/lib/*.ts`, and the whole Worker well, and largely
skip `.astro` templates. *Overlap:* Semgrep — complementary, not redundant.
*Maintenance:* very low. *False positives:* low; the JS/TS queries are mature.
*Expected value:* moderate-high — the Worker is exactly the kind of code (string
inputs → URL/fetch/KV sinks) CodeQL reasons about well. *Portfolio value:*
high — Security tab with code scanning enabled is instantly legible.
*Learning value:* high; CodeQL query authoring is a genuinely marketable skill.
*Cost:* **free public / requires paid GHAS private.** *GitHub Free:* yes, if
public. *Cloudflare Free:* N/A. *Personal project:* yes.
**Run:** on PR (changed languages) + weekly full scan.

### CodeRabbit — **Recommended** (free tier, public only)
*Purpose:* AI PR review with inline comments. *Advantages:* the best of the
three AI options at *code review* specifically — good at catching logic slips,
inconsistencies between comment and code, and missing edge cases. Understands
TypeScript well. Learns from your feedback. *Disadvantages:* verbose by default;
will comment on style you have already decided about. Needs a `.coderabbit.yaml`
to be tolerable. *Overlap:* Copilot Code Review; minimal overlap with SAST.
*False positives:* moderate — expect to dismiss 30–50% initially, less once
tuned. *Expected value:* high at your PR velocity (104/month) — this is where an
extra reviewer pays off most. *Portfolio value:* moderate. *Learning value:*
moderate. *Cost:* **free for public repos; ~$12–24/user/month private.**
*Personal project:* yes, if public.

### GitHub Copilot Code Review — **Optional**
*Purpose:* same job, native to GitHub. *Advantages:* zero setup, in the PR UI,
included in Copilot Free (limited monthly reviews) and unlimited on paid Copilot
tiers you may already have. *Disadvantages:* noticeably shallower than
CodeRabbit — good at style and obvious bugs, weak at cross-file reasoning and
security-specific logic. *Overlap:* CodeRabbit — pick one, running both is
noise. *False positives:* low-moderate, mostly trivial. *Expected value:*
low-moderate. *Portfolio value:* low (invisible to a repo browser). *Cost:*
free tier exists. *Recommendation:* use only if you decline CodeRabbit.

### Trivy — **Not worth it**
*Purpose:* vulnerability + misconfiguration scanning for containers, filesystems,
IaC. *The honest assessment:* **you have no containers and no IaC.** Trivy's
dependency scanning would duplicate OSV-Scanner against the same GHSA/OSV data.
Its misconfig scanners target Dockerfile/Kubernetes/Terraform/CloudFormation —
none of which exist here; `wrangler.toml` is not a supported target. *Overlap:*
near-total with OSV-Scanner for the only part that would run. *Expected value:*
**near zero.** *Portfolio value:* negative — a reviewer who reads your workflows
will notice Trivy scanning nothing, and that undercuts the credibility of every
other well-justified choice. **This is the clearest "you already have enough"
in the list.** Add it the day you containerise something.

### Nuclei — **Optional, post-launch**
*Purpose:* template-based active scanning for known exposures/CVEs/misconfigs.
*Advantages:* fast, huge community template set, genuinely useful for catching
exposed `.env`, `.git`, admin panels, stale endpoints. *Disadvantages:* against
*this* target it will find almost nothing — a static Astro site with 11
read-only JSON endpoints, no CMS, no framework with known CVEs, no login. Most
templates target WordPress/Jira/Confluence/etc. *Overlap:* the header templates
duplicate `headers.yml`; the exposure templates duplicate what your own honeypot
decoy routes already cover. *False positives:* low-moderate. *Expected value:*
low. *Portfolio value:* moderate — a weekly external-scan job reads well, and
scanning *your own honeypot decoys* to prove they respond correctly is a genuinely
clever use. *Cost:* free, ~2 min/run. *Recommendation:* weekly, post-launch,
scoped to a small template set. Not before H2.

### OWASP ZAP — **Not worth it**
*Purpose:* full DAST proxy/spider/active scanner. *Advantages:* the standard
open-source DAST; baseline mode is CI-friendly. *Disadvantages:* built for
stateful applications with authentication, sessions, and forms. You have none of
those — one form (`SubnetCalc`) that calls `preventDefault()` and never submits,
which is why `form-action 'none'` is valid. ZAP baseline against this site would
return a handful of informational findings about headers you already verify
declaratively, and the active scanner has nothing to attack. *Overlap:*
`headers.yml` (better, because it is a declarative allowlist you version) and
Nuclei. *False positives:* **high** — ZAP is notoriously noisy on modern static
sites, and the triage burden is real. *Expected value:* low. *Portfolio value:*
low-moderate, and only if you can show it found something. *Recommendation:*
skip. If you want DAST signal, Nuclei gives you 80% of it for 10% of the runtime
and noise.

### Strix — **Not worth it for this target**
*Purpose:* autonomous AI pentesting agent — spawns tools, probes, chains
findings. *Advantages:* the most interesting thing on this list conceptually,
and 2026-relevant. *Disadvantages, specific to you:* an autonomous agent's value
scales with attack surface complexity, and yours is deliberately minimal — no
auth, no authz, no database, no user accounts, no file uploads to a server, no
multi-tenancy, no session state. Eleven GET endpoints returning aggregated
public data plus two unauthenticated POSTs. **The most interesting vulnerability
class in your system (the KV write-budget exhaustion chain in §8) requires
reading the source and reasoning about Cloudflare Free plan quotas — it is
precisely the kind of economic/business-logic flaw an autonomous prober will not
find by probing.** *Overlap:* conceptually with Nuclei/ZAP. *False positives /
hallucination:* high — this is the least mature category here. *Cost:*
Anthropic API tokens; a meaningful run is realistically $2–10, and unbounded if
misconfigured. *Expected value:* low. *Portfolio value:* moderate-high **if
framed honestly** — "I ran an autonomous pentest agent against my own
infrastructure, here is the methodology and here is why it found nothing" is a
genuinely good blog post and a better artefact than a badge. *Recommendation:*
**manual, once, as an experiment to write up.** Not in CI. See §5.

---

## 5. AI-assisted security review, compared

| | **Strix** | **CodeRabbit** | **Copilot Code Review** |
| --- | --- | --- | --- |
| **Category** | Autonomous DAST agent | AI PR reviewer | AI PR reviewer |
| **Security reasoning** | Probes runtime; no source context | Good — reasons over the diff *and* repo context | Shallow; pattern-level |
| **Business logic detection** | Weak (black-box) | **Best of the three** — reads intent from code + comments | Weak |
| **TypeScript understanding** | N/A | Strong | Good |
| **Cloudflare Workers support** | Treats it as a black-box HTTP target | Understands the runtime; will reason about KV/`ctx.waitUntil` | Generic JS assumptions; may suggest Node APIs that don't exist in workerd |
| **PR review quality** | Not a PR reviewer | High, tunable | Moderate |
| **Hallucination risk** | **High** | Moderate | Low-moderate |
| **API cost** | $2–10 per meaningful run, unbounded if unconstrained | $0 public / $12–24 mo private | $0 (Copilot Free tier) |
| **ROI here** | Low | **High** | Moderate |

**Recommendation: CodeRabbit, on every PR, free tier, after going public.**

The reasoning is specific to this repository. Your code's defining
characteristic is that *intent lives in the comments* — extraordinarily detailed
ones explaining why `routes` must precede `[vars]` in TOML, why the cap is daily
rather than hourly, why `--severity` is an equality filter and not a minimum.
CodeRabbit reads that context and can flag when a change contradicts a stated
invariant. That is the highest-value automated review you can get here, and
neither a black-box prober nor a shallow diff reviewer can do it.

Copilot Code Review is a reasonable zero-effort fallback if you already pay for
Copilot, but do not run both — at 104 PRs/month, duplicate AI commentary will
train you to ignore all of it.

### Should Strix run on every PR / weekly / backend-only / pre-release / manually?

**Manually, once, and then probably never again on a schedule.**

Walk the options honestly:
- **Every PR** — indefensible. Non-deterministic results, dollar cost per run,
  minutes cost, and it tests a *deployed* target that your PR hasn't changed.
- **Weekly** — you would be paying to re-probe an unchanged 11-endpoint API. The
  second run tells you nothing the first didn't.
- **Backend changes only** — closer to sane, but `dynamic/worker/` changes
  frequently and the surface barely moves. Still mostly repeat runs.
- **Before releases** — you have no releases; the site is continuously deployed.
- **Manually** — correct. Run it once against production *after* launch (H2),
  when there is something real to probe. Capture the methodology, the findings
  (probably none), and the analysis of *why* an autonomous agent finds nothing
  against a deliberately minimal surface. That write-up is worth more than any
  badge.

### Are the Anthropic API costs justified?

**For Strix: no.** $2–10 per run against a surface you have already
threat-modelled by hand, to find a class of bug your architecture excludes.

**For LLM-assisted review generally: yes, and you are already doing it** — this
review is an instance. The high-ROI pattern for you is not a scheduled
autonomous scanner; it is a *periodic deep review with full source access*,
which is how the KV budget-exhaustion chain, the `SET-ME` no-op, and the
untested-CI-controls findings surfaced in this repo's history. Budget for that
quarterly, not for a nightly agent.

---

## 6. Cloudflare-specific review

**Wrangler configuration — strong.** `workers_dev = false` + `preview_urls =
false` closes a real bypass (a `*.workers.dev` hostname would sidestep the
zone's Access application and WAF entirely) and the reasoning is recorded.
Explicit `routes` scoping rather than a wildcard. `compatibility_date` recently
moved to `2026-01-01` with a documented validation plan. `[limits] cpu_ms = 10`
makes the platform ceiling explicit. The two TOML ordering warnings (keys after a
table header get absorbed into that table) are hard-won and correctly placed.

**Secrets — good.** Nothing sensitive in `wrangler.toml`; every secret is
documented as `wrangler secret put` with the exact Cloudflare permission scopes
required. `CF_API_TOKEN` is read-only analytics scope — correct least privilege.
`RATE_SALT` has a documented weekly rotation cadence *and* an automatic daily
component (`salt = RATE_SALT + UTC date`), which is a genuinely nice design: it
makes cross-day re-identification of an IP impossible even if the secret leaks.
**Gap:** no rotation cadence documented for `CF_API_TOKEN`.

**Environment separation — the main gap.** One Worker, one KV namespace, no
`[env.staging]`. `preview_id` is declared but unused in practice. You cannot
rehearse a deploy, and `wrangler deploy` from a laptop goes straight to
production. Add:
```toml
[env.staging]
name = "personal-site-worker-staging"
workers_dev = true   # staging only; production stays false
[[env.staging.kv_namespaces]]
binding = "KV"
id = "<separate namespace>"
```
Cost: €0 (Free plan allows multiple Workers and KV namespaces).

**KV — the architectural weak point.** KV is eventually consistent with a
~60-second global propagation window. You use it for four things:
1. *Aggregated counters* (honeypot, CSP, vitals) — appropriate. Eventual
   consistency costs you precision you don't need.
2. *Read caching with SWR* — appropriate and well implemented (`cached()` with
   `ctx.waitUntil` refresh is textbook).
3. *Write-budget caps* — appropriate-ish, correctly documented as best-effort.
4. *Rate limiting* — **inappropriate.** Eventually-consistent storage cannot
   enforce a rate limit; concurrent requests across colos read stale counts. The
   code acknowledges this, but the mitigation (the daily write cap) introduces a
   worse failure mode (§8 A1).

**D1 / R2 / Durable Objects — correctly absent.** Do not add them. D1 buys you
nothing over KV for counter aggregation. R2 has no use case here. **Durable
Objects are the textbook correct answer for rate limiting** — and on the Free
plan they are available with the SQLite backend — but see §8: Cloudflare's
native Rate Limiting rules are simpler, cheaper, and require zero code. Reach
for DO only if you need per-client logic the WAF cannot express.

**Cache API — underused.** You cache via KV, which costs reads against your
quota. `caches.default` is free, colo-local, and has no quota. For `/api/ticker`,
`/api/ct`, `/api/cf-stats` — public, non-personalised, already
`Cache-Control`-tagged — putting a Cache API layer *in front of* the KV lookup
would cut KV reads substantially. Given you hit a real 50%-of-daily-quota alarm
with the site not even launched, this is worth doing. Trade-off: colo-local, so
each of ~300 colos misses independently; KV stays as the shared second tier.

**Authentication / authorization — none, correctly.** Every endpoint serves
public aggregated data. There is no privilege to escalate. The only credentials
in the system are the Access service tokens (used outbound by `runScan`) and
`CF_API_TOKEN` (outbound to Cloudflare's GraphQL API), and `fetchSameOrigin()`
exists specifically to stop the former leaking across a redirect — an unusually
sharp catch. The right call is to keep it this way: an auth system would be pure
added attack surface.

**CORS — correct.** `ALLOWED_ORIGINS` empty in production, strict allowlist
membership test, `Vary: Origin` always set (frequently forgotten, causes real
cache-poisoning bugs). No wildcard, no `Access-Control-Allow-Credentials`.

**CSP — excellent, and the best single artefact in the repo.** `default-src
'self'` with no `unsafe-inline` anywhere, `object-src`/`frame-src`/`worker-src`/
`base-uri`/`form-action`/`frame-ancestors` all `'none'`, plus
`require-trusted-types-for 'script'` with `trusted-types 'none'` — that last pair
is genuinely rare in the wild and is only honest because the codebase really does
build DOM via `createElement`/`textContent`. The documented journey (hash-based
CSP → header exceeded Cloudflare Pages' 2000-char limit → Pages silently dropped
the entire header → solved by eliminating inline rather than cataloguing it,
enforced by two specific Astro/Vite levers) is the strongest engineering
narrative in the repository. The single JSON-LD hash exception is correctly
reasoned. **Make sure this story is prominent — it is your best interview
material.**

**Security headers — comprehensive.** COOP + COEP `require-corp` + CORP
`same-origin` (full cross-origin isolation, unusual and correct here), HSTS 2
years, `Permissions-Policy`. The `!` detach syntax for the OG images — because
Cloudflare Pages *concatenates* rather than replaces duplicate headers, producing
an invalid value the browser drops entirely — is exactly the kind of hard-won
detail that signals real operational experience. The Worker sets its own headers
independently, which is necessary since `_headers` only covers Pages-served
content.

**Logging — instrumented, unwatched.** See §1. Logpush is paid; Workers
Observability (which you have enabled) is the free substitute and retains logs
for a limited window. Practical mitigation: a scheduled workflow asserting
invariants against `/api/health` and the public endpoints, opening an Issue on
failure. That is your alerting layer on the Free plan.

**Rate limiting — see §8 A1.** Move to native.

**Edge runtime risks.** Correctly handled: the 10ms CPU ceiling is explicit;
`AbortSignal.timeout` bounds every upstream fetch; `ctx.waitUntil` is used for
all fire-and-forget writes so responses aren't blocked; errors return a generic
502 with stacks confined to logs. One thing to watch: `readThreatBuckets` fans
out to 168 + 7 + 1 KV reads. It is cache-warmed at 6h TTL so it rarely executes,
but a cold cache plus concurrent requests could brush the CPU limit — the
`cached()` SWR path largely protects you, and the risk is documented.

### Cloudflare Free plan limitations and practical mitigations

| Limitation | Impact | Mitigation |
| --- | --- | --- |
| KV ~1,000 writes/day, account-wide | The dominant constraint; drives every cap in the code | Native rate limiting (removes the largest writer), Cache API tier for reads, keep daily caps |
| KV eventual consistency | Rate limiting cannot be correct | Move to WAF rate limiting rules |
| 10ms CPU per invocation | Bounds fan-out patterns | Already explicit via `[limits]`; keep SWR caching |
| `firewallEventsAdaptiveGroups` is Pro+ | No aggregated firewall data | **Already solved** — raw dataset + aggregate in the Worker + daily KV snapshots to extend 24h → 7d. Genuinely the best work in the repo. |
| Adaptive datasets limited to 24h | Short analytics window | Same snapshot pattern |
| No Logpush | No log export | Scheduled invariant checks (M2) |
| 100k Worker requests/day | Not a real constraint at your volume | None needed |
| 5 WAF custom rules | Adequate | Prioritise: rate limit, bad-bot challenge, method allowlist |

---

## 7. CI/CD pipeline design

Two designs, because H1 changes the economics completely.

### If the repo stays private (2,000 min/month)

You are already over budget. You must cut. Priorities:
- Drop the `push: main` trigger from `security.yml`. On a PR-gated repo, every
  commit on `main` has already been scanned as a PR. **This alone halves your
  security-scan minutes.**
- Merge `osv-scanner` and `gitleaks` into one job (one checkout, ~1 min saved).
- Cache the `pipx` installs for semgrep/zizmor (~1.5 min/run).
- Run `zizmor` only when `.github/**` changes (`paths:` filter).

Estimated saving: ~50–60%, landing you around 1,200–1,600 min/month. Workable,
but you are optimising a constraint you can delete for free.

### If the repo goes public (unlimited minutes) — the recommended design

| Stage | Trigger | Jobs | Runtime | Why |
| --- | --- | --- | --- | --- |
| **PR** | `pull_request` | build + `astro check` + tests + `npm audit`; worker tests + `wrangler deploy --dry-run`; gitleaks; OSV; Semgrep; zizmor (paths-filtered); **Dependency Review**; **CodeQL**; CodeRabbit | ~8 min wall (parallel) | Everything that can block a bad change. Dependency Review and CodeQL are new and free once public. |
| **Merge to main** | `push: main` | Build → **deploy Pages + Worker** → `attest-build-provenance` → post-deploy `headers.yml` → smoke test `/api/health` | ~5 min | **This is the big one (H3).** Deploy moves into CI with a scoped token in a GitHub Environment. Provenance links artefact to commit. |
| **Nightly** | `schedule` 06:17 | `headers.yml` against production; endpoint invariant checks (health, non-empty dashboards, correct security headers on `/api/*`); open an Issue on failure | ~2 min | Your alerting layer (M2). Catches drift the PR gate cannot see. |
| **Weekly** | `schedule` Mon | Full CodeQL (all queries incl. `security-extended`); OSV over full dep tree; SBOM generation + artefact upload; Nuclei against production (scoped templates); OpenSSF Scorecard | ~15 min | Deep, slow checks that would bloat PR latency. |
| **Release** | `workflow_dispatch` / tag | Tag → SBOM attached → provenance attestation → GitHub Release with changelog | ~5 min | You have no releases today. Introducing monthly tagged snapshots is *optional* but gives a clean home for SBOM + attestation, and reads well. |

**Cost:** €0 public. **Maintenance:** low — the only stage needing care is the
deploy job, and it replaces a manual step you already perform.

**On the deploy job specifically.** Use a GitHub Environment (`production`) with
a Cloudflare API token scoped to *Workers Scripts:Edit* on that account only.
Set `permissions: { contents: read, id-token: write, attestations: write }`.
This is the change that most improves both your actual security posture and how
this repository reads to a reviewer, because it closes the one gap where the
whole carefully-built pipeline currently doesn't reach.

---

## 8. Threat model

**Assets.** (1) The Cloudflare account — by far the highest value; compromise
means DNS control, cert issuance, and traffic interception for the domain. (2)
The GitHub repository and its Actions secrets. (3) Domain reputation / integrity
of published content. (4) Visitor privacy — the site's explicit zero-PII promise
is a reputational asset. (5) Availability of the Free-plan quotas (KV writes,
Worker invocations) — unusually, a *budget* is an asset here. (6) The published
security claims themselves: a site that documents its own controls takes
reputational damage if one is demonstrably false.

**Trust boundaries.** Internet → Cloudflare edge (WAF/Access) → Worker →
KV/upstream APIs. Developer laptop → GitHub → *(gap: manual)* → Cloudflare.
npm registry → lockfile → build → deployed artefact. Upstream feeds (NVD, CISA
KEV, crt.sh, HIBP) → Worker → browser DOM. Browser → POST endpoints → KV.

**Attack surfaces.** 11 GET endpoints (mostly no input); 2 unauthenticated POST
endpoints (`/api/csp-report`, `/api/vitals`); 6 decoy routes; the static site;
the client-side tools (all local-only except `pwned`, `self-scan`, `mirror`);
the GitHub Actions supply chain; the npm dependency tree; the Cloudflare
dashboard/API credentials.

### Most likely attacks

**A1 — Rate-limit disablement via write-budget exhaustion. (Highest-value
finding in this review.)**
`RATE_LIMIT_WRITE_CAP` is 300 writes/day globally. When exhausted, `rateLimit()`
still returns `allowed: true` but **stops persisting the per-client state**
(`index.js:477-489`). Since the counter never increments, every client's window
stays frozen — **rate limiting is globally disabled for the remainder of the UTC
day.** An attacker reaches this with ~300 requests spread across `/api/mirror`
(30/min) and `/api/vitals` (30/min): roughly ten minutes of trivial traffic, no
distribution required. Once disabled, the remaining daily caps (honeypot 60, CSP
50, vitals 150) fall quickly, blinding every dashboard.
The code documents this as a deliberate trade-off ("degrada em vez de continuar a
consumir o orçamento"), but the reasoning assumes exhaustion happens *accidentally*
under load. Reached *deliberately*, it is a cheap, reliable control bypass.
**Fix:** move rate limiting to a Cloudflare **Rate Limiting rule** at the edge —
free tier includes rate limiting rules, enforcement happens before the Worker
runs, costs zero KV writes, zero CPU, and is not eventually consistent. This
deletes `ratelimit.js`, the `rl:`/`rlcap:` key space, and ~300 daily writes.
Complexity goes *down*. If you need per-route logic the WAF cannot express, a
Durable Object is the correct second choice.

**A2 — Honeypot / dashboard data poisoning.** The 60-events/day cap means an
attacker can fill the day's Threat Intel budget with 60 requests to decoy paths
from a chosen ASN, making the dashboard show attacker-chosen data and hiding
genuine scanning. Low impact (no security control depends on it) but directly
undermines a headline portfolio feature. *Mitigation:* per-ASN sub-caps, or
reserve a fraction of the daily budget for previously-unseen ASNs.

**A3 — Vitals/CSP metric poisoning.** Both POST endpoints are unauthenticated by
necessity. An attacker can submit fabricated LCP/CLS values or fake CSP
violations within the caps, skewing the public performance panel. Impact:
cosmetic/reputational. *Mitigation:* accept it, but say so on the page — "these
are unauthenticated first-party beacons; treat as indicative" is a more
impressive statement than a silently wrong p75.

**A4 — Dependency compromise via npm.** Partially mitigated (`minimumReleaseAge:
3 days`, OSV, `npm audit`, lockfiles). Residual: `npm ci` executes lifecycle
scripts (M4).

### Highest impact attacks

**B1 — Cloudflare account compromise.** Catastrophic and unmitigated in the
material sense: DNS control means cert issuance and full traffic interception,
and no amount of CSP helps. *Controls to verify:* hardware-key MFA on the
Cloudflare account, API tokens scoped and rotated, account audit log reviewed.
**Worth confirming explicitly — it is the top risk and the least discussed in
the repo.**

**B2 — GitHub account or Actions compromise.** Well mitigated for the *pipeline*
(SHA pins, `permissions: {}`, `persist-credentials: false`, zizmor). Residual:
account-level MFA, and — once you implement H3 — the deploy token becomes a new
high-value secret that must live in a protected Environment.

**B3 — Compromise of the developer laptop.** Currently the **only** path to
production (`wrangler deploy` by hand). This is exactly why H3 matters: moving
deploy into CI replaces an unauditable trust boundary with an auditable one.

**Abuse cases.** Quota exhaustion (A1) is the dominant one. The `/api/pwned-range`
relay could theoretically be used as a HIBP proxy, but `normalizePrefix()`
restricts input to exactly 5 hex characters, rate limits apply, and results are
cached 24h — well contained. `/api/scan` cannot be pointed at third parties
(`SCAN_TARGET` is a fixed var), and `fetchSameOrigin()` prevents credential leak
if that ever changes.

**Supply-chain risks.** Unpinnable Semgrep `p/*` registry packs (documented,
mitigated by local rules + retry logic). npm lifecycle scripts. GitHub Actions —
well handled. **No provenance from CI to production (H3) — the largest one.**

**GitHub risks.** Private repo means no native secret scanning or push
protection; gitleaks is your sole compensating control. Actions quota pressure
may be silently skipping runs. Branch protection unverified.

**Cloudflare risks.** Free-plan quota exhaustion as a DoS vector (A1). Eventual
consistency defeating security logic. No Logpush, so incident reconstruction
depends on the Observability retention window.

**Residual risks — accept explicitly.** Data poisoning of public dashboards
(A2/A3) is unavoidable without authentication, which would cost more than it
buys. Free-plan analytics limits cap the fidelity of the firewall panels. crt.sh
availability. Zero-day in Astro or workerd. Cloudflare-as-a-single-point-of-
failure — accepted deliberately, and the right call for a personal site.

---

## 9. Additional recommendations (beyond the proposed list)

1. **Cloudflare native Rate Limiting rules** — the A1 fix. Free, less code, more
   correct. Highest-value single change in the Worker.
2. **`npm sbom --sbom-format cyclonedx`** — built into npm 10+, no new
   dependency, produces a real CycloneDX SBOM. Attach to weekly runs.
3. **`actions/attest-build-provenance`** — free once public, and the natural
   companion to H3.
4. **`npm audit signatures`** — verifies registry signatures on your
   dependencies. One line, free, and a genuinely under-used control.
5. **OpenSSF Scorecard** — free once public, produces a badge that is actually
   backed by analysis (pinned deps, branch protection, workflow permissions).
   You would score unusually well immediately, because you already do the hard
   parts.
6. **Cache API tier in front of KV reads** — directly addresses the quota
   pressure that drives every cap in the codebase.
7. **Scheduled invariant checks** (M2) — your alerting layer, ~30 lines.
8. **A `SECURITY_INSIGHTS.yml`** (OpenSSF spec) — niche, cheap, and signals
   awareness of supply-chain metadata standards.
9. **Threat model as a living document** — this section, promoted to
   `docs/threat-model.md`, reviewed quarterly.

**Deliberately not recommended:** Snyk (free tier is restrictive, and OSV +
Dependabot already cover it), SonarCloud (heavy, poor Astro support, overlaps
Semgrep+CodeQL), Checkov/tfsec (no IaC), Falco/eBPF tooling (no infrastructure to
observe), any commercial SAST, any "AI security posture management" product.

---

## 10. Portfolio review

**As a Staff Engineer, I would notice, in order:** the comment quality — this
repo explains *why* at a level almost no personal project does, and several
comments document reversals and failures (the CSP hash approach that broke at
scale, the two corrections about which Cloudflare dataset is Pro-gated, the
zizmor version pulled from PyPI). Documented failure is the single strongest
signal of engineering maturity, and you have it in abundance. Then the PT/EN
architecture with thin routes and shared components. Then the pure-logic/DOM
separation that makes 113 tests possible without a browser.

**As a Security Engineer, I would notice:** `permissions: {}` and SHA-pinned
actions before anything else. Then Trusted Types in a real CSP. Then zizmor
(most candidates have never heard of it). Then the zero-PII discipline —
`clientIP` being *available* in the Cloudflare dataset and deliberately never
requested, documented as a choice rather than a limitation, is a better privacy
signal than any policy page. I would then ask: "how do you know what you tested
is what's deployed?" — and today there is no answer (H3).

**As a Hiring Manager, I would notice:** that I cannot see any of it. The
repository is private and the site is behind Access. Everything above is
invisible.

### Priority improvements

1. **Make the repository public.** Nothing else on this list matters until this
   is done.
2. **Launch the site.** Live honeypot data is the demo.
3. **Move deploy into CI with provenance.** Closes the credibility gap.
4. **Promote `dynamic/PLAN.md` into ADRs.** It is already a decision log of rare
   quality — including self-corrections. `docs/adr/0001-*.md` makes that legible
   to a reviewer who won't read a 500-line planning file.
5. **Add an architecture diagram** (Mermaid, renders natively on GitHub) showing
   browser → Pages → Worker → KV/upstreams, with trust boundaries drawn.
6. **Publish this threat model** as `docs/threat-model.md`.
7. **Write up the CSP journey** as a blog post — hash-based CSP hitting the
   Cloudflare Pages 2000-char header limit, the header being silently dropped,
   and eliminating inline rather than cataloguing it. That is a genuinely
   original war story and better than any certification badge.
8. **Document the testing strategy** in the README — why pure logic is separated,
   why `node --test` and no framework, what is deliberately untested (the
   Cloudflare runtime) and how that risk is managed instead.
9. **Move `SECURITY.md` to the repo root** (or keep in `.github/` — GitHub reads
   both, but root is more visible to a browsing human).
10. **A public security dashboard page** aggregating CI status, headers grade,
    CT watch, and honeypot stats — you already have every data source.

---

## 11. Emerging technologies worth your time in 2026

**Agentic code review (CodeRabbit-class).** *Why:* it is becoming the default
first-pass reviewer on serious projects. *Production ready:* yes. *Portfolio
value:* moderate. *Worth it:* **yes** — free, and the highest-value AI tooling
for your workflow.

**AI pentesting agents (Strix-class).** *Why:* genuinely interesting direction.
*Production ready:* **no** — high false-positive and hallucination rates, poor
cost predictability. *Portfolio value:* high *if you write up the evaluation
honestly, including negative results*. *Worth it:* as a one-off experiment and
blog post, not as tooling.

**MCP security.** *Why:* MCP is now the default agent-tool interface, and its
security model (prompt injection through tool descriptions and returned content,
over-broad tool grants, confused-deputy patterns) is genuinely unsolved.
**You already have `.mcp.json` in this repo** — you are a practitioner, not an
observer. *Production ready:* the protocol yes, the security practice no.
*Portfolio value:* **very high** — this is a scarce specialism and a security
professional who can articulate MCP threat models is rare in 2026. *Worth it:*
**yes — the highest-upside learning investment on this list.** A blog post
threat-modelling the MCP servers this repo uses would be genuinely differentiated
content.

**Supply-chain provenance (SLSA, Sigstore, in-toto attestations).** *Why:* it is
where regulation and industry practice are both converging. *Production ready:*
yes — `attest-build-provenance` makes SLSA L2-ish trivial. *Portfolio value:*
high. *Worth it:* **yes**, and it doubles as the fix for H3. Best
effort-to-value ratio here.

**eBPF / cloud-native runtime security (Falco, Tetragon).** *Why:* dominant in
container security. *Production ready:* yes. *Worth it:* **no — not for this
project.** You have no containers and no nodes. Learn it against a homelab
(which you have — `content/projects/*/homelab.md`), not by bolting it onto a
Worker.

**WebAssembly at the edge / Workers AI.** *Why:* natural extension of your
Cloudflare specialism. *Production ready:* yes. *Worth it:* only if it serves a
real feature. Do not add it for the badge — that contradicts the discipline this
repo otherwise shows.

**Post-quantum TLS.** *Why:* Cloudflare already negotiates X25519MLKEM768 by
default. *Worth it:* as a *measurement* exercise — add a panel showing the
negotiated key exchange for the visitor's own connection. Near-zero effort, very
on-brand for a site whose theme is "show what the server sees", and topical.

---

## 12. Final recommendations

### Top 10 highest ROI

1. **Make the repository public** — unlocks 6 free tools, unlimited CI minutes, and all portfolio value. 30 min.
2. **Launch the site (or wire an Access Service Token into CI)** — makes runtime controls real. Hours.
3. **Move deploy into CI with a scoped token + provenance attestation** — closes the supply-chain gap. 2h.
4. **Replace KV rate limiting with a Cloudflare Rate Limiting rule** — fixes A1, deletes code, frees ~300 KV writes/day. 2h.
5. **Enable CodeQL** (free once public) — the only real capability gap in your SAST. 30 min.
6. **Enable Dependency Review + secret scanning + push protection** (free once public) — 15 min.
7. **Scheduled invariant/alerting workflow** — turns instrumentation into observability. 2h.
8. **SBOM via `npm sbom`** — 30 min, no new dependency.
9. **CodeRabbit on PRs** (free once public) — highest-value AI reviewer for this codebase. 30 min.
10. **Cache API tier in front of KV reads** — attacks the root constraint behind every cap. 2h.

### Top 10 that best showcase engineering maturity

1. Deploy pipeline with provenance and a protected Environment.
2. ADRs extracted from `PLAN.md` — *including the reversals*.
3. Architecture diagram with trust boundaries.
4. Documented testing strategy, including what is deliberately untested and why.
5. The CSP-at-scale war story, written up.
6. Environment separation (`[env.staging]`) with a rehearsed deploy.
7. This threat model, published and reviewed quarterly.
8. Error-budget / SLO framing for the Worker endpoints.
9. A `CONTRIBUTING.md` describing the PR gates and how to run each locally.
10. Keeping the honest negative results visible — the `SET-ME` warning, the Pro-only dataset findings, the "a control that depends on discipline is not a control" lesson.

### Top 10 that best showcase security knowledge

1. Trusted Types in a working CSP with zero inline — already done; make it prominent.
2. `permissions: {}` + SHA-pinned actions + zizmor — already done; explain it in the README.
3. Cloudflare native rate limiting replacing an eventually-consistent implementation, *with the reasoning written down*.
4. The A1 budget-exhaustion finding, documented as a self-discovered vulnerability with its fix.
5. Zero-PII architecture where the identifying field is available and deliberately unused.
6. Salted, daily-rotating IP hashes with a documented panic-button rotation.
7. Build provenance / SLSA attestation.
8. `security.txt` + `SECURITY.md` + a real disclosure policy — already done.
9. An MCP threat model — scarce, topical, and you are already a user.
10. A post-quantum key-exchange panel showing the visitor's own negotiated cipher.

### Tools to avoid

- **Trivy** — no containers, no IaC; would duplicate OSV against the same data. The clearest "no" here.
- **OWASP ZAP** — built for stateful authenticated apps; high noise, near-zero yield on a static site.
- **Strix in CI** — non-deterministic, per-run cost, minimal surface to probe. Manual one-off only.
- **Both CodeRabbit and Copilot Review** — pick one; at 104 PRs/month, duplicates train you to ignore all AI comments.
- **Snyk / SonarCloud / commercial SAST** — restrictive free tiers, overlap what you have.
- **Dependabot version updates** — would collide with Renovate; your config already warns against this.

### Lean security stack (the recommendation)

**Keep:** gitleaks · OSV-Scanner · Semgrep · zizmor · Renovate + Dependabot(security-only) · `astro check` · `node --test` · `headers.yml`
**Add (all free once public):** CodeQL · Dependency Review · secret scanning + push protection · `attest-build-provenance` · `npm sbom` · OpenSSF Scorecard · CodeRabbit · scheduled invariant checks
**Add (Cloudflare, free):** native Rate Limiting rule · `[env.staging]` · Cache API tier
**Skip:** Trivy · ZAP · Strix-in-CI · Copilot Review (if taking CodeRabbit)

That is **8 additions, all €0**, and the two most valuable items on the list —
public repo and CI deploy — are not tools at all.

### Recommended GitHub Actions pipeline

See §7 (public-repo design). Five stages: PR gate (~8 min parallel), merge-to-main deploy with provenance (~5 min), nightly production verification (~2 min), weekly deep scan + SBOM + Scorecard (~15 min), optional tagged release.

### 6-month roadmap

| Month | Focus |
| --- | --- |
| **1** | H1 (public) + H2 (launch/Access token). Rotate secrets. Enable CodeQL, Dependency Review, secret scanning, push protection, CodeRabbit. Configure branch protection rulesets. |
| **2** | H3: deploy pipeline with `production` Environment, scoped token, provenance attestation. Post-deploy smoke test. |
| **3** | H4: native Cloudflare rate limiting; delete `ratelimit.js` and its key space. Cache API tier. `[env.staging]`. |
| **4** | Observability: scheduled invariant checks, Issue-on-failure alerting, SBOM in weekly runs, OpenSSF Scorecard badge. |
| **5** | Documentation: ADRs, architecture diagram, published threat model, testing strategy. The CSP war-story blog post. |
| **6** | The planned DNS/WHOIS tools — built on the now-proven patterns. One-off Strix run against production, written up honestly. |

### 12-month roadmap

Months 7–12, in priority order: **MCP security threat model + blog post** (highest differentiation available to you); post-quantum key-exchange panel; a second Worker to prove the multi-service pattern under the same CI discipline; quarterly threat-model reviews with dated updates in-repo; a CodeQL query written for one of your own patterns (e.g. flagging KV writes not covered by a cap — directly derived from A1, and an outstanding portfolio artefact); a conference-talk-shaped write-up of "building a security portfolio entirely on free tiers", where the honest cost/quota analysis in this repo is the substance.

### Scores

**Overall engineering: 87/100.** Architecture, documentation, testing discipline, and decision-recording are excellent — comfortably top decile for a personal project, and better than a lot of professional code. Deductions: deploy outside CI (−6), no environment separation (−3), no alerting (−3), one significant logic flaw in the write-cap design (−1).

**Overall security: 72/100.** Build-time posture is genuinely strong (CI/CD hardening would score 90+ on its own). Runtime posture is thinner and, critically, **unproven** — nothing has faced production traffic, one control fails open under trivial attack (A1), no provenance links CI to production, and nothing watches the logs. The score rises to roughly **85** on completing months 1–3 of the roadmap, and the ceiling on the Free tier is around 90.

---

### The single sentence

You have built something with unusually good engineering judgement and then hidden it behind a private repo and an Access policy, while the one gap in your otherwise excellent pipeline — the manual `wrangler deploy` — is precisely the one a security reviewer would ask about first. Fix those three things and add nothing else, and this becomes one of the better personal security portfolios on the internet.
