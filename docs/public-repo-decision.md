# Going public: decision record and readiness checklist

> **Language note.** English, for the same reason as
> [`security-review-2026-07-29.md`](security-review-2026-07-29.md): this is a
> reviewer-facing artefact. The rest of `docs/` is Portuguese.

**Date:** 2026-07-29 · **Status:** recommendation, pending owner decision
**Scope reviewed:** full git history (149 commits, 132 PRs), `.github/`,
`dynamic/worker/`, `static/`, `docs/`, `wrangler.toml`, `config.ts`.

**Recommendation: clean, then publish. Confidence: High.**
Do not squash. Do not start a new repository. Do not rewrite history.

---

## 1. What the audit actually found

Verified, not assumed:

| Check | Result |
| --- | --- |
| Secrets in full git history | **Clean.** Pattern sweep over `git log -p --all` returns only variable names, docs prose, and `wrangler secret put` instructions — zero credential values. |
| Actions pinned to commit SHA | **All 5**, Renovate-maintained. |
| Workflow token scope | `permissions: {}` at top level of every workflow, per-job least privilege. |
| `pull_request_target` / `workflow_run` | **Not used.** The single most common public-repo Actions foot-gun is absent. |
| Test suite | 114 Worker + 72 static = **186 tests, passing.** (3 static tests require `npm run build` first — by design, matching CI order; the failure message says so.) |
| Governance files | `LICENSE` (MIT), `SECURITY.md`, `threat-model.md`, 4 ADRs, PR template, `security.txt` (RFC 9116). |
| Secrets management | Everything sensitive via `wrangler secret put`; `wrangler.toml` documents each secret it deliberately does *not* contain. |

**This repository is in better shape for publication than most corporate
repositories I have reviewed.** The Actions hardening in particular —
`permissions: {}`, SHA pinning, no `pull_request_target` — is the exact
configuration most teams only reach after an incident.

### What is genuinely exposed (and is fine)

`wrangler.toml` contains the KV namespace IDs, `CF_ZONE_TAG`, and
`CF_ACCOUNT_ID`. These are **identifiers, not credentials** — they name a
resource, they do not authenticate to it. The file already says so in a
comment. Publishing them is normal and safe; every Cloudflare tutorial does it.

### The one real privacy item

`static/src/config.ts` exposes a personal Hotmail address. The file *already
carries a TODO recommending an alias*. Publishing the repo puts that address in
front of every scraper on the internet, permanently, in git history where
rotating `config.ts` will not remove it. Fix before flipping, not after.

---

## 2. Private vs public

The honest framing is not "open source good". It is: **this repository's entire
stated purpose is to be read by strangers who are deciding whether to hire its
author. A private portfolio is a contradiction in terms.**

### A) Keep it private

- **Advantages:** zero disclosure risk; no inbound noise; total control.
- **Disadvantages:** portfolio value is **zero** — not low, zero. Nobody can
  read it. It also forfeits, on GitHub Free: unlimited Actions minutes, CodeQL,
  native secret scanning + push protection, Dependency Review, artifact
  attestations, OpenSSF Scorecard, full rulesets/branch protection. Every one
  of those is paid (GHAS) while private and free while public. The repo is
  currently paying a real capability tax for a benefit it does not receive.
- **Long-term:** the gap widens. Each new security control added privately is
  one more thing nobody can verify.
- **Hiring impact:** strongly negative by omission. "I have a great private
  repo" is unfalsifiable, and reviewers discount unfalsifiable claims to zero.
- **Note:** the live site deep-links to the repo (`SITE.repo` in `config.ts`,
  used on the *Provas* page). While private, **those links 404 for every
  visitor** — the site's central credibility mechanism is currently broken.

### B) Make it public

- **Advantages:** the portfolio starts existing; six paid capabilities become
  free; the *Provas* deep-links resolve; verifiable claims become actually
  verifiable — which is the entire thesis of the site.
- **Disadvantages:** honeypot deception is disclosed (see §7); inbound issue
  spam becomes possible; the repo's claims become falsifiable by strangers.
- **Security impact:** **net positive, not negative.** You gain push protection
  and secret scanning — controls that prevent the exact failure mode people
  fear when going public. The attack surface that matters (the Cloudflare
  account, the Worker endpoints) is already internet-facing regardless of repo
  visibility. Making source readable does not widen it; the site is static plus
  11 GET endpoints and 2 unauthenticated POSTs, all already reachable.
- **Maintenance impact:** modest and controllable. Issues can be disabled or
  templated; Discussions left off.
- **Hiring impact:** this is the whole point. See §3.

---

## 3. The five reviewers

**Recruiter** — will not read code. Reads the README, the badges, the commit
graph, and whether the site loads. Public matters; contents barely do. *Action:
the README must be legible in 15 seconds and in English.*

**Engineering Manager** — looks for evidence you finish things and work
sustainably. 132 merged PRs with green CI is exactly that signal. Cares that
the site is **live**, not just built.

**Staff Engineer** — reads `docs/adr/` first and the tests second. Will find
four ADRs that state trade-offs and consequences, and 186 tests including
regression tests tied to specific past incidents. This is the strongest
material in the repo. Will also ask, fairly: *is a personal site with a threat
model and five CI workflows over-engineered?* — see §6.

**Security Engineer** — goes straight to `.github/workflows/` and the git
history, looking for leaked secrets and Actions misconfiguration. Finds SHA
pinning, `permissions: {}`, no `pull_request_target`, a real threat model with
an asset list, and ADR 0004 declining to collect IPs *when the data was
available*. That last one is the single most credible artefact here: it is a
privacy decision made against self-interest, which cannot be faked by tooling.

**Principal Engineer** — cares about judgment under constraint. Will value the
KV-quota incident and the rate-limit fail-closed fix more than any scanner.

**Does public improve chances? Yes, decisively — it is the difference between
having a portfolio and not having one.**

---

## 4. History: keep all 132 PRs

**Verdict: positive. Preserve it. Do not squash, rewrite, or restart.**

The history is 2.5 MB. There is no technical cost to keeping it.

What the history actually shows: a security review that criticised this
repository, findings tracked as N2–N8 and H1–H3, and follow-up commits closing
them — including `fix(worker): rate limit falha fechado quando o cap de escrita
esgota`, a fail-open→fail-closed correction. **A visible bug-to-fix trail with
regression tests is more persuasive than any amount of clean code**, because it
demonstrates the one thing a snapshot cannot: that you find your own mistakes.

Arguments against, and why they fail:

- *"130 PRs is noise."* Noise is 130 commits named "fix". These are
  conventional-commit scoped messages in a consistent voice. Reviewers skim the
  graph; they do not audit it.
- *"A clean v1 looks more professional."* A repository with one commit and a
  finished product looks like a template fork. It is the **least** credible
  possible presentation for a security portfolio.
- *"Squashing hides the AI assistance."* It does not — see §5 — and attempting
  it is the actual reputational risk.

**Rewriting history would destroy the most valuable asset in the repository to
solve a problem that does not exist.**

---

## 5. AI-assisted development

**Verdict: acceptable, trending beneficial. Disclose briefly, once, and move
on.**

First, the practical point that settles the question: **non-disclosure is not
available to you.** The branch names are in the merge commits — `Merge pull
request #132 from blindtk/claude/portfolio-security-review-e044du`. Every
reviewer who opens the commit log sees `claude/` on ~130 merges. The choice is
not *disclose or conceal*; it is *frame it yourself or let it be inferred*.
Inferred looks like concealment. Framed looks like process maturity.

Second, the 2026 hiring reality: AI-assisted development is the baseline
assumption, not a confession. No competent engineer will hold it against you.
What they *will* test is whether you can explain the code. You state you can —
that is the only thing that actually matters, and it will be verified in an
interview within about ten minutes regardless of what the README says.

**Do not rewrite code to disguise its origin.** Rewriting working, tested code
to look more hand-made is pure downside: you risk regressions in a system with
186 passing tests, to defeat a signal that the branch names already give away,
for an audience that does not care.

What converts AI usage from neutral to *positive* is evidence of direction and
verification — and this repo has an unusual amount of it: ADRs that reject
alternatives with reasons, a threat model listing "the site's own security
claims" as a breakable asset, a Semgrep rule written for `.astro` `<script>`
blocks because public rulesets do not parse that file type, and known-vector
validation for the crypto tools. That is a human setting direction and checking
the output. Say that.

Suggested README wording — one paragraph, no apology:

> Built with heavy use of Claude Code. Architecture, threat model, security
> decisions, and review are mine; the ADRs in `docs/adr/` record the trade-offs
> and the alternatives rejected. Every security-relevant change is covered by
> tests (`npm test`, 186 across the Worker and the site) and by the scanners in
> `.github/workflows/`. I can walk through any decision here.

That last sentence is an invitation to be tested. Only someone who actually
understands the code writes it — which is precisely why it is worth writing.

---

## 6. Portfolio improvements (engineering quality, not more tools)

The repo does not need another scanner. It has six. Adding a seventh is the
lowest-value thing available. What is missing is **legibility and proof**:

1. **Ship the site.** Cloudflare Access still gates production —
   `expected-headers.json` is deliberately reverted to `SET-ME` because the
   headers cron would otherwise check a login page. A portfolio site nobody can
   load is the same failure as a private repo. **This is the highest-value
   item in this document, ahead of publishing the repo itself.**
2. **English README** (or a prominent EN section). Currently Portuguese
   throughout. This silently removes most international reviewers. The
   Portuguese content is a feature; a Portuguese-only entry point is not.
3. **Answer the over-engineering question in the README, before it is asked.**
   A personal site with a threat model, 4 ADRs, 5 workflows and 186 tests is
   objectively disproportionate — *unless the README says the disproportion is
   the point*: this repo is a demonstration artefact for security engineering,
   deliberately built at a scale where the controls become meaningful. Stated,
   it reads as self-aware. Unstated, a Staff Engineer reads it as poor
   judgment about proportionality. **One paragraph converts your biggest
   apparent weakness into the thesis.**
4. **Lead the README with an architecture diagram and the three most
   interesting decisions**, each linking to its ADR. Reviewers give you 90
   seconds; spend them on judgment, not on `npm install` instructions.
5. **Write up the KV-quota incident as a short postmortem** (`docs/`). You hit
   50% of the Free daily write ceiling before launch and fixed it by aligning
   cache TTLs to the cron interval. Detection → diagnosis → fix → prevention,
   with a real constraint. Engineers rarely have a public postmortem of their
   own system; it outperforms any feature.
6. **Deploy via CI** (finding H3). Manual `wrangler deploy` is the visible gap
   in an otherwise complete supply chain. Closing it with a scoped token in a
   protected GitHub Environment completes the DevSecOps story end to end.

---

## 7. Risks: real vs overstated

**Real:**

- **Personal email harvested from git history.** Certain, permanent,
  irreversible by later edits. *Fix before flipping.*
- **Claims become falsifiable.** The site documents its own controls; a
  stranger can now check them. Your threat model already names this (asset #6).
  This is a real risk and also the reason the repo is worth publishing —
  falsifiability is what makes the claims worth anything. Mitigation is having
  the claims be true, which the tests and CI largely establish.
- **Deployment token, once H3 lands.** A deploy token in a public repo's
  Actions is a genuine high-value target. Protected Environment, scoped token,
  required reviewer.
- **Issue/PR spam.** Low severity, certain to occur at some volume. Disable
  Issues initially or use templates; leave Discussions off.

**Overstated:**

- **"Increased attack surface."** The Worker endpoints and the site are
  internet-facing today. Publishing source does not add an endpoint. Security
  by obscurity of source was never part of your threat model, and the site's
  design assumes an informed attacker.
- **"Automated scanning."** Your endpoints are already scanned constantly —
  that is literally what the honeypot exists to measure. Publication changes
  the volume marginally and the risk not at all.
- **"Dependency confusion."** Not applicable: nothing here is published to a
  registry, and there are no private-scoped internal packages to shadow.
- **"Supply-chain attack via contributors."** You will get few or no PRs. With
  SHA-pinned Actions, `permissions: {}`, and no `pull_request_target`, a
  malicious PR cannot reach your secrets — which is precisely why that
  hardening was worth doing.
- **"AI scraping."** Already happened. The training corpora do not care about
  repo visibility, and MIT-licensing it is a decision you already made.

**Honeypot disclosure — partially real, mostly overstated.** Publishing
`DECOYS` reveals that `/wp-login.php`, `/.env`, `/admin`, `/phpmyadmin/`,
`/.git/config` are traps with disguised 404s. But these are the *standard*
paths every commodity scanner already hits blindly — that is why they were
chosen. Automated traffic, which is ~all of your honeypot data, does not read
your repo. A targeted human could avoid the traps or poison the dataset with
junk events; consequence is a slightly wrong pattern chart on a personal site.
Accept it, and note in the README that the decoys are public by design — a
honeypot whose value is *demonstrating* the technique loses nothing by being
explained, which is a defensible security-engineering position worth stating
rather than hiding.

---

## 8. Pre-publication checklist

**Blocking — do before flipping**

- [ ] Replace the Hotmail address in `static/src/config.ts` with a domain alias
      (`hello@danielmala.co`). History exposure is permanent; a rotatable alias
      is the only real mitigation.
- [ ] Run `gitleaks detect` over full history **and** `gitleaks detect --no-git`
      locally; confirm clean outside CI.
- [ ] Rotate `RATE_SALT` and `CF_API_TOKEN` on flip day. Cheap insurance, and
      `wrangler.toml` already documents the procedure for both.
- [ ] Confirm no Actions secrets are stale or over-scoped before the repo
      becomes readable.
- [ ] Read `CLAUDE.md` as an outsider — it is now public and is genuinely good
      documentation. Keep it; it demonstrates deliberate AI-workflow design.
- [ ] Decide the AI-disclosure paragraph (§5) and put it in the README.

**Immediately after flipping — capture the free tier**

- [ ] Enable **secret scanning + push protection** (free once public; upgrades
      your gitleaks-only posture to defence in depth).
- [ ] Enable **CodeQL** default setup, and SARIF upload in `security.yml` —
      the existing comment explaining it "requires GHAS" becomes obsolete.
- [ ] Enable **Dependency Review** on PRs.
- [ ] Add **OpenSSF Scorecard** + badge. With SHA-pinned Actions and
      `permissions: {}` already in place, expect a high score immediately.
- [ ] Configure **branch protection / rulesets** on `main`: require CI +
      security workflows, no force-push, no deletion. Full rulesets are only
      available to public Free repos (finding M6).
- [ ] Point `expected-headers.json` at production once Access is off, so the
      Headers workflow verifies something real.
- [ ] Issues: disable, or add templates. Discussions: leave off.

**Documentation — the actual portfolio work**

- [ ] English README with architecture diagram, the three key decisions linked
      to ADRs, and the "why so much for a personal site" paragraph (§6.3).
- [ ] KV-quota postmortem (§6.5).
- [ ] Confirm `SECURITY.md` reporting path works end to end once public.

**Already done — verified, no action needed**

- [x] MIT `LICENSE`, `SECURITY.md`, `security.txt` (RFC 9116)
- [x] Threat model + 4 ADRs + PR template
- [x] All Actions SHA-pinned; `permissions: {}`; no `pull_request_target`
- [x] Gitleaks, Semgrep, OSV-Scanner, zizmor, Dependabot, Renovate in CI
- [x] 186 passing tests; secrets via `wrangler secret put`
- [x] No secret values anywhere in git history

**Deliberately not recommended**

- ~~Squash or rewrite history~~ — destroys the most valuable evidence (§4).
- ~~New repository / migrate latest version only~~ — same, plus it looks like a
  template fork.
- ~~Rewrite AI-assisted code to look hand-written~~ — regression risk, defeats
  nothing (§5).
- ~~Add a seventh scanner~~ — diminishing returns; ship the site instead.

---

## 9. Recommendation

**Clean the existing repository, then make it public. Confidence: High.**

If this were my portfolio I would: swap the email for an alias, rotate the two
secrets, write the English README with the AI paragraph and the
over-engineering paragraph, and flip it public the same day — probably within
one working session. Then turn on CodeQL, secret scanning, Scorecard and branch
protection, and only afterwards write the postmortem and close H3.

The reasoning is that the repository is already built to a standard most people
never reach, and it is currently invisible. The gap between what this repo *is*
and what anyone can *see* is the entire problem. Every week it stays private is
a week of finished work earning nothing.

**And the sharper point: publishing the repo is second priority. The site is
still behind Cloudflare Access — it does not load for anyone.** A public repo
pointing at an unreachable site is half a portfolio. Ship the site, publish the
repo, in that order, ideally the same week.

The risks are real but small, bounded, and mostly already mitigated by work
that is done. The upside is the entire stated purpose of the project.
