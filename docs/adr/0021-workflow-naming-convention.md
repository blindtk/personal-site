# ADR 0021 — Workflow naming: `<family>[-<object>].yml`, `name:` equal to the file name

**Status:** accepted and implemented (2026-09-25). Same decision, same
check script, in `blindtk`, `github-stars`, `homelab`,
`honeypot-vps-infra` and here. The full convention lives in
`knowledge-base/notes/nomenclatura-de-workflows.md`.

## Context

Five repos, ~45 workflows, and no two repos named them the same way.
Here: `dns-check.yml`, `tls-check.yml`, `headers.yml`, `invariants.yml`
— four scheduled checks of production, four different shapes of name,
none of which said they were the same kind of thing. The display names
added a second vocabulary on top (`DNS check`, `Headers`,
`Invariants`), so the Actions sidebar, the badges and the files didn't
match each other either. Across repos it got worse: the same job
(gitleaks + zizmor on every PR) was `security.yml` here, `security.yml`
in `honeypot-vps-infra`, and two files (`gitleaks.yml`,
`lint-actions.yml`) in `blindtk`.

## Decision

**File:** `.github/workflows/<family>[-<object>].yml` — kebab-case,
English, `.yml` (never `.yaml`). The family is a closed list, chosen by
*what the workflow does to the world*, not by which tool it runs:

| Family | Does | Trigger, typically | Here |
| --- | --- | --- | --- |
| `ci` | Build/test/lint gate. `ci-<suite>` for a suite outside the gate | PR + push to `main` | `ci`, `ci-fuzzing` |
| `security` | Security scans. `security-<tool>` when a tool needs its own triggers or permissions | PR + push, or cron | `security`, `security-codeql`, `security-dependency-review`, `security-scorecard`, `security-supply-chain` |
| `release` | Publishes a versioned artefact | tag | `release` |
| `deploy-<target>` | Changes a running system (CD) | manual | — |
| `verify-<target>` | Read-only pass/fail on a live system; opens/closes an Issue | cron + manual | `verify-dns`, `verify-tls`, `verify-headers`, `verify-observatory`, `verify-worker` |
| `audit-<target>` | Read-only snapshot of facts, no pass/fail | manual | — |
| `repair-<target>` | Puts a broken system back | manual | — |
| `ops-<target>` | One-off operation on a live system that is neither deploy nor repair | manual | — |
| `update-<target>` | Automation that writes back to the repo or to GitHub (commit, labels) | cron / event | `update-pr-labels` |

**`name:`** at the top of the file is **exactly the file name without
`.yml`**. One identifier, not two: what the Actions list shows, what the
badge says, what `gh workflow run` takes and what the file is called are
the same string.

**Job IDs and job `name:` do not change.** They are the check names — the
string a ruleset's required status check stores. The convention stops at
the workflow level on purpose.

**Enforced:** `.github/scripts/check-workflow-names.sh`, run as a step of
the `zizmor` job in `security.yml` (a step, not a new job — this repo is
over the free Actions minutes quota — see the header of
`security-supply-chain.yml`). Fails
closed if it finds no workflow at all.

### Renames in this repo

| Before | After |
| --- | --- |
| `codeql.yml` | `security-codeql.yml` |
| `dependency-review.yml` | `security-dependency-review.yml` |
| `scorecard.yml` | `security-scorecard.yml` |
| `supply-chain.yml` | `security-supply-chain.yml` |
| `fuzzing.yml` | `ci-fuzzing.yml` |
| `dns-check.yml` | `verify-dns.yml` |
| `tls-check.yml` | `verify-tls.yml` |
| `headers.yml` | `verify-headers.yml` |
| `observatory-check.yml` | `verify-observatory.yml` |
| `invariants.yml` | `verify-worker.yml` — named after what it verifies (the Worker's read endpoints), like the others |
| `labeler.yml` | `update-pr-labels.yml` |
| `ci.yml`, `security.yml`, `release.yml` | unchanged (only `name:` changed) |

Older ADRs and dated reviews (`docs/security-review-2026-07-29.md`) keep
the old names — they are a record of what was true then. This table is
the translation.

## Consequences

- **Run history splits.** A workflow's identity in GitHub is its file
  path: the old entries stay in the Actions sidebar with their runs, the
  new ones start empty. Nothing is lost, it is just in two places until
  the old ones age out.
- **Badges changed URL** — updated in `README.md`, alt text now equal to
  the workflow name.
- **Required checks are unaffected**, because no job ID or job `name:`
  changed. Check names appear as `<workflow> / <job>` in the PR UI, so
  the prefix there does change.
- **Rejected: Title Case display names (`Verify DNS`) with kebab-case
  files.** Nicer in the sidebar, but it brings back two names for one
  thing and a check can't verify a translation.
- **Rejected: prefixing by tool (`zizmor.yml`, `gitleaks.yml`).** The
  tool is an implementation detail that changes (semgrep was
  tested and rejected in `honeypot-vps-infra`; the second fuzzing harness
  here was removed along with its pipeline); what the workflow
  *does* doesn't.
- **Rejected: renaming job IDs to match.** It would break the required
  status checks in the rulesets for no reader-visible gain.
