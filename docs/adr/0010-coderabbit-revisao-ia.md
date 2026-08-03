# ADR 0010 — CodeRabbit for AI PR review, not Copilot Code Review or Strix in CI

**Status:** accepted and in production (`.coderabbit.yaml`).

## Context

With the repository public and a high PR rate, AI-assisted PR review has
real payoff — but there are three options with very different profiles:

- **GitHub Copilot Code Review** — zero setup, native to GitHub, but
  noticeably shallower: good at style and obvious bugs, weak at
  cross-file reasoning and security-specific logic.
- **Strix** (autonomous pentest agent) — the most interesting option in
  the abstract, but an autonomous agent's value scales with the
  complexity of the attack surface, and this site's is deliberately
  minimal (no auth, no database, no sessions). The system's most
  interesting bug class (KV write-budget exhaustion) requires reading the
  source and reasoning about Free-plan quotas — exactly the kind of
  business-logic flaw an autonomous prober won't find by probing. Cost
  per run ($2–10, non-deterministic) and hallucination risk are high for
  the expected value.
- **CodeRabbit** — reads the diff **and** the repository's context; the
  defining trait of this codebase is that intent lives in the comments
  (why `routes` has to come before `[vars]` in TOML, why the cap is daily
  and not hourly), and an AI that reads that context can flag when a
  change contradicts an already-stated invariant — something neither a
  black-box prober nor a shallow diff reviewer can do.

## Decision

Enable CodeRabbit on every PR (free on a public repo), with
`.coderabbit.yaml` calibrated per folder instead of generic —
`path_instructions` that remind it of the KV write budget in
`dynamic/worker/`, PT/EN key parity in `i18n/`, the ban on DOM XSS sinks
in `static/src/scripts/`, and the thin-routes rule in
`static/src/pages/`. **Not** enabling Copilot Code Review alongside it
(duplicate AI commentary just trains you to ignore both) nor running
Strix in CI — reserved for a single manual run, post-launch, documented as
an experiment rather than a recurring control.

## Consequences

- A second automated reviewer, free, calibrated to this repository's
  actual vocabulary and invariants — not a generic linter.
- `profile: chill` and `poem: false` to cut default verbosity (without
  that, CodeRabbit comments on style decisions already made).
- `content/**` excluded from review (`path_filters`) — it's editorial
  content, not code, per the CLAUDE.md rule.
- Full reasoning behind the three-way comparison in
  [`docs/security-review-2026-07-29.md`](../security-review-2026-07-29.md) §5.
