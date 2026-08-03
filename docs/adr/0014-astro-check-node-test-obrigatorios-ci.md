# ADR 0014 — `astro check` and `node --test` as required CI gates, not a human-confirmed checklist item

**Status:** accepted and in production (`.github/workflows/ci.yml`).

## Context

Two checks existed for a long time without ever running in CI:

- `astro check` — Astro's type checker. `npm run build` transpiles but
  deliberately doesn't fail on type errors (a fast-build/type-check split
  that's opt-in by design in Astro, the same distinction as `tsc build`
  vs. `tsc --noEmit`).
- `node --test` — the pure-logic test suite for the Worker and the tools
  in `static/src/scripts/`/`src/lib/`.

Both had test/check content written and available. Neither ran
automatically. The only thing asking anyone to run them was a line in
`.github/pull_request_template.md`, asking the human opening the PR to
tick a box confirming they'd run it by hand.

## Decision

Add both as required steps in `ci.yml`, gating every PR and every push to
`main`, instead of continuing to rely on the PR template's checklist.

## Consequences

- The first time `astro check` actually ran, it caught **37 real type
  errors** — including missing i18n strings that silently rendered as
  the literal text `"undefined"` in production HTML (`ToolPage.astro`,
  self-scan) and correct i18n keys read from the wrong dictionary object
  (`dict.security` instead of `dict.evidence`). None of these were
  hypothetical; they were live in production, invisible to a build that
  succeeds without type-checking.
- Discovered during a security review (2026-07): **a control that
  depends on discipline is not a control.** A human-checked box in a PR
  template is not a gate — it's a suggestion, and this repository had
  been running on that suggestion for its entire history up to that
  point.
- Both are now unconditional steps in `ci.yml` — a PR cannot merge with a
  type error or a failing pure-logic test, regardless of what the author
  remembered to run locally.
