# ADR 0015 — Semgrep: gated at ERROR and WARNING, with retry logic that never masks a real finding

**Status:** accepted and in production (`.github/workflows/security.yml`).

## Context

Two separate, related problems with the Semgrep step:

**Severity threshold.** Semgrep findings are classified ERROR / WARNING /
INFO. The obvious default is to gate CI only on ERROR — WARNING is, by
convention, lower confidence. Running Semgrep with no severity filter at
all against this codebase surfaced 16 findings: 2 ERROR (dead ternaries,
fixed), 8 WARNING (3 of them in the "security" category — exactly what
this gate exists to catch), and 6 INFO.

**Unpinnable rulesets.** Every other tool in this repository is pinned
exactly — GitHub Actions by commit SHA, Semgrep and zizmor themselves by
exact version. The `p/typescript` and `p/javascript` rulesets can't
follow that discipline: they're server-managed bundles from the public
semgrep.dev registry, fetched fresh on every run, with no commit-SHA or
`==version` equivalent available through the open-source CLI. Found
during a security review (round 4, N4): CI was running remote, mutable
rules on every execution, and a transient network failure reaching
semgrep.dev blocked every PR without distinguishing "no findings" from
"couldn't check".

## Decision

- Gate on **both ERROR and WARNING** (`--severity ERROR --severity
  WARNING` — `--severity` is an equality filter, not a minimum, so both
  flags are required or ERROR findings would stop counting). INFO stays
  excluded: those are low-confidence "audit" rules whose typical fix is
  adding a sanitization dependency, not a signal worth blocking a PR
  over. All 16 findings from the unfiltered baseline were triaged to 0.
- Accept that `p/typescript`/`p/javascript` can't be pinned, and mitigate
  it two ways instead of pretending it isn't a gap:
  1. The custom rules in `.semgrep/` (offline, versioned in the repo,
     pinned like everything else) cover the one concrete sink that
     matters most here — DOM XSS via `innerHTML`/`outerHTML`/
     `document.write`/`insertAdjacentHTML` — independent of whether the
     remote registry is reachable.
  2. A retry loop that inspects Semgrep's exit code: **only** retries on
     exit 2 (a configuration/network failure — couldn't fetch
     `--config`), never on exit 1 (a real ERROR/WARNING finding with
     `--error`). A transient 429 or timeout from semgrep.dev gets three
     tries with backoff; a genuine finding fails immediately, on the
     first attempt, with nothing masked.

## Consequences

- The marginal cost of including WARNING is zero today and covers
  security-category rules Semgrep itself classifies below ERROR.
- The repository is explicit, in the workflow's own comments, about the
  one place its "everything pinned" discipline doesn't hold — rather than
  the more common failure mode of not noticing an unpinned dependency at
  all.
- The retry logic's exit-code distinction is the actual safety property:
  network flakiness costs a few minutes of retries, never a false pass.
