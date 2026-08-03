# ADR 0013 — OSV-Scanner called directly, not via the official reusable workflow

**Status:** accepted and in production (`.github/workflows/security.yml`).

## Context

The standard, documented way to run OSV-Scanner in GitHub Actions is
Google's reusable workflow (`osv-scanner/.github/workflows/osv-scanner-reusable.yml`).
It's the obvious choice — one line, maintained upstream.

That reusable workflow, internally, uses `actions/download-artifact` and
`github/codeql-action/upload-sarif`, both pinned by *tag*, not by commit
SHA, on the reusable workflow's own side. This repository's action
allowlist and its "SHA pin required" rule ([ADR 0012](0012-baseline-de-hardening-github-actions.md))
would reject those transitive, tag-pinned dependencies outright — the CI
run would fail before ever scanning anything.

## Decision

Call the OSV-Scanner **action** directly (`google/osv-scanner-action/*`,
pinned to a commit SHA like everything else) instead of the reusable
workflow that wraps it. Same detection, same tool, without inheriting a
dependency chain this repository's own pinning discipline would
otherwise reject.

## Consequences

- Slightly more setup than the one-line reusable workflow, in exchange
  for never having an unpinned action reachable from a workflow run —
  the allowlist stays airtight rather than gaining a documented
  exception for one dependency.
- Both lockfiles (`static/` and `dynamic/worker/`) are scanned this way;
  the Worker's lockfile only started being covered in 2026-07, per a
  security review finding that `wrangler`/`miniflare`/`sharp` weren't
  covered by anything before that.
- Historical note, no longer a factor: before the repository went
  public, there was a second reason to avoid the reusable workflow — SARIF
  upload to Security → Code scanning required GitHub Advanced Security,
  unavailable on a private repo. That stopped applying once the repo went
  public ([ADR 0009](0009-repositorio-publico.md)); `codeql.yml` and
  `scorecard.yml` now publish SARIF directly.
