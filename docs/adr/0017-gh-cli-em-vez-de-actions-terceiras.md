# ADR 0017 — Prefer the `gh` CLI over third-party Actions for simple GitHub operations

**Status:** accepted and in production (`labeler.yml`, `invariants.yml`).

## Context

Two workflows need ordinary GitHub operations that a marketplace action
would normally handle: `labeler.yml` applies area labels to a PR based on
which paths changed; `invariants.yml` opens an Issue on failure, comments
on one already open instead of duplicating, and closes it once things
recover. Both are the kind of task usually reached for a third-party
Action.

Every third-party Action is one more entry in the SHA-pinning discipline
([ADR 0012](0012-baseline-de-hardening-github-actions.md)) — one more
digest for Renovate to track, one more supply-chain dependency, for
functionality the `gh` CLI (preinstalled on every GitHub-hosted runner)
already provides directly.

## Decision

Use `gh label create`, `gh issue list/create/comment/close`, etc.,
scripted inline in the workflow, instead of adding a labeler or
issue-management Action for either workflow.

## Consequences

- Two fewer third-party Actions in the dependency surface — nothing to
  pin, nothing for Renovate to update, nothing an upstream maintainer
  could repoint.
- Labels used by `labeler.yml` are managed by hand and must already exist
  in the repo before the workflow can apply them; a missing label fails
  the step on purpose, as a signal, instead of silently creating one.
- `invariants.yml`'s dedup logic (comment on the existing open
  `automated-alert` Issue instead of opening a new one, close it
  automatically on recovery) is plain shell against `gh`'s JSON output —
  no Action-specific configuration format to learn or audit.
