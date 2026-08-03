# ADR 0002 — Renovate for version updates, Dependabot only for security updates

**Status:** accepted and in production (`renovate.json5`).

## Context

Two dependency-management tools active at the same time is normally a
mistake — they collide, open duplicate PRs for the same dependency, and
nobody knows which one is "the source of truth." The obvious choice would
be one or the other, not both.

But they have different coverage by design: Renovate only opens PRs for
**direct** dependencies of `package.json` (what's in the lockfile by
choice). Dependabot's *security updates* can react to a vulnerability at
any level of the tree, including **transitive** dependencies — pulled in
by `wrangler` in `dynamic/worker/` (e.g. `sharp`/`libvips`), never
declared directly in this repository.

## Decision

- **Renovate**: all routine and major *version updates*. `group:allNonMajor`
  groups everything non-major into a single weekly PR; majors stay
  separate for unhurried review. `minimumReleaseAge: 3 days` — a security
  window against compromised packages published and pulled shortly after.
- **Dependabot**: **only** *security updates* (never *version updates* —
  that would collide with Renovate). Covers exactly Renovate's gap:
  vulnerabilities in transitive dependencies that no `package.json` in
  this repo lists.

## Consequences

- No collision: each tool has one exclusive, non-overlapping responsibility.
- `prConcurrentLimit: 3` keeps PR volume manageable at the repo's actual pace.
- If Dependabot ever starts opening *version update* PRs (e.g. a
  configuration change to the "Dependabot" app on GitHub), that's a signal
  this decision has regressed — check
  `Settings → Code security → Dependabot` on the repository.
