# ADR 0016 — A custom `check-npm-audit.mjs` wrapper instead of raw `npm audit`

**Status:** accepted and in production (`.github/scripts/check-npm-audit.mjs`, called from `ci.yml`).

## Context

`npm audit` has no built-in exception mechanism — no way to say "this
specific advisory is a known false positive, ignore it until a given
date". OSV-Scanner already has this, via `osv-scanner.toml`, which
requires a justification *and* an expiry per exception.

The gap wasn't theoretical: `astro` 7.1.0 was flagged under
GHSA-hpcx-pg6g-x697/MAL-2026-10726, a bad advisory the repository
confirmed was incorrect (documented with an upstream PR link). Raw `npm
audit` has no declarative way to except a single advisory — the only
options were failing every PR indefinitely or dropping the check
entirely.

## Decision

Run `npm audit --json` through a small wrapper
(`.github/scripts/check-npm-audit.mjs`) that fails only on
**high/critical** advisories not present in a versioned allowlist
(`.github/npm-audit-allowlist.json`), same pattern as `osv-scanner.toml`:
each entry needs a justification and an expiry, forcing periodic
re-review instead of a permanent silent exception.

## Consequences

- A known-bad advisory can be excepted with a paper trail (who, why,
  until when) instead of either blocking every PR or disabling the
  check.
- moderate/low-severity advisories with no available fix don't block CI
  — only high/critical do.
- Two independent dependency scanners (OSV-Scanner, `npm audit` via this
  wrapper) now share the same exception discipline: declarative,
  justified, and time-boxed, never a silent ignore.
