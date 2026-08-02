# ADR 0005 — CSP violation reporting: manual instead of automatic

**Status:** accepted and in production.

## Context

The CSP had `report-uri /api/csp-report` + `report-to csp-endpoint`
(`Reporting-Endpoints` header): the browser sent a POST to
`/api/csp-report` on every violation from **any** visitor, no exceptions —
the standard design for automatic regression detection.

In practice, with zero inline content on the site (see
[ADR 0001](0001-csp-sem-inline.md)), a `script-src`/`style-src` violation
could only mean one of two things: a build regression or a real injection.
But the overwhelming majority of reports were noise from browser
extensions (ad-blockers, password managers) injecting content into
visitors' pages — and every accepted POST costs KV writes on the Worker
(rate-limit + bucket + cap, ~3 writes/POST), shared with
honeypot/vitals/cron under the same tight Free-plan daily ceiling (~1,000
writes/day for the whole account). The volume of automatic noise pushed
the account close to that ceiling — prompted by a real Cloudflare alert,
"50% of your daily Workers KV operation limit reached".

## Decision

Remove `report-uri`, `report-to`, and the `Reporting-Endpoints` header.
Replace with 100% local capture: `static/public/js/csp-report.js` — the
first resource in `<head>`, deliberately without `defer`, to attach the
`securitypolicyviolation` listener before any script/link that could
violate the CSP, so the build's own regression signal isn't lost — stores
in `sessionStorage` (deduped by directive+origin, capped at 20). Nothing
leaves without a click: `CspViolations.astro` (the Evidence page) reads
the queue and offers a "Report" button that sends everything in a single
POST in the batch format `application/reports+json`, already supported by
`parseReports()` — zero change to the Worker's receiver beyond comments.

## Consequences

- Zero KV writes until someone actually decides to report, instead of one
  write per violation from any visitor.
- **Consciously accepted trade-off:** loses automatic detection of real
  production regressions — you only find out if someone (typically the
  owner, testing after a deploy) visits the Evidence page and clicks.
- Revisit if the KV ceiling stops being a problem (plan upgrade, or
  sampling instead of a total cutoff) — see `dynamic/PLAN.md`.
