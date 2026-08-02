# ADR 0009 — Public repository, not private

**Status:** accepted and executed (2026-07-31).

## Context

The repository was private during development. But the project's stated
purpose is to be read by strangers deciding whether to hire its author —
a private portfolio is a contradiction in terms. Concretely: the site in
production links back to the repository (`SITE.repo` in `config.ts`, the
Evidence page); while private, those links returned a 404 to every
visitor, breaking the site's own credibility mechanism.

Staying private had real advantages: zero disclosure risk, no external
Issue noise, total control. But also a concrete cost on GitHub Free:
limited Actions minutes (2,000/month, and the repo was already over that
quota), CodeQL, secret scanning + push protection, Dependency Review,
artifact attestations, and OpenSSF Scorecard — all require GHAS (paid) on
a private repo, and are free on a public one.

## Decision

Make the repository public (2026-07-31), after a pre-publication
checklist: replace the personal email exposed in `config.ts` with a
domain alias, rotate `RATE_SALT` and `CF_API_TOKEN`, and confirm (via
`gitleaks detect` over the full history) that no real secret ever entered
git. **History preserved in full** — no squash, no rewrite, no restarting
in another repository: the 132 PRs show the actual process of finding and
fixing mistakes (e.g. the rate limit's fail-open → fail-closed fix,
[ADR 0003](0003-rate-limit-kv-vs-nativo.md)), which is more persuasive
than any single-origin clean code.

## Consequences

- Six capabilities go from paid to free (CodeQL, secret scanning,
  Dependency Review, attestations, Scorecard, CodeRabbit) — enabled in
  the following days (`96ecfd8`, `641bf07`).
- Security impact assessed as **net positive, not negative**: the real
  attack surface (Cloudflare account, Worker endpoints) was already
  exposed to the internet regardless of repository visibility; making the
  code readable doesn't widen it.
- **Accepted trade-off:** the honeypot's five decoy paths (`DECOYS` in
  `src/index.js`) become publicly documented — but they're the standard
  paths any commodity scanner already probes blindly, so explaining them
  costs nothing and demonstrates the technique instead of hiding it (see
  "Why so much for a personal site?" in the README).
- Full reasoning, checklist, and risk analysis in
  [`docs/public-repo-decision.md`](../public-repo-decision.md) (a
  historical record of the decision, not a living document).
