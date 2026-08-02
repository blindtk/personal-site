# ADR 0011 — No Cloudflare deploy credential in GitHub Actions: Workers Builds over a CI-driven deploy

**Status:** accepted and in production.

## Context

The standard way to deploy a Cloudflare Worker from GitHub is a workflow
step: `CF_API_TOKEN` as a GitHub Actions secret, `wrangler deploy` run on
push to `main`. That gives CI a verifiable link between the commit that
was tested and the artifact that goes to production — the classic
provenance story.

This repository does the opposite. Every `wrangler deploy` in
`.github/workflows/` (`ci.yml`, `release.yml`) runs with `--dry-run` —
it packages the Worker and proves it builds, but never actually deploys.
Real production deploy happens through **Cloudflare Workers Builds**: a
Git integration configured on Cloudflare's side (`docs/cloudflare-deploy.md`
§4) that watches the same repository and deploys on push to `main`,
entirely outside GitHub Actions.

## Decision

Never put a Cloudflare API token with deploy permissions into GitHub
Actions secrets. Let Cloudflare's own Git integration (Workers Builds)
own the deploy step. The only Cloudflare credential that does live in
GitHub Actions secrets is `CF_API_TOKEN` used by `/api/cf-stats`
(`Analytics:Read` + `Firewall/WAF:Read` scope only — read, not deploy),
and it never reaches a workflow, only the Worker's own runtime secrets.

## Consequences

- **No high-value deploy credential ever exists in the GitHub side of
  this project.** A compromised GitHub Actions run, a malicious PR from a
  fork, or a leaked Actions secret cannot deploy to production — there's
  nothing to steal, because the deploy path never touches GitHub Actions
  at all. Every third-party action in `.github/workflows/` runs with this
  ceiling: even total compromise of the CI pipeline has no path to
  production.
- **The trade-off, and it's a real one:** there is no cryptographic or
  procedural link between "the commit CI tested" and "the code currently
  serving traffic". Workers Builds automates the deploy, but doesn't
  provide `attest-build-provenance` or a required-reviewer gate — because
  it runs entirely on Cloudflare's side, outside anything a GitHub
  Actions workflow can attach to. This is finding H3, tracked as a
  living, open item in [`docs/threat-model.md`](../threat-model.md)
  (not repeated here — that document owns its status).
- A secondary manual path still exists (`npx wrangler deploy` from a
  developer laptop, used to test a branch before merging, documented in
  `CLAUDE.md`) and points at the same production Worker — closing H3
  would need to account for both paths, not just the automated one.
- Closing this gap (a GitHub Actions deploy job with a scoped token in a
  protected Environment, plus `attest-build-provenance`) is the specific,
  recorded fix — but it would reintroduce exactly the credential this ADR
  currently avoids having in GitHub Actions at all. That tension is the
  actual decision left open here, not an oversight.
