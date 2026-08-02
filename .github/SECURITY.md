# Security policy

Thanks for helping keep this project secure. This repository contains
Daniel Malaco's personal site (static Astro in `static/`) and the
Cloudflare Worker behind its security features (`dynamic/worker/`).

## What's covered

- The site in production (the latest deploy from `main`).
- The Worker in `dynamic/worker/` and its endpoints (`/api/*`).
- The build chain itself (workflows in `.github/workflows/`).

Since this is a continuously-deployed site, **the only supported version is
what's currently in production** — there are no older releases to maintain.

## Reporting a vulnerability

Report it **privately**, never in a public Issue (an Issue exposes the flaw
to everyone before it's fixed):

- Via the contact page: <https://danielmala.co/en/contact/>

See also the site's `security.txt`
([`/.well-known/security.txt`](https://danielmala.co/.well-known/security.txt)),
in [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116) format.

Include, if possible: what you found, steps to reproduce, and the impact
you'd assign it. A minimal proof of concept helps a lot.

## What to expect

- A response typically within **24–48h on business days**.
- You'll be kept in the loop on the fix and disclosure timing.
- Coordinated disclosure is requested: give time to fix before going
  public. Good-faith research is welcome and will never be penalised.

## Out of scope

Automated scanner reports with no demonstrable impact (e.g. a missing
header on endpoints that serve no sensitive content, library versions with
no practical exploit) are low priority.

## This repository's security posture

The build pipeline itself is treated as attack surface: OSV-Scanner,
gitleaks, Semgrep, and zizmor run on every PR, and GitHub Actions are
pinned to commit SHA (kept current by Renovate). Full stage-by-stage
detail in [`docs/ci-cd.md`](../docs/ci-cd.md).
