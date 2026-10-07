# personal-site

[![ci](https://github.com/blindtk/personal-site/actions/workflows/ci.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/ci.yml)
[![security](https://github.com/blindtk/personal-site/actions/workflows/security.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/security.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/blindtk/personal-site/badge)](https://securityscorecards.dev/viewer/?uri=github.com/blindtk/personal-site)

Daniel Malaco's personal site ([danielmala.co](https://danielmala.co)):
interactive security tools and live, production-backed demonstrations of
defensive engineering — and a working demonstration of security
engineering practice at a scale most personal sites don't bother with.
That scale is deliberate; see
["Why so much for a personal site?"](#why-so-much-for-a-personal-site).

## Repository layout

| Path | What it is |
| --- | --- |
| `content/` | All editorial content in markdown/JSON (about, projects, blog, links, ATT&CK data) — **the single source of truth**, no code |
| `static/` | The static site (Astro): every page, the 8 tools, the Lab; security headers in `static/public/_headers` |
| `dynamic/` | The Cloudflare Worker backend (`dynamic/worker/`) and its decision log (`dynamic/PLAN.md`) |
| `docs/` | Architecture, threat model, CI/CD, deploy, headers, DNS/TLS, and the ADRs (`docs/adr/`) |
| `.github/` | Workflows, the scripts behind the production checks (`scripts/`), their expected values (`expected-headers.json`, `expected-dns.json`, `npm-audit-allowlist.json`), `CODEOWNERS`, `SECURITY.md` and the PR template |
| `.semgrep/` | Custom Semgrep rules for DOM-XSS sinks in `.astro` components |
| `.clusterfuzzlite/` | Fuzzing harness for the Worker's output sanitizers (Jazzer.js) |
| `renovate.json5` | Dependency and action-digest updates |
| `.coderabbit.yaml` | AI review instructions, per folder |
| `osv-scanner.toml`, `.gitleaksignore`, `.pre-commit-config.yaml` | Scanner configuration and the local gitleaks hook |
| `CLAUDE.md`, `CONTRIBUTING.md`, `LICENSE` | Repository conventions, how to contribute, the code's license |

## Features

| Feature | Page | Uses the Worker |
| --- | --- | --- |
| **Browser-only tools** — subnet calculator, hashes, password generator, email-header analyser, EXIF viewer, CSP analyser | `/ferramentas/` | No — no network calls |
| **Password breach check** — k-anonymity: only 5 characters of the hash leave the browser | `/ferramentas/pwned/` | `/api/pwned-range` |
| **Mirror** — what any server learns about you from a request | `/ferramentas/mirror/` | `/api/mirror` |
| **Cloudflare panels** — zone threats, firewall by action/source/country/network, mitigation per day | `/este-site/cloudflare/` | `/api/cf-stats`, `/api/threat-intel` |
| **Performance** — first-party Core Web Vitals, no third-party script | `/este-site/performance/` | `/api/vitals` |
| **Certificate Transparency watch** — certificates issued for the domain, checked against the expected CAs | `/este-site/provas/` | `/api/ct` |
| **MITRE ATT&CK heatmap** | `/attack/` | No |
| **Lab** — a terminal and the site's tools in windows | `/lab/` | No |

Every page also exists in English under `/en/`. The tools that use the
Worker carry a "requires server" badge, and Worker-backed panels show a
fallback note instead of breaking when it's unreachable. The Worker stores
no IP address anywhere — see its
[privacy section](dynamic/worker/README.md#privacy).

## Why so much for a personal site?

Nearly two hundred automated tests, more than a dozen CI workflows, and a
growing set of ADRs are disproportionate for what a personal site does —
unless the disproportion *is* the point. This repository exists to
demonstrate security-engineering practice at a scale where the controls
become meaningful, not to serve a blog efficiently. Every decision here is
meant to survive being asked about.

## Build pipeline and review

The build chain is treated as attack surface. Every PR goes through the
production build, type checking, tests in `static/` and `dynamic/worker/`,
`npm audit`, Dependency Review, OSV-Scanner, gitleaks, CodeQL, Semgrep
(with custom `.astro` DOM-XSS rules), and zizmor + actionlint on the
workflows themselves. Every action is pinned to a commit SHA,
`permissions: {}` is the default, and CI installs with
`npm ci --ignore-scripts`. Production gets scheduled checks of its
headers, TLS, DNS and Mozilla Observatory grade. Stage-by-stage detail and
the external scanner reports are in [`docs/ci-cd.md`](docs/ci-cd.md).

Implementation is AI-assisted: Claude Code writes most changes, CodeRabbit
reviews them on request (per-folder instructions in `.coderabbit.yaml`;
the free tier doesn't review automatically below 10 stars), and every PR
is approved by hand before merge. Architecture, threat model and
security trade-offs are mine — the ADRs record what was rejected and why —
and the repository's conventions live in [`CLAUDE.md`](CLAUDE.md).

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — how the site, the Worker, KV and the external APIs connect, and where the trust boundaries sit
- [`docs/threat-model.md`](docs/threat-model.md) — the living threat model, including "the site's own security claims" as a breakable asset (why every claim here is checked against the code)
- [`docs/adr/`](docs/adr/) — every architecture decision, with what was rejected and why
- [`docs/ci-cd.md`](docs/ci-cd.md) — CI/CD pipeline, stage by stage
- [`docs/cloudflare-deploy.md`](docs/cloudflare-deploy.md) — how deploy works (Pages + Workers Builds on push to `main`), incidents included
- [`docs/security-headers.md`](docs/security-headers.md) — current header values, portable to nginx/Caddy
- [`docs/dns-tls.md`](docs/dns-tls.md) — CAA, HTTPS redirect, HSTS preload, DNSSEC
- [`docs/catalog-sync.md`](docs/catalog-sync.md) — how the links catalog arrives (bot PR)
- [`dynamic/worker/README.md`](dynamic/worker/README.md) — Worker endpoints, privacy, KV budget, local development
- [`dynamic/PLAN.md`](dynamic/PLAN.md) — backend decision log and next tools

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for
running the site locally, the checks to run, and the conventions. The
repository is public, so its documentation (`docs/`, `dynamic/`, this
README, `CLAUDE.md`) is in English for anyone who reads it; the site itself
is bilingual PT/EN by construction, so `content/` stays in both languages.

## Security

To report a vulnerability, see [SECURITY.md](.github/SECURITY.md) or the
site's [`security.txt`](static/public/.well-known/security.txt)
([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)). Always report
privately, never in a public Issue.

## License

The **code** in this repository is [MIT](LICENSE) — reuse freely, keep the
copyright notice. **Editorial content** (blog posts and page copy in
`content/`, bio, and personal material) and brand elements are not covered
by the MIT license: all rights reserved.
