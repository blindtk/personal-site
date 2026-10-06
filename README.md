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

| Folder | What it is |
| --- | --- |
| `content/` | All editorial content in markdown/JSON (about, projects, blog, links, ATT&CK data) — **the single source of truth**, no code |
| `static/` | The static site (Astro): every page, the 8 tools, the Lab |
| `dynamic/` | The Cloudflare Worker backend (`dynamic/worker/`): Cloudflare/firewall panels, CT watch, Web Vitals, the password-check relay and the mirror — see [`dynamic/worker/README.md`](dynamic/worker/README.md) |

## What runs on the site

**Tools** — `/ferramentas/` (`/en/tools/`). Six run entirely in the
browser, with no network calls: subnet calculator, hash functions,
password generator, email-header analyser, EXIF viewer and CSP analyser.
Two talk to the Worker because the check can't run in a browser: `pwned`
(k-anonymity breach check) and `mirror` (what the server sees about you).
Those two carry a "requires server" badge; they're never presented as
client-side.

**Live demonstrations:**

| Feature | Where | Needs the Worker? |
| --- | --- | --- |
| **Cloudflare** — zone threats, firewall by action/source/country/network, mitigation per day | `/este-site/cloudflare/` | Yes — `/api/cf-stats`, `/api/threat-intel` |
| **Performance** — first-party Core Web Vitals (p75), no third-party script | `/este-site/performance/` | Yes — `/api/vitals` |
| **Certificate Transparency watch** — every certificate issued for the domain, checked against the expected CAs | `/este-site/provas/` | Yes — `/api/ct` |
| **MITRE ATT&CK heatmap** | `/attack/` | No — static (`content/attack.json`) |
| **Lab** — a desktop in the browser: a terminal and the site's tools in windows | `/lab/` | No |
| **Threat Intel** — an SSH/HTTP honeypot and its public feed | [`intel.danielmala.co`](https://intel.danielmala.co/), described on `/projetos/threat-intel/` | No — a separate project (`honeypot-vps-infra`) on its own VPS |

Every page has an English version under `/en/`. Worker-backed panels show
a fallback note instead of breaking when the Worker is unreachable. The
Worker stores no IP address anywhere ([ADR 0004](docs/adr/0004-zero-pii-honeypot.md),
[ADR 0022](docs/adr/0022-retire-internal-honeypot.md)).

## Architecture, threat model, and the decisions worth reading

[`docs/architecture.md`](docs/architecture.md) shows how the site, the
Worker, KV and the external APIs connect, and where the trust boundaries
sit. [`docs/threat-model.md`](docs/threat-model.md) is the living threat
model it answers to — including "the site's own security claims" as a
breakable asset, which is why every claim in this README is checked
against the code.

Of the ADRs in [`docs/adr/`](docs/adr/), these four say the most about how
this repository thinks:

1. **[ADR 0011 — no Cloudflare deploy credential in GitHub Actions](docs/adr/0011-sem-token-cloudflare-no-github-actions.md).**
   CI only ever runs `wrangler deploy --dry-run`; the real deploy happens in
   Cloudflare Workers Builds, so no compromised workflow or malicious fork
   PR can reach a high-value credential. The trade-off — no cryptographic
   provenance between the commit CI tested and what runs — is tracked as
   an open item in the threat model, not hidden.
2. **[ADR 0001 — CSP without inline, by elimination, not cataloguing](docs/adr/0001-csp-sem-inline.md).**
   Instead of hashing every inline `<script>`/`<style>`, the site emits no
   inline output, so the CSP is one static line with no `unsafe-inline`
   and no hash list to keep in sync.
3. **[ADR 0023 — the Mirror shows visitors their own IP, and never stores it](docs/adr/0023-mirror-echoes-client-ip.md).**
   A "what is my IP" on a site that promises to keep no IP: the echo
   itself is harmless, so the decision is about where the response could
   end up — a shared cache (`no-store`), a forged header (fail-closed
   validation), a screenshot (hidden until clicked).
4. **[ADR 0003 — rate limiting that fails closed, as a deliberate stopgap](docs/adr/0003-rate-limit-kv-vs-nativo.md).**
   A hand-rolled limiter with a documented migration path to a native
   Cloudflare rule. A security review found that exhausting its KV write
   budget silently turned it off; it now fails closed, and its per-client
   state moved to the Cache API, so normally it costs no KV writes.

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
reviews them with per-folder instructions (`.coderabbit.yaml`), and every
PR is approved by hand before merge. Architecture, threat model and
security trade-offs are mine — the ADRs record what was rejected and why —
and the repository's conventions live in [`CLAUDE.md`](CLAUDE.md).

## Run it locally

Requires [Node.js](https://nodejs.org) 22.12+ (CI uses Node 24).

```bash
cd static
npm install        # first time only
npm run dev        # http://localhost:4321, hot-reloads static/src/ and content/
npm run build      # → static/dist/
npm run preview    # serve dist/ locally
```

The Worker has its own instructions in
[`dynamic/worker/README.md`](dynamic/worker/README.md).

## Edit content

Each collection in `content/` is paired PT (`content/<collection>/pt/`) +
EN (`content/<collection>/en/`) with the **same filename** on both sides;
a new blog post is just a new file (`draft: true` until it's ready).
Personal data (name, handle, email, socials, domain) lives only in
`static/src/config.ts`. Collections and schemas:
`static/src/content.config.ts`.

## Deploy

Every push to `main` deploys both halves automatically: the site through
Cloudflare Pages and the Worker through Cloudflare Workers Builds. `npx
wrangler deploy` from a laptop is only for testing a branch before merge.
The full process, including the incidents hit along the way, is in
[`docs/cloudflare-deploy.md`](docs/cloudflare-deploy.md).

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — system diagram, trust boundaries
- [`docs/threat-model.md`](docs/threat-model.md) — assets, attack surfaces, residual risk
- [`docs/adr/`](docs/adr/) — every architecture decision, with rejected alternatives
- [`docs/ci-cd.md`](docs/ci-cd.md) — CI/CD pipeline, stage by stage
- [`docs/cloudflare-deploy.md`](docs/cloudflare-deploy.md) — how deploy works, incidents included
- [`docs/security-headers.md`](docs/security-headers.md) — current header values, portable to nginx/Caddy
- [`docs/dns-tls.md`](docs/dns-tls.md) — CAA, HTTPS redirect, HSTS preload, DNSSEC
- [`docs/catalog-sync.md`](docs/catalog-sync.md) — how the links catalog arrives (bot PR)
- [`dynamic/worker/README.md`](dynamic/worker/README.md) — Worker endpoints, privacy, KV budget
- [`dynamic/PLAN.md`](dynamic/PLAN.md) — backend decision log and next tools

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the
local checks and conventions. The repository is public, so its
documentation (`docs/`, `dynamic/`, this README, `CLAUDE.md`) is in
English for anyone who reads it; the site itself is bilingual PT/EN by
construction, so `content/` stays in both languages.

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
