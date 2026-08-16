# personal-site

[![CI](https://github.com/blindtk/personal-site/actions/workflows/ci.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/ci.yml)
[![Security](https://github.com/blindtk/personal-site/actions/workflows/security.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/security.yml)
[![CodeQL](https://github.com/blindtk/personal-site/actions/workflows/codeql.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/codeql.yml)
[![Headers](https://github.com/blindtk/personal-site/actions/workflows/headers.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/headers.yml)
[![Supply chain](https://github.com/blindtk/personal-site/actions/workflows/supply-chain.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/supply-chain.yml)
[![Invariants](https://github.com/blindtk/personal-site/actions/workflows/invariants.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/invariants.yml)
[![TLS check](https://github.com/blindtk/personal-site/actions/workflows/tls-check.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/tls-check.yml)
[![DNS check](https://github.com/blindtk/personal-site/actions/workflows/dns-check.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/dns-check.yml)
[![Observatory check](https://github.com/blindtk/personal-site/actions/workflows/observatory-check.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/observatory-check.yml)
[![Fuzzing](https://github.com/blindtk/personal-site/actions/workflows/fuzzing.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/fuzzing.yml)
[![Release](https://github.com/blindtk/personal-site/actions/workflows/release.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/release.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/blindtk/personal-site/badge)](https://securityscorecards.dev/viewer/?uri=github.com/blindtk/personal-site)

Daniel Malaco's personal site: technical writing, interactive security
tools, and production-backed demonstrations of defensive engineering — and,
more to the point, a working demonstration of security engineering practice
at a scale most personal sites don't bother with. That scale is deliberate,
not accidental — see
["Why so much for a personal site?"](#why-so-much-for-a-personal-site) below.

**Highlights**
- Living threat model and documented architecture decisions (ADRs)
- Production Cloudflare Worker powering live security demonstrations
- Interactive security tools (client-side and Worker-backed)
- CI/CD pipeline designed as part of the security model

## Repository layout

| Folder | What it is | Status |
| --- | --- | --- |
| `content/` | All editorial content in markdown/JSON (posts, about, projects, links, ATT&CK/detection data) — **the single source of truth** | ✅ active |
| `static/` | The static site (Astro): blog, 10 security tools, all pages | ✅ active |
| `dynamic/` | Cloudflare Worker backend (`dynamic/worker/`): honeypot, hostile-traffic map, CT watch, SOC ticker | ✅ **in production** — see [`dynamic/worker/README.md`](dynamic/worker/README.md) and [`dynamic/PLAN.md`](dynamic/PLAN.md) |

## Architecture, threat model, and the four decisions worth reading

Start with [`docs/architecture.md`](docs/architecture.md) — a diagram of how
the site, the Worker, KV, and external APIs connect, and where the trust
boundaries sit.

[`docs/threat-model.md`](docs/threat-model.md) is the living threat model
that architecture answers to: assets, attack surfaces, most-likely/highest-
impact attacks, accepted residual risk — including "the site's own security
claims" as a breakable asset, which is the reason every verifiable claim in
this README is checked against the code, not asserted from memory.

Of the ADRs in [`docs/adr/`](docs/adr/) that respond to that threat model,
these four say the most about how this repository actually thinks:

1. **[ADR 0011 — no Cloudflare deploy credential in GitHub Actions](docs/adr/0011-sem-token-cloudflare-no-github-actions.md).**
   Every `wrangler deploy` in CI runs `--dry-run`; real deploy happens through
   Cloudflare Workers Builds, entirely outside GitHub Actions, so there is no
   high-value credential anywhere a compromised workflow or a malicious fork
   PR could reach. The honest trade-off that comes with it — no cryptographic
   provenance between the commit CI tested and what's actually running — is
   tracked as an open item in [`docs/threat-model.md`](docs/threat-model.md),
   not hidden.
2. **[ADR 0004](docs/adr/0004-zero-pii-honeypot.md) / [ADR 0020](docs/adr/0020-honeypot-public-ip.md) — a privacy decision revisited on purpose, not forgotten.**
   The Cloudflare Status/firewall panel still never stores a visitor's
   IP (ADR 0004, unchanged) — that data wasn't needed for the aggregates
   the dashboards show. The honeypot's own decoy-path events are
   different: they now record and publish the source IP (ADR 0020), so a
   separate external Cowrie honeypot project can correlate hits between
   the two sensors. Same rigor either way — a retention window shorter
   than that sibling project's, because HTTP-scanning botnets are more
   likely to run on compromised home devices than SSH ones are.
3. **[ADR 0001 — CSP without inline, by elimination, not cataloguing](docs/adr/0001-csp-sem-inline.md).**
   Rather than hash every inline `<script>`/`<style>` Astro emits, the site
   eliminates inline output entirely, so the CSP is one static line with no
   `unsafe-inline` and no hash list to keep in sync as pages change.
4. **[ADR 0003 — rate limiting in KV, with fail-closed, as a deliberate stopgap](docs/adr/0003-rate-limit-kv-vs-nativo.md).**
   A hand-rolled rate limiter with a documented migration path to a native
   Cloudflare rule, plus the incident that shaped it: the honeypot came close
   to the Workers KV free-tier daily write ceiling before launch, diagnosed
   and fixed by aligning cache TTLs to the cron interval rather than by
   reaching for a bigger plan.

## Why so much for a personal site?

Hundreds of automated tests, more than a dozen CI workflows, and a growing
set of ADRs are disproportionate for what a personal site does — unless the
disproportion *is* the point. It is: this repository exists to demonstrate
security-engineering practice at a scale where the controls become
meaningful, not to serve a blog efficiently.
The honeypot's decoy paths (`/wp-login.php`, `/.env`, `/admin`,
`/phpmyadmin/`, `/.git/config`) are published on purpose, not despite being a
honeypot — they're the standard paths every commodity scanner already probes
blindly, so explaining them costs nothing and demonstrates the technique
instead of hiding it. If any of the above sounds interesting to talk through,
that's the intent — every decision here is meant to survive being asked about.

## Run it locally

Requires [Node.js](https://nodejs.org) 22.12+ (built with Node 24, the current LTS).

```bash
cd static
npm install        # first time only
npm run dev        # http://localhost:4321
```

`npm run dev` hot-reloads on save, for both `static/src/` code and `content/`
markdown.

To build the production bundle:

```bash
cd static
npm run build      # → static/dist/
npm run preview    # serve dist/ locally
```

## Edit content

All editorial content is markdown/JSON under `content/` — no code, ever
(`static/` reads it via loaders). Each collection is paired PT
(`content/<collection>/pt/`) + EN (`content/<collection>/en/`) with the
**same filename** on both sides; a new blog post is just a new file
(`draft: true` until it's ready). Personal data (name, handle, email,
socials, domain) lives only in `static/src/config.ts`. Full collection list
and schemas: `static/src/content.config.ts`.

## Deploy

Both halves deploy automatically from Git on every push to `main`: the
static site via Cloudflare Pages, and the backend Worker
(`dynamic/worker/`) via Cloudflare Workers Builds — the same Git
integration, configured separately in the Cloudflare dashboard. `npx
wrangler deploy` from a laptop is a secondary path, used to test a branch
before merge, not the production path. `SITE_URL` in
`static/src/config.ts` points at the production domain. The deploy process
this repo actually follows — including the real incidents hit along the
way — is documented in
[`docs/cloudflare-deploy.md`](docs/cloudflare-deploy.md).

## Build pipeline security

The repository treats its own build chain as attack surface. Every push/PR
goes through build + tests + `npm audit`, Dependency Review, OSV-Scanner,
gitleaks, CodeQL, Semgrep (with custom `.astro` DOM-XSS rules), zizmor
auditing the workflows themselves, and CodeRabbit for AI-assisted review
(calibrated per-folder, not generic — `.coderabbit.yaml`). Production gets
its own scheduled checks:
security headers against a versioned allowlist, a TLS/cipher scan, DNS
hygiene, and a Mozilla Observatory grade. Fuzzing of the two real trust
boundaries (CSP-report parsing, output sanitizers) is manual-only. Every action is pinned to
a commit SHA (Renovate keeps digests current), `permissions: {}` by default,
`persist-credentials: false` everywhere, and `npm ci --ignore-scripts` in CI.

Full stage-by-stage table, cadence rationale, and the external (manual)
scanner reports for `danielmala.co` — Qualys SSL Labs, Security Headers,
Mozilla Observatory, Hardenize, DNSViz, ImmuniWeb, and more — are in
[`docs/ci-cd.md`](docs/ci-cd.md).

## Security features

### Interactive tools

`/ferramentas/` (`/en/tools/`) has **10 tools**. 8 run entirely client-side —
subnet calculator, hash functions, encoder/decoder, password strength,
email-header analyzer, EXIF viewer, CSP builder, passkey/WebAuthn inspector —
no network calls, no backend dependency. The other 2 talk to the Worker
because the check genuinely can't run in a browser: `pwned` (k-anonymity
breach check) and `mirror` (what the server sees about you). The two
server-backed ones are marked with a "requires server" badge on the tools
index; they are never hidden as if they were client-side.

### Live demonstrations

The site also runs several live cybersecurity showcases:

| Feature | Where | Needs the Worker? |
| --- | --- | --- |
| **MITRE ATT&CK heatmap** | `/attack` | No — 100% static (`content/attack.json`) |
| **Perimeter** (honeypot panel, hostile-traffic map, detection rules, Cloudflare stats, trends, logs) | `/perimetro/` (`/en/perimeter/`) | Yes — `/api/honeypot`, `/api/map`, `/api/cf-stats`, `/api/threat-intel`, `/api/ct` |
| **SOC ticker** (CISA KEV + NVD) | top of Security page | Yes — `/api/ticker` |

The Worker-backed features degrade gracefully when it isn't reachable (they
show a fallback note instead of breaking). The backend, its endpoints, its
privacy stance — no IP ever stored for the Cloudflare Status/firewall
panel (ADR 0004); the honeypot's own decoy-path events are the deliberate
exception, publishing the source IP for cross-honeypot correlation
(ADR 0020) — and its deploy are documented in
[`dynamic/worker/README.md`](dynamic/worker/README.md). The ATT&CK heatmap
always works, since it's fully static.

**Note on the honeypot's decoys being public:** see
["Why so much for a personal site?"](#why-so-much-for-a-personal-site) above —
this is a deliberate stance, not an oversight.

## AI-assisted development

**Tools:** Claude Code for implementation — the branch name on every merge
commit records this; CodeRabbit for review, calibrated to this repo's
own invariants rather than generic (`.coderabbit.yaml`).

**Decisions:** architecture, threat model, and security trade-offs are
mine — the ADRs in [`docs/adr/`](docs/adr/) record what was rejected and why.

**Review:** every PR is gated by the production build, type checking, and
tests in both `static/` and `dynamic/worker/`, plus the security scanners
in [`.github/workflows/`](.github/workflows/) (full detail in
[`docs/ci-cd.md`](docs/ci-cd.md)), then reviewed by CodeRabbit, then
approved manually before merge.

**Guardrails:** the repo's own conventions live in
[`CLAUDE.md`](CLAUDE.md); a change that doesn't follow them isn't merged
as-is, even if the logic is correct.

## Documentation

- [`docs/architecture.md`](docs/architecture.md) — system diagram, trust boundaries
- [`docs/threat-model.md`](docs/threat-model.md) — assets, attack surfaces, residual risk
- [`dynamic/worker/README.md`](dynamic/worker/README.md) — backend endpoints and privacy stance
- [`docs/ci-cd.md`](docs/ci-cd.md) — full CI/CD pipeline, stage by stage
- [`docs/cloudflare-deploy.md`](docs/cloudflare-deploy.md) — how deploy actually works, incidents included
- [`docs/adr/`](docs/adr/) — every architecture decision, with rejected alternatives
- [`docs/security-review-2026-07-29.md`](docs/security-review-2026-07-29.md) — the review that seeded the threat model

## Contributing

Single-maintainer project, but the repo is public and contributions are
welcome. Contributors are expected to run the relevant local checks before
opening a PR — see [CONTRIBUTING.md](CONTRIBUTING.md) for the exact
workflow and repository conventions (`CLAUDE.md`). `docs/` and `CLAUDE.md`
are in English; `content/` (blog posts, page copy) is bilingual PT/EN by
construction — see CLAUDE.md's architecture rules.

## Security

To report a vulnerability, see [SECURITY.md](.github/SECURITY.md) or the
site's [`security.txt`](static/public/.well-known/security.txt)
([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)). Always report privately,
never in a public Issue.

## License

The **code** in this repository is [MIT](LICENSE) — reuse freely, keep the
copyright notice. **Editorial content** (blog posts and page copy in
`content/`, bio, and personal material) and brand elements are not covered by
the MIT license: all rights reserved.
