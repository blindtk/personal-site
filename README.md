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

Daniel Malaco's personal site — and, more to the point, a working demonstration
of security engineering practice: a threat model, ADRs, a CI/CD pipeline that
treats its own build chain as attack surface, and a live honeypot generating
real data for the dashboards it feeds. 233 tests, fourteen CI workflows, ten
ADRs, for a personal site. That is deliberate, not accidental — see
["Why so much for a personal site?"](#why-so-much-for-a-personal-site) below.

## What this is

| Folder | What it is | Status |
| --- | --- | --- |
| `content/` | All editorial content in markdown/JSON (posts, about, projects, links, ATT&CK/detection data) — **the single source of truth** | ✅ active |
| `static/` | The static site (Astro): blog, 11 security tools, all pages | ✅ active |
| `dynamic/` | Cloudflare Worker backend (`dynamic/worker/`): honeypot, hostile-traffic map, self-scan, SOC ticker, CSP-violation pipeline | ✅ **in production** — see [`dynamic/worker/README.md`](dynamic/worker/README.md) and [`dynamic/PLAN.md`](dynamic/PLAN.md) |

## Architecture and the three decisions worth reading

Start with [`docs/architecture.md`](docs/architecture.md) — a diagram of how
the site, the Worker, KV, and external APIs connect, and where the trust
boundaries sit. Then, of the ADRs in [`docs/adr/`](docs/adr/), these three
say the most about how this repository actually thinks:

1. **[ADR 0004 — zero PII in the honeypot](docs/adr/0004-zero-pii-honeypot.md).**
   The honeypot and analytics never store the visitor's IP — not because the
   plan doesn't allow it, but because the data wasn't needed for the
   aggregates the dashboards show. A privacy decision made against the
   author's own convenience, on a project with no external pressure to make it.
2. **[ADR 0001 — CSP without inline, by elimination, not cataloguing](docs/adr/0001-csp-sem-inline.md).**
   Rather than hash every inline `<script>`/`<style>` Astro emits, the site
   eliminates inline output entirely, so the CSP is one static line with no
   `unsafe-inline` and no hash list to keep in sync as pages change.
3. **[ADR 0003 — rate limiting in KV, with fail-closed, as a deliberate stopgap](docs/adr/0003-rate-limit-kv-vs-nativo.md).**
   A hand-rolled rate limiter with a documented migration path to a native
   Cloudflare rule, plus the incident that shaped it: the honeypot came close
   to the Workers KV free-tier daily write ceiling before launch, diagnosed
   and fixed by aligning cache TTLs to the cron interval rather than by
   reaching for a bigger plan.

[`docs/threat-model.md`](docs/threat-model.md) is the living threat model:
assets, attack surfaces, most-likely/highest-impact attacks, accepted residual
risk — including "the site's own security claims" as a breakable asset, which
is the reason every verifiable claim in this README is checked against the
code, not asserted from memory.

## Why so much for a personal site?

The numbers above are disproportionate for what a personal site does —
unless the disproportion *is* the point. It is: this repository exists to
demonstrate security-engineering practice at a scale where the controls
become meaningful, not to serve a blog efficiently. The honeypot's decoy paths (`/wp-login.php`, `/.env`, `/admin`,
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
hygiene, a Mozilla Observatory grade, and fuzzing of the two real trust
boundaries (CSP-report parsing, output sanitizers). Every action is pinned to
a commit SHA (Renovate keeps digests current), `permissions: {}` by default,
`persist-credentials: false` everywhere, and `npm ci --ignore-scripts` in CI.

Full stage-by-stage table, cadence rationale, and the external (manual)
scanner reports for `danielmala.co` — Qualys SSL Labs, Security Headers,
Mozilla Observatory, Hardenize, DNSViz, ImmuniWeb, and more — are in
[`docs/ci-cd.md`](docs/ci-cd.md).

## Security features

`/ferramentas/` (`/en/tools/`) has **11 tools**: 8 run entirely client-side
(subnet calculator, hash functions, encoder/decoder, password strength,
email-header analyzer, EXIF viewer, CSP builder, passkey/WebAuthn inspector —
no network calls, no backend dependency), and 3 talk to the Worker because the
check genuinely can't run in a browser (`pwned` — k-anonymity breach check,
`self-scan` — header analysis of an arbitrary target, `mirror` — what the
server sees about you). The three server-backed ones are marked with a
"requires server" badge on the tools index; they are never hidden as if they
were client-side.

Beyond the tools, the site has several live cybersecurity showcases:

| Feature | Where | Needs the Worker? |
| --- | --- | --- |
| **MITRE ATT&CK heatmap** | `/attack` | No — 100% static (`content/attack.json`) |
| **Perimeter** (honeypot panel, hostile-traffic map, detection rules, Cloudflare stats, trends, logs) | `/perimetro/` (`/en/perimeter/`) | Yes — `/api/honeypot`, `/api/map`, `/api/cf-stats`, `/api/threat-intel`, `/api/ct` |
| **Self-scan of security headers** | Security page | Yes — `/api/scan` |
| **SOC ticker** (CISA KEV + NVD) | top of Security page | Yes — `/api/ticker` |

The Worker-backed features degrade gracefully when it isn't reachable (they
show a fallback note instead of breaking). The backend, its endpoints, its
privacy stance (no IP ever stored), and its deploy are documented in
[`dynamic/worker/README.md`](dynamic/worker/README.md). The ATT&CK heatmap
always works, since it's fully static.

**Note on the honeypot's decoys being public:** see
["Why so much for a personal site?"](#why-so-much-for-a-personal-site) above —
this is a deliberate stance, not an oversight.

## AI-assisted development

Built with heavy use of Claude Code — the branch names in the merge commits
already say so, on every PR. Architecture, threat model, security decisions,
and review are mine; the ADRs in [`docs/adr/`](docs/adr/) record the
trade-offs and the alternatives rejected. Security-relevant changes are
checked by tests (`npm test`) and by the scanners in
[`.github/workflows/`](.github/workflows/) — not a measured coverage
guarantee, but the gate every PR has to clear. CodeRabbit reviews every PR
too, calibrated to this repo's own invariants rather than generic
(`.coderabbit.yaml`) — AI reviewing AI-assisted code, not a substitute for
the review that's mine. I can walk through any decision in this repository.

## Contributing

Single-maintainer project, but the repo is public and contributions are
welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the process — bug
reports, PR conventions, and where the project's own conventions live
(`CLAUDE.md`). `docs/` and `CLAUDE.md` are in English; `content/` (blog
posts, page copy) is bilingual PT/EN by construction — see CLAUDE.md's
architecture rules.

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
