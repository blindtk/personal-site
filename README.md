# personal-site

[![CI](https://github.com/blindtk/personal-site/actions/workflows/ci.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/ci.yml)
[![Security](https://github.com/blindtk/personal-site/actions/workflows/security.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/security.yml)
[![CodeQL](https://github.com/blindtk/personal-site/actions/workflows/codeql.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/codeql.yml)
[![Headers](https://github.com/blindtk/personal-site/actions/workflows/headers.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/headers.yml)
[![Supply chain](https://github.com/blindtk/personal-site/actions/workflows/supply-chain.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/supply-chain.yml)
[![Invariants](https://github.com/blindtk/personal-site/actions/workflows/invariants.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/invariants.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/blindtk/personal-site/badge)](https://securityscorecards.dev/viewer/?uri=github.com/blindtk/personal-site)

Two of the nine workflows in [`.github/workflows/`](.github/workflows/) have
no badge above: `dependency-review.yml` (PR-scoped, listed in the build
pipeline table below) and `labeler.yml` (applies area labels to PRs — repo
hygiene, not a security check).

Daniel Malaco's personal site — and, more to the point, a working demonstration
of security engineering practice: a threat model, ADRs, a CI/CD pipeline that
treats its own build chain as attack surface, and a live honeypot generating
real data for the dashboards it feeds. 233 tests, nine CI workflows, four ADRs,
for a personal site. That is deliberate, not accidental — see
["Why so much for a personal site?"](#why-so-much-for-a-personal-site) below.

> **Note:** this README is in English because most people who read it
> professionally (recruiters, engineers) don't read Portuguese — the site
> itself is bilingual by construction, PT at `/` and EN at `/en/`, and all
> editorial content (`content/`) exists in both languages. See
> [`CLAUDE.md`](CLAUDE.md) for the project's conventions (written in
> Portuguese, like the rest of `docs/`).

## What this is

| Folder | What it is | Status |
| --- | --- | --- |
| `content/` | All editorial content in markdown/JSON (posts, about, projects, links, ATT&CK/detection data) — **the single source of truth** | ✅ active |
| `static/` | The static site (Astro): blog, 11 security tools, all pages | ✅ active |
| `dynamic/` | Cloudflare Worker backend (`dynamic/worker/`): honeypot, hostile-traffic map, self-scan, SOC ticker, CSP-violation pipeline | ✅ **in production** — see [`dynamic/worker/README.md`](dynamic/worker/README.md) and [`dynamic/PLAN.md`](dynamic/PLAN.md) |

## Architecture and the three decisions worth reading

Start with [`docs/architecture.md`](docs/architecture.md) — a diagram of how
the site, the Worker, KV, and external APIs connect, and where the trust
boundaries sit. Then, of the four ADRs in [`docs/adr/`](docs/adr/), these three
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

A personal site with a threat model, four ADRs, nine CI workflows, and 233
tests is disproportionate for what it does — unless the disproportion *is* the
point. It is: this repository exists to demonstrate security-engineering
practice at a scale where the controls become meaningful, not to serve a blog
efficiently. The honeypot's decoy paths (`/wp-login.php`, `/.env`, `/admin`,
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

## Edit content (no code required)

- **New post:** create `content/blog/pt/my-post.md` (and optionally its
  English twin in `content/blog/en/` with the same filename). Use
  `draft: true` in the frontmatter until it's ready to publish.
- **About page:** `content/pages/sobre.md` (PT) and `content/pages/about.md` (EN).
- **Projects:** one file per project in `content/projects/pt/` + `en/`.
- **Links:** `content/links.json`.
- **Structured data that feeds real pages:** `content/attack.json` (ATT&CK
  heatmap, `/attack`), `content/certs.json` (Certifications page),
  `content/awards.json` (CTF/awards list on About and Home), `content/detections.json`
  (Sigma-style rules shown on the Perimeter page), `content/honeypot-attack.json`
  (decoy-path → technique mapping), `content/catalog.json` (curated list on
  the Links page).
- **Name/handle, email, socials, domain:** all in `static/src/config.ts`.

## Deploy — Cloudflare Pages

Exact steps for a first-time deploy:

1. **Create a free Cloudflare account:** <https://dash.cloudflare.com/sign-up>.
2. In the dashboard: **Workers & Pages → Create → Pages → Connect to Git**.
3. Authorize Cloudflare against your GitHub and pick the `personal-site` repo.
4. In the build configuration screen, set **exactly**:
   - **Production branch:** `main`
   - **Framework preset:** `Astro`
   - **Build command:** `npm run build`
   - **Build output directory:** `dist`
   - **Root directory (advanced):** `static` ← important! The Astro project
     lives in the `static/` subfolder, not the repo root.
5. Click **Save and Deploy**. Cloudflare installs dependencies, builds, and
   publishes — about 2 minutes to a `https://personal-site-abc.pages.dev` URL.
6. From then on, **every push to `main` deploys automatically**. Pushes to
   other branches get their own preview URL (handy for reviewing PRs).

### Custom domain

The live site runs on `danielmala.co` (registered at Namecheap, DNS on
Cloudflare — nameservers switched at the registrar). `SITE_URL` in
`static/src/config.ts` already points there. For the full process (nameserver
switch, wiring the Worker, Access during development, WAF rules), see
[`docs/cloudflare-deploy.md`](docs/cloudflare-deploy.md).

### Alternative: serve from your own VPS (Cloudflare as proxy)

1. `npm run build` and copy `static/dist/` to the VPS, e.g.
   `rsync -avz --delete static/dist/ user@vps:/var/www/site/`.
2. Serve the folder with nginx/Caddy — it's a 100% static site, any file
   server works.
3. On Cloudflare: **DNS → Add record** → type `A`, name `@`, the VPS IP, with
   the **orange cloud** (proxied) for CDN + TLS + IP masking.

Pages is simpler (zero maintenance) and is what's actually in production —
the `dynamic/` backend already runs on its own Worker, separate from wherever
the static site is served, so the VPS route stays a real alternative, not a
requirement.

## Build pipeline security

The repository treats its own build chain as attack surface. Every push/PR
goes through:

| Check | Where | What it guarantees |
| --- | --- | --- |
| **Build + `npm audit`** | `ci.yml` | The site builds clean, no high/critical advisories in dependencies. |
| **Dependency Review** | `dependency-review.yml` | Blocks PRs that introduce a new dependency with a known vulnerability, scoped to the PR's diff (the GitHub Dependency Graph) — the fast gate, complementary to the full-lockfile OSV-Scanner sweep below. |
| **OSV-Scanner** | `security.yml` | `package-lock.json` has no known vulnerabilities ([OSV.dev](https://osv.dev), includes GHSA); fails CI on any known advisory. |
| **gitleaks** | `security.yml` + local hook | No secret (Cloudflare tokens, keys) ever enters git history. Locally: `pipx install pre-commit && pre-commit install`. |
| **Semgrep** | `security.yml` | SAST via `p/typescript`/`p/javascript` plus custom rules for DOM-XSS sinks in `.astro` components (`.semgrep/`) — public rulesets don't parse that file type. |
| **zizmor** | `security.yml` | Audits the workflows themselves: missing pins, excessive permissions, template injection, persisted credentials. |
| **Headers in production** | `headers.yml` | After every deploy (and a daily cron), production is checked against `.github/expected-headers.json` — a missing or regressed security header fails the workflow. |
| **`npm audit signatures` + SBOM** | `supply-chain.yml` (weekly + manual) | Verifies npm registry signatures (catches a package served without its expected signature) and generates a CycloneDX SBOM for both lockfiles, as an artifact. |
| **Production invariants** | `invariants.yml` (daily + manual) | Checks `/api/health` and the Worker's read routes; opens an Issue if something is genuinely broken (self-closes when it recovers). Closes the loop the honeypot/threat-intel dashboards otherwise leave open — they're pull-only, so nothing used to alert anyone without someone looking. |

Cross-cutting practices: every action **pinned to a commit SHA** ([Renovate](renovate.json5)
keeps the digests current and batches updates into a weekly PR),
`permissions: {}` by default with least-privilege per job, `persist-credentials: false`
on every checkout, and `npm ci --ignore-scripts` in `ci.yml` (no dependency
runs an arbitrary postinstall in CI). The CSP is one static line in
`static/public/_headers` — no hashes, because there is zero inline
`<script>`/`<style>` on the site (see [docs/security-headers.md](docs/security-headers.md)
and [ADR 0001](docs/adr/0001-csp-sem-inline.md)). The DNS/TLS plan (CAA, HSTS
preload, DNSSEC) lives in [docs/dns-tls.md](docs/dns-tls.md). The Cloudflare
deploy process (domain, Pages, Worker, Access, WAF) and the real incidents hit
along the way are in [docs/cloudflare-deploy.md](docs/cloudflare-deploy.md).

**On cadence:** the weekly-not-per-PR schedule for SBOM/signature verification
predates this repo going public, when Actions minutes were metered against
the private-repo free tier (2,000 min/month). Public repos get unlimited
Actions minutes, but the weekly cadence stays — SBOM drift and signature
checks don't need per-PR granularity, and there was no reason to change a
schedule that was working. Full context in
[docs/security-review-2026-07-29.md](docs/security-review-2026-07-29.md) §0.

## Security features (the site's actual subject matter)

Beyond the client-side tools, the site has several live cybersecurity showcases:

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

## Security tools

`/ferramentas/` (`/en/tools/`) has **11 tools**: 8 run entirely client-side
(subnet calculator, hash functions, encoder/decoder, password strength,
email-header analyzer, EXIF viewer, CSP builder, passkey/WebAuthn inspector —
no network calls, no backend dependency), and 3 talk to the Worker because the
check genuinely can't run in a browser (`pwned` — k-anonymity breach check,
`self-scan` — header analysis of an arbitrary target, `mirror` — what the
server sees about you). The three server-backed ones are marked with a
"requires server" badge on the tools index; they are never hidden as if they
were client-side.

## Code structure

```
content/               ← markdown/JSON: blog/, pages/, projects/, links.json, attack.json, …
static/
  src/
    config.ts          ← name, handle, email, socials, SITE_URL
    content.config.ts  ← collection schemas (reads from ../content)
    i18n/               ← UI strings (ui.ts) and route map (routes.ts)
    layouts/            ← BaseLayout (nav, footer, <head>)
    components/
      pages/            ← one component per page, shared by PT/EN
      tools/            ← the 11 security tools
    scripts/            ← pure tool logic (testable in Node)
    pages/              ← thin routes: / (PT) and /en/ (EN)
  public/               ← favicon and static files served as-is
dynamic/
  worker/               ← Cloudflare Worker in production — honeypot, traffic
                          map, self-scan, SOC ticker, CSP-violation pipeline
  PLAN.md               ← decisions log and what's still planned (DNS/whois tools)
```

Development conventions: see [CLAUDE.md](CLAUDE.md).

## AI-assisted development

Built with heavy use of Claude Code — the branch names in the merge commits
already say so, on every PR. Architecture, threat model, security decisions,
and review are mine; the ADRs in [`docs/adr/`](docs/adr/) record the
trade-offs and the alternatives rejected. Every security-relevant change is
covered by tests (`npm test`, 233 across the Worker and the site) and by the
scanners in [`.github/workflows/`](.github/workflows/). I can walk through any
decision in this repository.

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
