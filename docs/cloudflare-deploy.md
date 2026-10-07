# Cloudflare deploy — domain, Pages, Worker, Access, and WAF

Record of the real process of putting `danielmala.co` into production: the
domain was bought on Namecheap, DNS moved to being managed by Cloudflare,
and the site (Pages) + backend (Worker) were wired to that domain's
routes. This document exists so what only ever lived in conversation
isn't lost — it includes the real problems that came up and how they were
fixed.

## 1. Domain: Namecheap → Cloudflare

The domain is still **registered at Namecheap** — only DNS moved to being
managed by Cloudflare (a nameserver swap, not a transfer).

1. Namecheap: turn off domain parking/redirect and disable PremiumDNS
   (incompatible with third-party nameservers).
2. Cloudflare: `Add a site` → `danielmala.co` → Free plan. Since it was a
   new domain, there were no DNS records to import.
3. Cloudflare gives you 2 nameservers → paste them into Namecheap at
   `Domain List → Manage → Nameservers → Custom DNS`.
4. Wait for Cloudflare's "Active" email (minutes to a few hours).

Cloudflare's onboarding screen also surfaced **AI Crawl Control**
("Configure AI training & search policies"): `Search` and `Agent` were
left on Allow (for SEO, and so AI assistants can answer questions about
the site), `Training` was changed to **Block** (the default "block on
pages with ads" didn't apply — the site has no ads, so the default
amounted to allowing everything).

## 2. Cloudflare Pages (static site)

`Workers & Pages → Create application → Pages → Connect to Git`, with
Cloudflare's GitHub App installed in **"Only select repositories"** mode
(just this repo — works with a private repo, doesn't require a public one).

Project configuration:
- Root directory (advanced): `static`
- Build command: `npm run build`
- Build output directory: `dist` (relative to the root directory, **not**
  `static/dist`)
- Custom domains: `danielmala.co` and `www.danielmala.co`

### Problem: `*.pages.dev` ended up public by accident

As soon as the build passed, `personal-site-4fm.pages.dev` became
**accessible to anyone**, with no protection at all — the WAF rules on the
`danielmala.co` zone (section 4) don't cover `*.pages.dev`, which is a
Cloudflare-owned domain, outside the zone. Fixed with a **Zero Trust
Access application** (section 3), not with WAF.

## 3. Cloudflare Access — lockdown during development

> **Update (2026-07-31, confirmed by the repo owner):** Access no longer
> blocks `danielmala.co`/`www.danielmala.co` — the WAF geo policy
> (section 5) is now the real protection for production, as anticipated
> below. **`*.pages.dev` is still behind Access** (confirmed) — only the
> production application/destination was adjusted; the rest of this
> section describes the lockdown as it was configured during development,
> and it still applies to previews.

While the site wasn't ready for public launch, it sat behind email login
(One-Time PIN) via Cloudflare Access — covering `*.pages.dev` **and**
`danielmala.co`/`www.danielmala.co` at the same time, unlike the zone WAF.

`Zero Trust → Access → Applications` — Cloudflare had already created a
"legacy" application for the Pages project, but misconfigured:

- **Destinations**: only had `*.personal-site-4fm.pages.dev` (subdomain
  wildcard) — covered only the *previews*, not production
  (`personal-site-4fm.pages.dev` exact, no subdomain). Fixed: added
  no-subdomain entries for `personal-site-4fm.pages.dev`,
  `danielmala.co`, and `www.danielmala.co`.
- **Policy**: Source was set to "Everyone"/"All authenticated users" with
  every identity provider — since the only IdP is the One-Time PIN, this
  let **anyone** with any email in. Fixed: Source changed to `Emails` =
  only the owner's email.

At launch (2026-07-31) this Access instance was removed from the
production destinations and the WAF geo rule (section 5) became the real
protection; it still covers `*.pages.dev`.

## 4. Worker (`dynamic/worker/`) — deploy and problems solved

Method used: **Workers Builds** (automatic deploy via Git), not a manual
`wrangler deploy`.

`Workers & Pages → Create application → Connect to Git` → repo
`blindtk/personal-site` → configuration:
- **Path**: `dynamic/worker` (critical — it's a monorepo, `wrangler.toml`
  isn't at the root)
- **Build command**: empty (no build step — confirmed in `package.json`,
  only `wrangler deploy` handles bundling)
- **Deploy command**: `npx wrangler deploy`
- **Builds for non-production branches**: **off** — see the problem below

KV namespace created via the dashboard (`Storage & Databases → KV →
Create a namespace`, one for production and one `_PREVIEW`), with the IDs
pasted into `wrangler.toml`. Secrets (`RATE_SALT`, `CF_API_TOKEN`) via
`Settings → Variables and Secrets` on the Worker, with **Encrypt**
enabled — never in `wrangler.toml` (it's a versioned file; CI's gitleaks
catches any slip-up).

### Problem 1: `workers.dev` and preview URLs public by default

The first deploy published `personal-site-worker.<account>.workers.dev`
**with no protection at all** — outside the reach of both Access and the
zone WAF (same reason as `*.pages.dev`: a Cloudflare-owned domain, not
part of the zone). Fixed in `wrangler.toml`:

```toml
workers_dev = false
preview_urls = false
```

### Problem 2: branch/PR previews stayed exposed

Even with the above, every PR generated two extra URLs
(`<hash>-personal-site-worker.<account>.workers.dev` and
`<branch>-personal-site-worker.<account>.workers.dev`), published with no
protection in a comment from the `cloudflare-workers-and-pages` bot on the
PR — the URLs themselves had no protection at all, reachable by anyone
who obtained one regardless of repository access. Separately, *finding
out* a URL existed was gated by repo access (only the owner, at the
time; the repository was still private and went public later, on
2026-07-31, so that discovery path would have extended to everyone had
this not been fixed first). Fixed by turning off **"Builds for
non-production branches"** in the Worker's Settings — stops generating
previews on every PR.

### Problem 3: `routes` read as an environment variable

The hardest bug to catch: the `routes = [...]` block was placed **after**
the `[vars]` header in `wrangler.toml`. In TOML, a loose key after opening
a table belongs to that table — so `routes` was being read as
`env.routes` (visible in the deploy log: `env.routes (...) Environment
Variable`), never as real route configuration. Symptom: every deploy via
CI said `No targets deployed`, even though the code upload ran without
error. **It wasn't an API token permissions problem** (that was suspected
first, and fixed anyway — with no effect, because it wasn't the cause).
The real fix was moving `routes` to before any table (`[[kv_namespaces]]`,
`[vars]`) in the file.

While this wasn't fixed, routes were added by hand in the dashboard
(`Worker → Domains → Custom Domains and Routes → Add Route`) as a
temporary workaround — no longer needed after the fix.

## 5. WAF — custom rules on the `danielmala.co` zone

`Security → WAF → Custom rules` (the zone, not the Worker/Pages). In broad
terms: verified bots are skipped; the scheduled CI checks
(`verify-headers.yml`, `verify-worker.yml`, `verify-tls.yml`) are skipped
by a header carrying the `CI_WAF_TOKEN` secret (rotate it in GitHub Actions
and in the rule at the same time, same discipline as
`RATE_SALT`/`CF_API_TOKEN`); everything else goes through a geographic
policy with a challenge or a block. The exact conditions and their history
are kept out of this public repository on purpose — they live in the
dashboard and in the owner's private notes.

The **Log** action (to observe without affecting traffic) is unavailable
on the Free plan for Custom Rules — only `Managed Challenge`/`Block`/etc.

## 6. GitHub repository

It was **private** during development — Cloudflare Pages/Workers Builds
work with a private repo (the GitHub App is granted access explicitly,
"Only select repositories"; unlike GitHub Pages, it doesn't require a
public repo). **Update: the repository is now public** (2026-07-31). The
checklist that goes with that — full-history secret scan, Actions
permissions for fork PRs, secret scanning and push protection — lives in
GitHub's settings, not in the code. The owner confirmed secret scanning,
push protection and approval for fork-PR workflows on 2026-10-07; what's
still open is tracked in section 7. (`main` is behind a ruleset —
`docs/catalog-sync.md`.)

**Deployment-triggered workflows and fork PRs (2026-09-25 security
audit).** `verify-headers.yml` runs on `deployment_status`. For that event GitHub
runs the workflow file and checks out the code from the **deployment's
commit**, not from `main`. So if the Pages project ever deploys a commit
from a fork PR, that PR's own version of the workflow runs, with whatever
repository secrets it asks for. The code no longer sends `CI_WAF_TOKEN` on
those runs, and only ever sends it to `https://danielmala.co`. A modified
workflow file can still ask for the secret, and only settings can close
that:

- **Pages → Settings → Builds:** make sure pull requests from forks are
  not built. Preview deployments for this project's own branches are
  fine, because only people with write access create those branches.
- **GitHub → Settings → Actions → General:** require approval for all
  outside collaborators' fork workflows.
- **GitHub → Settings → Environments:** create an environment such as
  `production-checks` restricted to the `main` branch. Move
  `CI_WAF_TOKEN`, `ACCESS_CLIENT_ID` and `ACCESS_CLIENT_SECRET` from
  repository secrets into it, and add `environment: production-checks` to
  the jobs that use them (`verify-headers.yml`, `verify-worker.yml`,
  `verify-tls.yml`). A workflow from any other ref then cannot read them.

## 7. Current status and what's left

**Done:** production launch (Phase 3, 2026-07-31 — Access disabled for
`danielmala.co`/`www.danielmala.co`, WAF rule 2 now authenticated via a
signed header instead of a public User-Agent, section 5); WAF design
decisions confirmed as deliberate, not forgotten (section 5);
`.github/expected-headers.json` now points at real production instead of
`SET-ME`; email alias (`me@danielmala.co`) in `static/src/config.ts` and
`docs/dns-tls.md` (2026-07-30); public repository (section 6), with
secret scanning, push protection and approval for fork-PR workflows
confirmed in GitHub's settings (2026-10-07); the honeypot's leftovers
removed — WAF rule 3 and the `NVD_API_KEY` secret (2026-10-07).

**Left to do:**

- [ ] Move `CI_WAF_TOKEN`, `ACCESS_CLIENT_ID` and `ACCESS_CLIENT_SECRET`
  into a `main`-only GitHub Environment (`production-checks`) and add
  `environment: production-checks` to the jobs that use them (section 6).
- [ ] Keep Cloudflare Pages from building pull requests from forks
  (Pages → Settings → Builds; section 6) — not yet confirmed.
- [ ] HSTS preload — CAA and DNSSEC are done (see
  [`docs/dns-tls.md`](dns-tls.md)); preload is the one item still pending
  there.
