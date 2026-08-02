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

Before launching for real (see section 5), this Access instance is
disabled/adjusted at the same time the WAF geo rule becomes the real
protection.

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
pasted into `wrangler.toml`. Secrets (`RATE_SALT`, `NVD_API_KEY`) via
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

## 5. WAF — rules on the `danielmala.co` zone

`Security → WAF → Custom rules` (the zone, not the Worker/Pages). These
rules diverge from the original design prepared before launch — see
["History: original design vs. production"](#history-original-design-vs-production)
at the end of this section for what changed and why.

Exact rule order in production (`Skip` rules come first; the honeypot
rule comes before the country policy, and each rule acts **on evaluation
order**):

| # | Rule | Condition (summary) | Action |
|---|---|---|---|
| 1 | Verified bots | `cf.client.bot` (Cloudflare-verified bots) | Skip |
| 2 | CI headers check | `http.request.headers["x-ci-waf-token"][0] eq "<CI_WAF_TOKEN secret value>"` (migrated 2026-07-31 — see note below) | Skip |
| 3 | Honeypot Paths | Path is `/.env`, `/.git/config`, `/wp-login.php`, `/admin`, or starts with `/phpmyadmin` | **Managed Challenge**, stops evaluation |
| 4 | Allowed Countries - Site | outside the paths above **and** country is PT | **Managed Challenge**, stops evaluation |
| 5 | Blocked Countries - Site | outside the paths above **and** country is not PT | **Block**, stops evaluation |

Why each rule:
- **2**: `.github/workflows/headers.yml` and `.github/workflows/invariants.yml`
  `fetch` production from GitHub runners (usually outside PT) — without
  this rule, both workflows fall into the country policy (rules 4/5) after
  launch and start reporting production as broken because of the WAF
  itself, not a real regression.
  > **Note (2026-07-30):** the original match ("User-Agent contains
  > `headers-check`") was a public string, documented in this very
  > file — any request from anywhere in the world could copy it and
  > bypass the country policy (found during a launch-validation session).
  > **Resolved (2026-07-31, confirmed by the repo owner):** the rule in
  > the dashboard now matches on the signed header `X-Ci-Waf-Token`
  > (`http.request.headers["x-ci-waf-token"][0] eq "<secret value>"`),
  > not the User-Agent — the scripts (`check-headers.mjs`,
  > `check-invariants.mjs`) were already sending the `CI_WAF_TOKEN`
  > (GitHub Actions secret) in this header. Rotation: change the value in
  > GitHub Actions (Settings → Secrets → Actions → `CI_WAF_TOKEN`) and in
  > the WAF rule at the same time, same discipline as
  > `RATE_SALT`/`CF_API_TOKEN`.
- **3**: the honeypot's five decoy paths (`dynamic/worker/`, `DECOYS` in
  `src/index.js`) get a `Managed Challenge` instead of passing straight
  through to the Worker, for any visitor — an explicit decision by the
  repo owner: the decoys don't stay open to the world without some
  barrier, even though they're just a sensor returning a 404.
  **A consequence to accept, not a side effect:** a Managed Challenge
  exists to filter automated bots — exactly the traffic the honeypot
  exists to observe. While this rule is active, the honeypot only
  records whoever *solves* the challenge (a real browser with JS, in some
  cases advanced scanners with browser-like automation), not the
  indiscriminate mass scanning that dominates the Internet. See
  `docs/backlog.md` for a summary of the analysis of this trade-off
  (protection vs. observability) — the full detail lives in git history
  after `docs/proposals/` was consolidated on 2026-07-31.
- **4/5**: the geographic policy hardened from "27 EU countries, Managed
  Challenge" (original design below) to "only PT gets through, with a
  challenge; everything else is blocked" — more restrictive than
  planned, and without the `ip.geoip.is_in_european_union`
  approximation (that field still requires Business+, unavailable on
  Free; it stopped mattering because the list no longer tries to
  approximate the EU).
- The **Log** action (to observe without affecting traffic) is still
  **unavailable on Free** for Custom Rules — only `Managed
  Challenge`/`Block`/etc.

### History: original design vs. production

> This subsection is a historical record — it does not describe the
> current state (the table above is the source of truth). Kept because it
> explains *why* production diverges from what was planned.

The design below (bots + social previews + CI + the owner's IP as
*Skip*, a catch-all of 27 EU countries as `Managed Challenge`) was what
got prepared ahead of time, with Access (section 3) as the real
protection in the meantime — the recorded idea was that the final rule
would already be in its definitive action with no risk, since nobody from
outside could reach it anyway.

| # | Rule | Expression | Action |
|---|---|---|---|
| 1 | Verified bots (SEO) | `(cf.client.bot)` | Skip |
| 2 | Social previews | `(http.user_agent contains "LinkedInBot") or (http.user_agent contains "Twitterbot") or (http.user_agent contains "facebookexternalhit")` | Skip |
| 3 | GitHub Actions CI | `(http.user_agent contains "headers-check")` | Skip |
| 4 | The owner, always | `(ip.src eq <IP>)` | Skip |
| 5 | Geo catch-all | `not (ip.geoip.country in {"PT" "AT" "BE" "BG" "HR" "CY" "CZ" "DK" "EE" "FI" "FR" "DE" "GR" "HU" "IE" "IT" "LV" "LT" "LU" "MT" "NL" "PL" "RO" "SK" "SI" "ES" "SE"})` | Managed Challenge |

**What changed, and why (2026-07-29):** the rules in production today are
more restrictive in some ways (a single country instead of 27, `Block`
instead of `Managed Challenge` for the rest of the world) and have one new,
deliberate piece (rule 3, dedicated to the honeypot) that the original plan
didn't anticipate. The "Social previews" and "The owner, always" rules
from the original design **were not created, by choice, not by
oversight** — confirmed 2026-07-29 (see section 7): social preview bots
are already caught by rule 1 (`cf.client.bot` includes known preview
crawlers), and as for the owner, traveling outside PT subjects them to
rule 5 (Block) like any visitor — a decision kept on purpose.

## 6. GitHub repository

It was **private** during development — Cloudflare Pages/Workers Builds
work with a private repo (the GitHub App is granted access explicitly,
"Only select repositories"; unlike GitHub Pages, it doesn't require a
public repo). **Update: the repository is now public** (2026-07-31). The
checklist that should have been confirmed before that — full-history
secret scan, Actions permissions for fork PRs, branch protection, secret
scanning — **was not re-verified by this agent** (outside the scope of a
session with no access to the repository's GitHub settings); worth
confirming manually that it was done.

## 7. Current status and what's left

**Done:** production launch (Phase 3, 2026-07-31 — Access disabled for
`danielmala.co`/`www.danielmala.co`, WAF rule 2 now authenticated via a
signed header instead of a public User-Agent, section 5); WAF design
decisions confirmed as deliberate, not forgotten (section 5);
`.github/expected-headers.json` now points at real production instead of
`SET-ME`; email alias (`me@danielmala.co`) in `static/src/config.ts` and
`docs/dns-tls.md` (2026-07-30); public repository (section 6) — section
6's prerequisite checklist was not re-verified by this agent, worth
confirming manually.

**Left to do:**

- [ ] HSTS preload — CAA and DNSSEC are done (see
  [`docs/dns-tls.md`](dns-tls.md)); preload is the one item still pending
  there.
