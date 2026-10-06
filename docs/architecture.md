# Architecture

High-level view of the system — what talks to what, and where the trust
boundaries sit. Complements `README.md` (folder structure) and
`dynamic/PLAN.md` (detailed backend decisions).

```mermaid
flowchart TB
    subgraph internet["Internet"]
        visitor["Visitor / browser"]
        scanner["Scanner / hostile bot"]
    end

    subgraph cf["Cloudflare (trust boundary 1)"]
        direction TB
        waf["WAF\n(challenge, firewall rules)"]
        pages["Cloudflare Pages\nstatic site (Astro)"]
        worker["Worker\ndynamic/worker/"]
        kv[("KV\naggregated counters,\nSWR cache")]
        cacheapi[("Cache API\nrate-limit state,\nHIBP + response cache")]
    end

    subgraph upstream["External APIs (read-only)"]
        hibp["HIBP range API\n(k-anonymity)"]
        crtsh["crt.sh (CT logs)"]
        cfgraphql["Cloudflare GraphQL\nAnalytics API"]
    end

    visitor -->|HTTPS| waf
    scanner -->|probes, /api/*| waf
    waf --> pages
    waf -->|"/api/*"| worker
    worker <--> kv
    worker <--> cacheapi
    worker --> hibp
    worker --> crtsh
    worker -->|"CF_API_TOKEN (read-only)"| cfgraphql

    subgraph dev["Development (trust boundary 2)"]
        laptop["Developer laptop"]
        gh["GitHub Actions\nCI/CD"]
    end

    laptop -->|push| gh
    gh -->|"npm ci --ignore-scripts,\nbuild, test, SAST"| gh
    laptop -.->|"wrangler deploy\n(manual, only to test\na branch before merge —\nsee CLAUDE.md)"| worker
    gh -.->|"Workers Builds: automatic\ndeploy on push to main"| worker
    gh -.->|"Pages: automatic deploy\non push to main"| pages
```

The honeypot is not in this diagram on purpose: since
[ADR 0022](adr/0022-retire-internal-honeypot.md) it is a separate system
(`honeypot-vps-infra` — its own VPS, domain `intel.danielmala.co` and
privacy policy) with no code, data or credential shared with this one. The
site only links to it.

## Trust boundaries

1. **Internet → Cloudflare.** All inbound traffic passes through the zone
   WAF before reaching Pages or the Worker (Cloudflare Access now covers
   only the `*.pages.dev` previews — `docs/cloudflare-deploy.md` §3). Nothing in the application trusts
   client headers without validating them (`normalizeCountry`,
   `normalizeAsn`, etc. in `sanitize.js`).
2. **GitHub → production (Worker and Pages).** Both automatic: a push to
   `main` triggers Pages' build/deploy (Cloudflare's native Git
   integration) and, in parallel, the Worker's deploy via **Workers
   Builds** (the same Git integration, configured separately in the
   Cloudflare dashboard — see `docs/cloudflare-deploy.md` §4). There's no
   manual step in the normal path; a secondary manual path exists
   (`npx wrangler deploy` from the developer's laptop, documented in
   `CLAUDE.md` as a way to test a branch before merging) that points at
   the same production Worker. The risk associated with this boundary
   (absence of verifiable provenance and a reviewer gate between commit
   and deploy) is recorded and kept current only in
   [`docs/threat-model.md`](threat-model.md) (finding H3, B2/B3) — not
   repeated here.
3. **Worker → external APIs.** All calls are one-directional (the Worker
   only reads), with a timeout (`AbortSignal.timeout`).

## One zone, two deploy paths

| | Trigger | Automated? |
| --- | --- | --- |
| `static/` (Pages) | push to `main` | Yes — Cloudflare's native Git integration |
| `dynamic/worker/` | push to `main` (Workers Builds) | Yes — same Git integration, configured separately in the dashboard (see `docs/cloudflare-deploy.md` §4) |

Both paths are automated, but neither goes through GitHub Actions — see
[`docs/threat-model.md`](threat-model.md) (finding H3) for what that gap
implies and the current status.
