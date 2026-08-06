# Security headers — portable configuration

This site serves the same security headers on **Cloudflare Pages** and on
a **VPS** (nginx or Caddy). This document is the single source for
replicating that configuration on any server, so that migrating from
Pages to a VPS is *copying config*, not rebuilding it.

## How security is split

All security headers, including the CSP, live in a single static line in
`static/public/_headers` (read natively by Cloudflare Pages) — no
build-time generation, no per-page `<meta>`.

> **Why there's no two-layer approach (hashes + header):** see
> [ADR 0001](adr/0001-csp-sem-inline.md) — the decision to eliminate all
> inline `<script>`/`<style>` instead of cataloguing hashes per block, and
> the single exception (the JSON-LD in `BaseLayout.astro`, with a fixed
> SHA-256 hash). This document only keeps the header's current *values*
> and how to maintain them, replicable on any server; the decision's
> history and reasoning live only in the ADR.
>
> **Recomputing the JSON-LD hash**, if `role[pt]`/`role[en]` or another
> `config.ts` field used in the block ever diverges between PT and EN
> (today a single hash covers both pages):
> ```bash
> node -e "console.log('sha256-' + require('crypto').createHash('sha256').update(EXACT_SCRIPT_CONTENT,'utf8').digest('base64'))"
> ```
> (use the exact text between `<script type="application/ld+json">` and
> `</script>` in the generated HTML, e.g. `dist/index.html`) and append
> the second hash alongside the first in `script-src` — it grows by
> *content variant*, not by page.
>
> **Violation reporting — removed (2026-08), after two prior forms.** The
> CSP used to have `report-uri /api/csp-report` + `report-to
> csp-endpoint` (`Reporting-Endpoints` header): the browser sent a POST on
> every violation from ANY visitor, no exceptions. That was removed in
> 2026-07 — every accepted POST cost KV writes on the Worker
> (`dynamic/worker/`), and Cloudflare's Free plan has a tight daily
> ceiling, shared with honeypot/vitals/cron — and replaced with a manual
> pipeline (local capture + a "Report" button on the Evidence page). The
> manual pipeline was itself removed in 2026-08: most `self`/`self`
> reports (nominally same-origin violations, which should be impossible
> under this CSP) turned out to come from Cloudflare's own managed
> challenge page intercepting the request, not from a build regression or
> a real injection — a false signal, not evidence the CSP itself needed
> reporting. The CSP is enforced either way; only the reporting layer on
> top of it is gone. See `dynamic/PLAN.md`.
>
> The presence of these headers in production is checked automatically by
> the `Headers` workflow (`.github/workflows/headers.yml`) against the
> versioned list in `.github/expected-headers.json` — after every deploy
> and on a daily cron.

The source of truth for the values is always `static/public/_headers`. If
you change it, update the mirrored blocks below.

## Current values (mirror of `_headers`)

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'sha256-/RztAGp2rIIt3aqLYwLYPT9MWtDrHCcQxZQBSY9sugY='; style-src 'self'; img-src 'self' blob:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests; require-trusted-types-for 'script'; trusted-types 'none'
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

> **COEP `require-corp`:** the whole site is same-origin (CSS/JS/fonts/
> images), so nothing breaks; together with COOP it enables
> *cross-origin isolation*. The OG images are cross-origin, but only
> **other** sites fetch them (previews), never our own pages — hence the
> `CORP: cross-origin` specific to them.

Exception for the Open Graph images (`/og-image.png`, `/og-image-en.png`),
which need to be loadable from other origins (LinkedIn/Slack/etc. previews):

```text
! Cross-Origin-Resource-Policy
Cross-Origin-Resource-Policy: cross-origin
Cache-Control: public, max-age=31536000, immutable
```

> **Watch out (Cloudflare Pages):** when several `_headers` rules match
> the same path, Pages does **not** override a repeated header — it
> **concatenates** the values with a comma (`same-origin, cross-origin`),
> which is invalid and makes the browser ignore the header entirely. The
> `! Cross-Origin-Resource-Policy` line first removes the value inherited
> from the `/*` block; only then is the new one set. (On nginx the problem
> is the reverse — see the warning below; on Caddy, matcher-based
> overrides already substitute correctly.)

Homepage (`/` and `/en/`), `Link` header (RFC 8288) — same relations
already in `<head>` (`rel="canonical"`/`rel="alternate" hreflang`,
`BaseLayout.astro`), for agents that never get around to parsing HTML:

```http
Link: <https://danielmala.co/>; rel="canonical", <https://danielmala.co/en/>; rel="alternate"; hreflang="en"
```
```http
Link: <https://danielmala.co/en/>; rel="canonical", <https://danielmala.co/>; rel="alternate"; hreflang="pt"
```

---

## nginx

Inside the site's `server { … }` (assumes TLS already terminated at nginx
or at Cloudflare in front). `always` guarantees the headers also go out
on error responses (404, etc.).

```nginx
server {
    listen 443 ssl http2;
    server_name danielmala.co;
    root /var/www/site;          # rsync target for static/dist/
    index index.html;

    # --- Security headers (mirror of static/public/_headers) ---
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'sha256-/RztAGp2rIIt3aqLYwLYPT9MWtDrHCcQxZQBSY9sugY='; style-src 'self'; img-src 'self' blob:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests; require-trusted-types-for 'script'; trusted-types 'none'" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;

    # security.txt and the rest of the static content are served as-is.
    location / {
        try_files $uri $uri/ =404;
    }

    # Open Graph images: relaxed CORP + long cache.
    location ~ ^/og-image(-en)?\.png$ {
        add_header Cross-Origin-Resource-Policy "cross-origin" always;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        # Reassert the rest: an add_header block inside a location
        # overrides those inherited from server, so the essentials are
        # repeated here.
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
        add_header X-Content-Type-Options "nosniff" always;
    }
}
```

> **Watch out (nginx):** `add_header` is **not** additive — declaring any
> `add_header` inside a `location` makes that block *ignore* all
> `add_header`s inherited from `server`. That's why the OG images'
> `location` repeats the headers it still wants to keep. If you'd rather
> avoid the repetition, use the `headers-more` module
> (`more_set_headers`), which is additive.

## Caddy

Caddy terminates TLS automatically (Let's Encrypt) and HSTS isn't
mandatory to declare — but it's kept explicit for parity with `_headers`.

```caddy
danielmala.co {
    root * /var/www/site        # rsync target for static/dist/
    encode gzip zstd
    file_server

    header {
        Content-Security-Policy "default-src 'self'; script-src 'self' 'sha256-/RztAGp2rIIt3aqLYwLYPT9MWtDrHCcQxZQBSY9sugY='; style-src 'self'; img-src 'self' blob:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests; require-trusted-types-for 'script'; trusted-types 'none'"
        Strict-Transport-Security "max-age=63072000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=()"
        Cross-Origin-Opener-Policy "same-origin"
        Cross-Origin-Resource-Policy "same-origin"
        Cross-Origin-Embedder-Policy "require-corp"
        -Server                 # remove the Server header (less fingerprinting)
    }

    # Open Graph images: relaxed CORP + long cache (overrides the CORP above).
    @og path /og-image.png /og-image-en.png
    header @og {
        Cross-Origin-Resource-Policy "cross-origin"
        Cache-Control "public, max-age=31536000, immutable"
    }
}
```

Unlike nginx, Caddy's `header @og` block is additive/overridable: it only
changes the headers it names, keeping the rest from the global block.

---

## HSTS preload (future decision, deliberately deferred)

`max-age` is 2 years with `includeSubDomains`, but **without** the
`preload` directive — on purpose, to keep the configuration reversible
until the subdomain family is decided (see `docs/dns-tls.md`). Submitting
`preload` bakes the domain (and subdomains) into browsers' *hard-coded*
list and is hard to reverse.

Once the subdomain family is settled and you want preload:

1. Add `; preload` to the value (`max-age=63072000; includeSubDomains; preload`)
   in `static/public/_headers` **and** in the nginx/Caddy blocks above.
2. Submit the domain at <https://hstspreload.org>.

## Verify after deploy

```bash
curl -sI https://danielmala.co | grep -iE 'content-security-policy|strict-transport|content-type-options|frame-options|referrer|permissions|cross-origin'
curl -s  https://danielmala.co/.well-known/security.txt
```

Public scanners (run once the site is published):

- <https://securityheaders.com/?q=danielmala.co&followRedirects=on>
- <https://developer.mozilla.org/en-US/observatory/analyze?host=danielmala.co>
