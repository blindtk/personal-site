# ADR 0001 — CSP without `unsafe-inline`, without hashes: eliminate inline instead of cataloguing it

**Status:** accepted and in production (`static/public/_headers`).

## Context

A strict CSP (`default-src 'self'`, no `unsafe-inline`) needs some way to
authorize whatever `<script>`/`<style>` the site itself produces. By
default, Astro inlines small CSS and small *hoisted* scripts directly into
each page's HTML.

The first approach was Astro's native mechanism (`security.csp` / SHA-256
hashes per inline block): compute a hash for each inline
`<script>`/`<style>` at build time and union them into a single header. It
worked until the site grew: each page combines its shared script/style
with its page-specific one into a single inline block — the number of
hashes grows with the number of page × script **combinations**, not with
the number of real scripts. After ~50 pages, the header line exceeded
Cloudflare Pages' 2000-character-per-header maximum, and Pages
**silently dropped the entire CSP header in production** — no warning, no
build error, just the site's most important header quietly missing.

## Decision

Eliminate inline instead of cataloguing it. Two levers in `astro.config.mjs`:

- `build.inlineStylesheets: 'never'` — all CSS becomes an external `<link>`.
- `vite.build.assetsInlineLimit: 0` — every hoisted `<script>` becomes an
  external `<script src="/_astro/…">`.

With zero inline `<script>`/`<style>` across the whole site, `'self'` is
already as strict as a hash list — but with a fixed-size header
(~395 characters) that never grows again as pages or tools are added.

**Single exception:** the `<script type="application/ld+json">` (schema.org
Person structured data) in `BaseLayout.astro`. JSON-LD has no reliable
equivalent to an external `<link>` for crawlers, and the HTML parser
applies `script-src`/`script-src-elem` to any `<script>` regardless of
`type` — so this block gets a single SHA-256 hash of its exact content,
instead of reopening `unsafe-inline`. It grows by *content variant* (if PT
and EN ever diverge), not by page.

## Consequences

- The CSP includes `require-trusted-types-for 'script'` + `trusted-types
  'none'`: only honest because the whole DOM is built via
  `createElement`/`textContent`, never `innerHTML`/`eval` — zero-inline
  and Trusted Types reinforce each other.
- The CSP now lives entirely in `static/public/_headers` (a static line,
  not build-generated) — a single source of truth, with no build step to
  keep in sync.
- Cost: any new inline `<script>`/`<style>` introduced by mistake breaks
  the page instead of silently opening up the policy (fails loud, not
  quiet — the desired behavior).
