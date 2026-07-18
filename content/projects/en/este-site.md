---
title: 'This site'
description: 'Monorepo with an Astro static site, markdown content, and client-side tools.'
tags: ['astro', 'typescript', 'cloudflare']
repo: 'https://github.com/blindtk/personal-site'
order: 1
---

Bilingual personal site built with Astro: subnet calculator, hash generator
and more — the tools run in the browser, and the little that genuinely needs
a server lives in an isolated Worker, kept apart.

Bilingual by construction: content (markdown/JSON) lives separate from the
code and feeds both versions (PT/EN) from the same shared components — no
duplicated logic between languages.

Security was treated as part of the design, not an afterthought: strict
Content-Security-Policy with no 'unsafe-inline', security headers, and a
published responsible-disclosure policy. Details at [Security](/en/security/).

## Architecture decisions

**Why Astro with no client-side framework.** No React/Vue/Svelte by
default — pages ship with zero JavaScript, and the islands that need
interactivity (the networking tools, the Lab) load no hydration runtime at
all. That's not only a performance choice: it keeps the strict CSP with no
`'unsafe-inline'` easy to maintain, because there's no framework injecting
inline style or script at runtime behind the scenes — only the `<script>`
tags I write myself, each with its own SHA-256 hash computed at build time.

**Why the Worker is separate from the static site in the monorepo.** The
`static/` site (this one) keeps the threat model described on the
[Security](/en/security/) page as simple as possible: no backend, no
database, no user input that reaches a server. The features that genuinely
need a server — the honeypot, the traffic map, the header self-scan, the
threat-intel ticker — live isolated in a Cloudflare Worker
(`dynamic/worker/`), published separately. That means the static site keeps
working (and keeps its "no backend" promise) even when the Worker is down or
not published at all — the sections that depend on it degrade gracefully
instead of breaking the rest of the site.
