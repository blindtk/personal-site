---
title: 'This site'
description: 'Monorepo with an Astro static site, markdown content, and client-side tools.'
tags: ['astro', 'typescript', 'cloudflare']
repo: 'https://github.com/blindtk/personal-site'
order: 1
---

Bilingual personal site built with Astro: subnet calculator, hash generator
and more — all running in the browser, no backend.

Bilingual by construction: content (markdown/JSON) lives separate from the
code and feeds both versions (PT/EN) from the same shared components — no
duplicated logic between languages.

Security was treated as part of the design, not an afterthought: strict
Content-Security-Policy with no 'unsafe-inline', security headers, and a
published responsible-disclosure policy. Details at [Security](/en/security/).
