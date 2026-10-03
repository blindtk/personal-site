---
title: 'This site'
description: 'A personal site run like a production system: threat model, strict CSP and evidence you can check.'
tags: ['astro', 'typescript', 'cloudflare']
order: 1
---

### Astro, with no framework in the browser

Pages are generated at build time and reach the browser with no JavaScript.
The interactive parts (the tools and the Lab) use small scripts, with no
React, Vue or other hydration runtime.

Performance was not the only reason. With no framework injecting inline styles
or scripts, the Content-Security-Policy can stay at `script-src 'self'` and
`style-src 'self'`, with no `'unsafe-inline'` and not a single hash. I tried
the opposite first, with a SHA-256 hash for every inline script and style, but
the number of hashes grew with the number of pages, and after a few dozen the
CSP was over the 2000 characters Cloudflare Pages allows per header line.
Removing the inline code fixed the problem at its source.

### A separate Worker for what needs a server

The site has no backend, no database and no visitor input that reaches a
server, which keeps the threat model very simple. The few functions that
really need a server live in a Cloudflare Worker deployed on its own, which
stores no personal data. If the Worker is down, the site keeps working and
each panel that depends on it says it is unavailable instead of breaking the
page.

### Content kept apart from code, in both languages

The text lives in Markdown and JSON, outside the code, and the Portuguese and
English pages come out of the same components. No logic is written twice, and
a page never exists in only one of the languages.
