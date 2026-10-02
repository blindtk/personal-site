---
title: 'This site'
description: 'A personal site run like a production system: threat model, strict CSP, verifiable evidence.'
tags: ['astro', 'typescript', 'cloudflare']
order: 1
---

How this site was built, and why. The running system — what is in place,
what happens live and the proof — is in the [This site](/en/this-site/)
section; this page holds the decisions behind it.

## What it is

A bilingual (PT/EN) static personal site, with networking and security
tools that run in the browser. The little that genuinely needs a server —
the password checker, the mirror, the certificate watch and the Cloudflare
and Performance panels — lives in an isolated Cloudflare Worker, apart from
the site.

Content (markdown/JSON) lives separate from the code and feeds both
languages from the same components, with no logic duplicated between PT
and EN.

Security shaped the design from the start: a strict Content-Security-Policy
with no `'unsafe-inline'`, security headers and a published
responsible-disclosure policy. What is in place and why is on
[Security](/en/this-site/security/); what you can check — commit, live
headers, workflows — is on [Evidence](/en/this-site/evidence/).

## Architecture decisions

**Why Astro with no framework in the browser.** No React/Vue/Svelte by
default — pages ship with zero JavaScript, and the parts that need
interactivity (the tools, the Lab) load no hydration runtime at all. That
is not only a performance choice: it keeps the strict CSP with no
`'unsafe-inline'` easy to maintain, because no framework injects inline
style or script at runtime — and since my own `<script>` tags are external
files, never inline, `script-src 'self'` and `style-src 'self'` need no
hash at all. (I tried the reverse first — a SHA-256 hash per inline
script/style — but the hash count grows with the page count, and after a
few dozen pages the CSP passes the 2000 characters Cloudflare Pages allows
per header line. Removing the inline code instead of cataloguing it fixes
the root cause.)

**Why the Worker sits apart from the static site.** The site itself has no
backend, no database and no visitor input that reaches a server — so the
threat model on [Security](/en/this-site/security/) stays as simple as
possible. What genuinely needs a server lives isolated in the Worker,
published separately, and stores no personal data. If the Worker is down,
the site keeps working: the parts that depend on it say they are
unavailable instead of breaking the rest. The live result is on
[Cloudflare](/en/this-site/cloudflare/) and
[Performance](/en/this-site/performance/).
