---
title: 'Honeypot'
description: 'Decoy endpoints that log automated Internet scanning — metadata only, no IPs, correlated with MITRE ATT&CK and CISA KEV.'
tags: ['cloudflare-workers', 'honeypot', 'threat-intel', 'mitre-attack']
order: 2
---

A few paths no human visits on purpose — `/wp-login.php`, `/.env`,
`/.git/config`, `/admin`, `/phpmyadmin/` — exist on this site for one reason
only: they're bait. Whoever touches them is, by definition, an automated
scanner. A Cloudflare Worker logs the attempt (metadata only) and returns the
same old 404, indistinguishable from a path that never existed. The live
result is on the [Honeypot](/en/this-site/honeypot/) panel — what Cloudflare
blocks across the whole zone is separate, on [Cloudflare](/en/this-site/cloudflare/).

## Why it lives in the Worker, not the static site

The monorepo rule is simple: `static/` stays 100% client (see
[This site](/en/projects/este-site/)), and the honeypot is one of the
exceptions that genuinely needs a server — someone has to see the request
arrive. So it lives isolated in a Cloudflare Worker under `dynamic/worker/` —
the first real code in that area — published separately. If the Worker is
down, the static site doesn't notice: the panel degrades gracefully instead
of breaking.

## Privacy by construction

**No IP is ever stored.** Each event keeps only country (`cf-ipcountry`), ASN
and the decoy path, with the timestamp rounded to 5 minutes — and the rounding
is anonymisation: without the precise moment you can't cross-match ASN+path+time
against third-party logs. The only thing derived from the IP is the rate-limit
key, a salted truncated SHA-256 that rotates, kept only for the limit window
and never tied to the events. This isn't a promise: it's covered by a test
(`test/logic.test.mjs` asserts the IP never appears in KV or in the logs).

## Correlation: honeypot ↔ ATT&CK ↔ threat intel

Each decoy path is classified with the MITRE ATT&CK technique that best
describes it — the same IDs as the [ATT&CK heatmap](/en/attack/). And when
one of those techniques shows up being exploited right now in the CISA KEV
catalog, the panel lights the correlation: the automated targeting this site
catches stops being theoretical and links to an active CVE. It's the same idea
as the rest of the site — don't trust, verify — applied to real hostile
traffic.
