---
title: 'Honeypot'
description: 'Decoy endpoints that log automated Internet scanning — the source IP is published by explicit design decision, correlated with MITRE ATT&CK and CISA KEV.'
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

## Privacy — two postures, by design

The Cloudflare panel (whole-zone traffic, which includes every legitimate
visitor) still never stores an IP: only country (`cf-ipcountry`), ASN and
the decoy path, with the timestamp rounded to 5 minutes — the rounding is
anonymisation, not tidiness, and the only thing derived from the IP on
that path is the rate-limit key, a salted truncated SHA-256 that rotates
daily, kept only for the limit window. This is covered by a test
(`test/logic.test.mjs`).

The honeypot's own events are different, by a later and explicit
decision: the source IP is now recorded in a separate list (never mixed
into the anonymous buckets above) and published, to correlate hits with
a second honeypot (Cowrie, on an external VPS) that exists specifically
to publish this. Only valid, public IPs get in — private, reserved, and
documentation ranges are excluded before anything is written. Entries
expire after 30 days without a repeat sighting — more conservative than
the VPS's sibling list (60–90 days): the HTTP scanners this honeypot
catches are more likely to run on compromised home routers or cameras
than SSH brute-forcers are, so an IP seen here has a higher chance of
belonging to an actual household. Anyone who recognises themselves in an
entry can request removal — the contact is on the
[Contact](/en/contact/) page.

## Correlation: honeypot ↔ ATT&CK ↔ threat intel

Each decoy path is classified with the MITRE ATT&CK technique that best
describes it — the same IDs as the [ATT&CK heatmap](/en/attack/). And when
one of those techniques shows up being exploited right now in the CISA KEV
catalog, the panel lights the correlation: the automated targeting this site
catches stops being theoretical and links to an active CVE. It's the same idea
as the rest of the site — don't trust, verify — applied to real hostile
traffic.
