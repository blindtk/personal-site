---
title: 'Threat Intel'
description: 'An SSH/HTTP honeypot on its own VPS and the public threat feed it produces.'
tags: ['honeypot', 'mitre-attack']
order: 2
---

A real sensor, exposed to the Internet with no proxy in front, on a machine
that has nothing to do with this site. What it catches is processed, enriched
and published at [intel.danielmala.co](https://intel.danielmala.co/): a
report, dossiers, a page per address and per artifact, and a machine-readable
feed.

## What runs on the sensor

- **Emulated SSH access**: a fully emulated shell, never a real one, that
  records what the attacker types. The bait credentials in the fake
  filesystem are generated at each install and are never stored in the
  repository.
- **An HTTP maze**: endless generated text with links that only lead to more
  text, to trap crawlers and scanners. It is capped on connections, bytes and
  time, so the sensor isn't the one that runs out first.
- **Logging and tarpits** on the services scanners look for most: it holds
  the connection by dripping a banner instead of refusing it.

## From log to feed

Events from the services go into a state database and come out every
15 minutes as `feed.json`/`feed.txt`, a MISP export, a STIX 2.1 bundle and
the HTML report. Along the way:

- **ATT&CK by command, not by loose keyword**: the SSH access captures
  what the attacker types, so each pattern (`curl … | sh`, `chmod +x`, `crontab`,
  miners, reading `.ssh/id_rsa`…) maps to the technique it stands for. No
  clear pattern, no technique: never a guess.
- **Enrichment with explicit rules**: ten sources (RDAP, AbuseIPDB,
  GreyNoise, ThreatFox, OTX, Shodan, ANY.RUN…), each with what it may and
  may not conclude. Shodan, for instance, never decides whether an IP is
  malicious. A disagreement is settled by each source's reliability, and
  missing data says it is missing.
- **Malware**: files attackers try to download are held under size and
  rate limits, and the hash is looked up with analysis services
  (MalwareBazaar, VirusTotal…). Submitting the sample itself is opt-in and
  tightly gated. The artifact page shows the hash and the verdict, never
  the sample.
- **Dossiers that group behaviour, not people**: addresses linked by the
  same hashes (a reused SSH key, the same artifacts) are grouped and
  published as an inference the reader can reject, with no campaign or
  actor names.

## Privacy and retention

An IP address is personal data, even when it is almost always botnet
infrastructure. The legal basis is legitimate interest (GDPR Art. 6(1)(f)),
with safeguards: an address leaves publication after 75 days without a new
sighting and the database after 365; private and reserved ranges never get
in; an IP seen only once, passively, is not published. Username/password
pairs are only published when they come from at least 5 different ASNs
**and** 5 different /24 networks, over at least 3 days. Without ASN data
it fails closed and publishes nothing.

## Operations

The sensor is disposable: everything needed to rebuild it from scratch is in
the infrastructure repository, and the state database is encrypted and copied
off the machine on every run. CI runs the tests, dependency analysis, static
analysis and checks that the documentation matches the code. The published
pages have no JavaScript at all, with a CSP that allows no scripts.
