---
title: 'Honeypot'
description: 'An SSH and HTTP honeypot on its own VPS, with enrichment, ATT&CK mapping and a public threat feed.'
tags: ['cowrie', 'threat-intel', 'mitre-attack', 'python', 'oracle-cloud']
order: 2
---

A real sensor, exposed to the Internet with no proxy in front, on a machine
that has nothing to do with this site: an Oracle Cloud VPS on Always Free
resources, configured entirely as code in the `honeypot-vps-infra` repository. What it
catches is processed, enriched and published at
[intel.danielmala.co](https://intel.danielmala.co/) — a report, dossiers, a
page per address and per artifact, and a machine-readable feed.

## What runs on the VPS

- **Cowrie** on port 22: full shell emulation — never a real shell. Login only succeeds after 2 to 5 different credentials, and the
  one that "worked" keeps working, like a genuinely compromised box;
  accepting anything on the first try was the easiest tell that it's a
  honeypot. The fake filesystem holds bait credentials (AWS, `.env`, bash
  history) generated at each install, never stored in the repository.
- **An HTTP maze** on ports 80/443: endless generated text with links that
  only lead to more text, to trap crawlers and scanners — capped on
  connections, bytes and time, so the VPS isn't the one that runs out
  first.
- **portlogger and endlessh**: logging and tarpitting on the ports cloud
  service scanners look for (Docker, Redis, Elasticsearch, RDP, VNC), and
  a tarpit on port 23 and other secondary ports that holds the connection
  by dripping a banner.

## From log to feed

Events from the four services go into a state database and come out every
15 minutes as `feed.json`/`feed.txt`, a MISP export, a STIX 2.1 bundle and
the HTML report. Along the way:

- **ATT&CK by command, not by loose keyword**: Cowrie captures what the
  attacker types, so each pattern (`curl … | sh`, `chmod +x`, `crontab`,
  miners, reading `.ssh/id_rsa`…) maps to the technique it stands for. No
  clear pattern, no technique — never a guess.
- **Enrichment with explicit rules**: ten sources (RDAP, AbuseIPDB,
  GreyNoise, ThreatFox, OTX, Shodan, ANY.RUN…), each with what it may and
  may not conclude — Shodan, for instance, never decides whether an IP is
  malicious. A disagreement is settled by each source's reliability, and
  missing data says it is missing.
- **Malware**: files attackers try to download are held under size and
  rate limits, and the hash is looked up with analysis services
  (MalwareBazaar, VirusTotal…) — submitting the sample itself is opt-in and
  tightly gated. The artifact page shows the hash and the verdict, never
  the sample.
- **Dossiers that group behaviour, not people**: addresses linked by the
  same hashes (a reused SSH key, the same artifacts) are grouped and
  published as an
  inference the reader can reject — no campaign or actor names.

## Privacy and retention

An IP address is personal data, even when it is almost always botnet
infrastructure. The legal basis is legitimate interest (GDPR Art. 6(1)(f)),
with safeguards: an address leaves publication after 75 days without a new
sighting and the database after 365; private and reserved ranges never get
in; an IP seen only once, passively, is not published. Username/password
pairs are only published when they come from at least 5 different ASNs
**and** 5 different /24 networks, over at least 3 days — without ASN data
it fails closed and publishes nothing.

## Operations

The VPS is disposable: Oracle can reclaim an Always Free instance, so
everything needed to rebuild it from scratch is in the repository (an
idempotent `provision.sh` and optional Terraform). The state database is
encrypted with `age` and copied off the machine on every run. CI runs the
five test suites, `pip-audit` against hashed lockfiles (the same ones the
VPS installs), SBOMs, `ruff`, `bandit`, `shellcheck` and checks that the
documentation matches the code. The published pages carry no JavaScript at
all, under a CSP that allows no scripts.

## What about this site?

This site used to have its own honeypot — a few decoy paths
(`/wp-login.php`, `/.env`…) served by the Worker. It's gone (ADR 0022): it
sat behind a Cloudflare Managed Challenge, so it saw little of the mass
scanning it was meant to catch, and it kept IP addresses for a correlation
with this sensor that was never built. The two are now what they should
have been from the start: this site is static and keeps no IPs; the
honeypot is a separate machine, with its own domain and its own privacy
policy.
