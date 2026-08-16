# ADR 0019 — External Cowrie honeypot + spider trap: separate machine, separate privacy boundary

**Status:** accepted, not yet built.

## Context

The site's own honeypot (`dynamic/worker/`, ADR 0004, ADR 0007) is
deliberately zero-PII and, since ADR 0007, sits behind a Managed
Challenge on all five decoy paths — a trade of dataset breadth for a
security guarantee, accepted on purpose. The consequence, also accepted:
it observes mostly whoever solves an interactive challenge from Portugal,
not the indiscriminate mass scanning that dominates the Internet
(`docs/backlog.md`, item 3, has the fuller critique).

The repo owner wants a second, different asset: a real interaction
honeypot (Cowrie, SSH/Telnet) plus an HTTP tarpit, run on hardware outside
Cloudflare, with attacker IPs published as a threat-intel feed —
something the main site's zero-PII guarantee structurally cannot do.

Reference implementation: [ajcyberdefense/cowrie-honeypot](https://github.com/ajcyberdefense/cowrie-honeypot)
(Cowrie 3.x, Ubuntu, Oracle Cloud Always Free, static dashboard published
to GitHub Pages).

## Decision

Run this as a **second, independent trust boundary**, never touching
`dynamic/worker/`'s KV or code:

- **Host:** Oracle Cloud Always Free — the only free tier with a public
  IP, root access, and resources sufficient for Cowrie + a tarpit.
  Accepted risk: Oracle reclaims Always Free instances judged idle (95th
  percentile CPU under 20% over a 7-day window — [Oracle docs](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)),
  and free-tier accounts have a documented history of abrupt suspension.
  Mitigated by treating the machine as **disposable**: all configuration
  as code, rebuildable from scratch. Explicitly not converting to Pay As
  You Go to dodge the idle-reclaim policy — the repo owner asked for this
  to cost nothing, and PAYG billing (even at $0 actual spend) is out of
  scope for now.
- **DNS:** a subdomain of the existing zone (`intel.danielmala.co`),
  DNS-only — **not** proxied through Cloudflare, and never added to the
  main site's WAF/Access posture. A new standalone domain was rejected:
  it costs money and adds renewal/certificate overhead for no real
  benefit over a subdomain of a zone already owned.
- **What runs:** Cowrie (full shell emulation, never a real shell) as the
  primary data source; `endlessh` as a cheap SSH tarpit on secondary
  ports; a bounded, rate-capped HTTP maze (Nepenthes/Iocaine-style
  Markov-generated pages) as the "offensive posture" piece the repo owner
  asked for on the web side. Resource caps (connections, bytes/session,
  timeouts) are mandatory, not optional — a two-vCPU free instance can
  DoS itself before it wastes an attacker's time.
- **Publishing attacker IPs is the point, not an oversight.** Unlike the
  main honeypot (ADR 0004), this is accepted as a deliberate,
  differently-scoped project: legitimate interest (GDPR Art. 6(1)(f)) for
  a self-run security research asset, mitigated by entry expiry (60–90
  days without a repeat sighting), a takedown/dispute contact, and
  exclusion of private/reserved ranges — the same discipline any IP
  blocklist (Spamhaus, AbuseIPDB) already runs on. Captured credentials
  are filtered before publication: only pairs seen from N distinct
  sources go public, which keeps botnet dictionaries and drops anything
  that looks like a real, unique password. Malware samples Cowrie may
  fetch are never published or committed, full stop.
- **No coupling to the main site beyond a link.** The only thing that
  reaches `danielmala.co` is a new project page in `content/projects/`
  describing the project and stating, explicitly, that its data policy is
  different from — and doesn't change — the honeypot's zero-IP guarantee.

## Consequences

- The two honeypots answer different questions and must never be
  described with the same language: the Worker-based one demonstrates a
  privacy-first sensor under real platform constraints; this one
  demonstrates real-interaction capture and a maintained threat-intel
  feed. Conflating them in copy would make the zero-IP claim read as
  situational instead of absolute.
- Full operational detail — service topology, feed format, retention and
  dispute process, risk list — lives in
  [`docs/external-honeypot-vps.md`](../external-honeypot-vps.md), kept
  separate from this ADR because it's implementation reference, not a
  one-time decision record.
- **Not implemented yet.** Provisioning the Oracle instance is outside
  this repository's reach; the concrete artifacts (systemd units, Cowrie
  config, the feed generator script, the project page) are written once
  the port topology and subdomain name are confirmed against a real
  instance, not designed speculatively against one that doesn't exist.
