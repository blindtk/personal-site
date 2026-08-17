# ADR 0019 — External Cowrie honeypot + spider trap: separate machine, separate privacy boundary

**Status:** accepted and implemented — see
[`blindtk/honeypot-vps-infra`](https://github.com/blindtk/honeypot-vps-infra).
The reasoning below is the decision as originally made; where it
describes a port/subdomain topology, that detail is superseded by what's
actually in the linked repo (three subdomains — `access.`, `web.`,
`intel.` — not the single `intel.` subdomain assumed below when this ADR
was written). `docs/external-honeypot-vps.md` carries the current
operational detail; this ADR is left as the historical decision record.

## Context

The site's own honeypot (`dynamic/worker/`, ADR 0004, ADR 0007) was, at
the time this decision was made, deliberately zero-PII, and, since
ADR 0007, sits behind a Managed Challenge on all five decoy paths — a
trade of dataset breadth for a security guarantee, accepted on purpose.
The consequence, also accepted: it observes mostly whoever solves an
interactive challenge from Portugal, not the indiscriminate mass
scanning that dominates the Internet (`docs/backlog.md`, item 3, has the
fuller critique).

The repo owner wants a second, different asset: a real interaction
honeypot (Cowrie, SSH/Telnet) plus an HTTP tarpit, run on hardware outside
Cloudflare, with attacker IPs published as a threat-intel feed —
something the main honeypot's *then*-zero-PII guarantee structurally
couldn't do. **That premise changed mid-discussion:** the repo owner
went on to decide the main honeypot's own decoy-path events should also
record and publish the source IP, for cross-honeypot correlation — see
[ADR 0020](0020-honeypot-public-ip.md), decided and implemented after
this one. The reasoning above is left as it stood when this ADR was
written; it's still what motivated a *separate* asset (a materially
different environment, SSH/Telnet rather than HTTP, its own retention
policy) — it just no longer describes the main honeypot as zero-IP in the
present tense. The Cloudflare Status/firewall panel (whole-zone traffic,
not just the honeypot) remains zero-IP, unaffected by ADR 0020.

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
- **DNS:** three subdomains of the existing zone, configured differently
  per what they serve — `access.danielmala.co` (Cowrie + endlessh) and
  `web.danielmala.co` (the HTTP maze) are DNS-only, **not** proxied
  through Cloudflare and never added to the main site's WAF/Access
  posture; `intel.danielmala.co` (the feed + report) is a Cloudflare
  Pages custom domain instead, since it's the one piece meant to be
  served *through* Cloudflare rather than as a raw sensor. This is a
  refinement made during implementation — a single `intel.` subdomain was
  the working assumption when this ADR was first written, but Cowrie/SSH,
  the HTTP maze, and the Pages-hosted feed each need different Cloudflare
  treatment, so one subdomain per differently-configured surface turned
  out to be the honest shape. A new standalone domain was still rejected:
  it costs money and adds renewal/certificate overhead for no real
  benefit over subdomains of a zone already owned.
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
  a self-run security research asset, mitigated by entry expiry (75 days
  without a repeat sighting, `FEED_EXPIRE_AFTER_DAYS` in the linked repo —
  settled at implementation time from the 60–90 day range considered
  here), a takedown/dispute contact, and
  exclusion of private/reserved ranges — the same discipline any IP
  blocklist (Spamhaus, AbuseIPDB) already runs on. Captured credentials
  are filtered before publication: only pairs seen from N distinct
  sources go public, which keeps botnet dictionaries and drops anything
  that looks like a real, unique password. The malware samples Cowrie
  may fetch are never published or committed, full stop — the URL
  requested and the SHA-256 of what came back are a separate, later
  refinement (standard IOC metadata, not the sample itself), detailed in
  the reference doc below.
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
- **Implemented as a separate repository**, not inside `personal-site`:
  [`blindtk/honeypot-vps-infra`](https://github.com/blindtk/honeypot-vps-infra)
  holds the Cowrie config, endlessh config, the HTTP maze (Markov-chain
  generated Portuguese public-domain prose, per §2 above), the feed
  generator (privacy filter, command→ATT&CK mapping, Cloudflare Pages
  publish), systemd units, and the idempotent `provision.sh`. Keeping it
  a separate repo — not a subdirectory here — matches the separate-trust-
  boundary framing of this ADR literally: this repository's tooling,
  CI, and history never need to touch the VPS's config, and vice versa.
  The remaining piece that *does* belong in `personal-site` — the project
  page in `content/projects/{pt,en}/` (§5 of the operational doc) — is
  not yet written.
