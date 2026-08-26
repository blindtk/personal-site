# ADR 0019 — External Cowrie honeypot + spider trap: separate machine, separate privacy boundary

**Status:** accepted, infra written, not yet deployed. The concrete
implementation lives in a separate repository,
[`honeypot-vps-infra`](https://github.com/blindtk/honeypot-vps-infra) —
config-as-code for the VPS, Terraform provisioning, and the feed
generator. That repo's own README takes precedence over this ADR and
`docs/external-honeypot-vps.md` wherever they disagree; this ADR stays a
snapshot of the decision, not a live spec.

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
- **DNS:** three subdomains of the existing zone, split by function and
  *not* identically configured. `access.danielmala.co` (Cowrie +
  `endlessh`, SSH/Telnet) and `web.danielmala.co` (the HTTP maze/spider
  trap) are DNS-only, **not** proxied through Cloudflare, and never added
  to the main site's WAF/Access posture — both are attacker-facing
  sensors that need to look unprotected. `intel.danielmala.co` (the
  threat-intel feed + static report) is different in kind: it publishes
  an already-curated artifact, not raw attacker traffic, so it's served
  from a **dedicated Cloudflare Pages project (Direct Upload, no Git
  connection)** — the VPS's cron pushes a fresh snapshot with `wrangler
  pages deploy` on each run, and old deployments are pruned via the
  Cloudflare API so an "expired" IP can't stay reachable forever through a
  leftover preview URL. This gets CDN caching and DDoS/bot protection for
  a page meant to be publicly linked and pulled by third-party blocklist
  consumers, without needing a live origin server behind it. One name per
  surface, so each can be referenced, disabled, re-pointed, or — as with
  `intel.` — given a completely different hosting mechanism, independently
  of the other two. A new standalone domain was rejected: it costs money
  and adds renewal/certificate
  overhead for no real benefit over subdomains of a zone already owned.
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
  a self-run security research asset, mitigated by entry expiry (75
  days without a repeat sighting — `FEED_EXPIRE_AFTER_DAYS` in
  `honeypot-vps-infra`), a takedown/dispute contact, and
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
- **Written, not yet deployed.** The concrete artifacts (systemd units,
  Cowrie/`endlessh`/maze config, Terraform, the two-phase provisioning
  workflow, the feed generator + Cloudflare Pages publisher) all exist in
  `honeypot-vps-infra`, ready to run — provisioning the actual Oracle
  instance is outside this repository's reach, and is the one step left.
  This site's project page (`content/projects/{pt,en}/`) is still
  intentionally unwritten until the VPS is confirmed live, so it never
  describes infrastructure that doesn't exist yet.
