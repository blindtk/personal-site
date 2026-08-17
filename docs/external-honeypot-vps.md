# External Cowrie honeypot + spider trap — operational reference

Decision record: [ADR 0019](adr/0019-external-cowrie-honeypot-vps.md). This
document is the implementation reference — service topology, data format,
and the risks accepted along the way. Update it as the design changes;
the ADR stays a snapshot of the decision.

**Implemented in [`blindtk/honeypot-vps-infra`](https://github.com/blindtk/honeypot-vps-infra)**,
a separate repository (ADR 0019's "separate trust boundary" applied
literally — this repo's own tooling and history never touch the VPS's
config). This document describes the architecture as built there; where
anything below is more detailed or has drifted from that repo's README,
the repo's README and code are the source of truth.

This is a **separate project from `danielmala.co`'s honeypot**
(`dynamic/worker/`, ADR 0004, ADR 0007). Different machine, different
domain, different data policy. The single rule that keeps the two from
contaminating each other:

> **No data from this VPS ever reaches the Worker's KV or the main site's
> pages.** The VPS publishes its own feed; `danielmala.co` only links to
> it.

---

## 1. Hosting — Oracle Cloud Always Free

Chosen because it's the only tier that's actually free and permanent, with
a public IP, root access, and enough resources for Cowrie + `endlessh` +
a capped HTTP maze. Google Cloud's free e2-micro is US-region-only
(useless latency from Portugal); Fly.io/Render don't give easy access to
raw sockets.

**Confirmed risk, not hypothetical:** Oracle reclaims Always Free
instances judged idle — 95th-percentile CPU under 20% over a 7-day window
([Oracle, Always Free Resources](https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm)),
corroborated independently
([51 Security](https://blog.51sec.org/2023/02/oracle-cloud-cleaning-up-idle-compute.html),
[LowEndTalk](https://lowendtalk.com/discussion/184161/oracle-may-reclaim-your-idle-vps),
[Hacker News, quoting Oracle](https://news.ycombinator.com/item?id=34680826)).
A honeypot is mostly CPU idle between attacks; the scanning traffic that
feeds it may not be enough to clear the threshold. Free-tier accounts also
have a documented history of abrupt suspension for account-level abuse
triggers, independent of the idle-reclaim mechanism.

The mitigation is not converting to Pay As You Go — that would remove the
idle-reclaim risk (PAYG billing profiles aren't subject to it, without
implying any actual spend as long as no paid resource is provisioned) but
is explicitly out of scope: the repo owner asked for this to cost
nothing, full stop. The real mitigation: **treat the machine as
disposable.** Every piece of configuration lives as code, rebuildable
from scratch in an afternoon. Losing the tenancy means losing
attack history, not the project.

---

## 2. What runs on the machine

Three subdomains, each configured differently (implemented topology —
see `blindtk/honeypot-vps-infra`'s README for the full rebuild sequence):

| Subdomain | Cloudflare | Service | Role | Port(s) |
|---|---|---|---|---|
| `access.danielmala.co` | DNS-only | **Cowrie** | Full SSH shell emulation — session capture, commands, credentials, download attempts | 22 externally, DNAT'd locally to 2222 (Cowrie itself never binds a privileged port or runs as root) |
| `access.danielmala.co` | DNS-only | **`endlessh`** | SSH tarpit — drips a banner one byte at a time, holding low-effort scanners' connections open at near-zero cost | 23 + a small set of secondary commonly-scanned ports, one systemd instance per port |
| `web.danielmala.co` | DNS-only | **HTTP maze** (Nepenthes/Iocaine-style, Markov-generated infinite pages over an aggregated Portuguese public-domain prose corpus) | The "offensive posture" on the web side: wastes the resources of aggressive crawlers/scrapers that ignore `robots.txt`, generated in streaming so the cost sits on the client, not the server | 80/443 |
| `intel.danielmala.co` | Cloudflare Pages (Direct Upload, no Git link) | feed + static report | Published threat intel — see §3 | HTTPS via Cloudflare |

Real admin SSH lives on a non-standard port (moved there by
`provision.sh`'s first phase, with an explicit safety gate — the wrong
order here can lock the operator out with no reliable Always-Free serial
console to recover through), restricted the same way any other exposed
admin surface would be.

**Port topology, as built:** `endlessh` and Cowrie can't both own port
22. Cowrie sits on the real port 22 (matches the reference
implementation, maximizes the primary data source — full sessions);
`endlessh` covers port 23 and a small configurable set of other
commonly-scanned secondary ports, where there's nothing lost by holding a
scanner indefinitely instead of capturing a session. The maze is on its
own subdomain/ports entirely (80/443 on `web.`), never sharing a listener
with the SSH-side services.

**Resource caps are mandatory, implemented at two layers:**
- Cowrie's file-download emulation stays on, with hard caps: per-file
  size (Cowrie's own `download_limit_size`), and — since Cowrie has no
  native per-session/per-IP throttle — a companion script
  (`cowrie/dl-guard.py`, run by a systemd timer) that rate-limits
  downloads per session and per source IP by reading Cowrie's own event
  log and reacting with a temporary firewall drop, plus a total-size cap
  on the download directory with automatic oldest-first cleanup.
  **The sample itself** is never committed, never served from the VPS,
  never redistributed in any form, in any of this. Metadata about the
  retrieval (the URL requested, the SHA-256 of what came back) is a
  separate decision — see §3.
- The HTTP maze caps concurrent connections, bytes served per
  session/IP/day, connection timeout, and requests per second per IP —
  application-level (`maze/ratelimit.py`) *and* systemd-level
  (`CPUQuota`/`MemoryMax` on every unit, not just the maze's). Without
  both layers, an aggressive crawler exhausts the instance's own
  resources before it wastes any of its own.
- Aggressive log rotation — Cowrie under sustained brute-force fills disk
  fast on a small instance.

---

## 3. Public threat-intel feed

Publishing IPs here is a deliberate, scoped decision (ADR 0019). It's
established practice for honeypot operators (Shodan honeypot feeds,
independent researcher-run blocklists). **Note:** the main honeypot's
decoy-path events now publish IPs too, by a later, separate decision
(ADR 0020) — the two aren't in tension, but this project's design
predates that decision and was written when publishing IPs was still
something only this project did; see ADR 0020 and §3's "Cross-honeypot
correlation" below for the current state of both.

**Published per IP:**
- IP address (the point of the list — without it, it's not usable)
- first seen / last seen
- number of sightings
- ASN + country (same shape as the main honeypot's aggregates)
- technique(s)/port(s) attempted, mapped to ATT&CK (same mapping
  discipline as `dynamic/worker/src/lib/attack-map.js`, not shared code —
  different runtime)
- optional: a simple classification derived from sighting count
  (one-off vs. recurring)

**Published per malware retrieval (metadata only, revised 2026-08-16):**
- The URL Cowrie was told to fetch from.
- The SHA-256 of what was actually retrieved.

This is a correction to an earlier, blanket "never publish anything
about malware" stance in this document — too conservative. URL + hash is
a standard IOC (the same shape VirusTotal, MalwareBazaar, and the
[ajcyberdefense/cowrie-honeypot](https://github.com/ajcyberdefense/cowrie-honeypot)
reference's own "Malware Retrieved" table all publish, verified against
its live output on 2026-08-16) — it identifies a threat without handing
anyone the threat itself. Publishing the two is genuinely different from
publishing the sample.

**Never published:**
- **The malware sample itself.** Never committed to this repo, never
  served from the VPS, never redistributed in any form — the one
  absolute in this section, no exceptions.
- Full raw sessions tied to an IP without curation — the feed's value is
  in IPs and patterns, not a verbatim replay of every simulated
  intrusion.
- Captured credentials without filtering: only a username/password pair
  seen from **≥5 distinct sources** gets published, where a source is a
  distinct **/24 or ASN — never a distinct IP** (a single botnet clears a
  distinct-IP threshold trivially; a distinct-network one is a real bar).
  That keeps the botnet-dictionary noise (`admin`/`123456`/`root`,
  repeated by hundreds of IPs in one /24 or one hosting ASN) and drops
  anything that looks like a single, real person's password — via a
  documented heuristic (`feed/lib/privacy_filter.py`
  `looks_like_a_real_password`: not a common default, ≥10 characters, and
  mixing ≥3 character classes). Publishing full credential pairs at all
  is off by default (`PUBLISH_CREDENTIAL_PAIRS=false`) — usernames and
  aggregate stats alone already carry ~90% of the analytic value for a
  fraction of the risk; see the repo README's "Credential publication"
  section for the full trade-off.

**Legal basis (GDPR):** an IP is personal data even when it's almost
always cloud/botnet infrastructure rather than an identifiable
residential user. The basis is legitimate interest (Art. 6(1)(f)) —
traffic captured against a self-owned research asset, for defensive
purposes, with proportionate safeguards. This isn't novel ground:
Spamhaus, AbuseIPDB, and independent honeypot feeds have run on the same
basis for years. Three things make it defensible and need to exist from
day one, not "added later":
1. **Expiry.** Entries age out after a period without a repeat sighting —
   **75 days** (`FEED_EXPIRE_AFTER_DAYS`, settled at implementation time
   from the 60–90 day range originally proposed here), enforced both on
   what each publication run includes and on the underlying state
   database itself, so the state doesn't quietly become the permanent
   record the expiry is meant to prevent. A feed that never forgets stops
   being threat intel and becomes a permanent personal record — that
   distinction is what legitimate interest rests on.
2. **Dispute/removal process.** A simple contact (the site's existing
   email) for anyone who identifies with a listed IP and requests
   removal — shared hosting, carrier NAT, IP reassignment. Cheap to run,
   disproportionately reduces exposure.
3. **Exclude private/reserved ranges** before anything is published
   (bogons, RFC 1918 shouldn't reach here anyway, but validate regardless).

**Format:** JSON (structured, the fields above) + a plain-text variant
(one IP per line) for direct use in `fail2ban`/third-party allowlists —
what makes this an actual usable "threat list" rather than a display
piece.

### Command → ATT&CK mapping (new, 2026-08-16)

The main honeypot's path-based mapping (`attack-map.js`: one path, one
technique) doesn't fit here — Cowrie doesn't have "paths," it has a shell
session and whatever the attacker types into it. The signal is richer
and needs its own heuristic, matching *commands* to techniques by
pattern — the same idea
[ajcyberdefense/cowrie-honeypot](https://github.com/ajcyberdefense/cowrie-honeypot)
uses on its own dashboard (verified against its live output,
2026-08-16): a download-and-pipe-to-shell classifies toward
`T1222.002`/`T1105`; a `base64 -d` chain toward `T1140` (Deobfuscate/
Decode Files or Information); `iptables -F` toward `T1562.004` (Impair
Defenses); a completed login toward `T1078` (Valid Accounts); a shell
spawned at all toward `T1059.004` (Unix Shell). Same discipline as the
rest of this project and as the main site's own `techniquesForText`: no
confident pattern match → no technique, never a guessed one — the
reference's own report shows plenty of commands left unmapped (a bare
`—`) for exactly this reason.

Implemented as `feed/lib/attack_map.py` in `blindtk/honeypot-vps-infra`
— not shared code with `dynamic/worker/src/lib/attack-map.js`
(path-based, different runtime); a parallel, command-based version for
this project.

### No Sigma content, for any surface (settled 2026-08-16)

Considered and dropped, for this project and for `danielmala.co`'s own
honeypot alike — worth recording why, since it was a real back-and-forth,
not an obvious call from the start.

The case that seemed to hold up at first: Cowrie captures actual command
strings, which map onto genuine Sigma logsource categories (SSH
authentication logs for brute-force patterns, `process_creation` for the
command patterns behind the ATT&CK mapping above) — real content, not
guesswork. But it doesn't earn a second artifact type once the ATT&CK
mapping and Navigator layer above already exist: both would describe the
same handful of techniques, just in a different notation. Two
representations of the same 13-or-so techniques is redundancy, not
depth — and the reference project itself proves the point: it maps to
ATT&CK, ships a Navigator layer, and stops there. No Sigma.

Reopening this made clear the main honeypot's own Sigma section
(`content/detections.json`, one rule per decoy path) didn't hold up
either, on a harder version of the same argument — it was never more
than the path→technique mapping already published in
`content/honeypot-attack.json`, reformatted with SigmaHQ field names.
Removed entirely, along with the "pipeline" explanation that used to
frame it.

### Cross-honeypot correlation

The main site's own honeypot now publishes IPs too, by a separate
decision ([ADR 0020](adr/0020-honeypot-public-ip.md)) — so correlation
between the two sensors is possible as a direct set intersection, not the
salted-hash workaround considered before that decision existed. **Not yet
implemented**, though: `blindtk/honeypot-vps-infra`'s feed generator
currently only reads Cowrie's own logs, never `danielmala.co`'s public
honeypot data — the one-way-read design this paragraph describes (this
VPS consuming from the Worker's public API, never writing to it) is the
intended shape for it, should it get built, but as of this writing the
two feeds are independent and nothing cross-references them. Retention
already differs between the two either way — this project's entries
expire after 75 days, the main honeypot's after a fixed 30 (ADR 0020's
more conservative window, given HTTP-scanning botnets' higher odds of
running on compromised residential/IoT devices) — so a match found today
may no longer be confirmable in three months, whenever correlation is
actually added; that's an accepted limitation of keeping two
independently-tuned retention policies rather than a shared one.

---

## 4. DNS

Three subdomains, configured differently by what they need to be (§2's
table has the full picture):

- **`access.danielmala.co`** and **`web.danielmala.co`** — DNS-only
  records (grey-clouded, no Cloudflare proxy), pointing directly at the
  VPS IP. Not proxied because SSH doesn't go through an HTTP proxy
  anyway, and the HTTP maze is meant to be exposed as-is — this VPS
  doesn't inherit, or pretend to inherit, the main site's protection
  (WAF, Managed Challenge). That absence is exactly what makes it a real
  sensor, unlike the main HTTP honeypot (ADR 0007).
- **`intel.danielmala.co`** — a Cloudflare Pages custom domain (Direct
  Upload project, no Git connection), not a plain DNS record. This is
  the one surface actually meant to sit behind Cloudflare: it's a static
  publish target (the feed + report), not a raw sensor, so there's no
  tension with the "expose it as-is" reasoning above — that reasoning
  applies to `access.`/`web.` specifically, not to every subdomain this
  project uses.

A new standalone domain was considered and rejected: it costs money
(annual registration) and adds certificate/renewal overhead for no real
gain over subdomains of a zone already owned and paid for. Avoid
"free domain" services (e.g. the old Freenom) — poor reputation, poor
abuse handling, and unnecessary here.

Never referenced from `danielmala.co`'s `robots.txt`, sitemap, or any
link that could read as part of the same protected perimeter — only the
explicit reference on the project page (§5), with the boundary stated in
plain text.

---

## 5. What shows up on `danielmala.co`

**Only a project page**, in `content/projects/{pt,en}/` — not yet
written; the architecture it would describe is now built
(`blindtk/honeypot-vps-infra`), but the page itself should describe a
*running* instance (real DNS, a real feed with real entries), so it
waits on the VPS actually being provisioned (§7) rather than on any
remaining design question. Same documentary, sober tone as the rest of
the site (`CLAUDE.md`) — the infrastructure behind it can be technically
aggressive (the maze, the tarpit); the prose describing it doesn't change
register for that.

Minimum content:
- what it is and why it exists (research, not protecting the main site);
- the data boundary, stated accurately — **as of ADR 0020, both this
  project and `danielmala.co`'s own honeypot publish IPs, on different
  retention windows (75 days here, 30 there) and for different
  reasons (a dedicated research asset here; cross-honeypot correlation
  there).** The main site's Cloudflare Status/firewall panel is the one
  that stays zero-IP (ADR 0004, whole-zone traffic including every
  legitimate visitor) — that's the actual boundary worth stating clearly
  on the page, not "the other honeypot never publishes IPs," which would
  now be false;
- a link to the feed at `intel.danielmala.co`, whose report includes
  the ATT&CK mapping described in §3 — not just the IP list;
- a note on the VPS's disposable nature (Oracle Free) and why.

**Does not enter:** any data, IP, or event embedded in the main site's
pages. `dynamic/worker/` is untouched by this project — zero coupling is
what guarantees a bug here can never become a bug there.

---

## 6. Risks, stated plainly

- **Real, ongoing maintenance.** OS patches, log rotation, disk
  watching — not "publish and forget." The reference implementation
  needs five parts of setup docs for a reason.
- **The Oracle account can be suspended**, not just the instance
  reclaimed — free-tier accounts have a history of abrupt moderation;
  outbound traffic to malware-distribution infrastructure (if Cowrie's
  file-download emulation stays on) is a plausible trigger. Mitigated by
  keeping that function off, or tightly contained, and by accepting the
  possibility of losing the tenancy without warning.
- **Self-DoS.** A poorly capped maze or a Cowrie instance under heavy
  brute-force exhausts the machine's own scarce resources before the
  attacker's — the caps in §2 aren't optional.
- **Residual legal exposure.** Mitigated by the three controls in §3
  (expiry, dispute process, private-range exclusion), never fully zero —
  that's the cost of publishing personal data, even on a defensible
  legal basis.

---

## 7. Next steps

Systemd units, Cowrie config, `endlessh` config, the maze, and the feed
generator (log ingestion, privacy filter, command→ATT&CK mapping, JSON/
text IP feed, malware-IOC metadata, static report, Cloudflare Pages
publish + deployment pruning) are **implemented** — see
[`blindtk/honeypot-vps-infra`](https://github.com/blindtk/honeypot-vps-infra)
and its README for the exact rebuild sequence. What's left, in order:

1. **Outside any repository's reach:** create the Oracle tenancy,
   provision a real instance (arm64 or amd64 — `provision.sh` supports
   both), and run through the linked repo's README rebuild steps —
   including its safety-gated admin-SSH port move, which has to happen
   before anything else touches the instance's SSH access.
2. Point DNS (§4) at the real instance once it exists, and create the
   Cloudflare Pages project for `intel.danielmala.co`.
3. Write the project page in `content/projects/{pt,en}/` (§5, PT+EN) —
   this is the one piece of this project that belongs in
   `personal-site` itself, and the only reason it isn't written yet is
   that it should describe a running system, not a planned one.
