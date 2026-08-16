# External Cowrie honeypot + spider trap — operational reference

Decision record: [ADR 0019](adr/0019-external-cowrie-honeypot-vps.md). This
document is the implementation reference — service topology, data format,
and the risks accepted along the way. Update it as the design changes;
the ADR stays a snapshot of the decision.

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

| Service | Role | Port |
|---|---|---|
| **Cowrie** | Full SSH/Telnet shell emulation — session capture, commands, credentials, download attempts | 22 (real), 23 |
| **`endlessh`** | SSH tarpit — drips a banner one byte at a time, holding low-effort scanners' connections open at near-zero cost | secondary ports |
| **HTTP maze** (Nepenthes/Iocaine-style, Markov-generated infinite pages) | The "offensive posture" on the web side: wastes the resources of aggressive crawlers/scrapers that ignore `robots.txt`, generated in streaming so the cost sits on the client, not the server | 80/443 on the dedicated subdomain |

Real admin SSH lives on a non-standard port, restricted to the owner's
IP — same principle as the main site's WAF rule for the owner
(`docs/cloudflare-deploy.md` §5).

**Port topology decision:** `endlessh` and Cowrie can't both own port 22.
Cowrie sits on the real port 22 (matches the reference implementation,
maximizes the primary data source — full sessions); `endlessh` covers
port 23 and any other commonly-scanned secondary port, where there's
nothing lost by holding a scanner indefinitely instead of capturing a
session.

**Resource caps are mandatory:**
- Cowrie's file-download emulation (it fetches whatever the attacker
  tries to pull) is either disabled, or accepted as "malware lives on
  this disk and never leaves it" — never committed, never published.
- The HTTP maze caps concurrent connections, bytes served per
  session/IP, and connection timeout. Without this, an aggressive
  crawler exhausts the instance's own resources before it wastes any of
  its own.
- Aggressive log rotation — Cowrie under sustained brute-force fills disk
  fast on a small instance.

---

## 3. Public threat-intel feed

Publishing IPs here is a deliberate, scoped decision (ADR 0019) —
different from the main honeypot, where it would contradict an already
tested and published guarantee. It's established practice for honeypot
operators (Shodan honeypot feeds, independent researcher-run blocklists).

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

**Never published:**
- Malware samples (decided above, no exceptions).
- Full raw sessions tied to an IP without curation — the feed's value is
  in IPs and patterns, not a verbatim replay of every simulated
  intrusion.
- Captured credentials without filtering: only a username/password pair
  seen from **N distinct sources** gets published. That keeps the
  botnet-dictionary noise (`admin`/`123456`/`root`, repeated by hundreds
  of IPs) and drops anything that looks like a single, real person's
  password.

**Legal basis (GDPR):** an IP is personal data even when it's almost
always cloud/botnet infrastructure rather than an identifiable
residential user. The basis is legitimate interest (Art. 6(1)(f)) —
traffic captured against a self-owned research asset, for defensive
purposes, with proportionate safeguards. This isn't novel ground:
Spamhaus, AbuseIPDB, and independent honeypot feeds have run on the same
basis for years. Three things make it defensible and need to exist from
day one, not "added later":
1. **Expiry.** Entries age out after a period without a repeat sighting
   (proposed: 60–90 days). A feed that never forgets stops being threat
   intel and becomes a permanent personal record — that distinction is
   what legitimate interest rests on.
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

### Cross-honeypot correlation

The main site's own honeypot now publishes IPs too, by a separate
decision ([ADR 0020](adr/0020-honeypot-public-ip.md)) — so correlation
between the two sensors is a direct set intersection, not the
salted-hash workaround considered before that decision existed. This VPS
reads `danielmala.co`'s public IP-indexed honeypot data (same one-way
read the rest of this document already assumes: this project consumes
from the Worker's public API, never writes to it) and flags matches on
its own dashboard/feed. Retention differs between the two — this
project's entries expire after 60–90 days, the main honeypot's after
30–45 (ADR 0020's more conservative window, given HTTP-scanning botnets'
higher odds of running on compromised residential/IoT devices) — so a
match found today may no longer be confirmable in three months; that's
an accepted limitation of keeping two independently-tuned retention
policies rather than a shared one.

---

## 4. DNS

**`intel.danielmala.co`**, DNS-only record (grey-clouded — no Cloudflare
proxy), pointing directly at the VPS IP.

Not proxied because SSH doesn't go through an HTTP proxy anyway, and the
HTTP side (feed + eventual dashboard) is meant to be exposed as-is — this
VPS doesn't inherit, or pretend to inherit, the main site's protection
(WAF, Managed Challenge). That absence is exactly what makes it a real
sensor, unlike the main HTTP honeypot (ADR 0007).

A new standalone domain was considered and rejected: it costs money
(annual registration) and adds certificate/renewal overhead for no real
gain over a subdomain of a zone already owned and paid for. Avoid
"free domain" services (e.g. the old Freenom) — poor reputation, poor
abuse handling, and unnecessary here.

Never referenced from `danielmala.co`'s `robots.txt`, sitemap, or any
link that could read as part of the same protected perimeter — only the
explicit reference on the project page (§5), with the boundary stated in
plain text.

---

## 5. What shows up on `danielmala.co`

**Only a project page**, in `content/projects/{pt,en}/` — not yet
written; depends on the port topology and subdomain being confirmed
against a real instance first. Same documentary, sober tone as the rest
of the site (`CLAUDE.md`) — the infrastructure behind it can be
technically aggressive (the maze, the tarpit); the prose describing it
doesn't change register for that.

Minimum content:
- what it is and why it exists (research, not protecting the main site);
- the data boundary, stated without ambiguity: **this project publishes
  IPs by design; the honeypot on `danielmala.co` (Perimeter/Honeypot
  pages) stays zero-IP, and that doesn't change** — the single most
  important sentence on the page, so a reader doesn't generalize one
  project's policy onto the other;
- a link to the feed at `intel.danielmala.co`;
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

1. **Outside this repository's reach:** create/confirm the Oracle
   tenancy, provision the instance, generate the SSH key.
2. Confirm the port topology (§2) and the subdomain name (`intel.`
   proposed) against the real instance.
3. Once 1–2 are confirmed: systemd units, Cowrie config, `endlessh`
   config, the feed generator script (reads Cowrie's logs, produces the
   JSON/text feed per §3's rules), and the project page skeleton (§5,
   PT+EN). Not written speculatively now — designing scripts against a
   topology that might still change wastes the exercise.
