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
  this disk and never leaves it" — **the sample itself** is never
  committed, never served from the VPS, never redistributed in any
  form. Metadata about the retrieval (the URL requested, the SHA-256 of
  what came back) is a separate decision — see §3.
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

This needs its own small mapping table in the feed generator script
(§7) — not shared code with `dynamic/worker/src/lib/attack-map.js`
(path-based, different runtime); a parallel, command-based version for
this project.

### Sigma rules — where they belong, and where they don't (revised 2026-08-16)

Worth stating plainly, since the honeypot-wide approach to Sigma was
never actually reconsidered once this project entered the picture:
**the answer isn't "keep it as is" or "drop it everywhere" — it's
different per surface.**

`danielmala.co`'s existing Sigma rules (`content/detections.json`, one
per decoy path) stay as they are — a rule like "any request for
`/wp-login.php` on infrastructure that doesn't run WordPress is
hostile" is true regardless of how much traffic that site's own
honeypot happens to see under the Managed Challenge (ADR 0007). What's
worth revisiting **there**, separately from this project, is how much
weight the live hit-counter carries in the page's narrative when it's
often low or zero for reasons that have nothing to do with the rule's
validity — a copy fix on that page, not a reason to remove the rules.
Not done as part of this document; flagged for a decision on its own.

Cowrie is a stronger source for Sigma than the main honeypot ever was,
because it captures actual command strings instead of just which path
got hit — that maps onto real Sigma logsource categories used in
production SIEMs, not an invented one:
- **SSH brute-force / anomalous login** — `logsource: category:
  authentication` (or `product: linux, service: sshd`): failed-then-
  succeeded bursts, a pattern SigmaHQ's own public ruleset already
  covers for real SSH logs.
- **Command-pattern rules** — `logsource: category: process_creation,
  product: linux`: the same command strings behind the ATT&CK mapping
  above, translated into what a rule watching a real fleet's process
  telemetry (auditd, Sysmon for Linux) would need to catch the same
  technique. This is the richer half — the rules aren't guessing what an
  attacker might do, they're built from commands one actually typed.

These rules are **this project's own content** — they don't belong in
`content/detections.json`, which is `danielmala.co`'s honeypot's own
artifact. Same boundary already drawn for the IP data: the VPS publishes
its own detection content, on its own report, and `danielmala.co` only
links to it (§5). Concretely: folded into the static report (§7)
alongside the ATT&CK mapping — the reference project maps to ATT&CK but
doesn't generate Sigma; adding it is this project's own signature,
consistent with what `danielmala.co` already does for its own honeypot.

**No Sigma rule for the spider trap/maze — a deliberate omission, not a
gap to fill later.** A request landing in the maze is a bot-compliance
signal (a crawler that ignored `robots.txt`), not a TTP in the sense
Sigma rules usually describe. Forcing one into existence would
manufacture analytical weight that isn't really there — the same
reasoning that keeps the main honeypot's `/admin` rule at `level: low`
instead of treating every hit as high-fidelity. If a rule ever makes
sense here, it's a `category: webserver` match on requests to a
disallowed path from a UA not claiming to be a compliant crawler — worth
revisiting only if the maze turns out to catch more than isolated,
one-off compliance violations.

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
- a link to the feed at `intel.danielmala.co`, whose report includes
  the ATT&CK mapping and the Sigma rules described in §3 — not just the
  IP list;
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
   config, and the feed generator script — reads Cowrie's logs, produces
   the JSON/text IP feed and the malware-IOC list per §3's rules, runs
   the command→ATT&CK mapping, and emits the Sigma rules described in
   §3 alongside the static report — plus the project page skeleton (§5,
   PT+EN). Not written speculatively now — designing scripts against a
   topology that might still change wastes the exercise.
4. **Separate, smaller decision, not blocked on 1–3:** whether to soften
   the live hit-counter's role in `danielmala.co`'s own Deteções section
   now that ADR 0007 keeps its volume low — a copy change to
   `content/detections.json`/`static/src/i18n/ui.ts`, not a rules
   removal. Flagged in §3 above; not decided or scheduled yet.
