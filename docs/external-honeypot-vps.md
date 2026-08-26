# External Cowrie honeypot + spider trap — operational reference

Decision record: [ADR 0019](adr/0019-external-cowrie-honeypot-vps.md). This
document explains the reasoning behind the design — privacy posture, GDPR
basis, the DNS/hosting decisions. It is **not** the source of truth for
exact operational detail any more: the concrete implementation lives in
[`honeypot-vps-infra`](https://github.com/blindtk/honeypot-vps-infra) (a
separate, git-tracked repository — config-as-code for the VPS, Terraform,
the feed generator), and **that repo's own README wins wherever the two
disagree**. This happened once already — this document previously
described the wrong correlation mechanism (see §3) — precisely because
implementation detail duplicated here can drift out of sync with what
actually got built. Keep this document at the level of *why*, not *how*.

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
| **Cowrie** | Full SSH/Telnet shell emulation — session capture, commands, credentials, download attempts | 22 (real) on `access.danielmala.co`, 23 |
| **`endlessh`** | SSH tarpit — drips a banner one byte at a time, holding low-effort scanners' connections open at near-zero cost | secondary ports on `access.danielmala.co` |
| **HTTP maze** (Nepenthes/Iocaine-style, Markov-generated infinite pages) | The "offensive posture" on the web side: wastes the resources of aggressive crawlers/scrapers that ignore `robots.txt`, generated in streaming so the cost sits on the client, not the server | 80/443 on `web.danielmala.co` |

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
   (75 days, `FEED_EXPIRE_AFTER_DAYS`). A feed that never forgets stops being threat
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

### Cross-honeypot correlation (corrected — see repo note above)

**Superseded description:** this section previously said the VPS reads
`danielmala.co`'s public API and computes the correlation itself. That is
not what got built, and not what should be built — it would make the
disposable, external VPS depend on the Worker's uptime and API shape to
generate its own feed, exactly the coupling this project exists to avoid
(`honeypot-vps-infra`'s README: *"no shared data path... the only
connection is a link... and a fetch() of this project's public
feed.json"*).

**What actually happens:** the correlation runs **in the visitor's
browser**, on both sides independently, never on either server:
- On `danielmala.co`'s own honeypot page, a client-side `fetch()` to
  `intel.danielmala.co/feed.json` (CORS-enabled) cross-references its
  `ips[]` against the Worker's own `/api/threat-intel` results and
  surfaces a banner/badge on a match.
- On `intel.danielmala.co`'s own static report, the mirror: a client-side
  `fetch()` to a new Worker route, `/api/threat-intel.txt` (CORS-open,
  mirroring the shape of this project's own `feed.txt`), cross-referenced
  against the IPs already embedded in that page.

Either check degrades silently if the other side is unreachable — no
data is ever exchanged except two independent public reads, at the
moment a human happens to be looking at either page.

Retention differs between the two, and stays an accepted limitation, not
a bug: this project's entries expire after **75 days**
(`FEED_EXPIRE_AFTER_DAYS`), the main honeypot's after a fixed 30 (ADR
0020's more conservative window, given HTTP-scanning botnets' higher odds
of running on compromised residential/IoT devices) — so a match found
today may no longer be confirmable in three months.

---

## 4. DNS

Three subdomains, split by function — but **not** identically configured:
two point directly at the VPS, unprotected on purpose; the third is
proxied through Cloudflare, because it isn't a sensor.

| Subdomain | Serves | Cloudflare proxy |
|---|---|---|
| **`access.danielmala.co`** | Cowrie (real SSH/Telnet) + `endlessh` (tarpit ports) | Off — DNS-only, grey-clouded, points straight at the VPS IP |
| **`web.danielmala.co`** | the HTTP maze / spider trap | Off — DNS-only, grey-clouded, points straight at the VPS IP |
| **`intel.danielmala.co`** | the threat-intel feed + static report | **On** — custom domain of a dedicated Cloudflare Pages project (Direct Upload, no Git connection) |

`access.` and `web.` stay DNS-only for the same reason: SSH doesn't go
through an HTTP proxy anyway, and the maze is meant to be exposed as-is —
this VPS doesn't inherit, or pretend to inherit, the main site's
protection (WAF, Managed Challenge). That absence is exactly what makes
either one a real sensor, unlike the main HTTP honeypot (ADR 0007).

`intel.` is different in kind, not just configuration: it isn't
attacker-facing. It publishes an already-curated, already-generated
artifact (the JSON/text feed + the static ATT&CK report, §3), regenerated
periodically from Cowrie's logs on the VPS. Rather than sitting on the VPS
origin behind Cloudflare's reverse proxy, it's pushed to a **dedicated
Cloudflare Pages project** — `honeypot-vps-infra`'s cron runs `wrangler
pages deploy` on every regeneration, and separately prunes old
deployments older than the retention window via the Cloudflare API, so an
expired IP can't stay reachable forever through a leftover preview URL
(Pages keeps every past deployment individually addressable by default).
This gets the same CDN caching and DDoS/bot protection a reverse-proxied
origin would, plus one thing a reverse-proxied VPS origin wouldn't:
`intel.` stays up even if the VPS itself is offline or reclaimed —
visitors keep seeing the last published snapshot. No TLS to manage on the
VPS side for this subdomain; Cloudflare Pages handles it.

Splitting the three surfaces across separate names — instead of one name
doing all three jobs — means SSH, the maze, and the feed can each be
referenced, taken down, re-pointed, or (as here) given a different
Cloudflare posture, without touching the other two.

A new standalone domain was considered and rejected: it costs money
(annual registration) and adds certificate/renewal overhead for no real
gain over subdomains of a zone already owned and paid for. Avoid
"free domain" services (e.g. the old Freenom) — poor reputation, poor
abuse handling, and unnecessary here.

`access.` and `web.` are never referenced from `danielmala.co`'s
`robots.txt`, sitemap, or any link that could read as part of the same
protected perimeter — only the explicit reference on the project page
(§5) to `intel.`, with the boundary stated in plain text: `intel.` being
proxied doesn't mean the honeypot itself sits behind Cloudflare, only
that its published output does.

**HSTS caveat, noted for later:** the main site's HSTS header isn't
submitted with `preload` yet, specifically because `includeSubDomains`
would force every subdomain of `danielmala.co` onto valid HTTPS
permanently, and the removal process is slow (`docs/dns-tls.md` §3).
`access.` is TCP, not HTTP, so it's unaffected. `intel.` is already
covered once proxied (Cloudflare's Universal SSL terminates it). `web.`
is the one that still matters here: it stays unproxied by design, so its
own TLS posture needs to be settled — and kept working — before that
preload submission happens, not after.

---

## 5. What shows up on `danielmala.co`

**A project page**, in `content/projects/{pt,en}/` — intentionally still
unwritten; only gets written once the VPS is confirmed live, so it never
describes infrastructure that doesn't exist yet (see `honeypot-vps-infra`
`SETUP_CHECKLIST.md`, "Not yet done, no rush"). Same documentary, sober
tone as the rest of the site (`CLAUDE.md`) — the infrastructure behind it
can be technically aggressive (the maze, the tarpit); the prose describing
it doesn't change register for that.

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

**Also planned (§3, "Cross-honeypot correlation"), on the existing
honeypot page** (`/este-site/honeypot/`, `HoneypotPage.astro`) rather than
the new project page: a client-side correlation banner against
`intel.danielmala.co/feed.json`, and a light summary card for the
external sensor (aggregate numbers only — sessions, unique IPs — never
its session/command detail, which stays on `intel.` where it's generated;
see the "is this the best approach" discussion this design went through,
kept informally rather than re-litigated here). This needs a new,
CORS-open `/api/threat-intel.txt` route on the Worker (mirroring this
project's own `feed.txt` shape) and a `connect-src` exception in
`static/public/_headers` for `intel.danielmala.co` — not yet built; wait
until `intel.danielmala.co` is actually live before merging it, so the
fetch has something real to hit rather than shipping dead code against a
domain that doesn't resolve yet.

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

Everything speculative in this section originally — systemd units,
Cowrie/`endlessh`/maze config, the feed generator, Terraform, the
two-phase provisioning workflow — is **written**, in
`honeypot-vps-infra`. What's left, per that repo's own
`SETUP_CHECKLIST.md`:

1. **Outside this repository's reach:** run the two-phase provisioning
   workflow (Actions tab → "Provision VPS (phase 1)", verify externally,
   then "phase 2 — confirm & finish") — the actual Oracle instance
   doesn't exist yet.
2. Point DNS (`access.`, `web.` — DNS-only) and create the Cloudflare
   Pages project for `intel.` (§4), once the instance's public IP is
   confirmed.
3. Only then, on the `personal-site` side: the project page (§5) and the
   correlation banner/`api/threat-intel.txt` route — not before, so
   nothing here describes or fetches against infrastructure that isn't
   live yet.
