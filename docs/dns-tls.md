# DNS & TLS — domain hardening checklist

> **Status:** the domain (`danielmala.co`, in `static/src/config.ts`) is
> already active on Cloudflare (nameservers swapped at Namecheap — see
> `docs/cloudflare-deploy.md`). The items below are additional
> hardening steps, to execute/confirm in the dashboard — none of them are
> automatic just because the zone exists.

## 1. CAA — restrict who can issue certificates

CAA records limit which CAs are authorized to issue for the domain.
Without CAA, any public CA can issue. With the zone on Cloudflare and
**Universal SSL** active, Cloudflare issues through these CAs — all of
them need to be authorized, or issuance/renewal fails:

```
danielmala.co.  IN  CAA  0 issue "letsencrypt.org"
danielmala.co.  IN  CAA  0 issue "pki.goog; cansignhttpexchanges=yes"
danielmala.co.  IN  CAA  0 issue "ssl.com"
danielmala.co.  IN  CAA  0 issuewild "letsencrypt.org"
danielmala.co.  IN  CAA  0 issuewild "pki.goog; cansignhttpexchanges=yes"
danielmala.co.  IN  CAA  0 issuewild "ssl.com"
danielmala.co.  IN  CAA  0 iodef "mailto:me@danielmala.co"
```

- Create in the dashboard: **DNS → Records → Add record → CAA** (one per line).
- The `iodef` receives notifications for issuance requests that violate the policy.
- Note: with Universal SSL, Cloudflare itself adds/manages CAA records
  dynamically when needed; keeping the explicit records above documents
  intent and covers the case of leaving Cloudflare. Confirm the list of
  CAs in use in the official docs before applying (it can change):
  <https://developers.cloudflare.com/ssl/reference/certificate-authorities/>
- Verify afterward: `dig CAA danielmala.co +short`

> **Confirmed in production (2026-07-29, security review):** the query
> `dig CAA danielmala.co` returns **no answer** — the records above
> haven't been created yet. While this stays undone, any publicly trusted
> CA can issue a certificate for the domain, unrestricted. DMARC/SPF
> already confirmed correct in the same check (strict `p=reject`,
> `-all`) — only the CAA records from this list are missing.
>
> **Updated (2026-08-02):** the 7 records were created in the dashboard
> and `dig CAA danielmala.co +short` confirms all of them present. But the
> authoritative response returns **11** records, not 7 — Cloudflare adds
> `comodoca.com` and `digicert.com` (issue + issuewild) underneath, without
> appearing in the dashboard's editable list: exactly the Universal SSL CA
> diversification already anticipated in the note above, now confirmed
> live. This isn't a reason to remove the 7 explicit records — they remain
> the only declaration of the domain owner's intent (and the only place
> the `iodef` comes from); without them, CAA policy is entirely dependent
> on whatever Cloudflare decides to use internally, including if the
> domain ever leaves Cloudflare. The `dns-check.yml` workflow treats this
> as a subset check — it only fails if one of the 7 is missing, and warns
> (doesn't fail) if extra CAs show up.

## 2. HTTP → HTTPS redirect

- Cloudflare Pages already forces HTTPS on `*.pages.dev` and on custom domains.
- On the zone: **SSL/TLS → Edge Certificates → Always Use HTTPS: ON**.
- If ever serving from a VPS: **SSL/TLS → Overview → Full (strict)**
  (never "Flexible"), with a valid certificate at the origin.
- Verify: `curl -sI http://danielmala.co/ | grep -i location` → should
  respond `301` to `https://…`.

## 3. HSTS with preload

`_headers` already sends `max-age=63072000; includeSubDomains` (2 years),
**without** `preload` — deliberate until the subdomain family is decided
(see warning below). When it is:

1. Confirm the preload list prerequisites:
   - HTTP→HTTPS redirect on the domain itself (step 2);
   - a valid certificate; `max-age` ≥ 31536000 (we have 2× that);
   - `includeSubDomains` + `preload` in the header.
2. Add `; preload` to `Strict-Transport-Security` in
   `static/public/_headers` (and the mirror in `docs/security-headers.md`).
3. Submit at <https://hstspreload.org> and track the status.

> ⚠️ **Before submitting:** `includeSubDomains` + preload forces **every**
> subdomain to valid HTTPS for as long as the domain stays on the list
> (removal is slow and not guaranteed — it can take months and depends on
> browser rollout). If the homelab/`lab.` or another subdomain ever serves
> plain HTTP, it breaks. Only submit once the subdomain family is decided.

## 4. DNSSEC

- **Active.** Protects domain resolution against spoofing (**DNS →
  Settings → DNSSEC** on Cloudflare, `DS` registered at the registrar).

> **Confirmed (2026-07-30, launch validation):** `DNSKEY` returned by two
> independent validating resolvers (Cloudflare `1.1.1.1` and Google
> `8.8.8.8`, both with `AD: true`), with the matching `DS` already
> registered in the `.co` parent zone. Verify: `dig @1.1.1.1 danielmala.co
> DNSKEY +dnssec` (and the same against `@8.8.8.8`) should include the
> `ad` flag.

## Relationship to the rest of the repo

- The headers served (including HSTS) are checked in production by the
  `Headers` workflow (`.github/workflows/headers.yml`) against
  `.github/expected-headers.json`. When you enable `preload`, add
  `"preload"` to that file's `strict-transport-security` entry so the
  check starts requiring it.
