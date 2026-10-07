# ADR 0023 — The Mirror shows visitors their own public IP

**Status:** accepted and implemented (2026-10-05), at the owner's request.
Reverses the "never returns the IP" rule the Mirror launched with
(`dynamic/PLAN.md`). The zero-IP storage rule (ADR 0004, ADR 0022) is
unchanged.

## Context

The Mirror (`/ferramentas/mirror/`, `GET /api/mirror`) shows visitors what
any server learns about them at the handshake. It deliberately left out the
one field visitors most often want to see, their public IP, showing
"visible to the server, but we neither show nor store it" instead. The
owner asked for a "what is my IP" on the site, with the condition that
nothing is stored.

Echoing visitors their own IP tells them nothing they don't already
reveal to every server they talk to. The real risks are about where the
response ends up, not the echo itself:

1. **A shared cache** serving one visitor's response, and so their IP, to
   another.
2. **A forged `cf-connecting-ip`** (only possible off Cloudflare) turning
   the field into a reflection channel.
3. **The visitor exposing it by accident** in a screenshot or screen share
   of the page.

## Decision

`serverView` returns `ip` and `ipVersion` for the request it answers.

- The response stays `Cache-Control: no-store`, so no shared cache keeps it.
- `normalizeIp` validates the header fail-closed: canonical IPv4 (no
  leading zeros) or RFC 4291 IPv6. Anything else, including lists, ports,
  zone IDs and HTML, becomes `null`. The page renders with `textContent`
  anyway.
- Nothing is persisted. The only state the request touches is the
  rate-limit key, a salted hash (Cache API, with KV as fallback). A test
  asserts that no KV key or value contains the IP.
- The page shows the IP hidden (`•••`) until the visitor clicks "show".

A separate tool was rejected: the IP belongs in "what the server sees",
next to the country/ASN that the Mirror already derives from it.

## Consequences

- The endpoint now returns personal data, though only to its owner, in a
  response that is never cached or stored. Logging the response body
  would break this. The Worker logs only `path` on errors.
- Only the address of *this* connection is shown. A dual-stack client
  usually sees its IPv6. Showing both would need IPv4-only and IPv6-only
  hostnames, which are not worth it for now.
