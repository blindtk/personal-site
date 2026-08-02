# ADR 0008 — Cloudflare MCP servers in `.mcp.json`: read-only, no `cloudflare-bindings`

**Status:** accepted and in production (`.mcp.json`, repo root).

## Context

`.mcp.json` was added (PR #127) to validate `wrangler.toml` against the
real Cloudflare account, but it landed without going through the same
decision discipline this repository imposes on everything else — it
wasn't mentioned in the original security review nor in the threat model.
It registered seven remote MCP servers **at project scope** (versioned in
the repo, therefore proposed to any session — human or agent — that opens
it): `cloudflare-audit-logs`, `cloudflare-graphql-analytics`,
`cloudflare-dns-analytics`, `cloudflare-observability`,
`cloudflare-bindings`, `cloudflare-builds`, `cloudflare-docs`. All require
interactive OAuth before any call.

Of these, `cloudflare-bindings` was the only **write** one: it creates and
deletes KV namespaces, D1 databases, and R2 buckets. This opens a second
write path into the Cloudflare account from the repository's context, via
OAuth, parallel to the fact (praised in the security review) that no
Cloudflare token exists in GitHub Actions secrets — a path the original
threat model didn't account for.

## Decision

Remove `cloudflare-bindings` from `.mcp.json`. Keep the remaining six, all
read-only and covering the same kind of data already accessible manually
in the Cloudflare dashboard: `cloudflare-audit-logs`,
`cloudflare-graphql-analytics`, `cloudflare-dns-analytics`,
`cloudflare-observability`, `cloudflare-builds`, `cloudflare-docs`.

## Consequences

- No project-scoped MCP server in this repository can create, delete, or
  modify resources in the Cloudflare account — only read.
- If write access via MCP becomes necessary again in the future, the
  recorded option is to move `cloudflare-bindings` to a **personal**
  connector (outside the repo, not proposed to everyone who clones it),
  not to version it in `.mcp.json` again.
- `cloudflare-audit-logs` still exposes sensitive information about the
  account itself (administrative action history) — not destructive, but
  worth keeping in mind when authorizing OAuth in a session.
