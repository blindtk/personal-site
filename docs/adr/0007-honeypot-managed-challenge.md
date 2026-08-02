# ADR 0007 — Honeypot decoy paths behind Managed Challenge: protection over full observability

**Status:** accepted and in production (rule 3, WAF on the `danielmala.co` zone).

## Context

The honeypot's five decoy paths (`/wp-login.php`, `/.env`, `/admin`,
`/phpmyadmin/`, `/.git/config` — `DECOYS` in
`dynamic/worker/src/index.js`) exist to observe hostile scanning: the more
raw traffic reaches the Worker, the richer the Threat Intelligence panel's
dataset. The obvious option to maximize that dataset would be to leave
them completely open — subject only to the general geo policy (rules
4/5), like any other path on the site.

## Decision

Create a dedicated WAF rule (rule 3, evaluated **before** the country
policy) that applies `Managed Challenge` to the five decoy paths for
**any** visitor, regardless of country — an explicit decision by the repo
owner: the decoys don't stay open to the world without some barrier, even
though they're just a sensor returning a 404.

## Consequences

- **A consequence to accept, not a side effect:** a Managed Challenge
  exists precisely to filter automated bots — which is exactly the
  traffic the honeypot exists to observe. While this rule is active, the
  honeypot only records whoever *solves* the challenge (a real browser
  with JS, in some cases advanced scanners with browser-like automation),
  not the indiscriminate mass scanning that dominates the Internet.
- A deliberate trade of dataset breadth for a security guarantee that's
  easier to justify ("no visitor reaches a decoy path with zero barrier")
  than for maximizing signal for a panel.
- See [`docs/backlog.md`](../backlog.md) for honeypot-evolution ideas
  that reconsider this trade-off (protection vs. observability); none
  approved for implementation to date.
