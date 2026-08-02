# Backlog — ideas analyzed, not implemented

Three editorial/technical analysis sessions produced detailed proposals
that were never accepted or implemented. This file replaces the original
documents (~2,200 lines in `docs/proposals/`, removed 2026-07-31 to
reduce the file count in `docs/`) with a short summary of each idea — the
full reasoning stays preserved in git history if it's ever needed.

## 1. Reorganize the Perimeter section (Detections / Telemetry)

`PerimeterPage.astro` currently mixes editorial copy (text you read once)
with live dashboards (numbers that change every minute) in the same 5
tabs. Proposal: split into 3 pages — Perimeter (editorial, with 4 fixed
stat cards), Detections (Sigma rules), and Telemetry (live dashboards).
Without this split, the site's most argumentative page keeps changing
content, which contradicts the repository's documentary-rigor thesis.

## 2. New "Control mapping" page

Proposal for a sub-page under "This Site" that translates the controls
that already exist (CSP, rate limiting, honeypot, CI) into the vocabulary
of public frameworks (OWASP Top 10, CIS Controls, CISA CPG, MITRE
ATT&CK) — an indexing layer, not a new compliance claim. Proposed golden
rule: every row in the table either points to another page on this site,
or it doesn't get in.

## 3. Honeypot evolution

Critical analysis of the current honeypot — what already works well (pure
sensor, uniform 404, zero PII), what's too basic today (few decoy paths,
no attack-family variation), and what would be overkill for a personal
site (mimicking real interfaces, serving interactive fake content). Also
flags a correction to the ATT&CK mapping in
`content/honeypot-attack.json` (techniques by path family, not by
individual path) and suggests closing the observability gap between what
Cloudflare blocks and what reaches the Worker. Deliberately left without
operational detail here — see git history for the full analysis,
including the six structural constraints (KV write budget, Free-plan WAF
rule limit) any expansion has to respect.

---

If any of these ideas gets accepted, the work is implementing it for
real (new route, i18n key, test) — not expanding this summary again.
