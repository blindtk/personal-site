# ADR 0018 — Production-scan tool selection: automate by elimination, don't collect scanners

**Status:** accepted and in production (`tls-check.yml`, `observatory-check.yml`, `dns-check.yml`, and the external-scan list in `docs/ci-cd.md`).

## Context

There are far more security scanners available for a live domain than
this repository runs automatically — Qualys SSL Labs, Security Headers,
Mozilla HTTP Observatory, Hardenize, DNSViz, ImmuniWeb, and more all
produce a report for `danielmala.co`. Wiring all of them into CI would be
easy and would look thorough. Two concrete tool-selection decisions show
the actual rule applied instead:

**TLS check.** Qualys SSL Labs already grades TLS/cipher/certificate
configuration for free, continuously. The repository still runs its own
monthly `testssl.sh` scan (official Docker image, pinned by digest — the
same exact-pin discipline as everything else, applied to an image instead
of an Action, since testssl.sh isn't distributed as either). Why not just
link the SSL Labs report: **to not depend on a third-party service being
up, or on waiting for its cache**, when the check can run self-contained
against production directly. Monthly, not weekly or daily: the TLS
surface (ciphers, protocol, certificate) changes rarely — more frequent
runs wouldn't detect anything sooner, they'd only spend more of the
GitHub Actions Free-plan minutes the repository is already close to the
edge of.

**Observatory check.** Mozilla HTTP Observatory was picked over two
alternatives that were live candidates, each rejected for a specific,
checked reason, not by default: Qualys SSL Labs is redundant with the
TLS check above (same surface, already covered); Security Headers'
API was discontinued in April 2026. Observatory has a free,
no-key API built for CI/CD — the deciding factor. Weekly: cheaper than
the TLS check (one HTTP call, no Docker) but the rubric it tests (cookies,
redirects, cross-origin isolation) doesn't change with the frequency of
an individual deploy, so daily would be waste.

## Decision

Automate a check only when it has a free API that actually fits a
recurring cron, and running it yourself would add something a linked
external report wouldn't (independence from a third party's uptime and
cache, in the TLS case). When two candidate tools cover the same ground,
pick one by eliminating the redundant or broken option, not by running
both. Everything else — the tools with no API, or whose API duplicates a
check already running — stays a periodic **manual** check instead
(tool-by-tool reasoning in [PR #155](https://github.com/blindtk/personal-site/pull/155),
listed in [`docs/ci-cd.md`](../ci-cd.md)). Each scheduled check also gets
its own workflow rather than being folded into a shared "production
checks" job, so DNS, TLS, headers, and Observatory each keep an
independent run history and cadence sized to how often their specific
surface actually changes.

## Consequences

- The automated set (headers, invariants, TLS, DNS, Observatory) is
  small and each member earns its place for a stated reason, not because
  the tool exists.
- Cadence is deliberately mismatched across checks (daily for headers/
  invariants, weekly for DNS/Observatory, monthly for TLS) — sized to how
  fast each surface changes, not a single default schedule copy-pasted
  five times.
- The external-scan list keeps growing as new free tools appear (most
  recently Cloudflare Agent Readiness, per
  [PR #154](https://github.com/blindtk/personal-site/pull/154)) without
  needing a CI change — they stay manual until one earns automation by
  the same rule.
