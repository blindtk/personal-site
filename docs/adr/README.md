# ADRs (Architecture Decision Records)

Short record of architecture decisions with real trade-offs — what was
chosen, what was rejected, and why. Most of these decisions were already
documented in code comments, in `dynamic/PLAN.md`, or in the security
reviews in `docs/`; these files summarize them in a format that doesn't
require reading hundreds of lines of planning to get the essentials.

Format: Context → Decision → Consequences. No empty sections, no
"Alternatives considered" pretending there were options that never
existed.

| ADR | Decision |
| --- | --- |
| [0001](0001-csp-sem-inline.md) | CSP without `unsafe-inline`, without hashes: eliminate inline instead of cataloguing it |
| [0002](0002-renovate-dependabot-split.md) | Renovate for version updates, Dependabot only for security updates |
| [0003](0003-rate-limit-kv-vs-nativo.md) | Rate limiting in KV (fail-closed) as a transition to a native Cloudflare rule |
| [0004](0004-zero-pii-honeypot.md) | Honeypot and analytics zero-PII by choice, not plan limitation |
| [0005](0005-csp-report-manual.md) | CSP violation reporting: manual instead of automatic, to save the KV write budget |
| [0006](0006-caps-escrita-diarios.md) | Worker write caps: daily, sized to the budget, not to abuse resistance |
| [0007](0007-honeypot-managed-challenge.md) | Honeypot decoy paths behind Managed Challenge: protection over full observability |
| [0008](0008-mcp-cloudflare-so-leitura.md) | Cloudflare MCP servers in `.mcp.json`: read-only, no `cloudflare-bindings` |
| [0009](0009-repositorio-publico.md) | Public repository, not private |
| [0010](0010-coderabbit-revisao-ia.md) | CodeRabbit for AI PR review, not Copilot Code Review or Strix in CI |
| [0011](0011-sem-token-cloudflare-no-github-actions.md) | No Cloudflare deploy credential in GitHub Actions: Workers Builds over a CI-driven deploy |
| [0012](0012-baseline-de-hardening-github-actions.md) | GitHub Actions hardening baseline: SHA-pinned actions, `permissions: {}`, no `persist-credentials` |
| [0013](0013-osv-scanner-action-direta.md) | OSV-Scanner called directly, not via the official reusable workflow |
| [0014](0014-astro-check-node-test-obrigatorios-ci.md) | `astro check` and `node --test` as required CI gates, not a human-confirmed checklist item |
