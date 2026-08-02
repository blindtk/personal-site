# ADRs (Architecture Decision Records)

Registo curto das decisões de arquitetura com trade-offs reais — o que se
escolheu, o que se recusou e porquê. A maior parte destas decisões já estava
documentada em comentários no código, em `dynamic/PLAN.md` ou nas revisões
de segurança em `docs/`; estes ficheiros resumem-nas num formato que não
exige ler centenas de linhas de planeamento para perceber o essencial.

Formato: Contexto → Decisão → Consequências. Sem secções vazias, sem
"Alternativas consideradas" a fingir opções que nunca existiram.

| ADR | Decisão |
| --- | --- |
| [0001](0001-csp-sem-inline.md) | CSP sem `unsafe-inline`, sem hashes: eliminar o inline em vez de o catalogar |
| [0002](0002-renovate-dependabot-split.md) | Renovate para *version updates*, Dependabot só para *security updates* |
| [0003](0003-rate-limit-kv-vs-nativo.md) | Rate limiting em KV (com falha fechada) como transição para uma regra nativa da Cloudflare |
| [0004](0004-zero-pii-honeypot.md) | Honeypot e analytics zero-PII por escolha, não por limitação do plano |
| [0005](0005-csp-report-manual.md) | Relato de violações CSP: manual em vez de automático, para poupar orçamento de escrita do KV |
| [0006](0006-caps-escrita-diarios.md) | Caps de escrita do Worker: por dia e dimensionados ao orçamento, não à resistência a abuso |
| [0007](0007-honeypot-managed-challenge.md) | Paths-isco atrás de Managed Challenge: proteção sobre observabilidade total |
| [0008](0008-mcp-cloudflare-so-leitura.md) | Servidores MCP da Cloudflare em `.mcp.json`: só leitura, sem `cloudflare-bindings` |
| [0009](0009-repositorio-publico.md) | Repositório público, não privado |
| [0010](0010-coderabbit-revisao-ia.md) | CodeRabbit para revisão de PR por IA, não Copilot Code Review nem Strix em CI |
