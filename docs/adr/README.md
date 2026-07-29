# ADRs (Architecture Decision Records)

Registo curto das decisões de arquitetura com trade-offs reais — o que se
escolheu, o que se recusou e porquê. A maior parte destas decisões já estava
documentada em comentários no código ou em `dynamic/PLAN.md`; estes ficheiros
resumem-nas num formato que não exige ler 500 linhas de planeamento para
perceber o essencial.

Formato: Contexto → Decisão → Consequências. Sem secções vazias, sem
"Alternativas consideradas" a fingir opções que nunca existiram.

| ADR | Decisão |
| --- | --- |
| [0001](0001-csp-sem-inline.md) | CSP sem `unsafe-inline`, sem hashes: eliminar o inline em vez de o catalogar |
| [0002](0002-renovate-dependabot-split.md) | Renovate para *version updates*, Dependabot só para *security updates* |
| [0003](0003-rate-limit-kv-vs-nativo.md) | Rate limiting em KV (com falha fechada) como transição para uma regra nativa da Cloudflare |
| [0004](0004-zero-pii-honeypot.md) | Honeypot e analytics zero-PII por escolha, não por limitação do plano |
