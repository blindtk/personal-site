# Arquitetura

Visão de alto nível do sistema — o que fala com o quê, e onde ficam as
fronteiras de confiança. Complementa `README.md` (estrutura de pastas) e
`dynamic/PLAN.md` (decisões detalhadas do backend).

```mermaid
flowchart TB
    subgraph internet["Internet"]
        visitor["Visitante / browser"]
        scanner["Scanner / bot hostil"]
    end

    subgraph cf["Cloudflare (fronteira de confiança 1)"]
        direction TB
        waf["WAF + Access\n(challenge, regras de firewall)"]
        pages["Cloudflare Pages\nsite estático (Astro)"]
        worker["Worker\ndynamic/worker/"]
        kv[("KV\ncontadores agregados,\ncache SWR")]
    end

    subgraph upstream["APIs externas (só leitura)"]
        hibp["HIBP range API\n(k-anonimato)"]
        feeds["CISA KEV / NVD"]
        crtsh["crt.sh (CT logs)"]
        cfgraphql["Cloudflare GraphQL\nAnalytics API"]
    end

    visitor -->|HTTPS| waf
    scanner -->|paths-isco, /api/*| waf
    waf --> pages
    waf -->|"/api/*, paths-isco"| worker
    worker <--> kv
    worker -->|"self-scan (fetchSameOrigin)"| waf
    worker --> hibp
    worker --> feeds
    worker --> crtsh
    worker -->|"CF_API_TOKEN (read-only)"| cfgraphql

    subgraph dev["Desenvolvimento (fronteira de confiança 2)"]
        laptop["Laptop do developer"]
        gh["GitHub Actions\nCI/CD"]
    end

    laptop -->|push| gh
    gh -->|"npm ci --ignore-scripts,\nbuild, test, SAST"| gh
    laptop -.->|"wrangler deploy\n(MANUAL — ver ADR 0003\ne security-review §H3)"| worker
    gh -.->|"Pages: deploy automático\nno push a main"| pages
```

## Fronteiras de confiança

1. **Internet → Cloudflare.** Todo o tráfego de entrada passa pelo WAF/Access
   antes de chegar a Pages ou ao Worker. Nada na aplicação confia em headers
   de cliente sem validar (`normalizeCountry`, `normalizeAsn`, etc. em
   `sanitize.js`).
2. **Laptop do developer → produção.** A única fronteira sem controlo
   automatizado hoje: o deploy do Worker é manual (`npx wrangler deploy`).
   O Pages é automático (push a `main` → build → deploy), mas o Worker não
   tem esse mesmo caminho — ver `docs/security-review-2026-07-29.md` (achado
   H3) para o plano de fechar esta lacuna com um Environment do GitHub +
   token com escopo mínimo + `attest-build-provenance`.
3. **Worker → APIs externas.** Todas as chamadas são unidirecionais
   (o Worker só lê), com timeout (`AbortSignal.timeout`), e o self-scan usa
   `fetchSameOrigin` para nunca deixar as credenciais da Access seguirem um
   redirect para fora do domínio.

## Uma zona, dois caminhos de deploy

| | Trigger | Automatizado? |
| --- | --- | --- |
| `static/` (Pages) | push a `main` | Sim — integração Git nativa da Cloudflare |
| `dynamic/worker/` | `npx wrangler deploy` a partir do laptop | Não (ver acima) |

Isto não é uma inconsistência acidental — está documentado em
`dynamic/PLAN.md` e no topo de `wrangler.toml` como o fluxo atual ("validar
com o fluxo já documentado no CLAUDE.md antes de fazer merge"). É, no
entanto, a maior lacuna de proveniência do repositório, e fica assinalada
como tal.
