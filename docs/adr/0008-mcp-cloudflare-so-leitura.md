# ADR 0008 — Servidores MCP da Cloudflare em `.mcp.json`: só leitura, sem `cloudflare-bindings`

**Estado:** aceite e em produção (`.mcp.json`, raiz do repo).

## Contexto

`.mcp.json` foi adicionado (PR #127) para validar o `wrangler.toml` contra a
conta Cloudflare real, mas entrou sem passar pela mesma disciplina de
decisão que este repositório impõe a tudo o resto — não estava mencionado
na revisão de segurança original nem no modelo de ameaça. Registava sete
servidores MCP remotos **de âmbito de projeto** (versionados no repo,
portanto propostos a qualquer sessão — humana ou de agente — que o abra):
`cloudflare-audit-logs`, `cloudflare-graphql-analytics`,
`cloudflare-dns-analytics`, `cloudflare-observability`,
`cloudflare-bindings`, `cloudflare-builds`, `cloudflare-docs`. Todos exigem
OAuth interativo antes de qualquer chamada.

Destes, `cloudflare-bindings` era o único de **escrita**: cria e apaga
namespaces KV, bases D1 e buckets R2. Isto abre um segundo caminho de
escrita na conta Cloudflare a partir do contexto do repositório, por OAuth,
paralelo ao facto (elogiado na revisão de segurança) de não existir nenhum
token da Cloudflare nos secrets do GitHub Actions — um caminho que o modelo
de ameaça original não contemplava.

## Decisão

Remover `cloudflare-bindings` de `.mcp.json`. Manter os seis restantes,
todos de leitura e do mesmo tipo de dado já acessível manualmente no
dashboard da Cloudflare: `cloudflare-audit-logs`, `cloudflare-graphql-analytics`,
`cloudflare-dns-analytics`, `cloudflare-observability`, `cloudflare-builds`,
`cloudflare-docs`.

## Consequências

- Nenhum servidor MCP de âmbito de projeto neste repositório consegue criar,
  apagar ou modificar recursos na conta Cloudflare — só ler.
- Se a escrita via MCP voltar a ser necessária no futuro, a opção registada
  é mover `cloudflare-bindings` para um connector **pessoal** (fora do
  repo, não proposto a toda a gente que o clone), não voltar a versioná-lo
  em `.mcp.json`.
- `cloudflare-audit-logs` continua a expor informação sensível sobre a
  própria conta (histórico de ações administrativas) — não destrutivo, mas
  vale a pena ter presente ao autorizar OAuth numa sessão.
