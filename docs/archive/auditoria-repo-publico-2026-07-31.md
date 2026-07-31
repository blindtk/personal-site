# Auditoria de conteúdo e ficheiros — repositório público (2026-07-31)

> Relatório de análise gerado a partir do prompt reutilizável em
> `docs/prompts/prompt-repo-publico.md` (nota: apesar do nome semelhante, esse
> ficheiro é diferente do que gerou a ronda anterior — ver secção "meta"
> abaixo). Ficheiro fechado: todos os achados abaixo foram executados ou
> respondidos na mesma sessão de 2026-07-31 — ver `[FEITO]`/`[RESOLVIDO]` em
> cada um. Mantido em `docs/archive/` como registo do que foi encontrado e
> decidido, não como referência viva.

## Nota meta

`docs/prompts/prompt-repo-publico.md` é, com grande probabilidade, o prompt
que gerou uma ronda anterior desta mesma tarefa — já existe um relatório de
execução datado de um dia antes (`docs/archive/relatorio-preparacao-repo-
publico-2026-07-30.md`). Muitas correções óbvias (contagem de testes,
DNSSEC) já tinham sido feitas nesse ciclo; esta ronda partiu do estado atual
do repositório, encontrou 3 achados operacionais de alto impacto (resolvidos
nesta sessão, ver resumo executivo) e uma reorganização completa de
`docs/`.

---

## Resumo executivo — os 5 problemas que mais custavam a quem chega de fora

1. **[RESOLVIDO]** A verificação diária de cabeçalhos de produção estava
   desligada por placeholder porque a Cloudflare Access podia ainda estar a
   bloquear pedidos não autenticados — `.github/expected-headers.json` tinha
   `"url": "SET-ME: https://danielmala.co/"`. O dono confirmou que a Access
   já não bloqueia `danielmala.co`/`www.danielmala.co`; `url` aponta agora
   para `https://danielmala.co/` e o `$comment` foi atualizado.
2. **[RESOLVIDO]** Uma técnica de bypass de WAF ainda ativa estava
   documentada em claro em `docs/cloudflare-deploy.md` — a regra "CI headers
   check" fazia *match* por uma substring de User-Agent pública em vez do
   header assinado `X-Ci-Waf-Token` já implementado do lado do CI. O dono
   confirmou que a regra no dashboard já foi migrada; a documentação reflete
   isso.
3. **[RESOLVIDO]** `DEBUG_EXPOSE_SELF_PATH` (`dynamic/worker/src/lib/csp-
   report.js`) continuava `true`, com o risco aceite a assentar em "produção
   atrás de Cloudflare Access". Como essa premissa deixou de valer, revertido
   para `false` — decisão já pré-acordada em `dynamic/PLAN.md` para
   exatamente este cenário. 2 testes atualizados e 1 removido em
   `dynamic/worker/test/logic.test.mjs` (119 → 118 testes no Worker).
4. **[RESOLVIDO]** `content/blog/` não existia fisicamente, mas
   `getCollection('blog', ...)` corre em todas as páginas
   (`BaseLayout.astro`, `HomePage.astro`), gerando 68 avisos de build
   (`"The collection \"blog\" does not exist or is empty"`) — violando o
   crivo do `CLAUDE.md` ("sem warnings novos"). Corrigido com uma entrada
   `draft: true` em `content/blog/{pt,en}/reservado.md`, que satisfaz o
   content store sem publicar nada (o filtro `!e.data.draft` já usado em
   todo o código continua a esconder a nav e as rotas de `/blog/`). Build
   confirmado limpo, 0 avisos.
5. **[RESOLVIDO]** Três números diferentes de "quantos cabeçalhos de
   segurança" para o mesmo facto: Home dizia 8, a tabela-contrato da página
   Provas mostrava 9, a Segurança listava 7 linhas. Unificado em 9 nas 3
   páginas: `scan.js` (self-scan) passou a avaliar
   `cross-origin-embedder-policy`, `HomePage.astro` atualizado para 9, e a
   lista de `ui.ts` (Segurança) passou a ter 9 entradas em vez de agregar 3
   num só bullet.

**Achado adicional, também resolvido:** o README dizia "six CI workflows"
mas há 9 ficheiros em `.github/workflows/`. Corrigido para "nine CI
workflows" (3 ocorrências) e adicionada uma nota junto aos badges explicando
os 2 workflows sem badge (`dependency-review.yml`, `labeler.yml`).

---

## Eixo A — achados de texto (todos resolvidos)

Base positiva confirmada (sem ação): paridade PT/EN de `ui.ts` 100%, sem
brasileirismos no texto editorial, sem links internos partidos nas
componentes/conteúdo markdown, contagem "11 ferramentas / 3 server-side"
consistente em todo o site.

| # | Achado | Resolução |
|---|---|---|
| A1 | Contagem de cabeçalhos inconsistente (8/9/7) e self-scan sem COEP | **[RESOLVIDO]** Unificado em 9 — ver resumo executivo #5 |
| A2 | `EncoderTool.astro` placeholder `"olá, mundo"` fixo em PT, visível em `/en/tools/encoder/` | **[RESOLVIDO]** Chave `inputPlaceholder` adicionada a `ui.ts` (PT/EN), componente usa `s.inputPlaceholder` |
| A3 | `star-organizer.md` (pt/en): description "atualizado automaticamente" contradiz o corpo (é vendorizado à mão) | **[RESOLVIDO]** Description reescrita para refletir o processo real, nos dois idiomas |
| A4 | Build emite 68 avisos por `content/blog/` inexistente | **[RESOLVIDO]** Ver resumo executivo #4 |
| A5 | `expected-headers.json` podia mascarar Access ainda ativa | **[RESOLVIDO]** Ver resumo executivo #1 |
| A6 | `ExifTool.astro`: nome do ficheiro descarregado (`sem-metadados.jpg`) fixo em PT | **[RESOLVIDO]** Chave `downloadFilename` adicionada a `ui.ts` (PT/EN) |
| A7 | `PasskeyLab.astro`: domínio-isco (`login-seguro.xyz`) e RP name fixos, independentes do idioma | **[RESOLVIDO]** Chaves `decoySuffix`/`rpName` adicionadas a `ui.ts` (PT/EN) |
| A8 | `security.txt`: `Contact`/`Policy` só em PT, apesar de `Preferred-Languages: pt, en` | **[RESOLVIDO]** Adicionadas entradas EN (`/en/contact/`, `/en/security/`) |
| A9 | `content/certs.json`: "FCP Security Operations" expirada (2025-09-08) | **[RESOLVIDO]** Confirmado pelo dono como descontinuada — entrada removida |
| A10 | Densidade técnica alta em Perímetro/Deteções/Provas sem glossário | Sem ação — observação de tom, não erro; site dirigido a pares técnicos |

Cobertura de teste também fechada: `encoding.js`, `geo.js`,
`lab-terminal.js`, `md5.js`, `password.js`, `pwned.js` e `subnet.js` não
tinham testes — 7 ficheiros novos em `static/test/`, todos com vetores
conhecidos (RFC 1321 para MD5, RFC 4648 para Base64, FIPS 180/SHA-1,
fronteiras RFC 1918/3021 para subnets, saída exata capturada para o motor do
terminal). Total de testes do repositório: 233 (115 em `static/` + 118 no
Worker), README atualizado.

---

## Eixo B — classificação final de documentação

| Ficheiro | Decisão executada |
|---|---|
| `README.md` | Mantido, corrigido (contagem de workflows) |
| `docs/architecture.md` | Mantido |
| `docs/proposals/arquitetura-editorial-este-site.md` | Movido para `docs/proposals/`, banner de estado adicionado — proposta não implementada, sem confirmação de aceitação |
| `docs/cloudflare-deploy.md` | Mantido, corrigido (Access, regra WAF migrada) |
| `docs/dns-tls.md` | Mantido |
| `docs/archive/home-revisao-editorial.md` | Movido para `docs/archive/` tal como estava (já implementado, arquivado sem extração adicional) |
| `docs/proposals/honeypot-analise-evolucao.md` | Movido para `docs/proposals/`, banner de estado adicionado — proposta não implementada |
| `docs/proposals/pagina-mapeamento-controlos.md` | Movido para `docs/proposals/`, banner de estado adicionado — proposta não implementada |
| `docs/prompts/prompt-consistencia-textual.md` | Movido para `docs/prompts/` |
| `docs/prompts/prompt-repo-publico.md` | Movido para `docs/prompts/`; endereço pessoal antigo redigido |
| `docs/prompts/prompt-validacao-lancamento.md` | Movido para `docs/prompts/` |
| `docs/public-repo-decision.md` | Mantido tal como estava (decisão do dono: é o melhor texto em inglês para um leitor externo) |
| `docs/archive/relatorio-preparacao-repo-publico-2026-07-30.md` | Movido para `docs/archive/` (blocantes que rastreava — Access, WAF, debug flag — resolvidos nesta sessão); endereço pessoal antigo redigido |
| `docs/archive/relatorio-validacao-lancamento-2026-07-30.md` | Movido para `docs/archive/`, mesma razão |
| `docs/security-headers.md` | Mantido |
| `docs/security-review-2026-07-29.md` | Mantido, link para o log de trabalho atualizado |
| `docs/archive/security-review-2026-07.md` | Movido para `docs/archive/`, link cruzado mantido (a partir de `security-review-2026-07-29.md`) |
| `docs/threat-model.md` | Mantido |
| `docs/adr/README.md` + `0001`–`0004` | Mantidos |
| `dynamic/PLAN.md` | Mantido, decisão do `DEBUG_EXPOSE_SELF_PATH` atualizada |
| `dynamic/worker/README.md` | Mantido |
| `.github/SECURITY.md` | Mantido |
| `.github/pull_request_template.md` | Mantido |
| `LICENSE` | Mantido |
| Este ficheiro | Movido para `docs/archive/` — registo fechado, não referência viva |

---

## Achados de exposição/segredos — todos fechados ou sem ação

- Nenhum segredo real encontrado em código, config ou histórico de commits.
- `dynamic/worker/wrangler.toml`: IDs de conta/zona/KV em claro — identificadores, não segredos, tratados corretamente.
- `docs/cloudflare-deploy.md`: ordem das regras WAF e política geográfica — transparência deliberada; a técnica de bypass que aqui vivia está resolvida (ver #2).
- `static/public/ferramentas/exif-demo.jpg`: EXIF/GPS real, usado deliberadamente como demo — **confirmado pelo dono como foto própria/autorizada, sem ação necessária**.
- Endereço pessoal antigo (`daniel_malaco@hotmail.com`) em `docs/prompts/prompt-repo-publico.md` e `docs/archive/relatorio-preparacao-repo-publico-2026-07-30.md` — **redigido** em ambos.
- `.gitleaksignore`: falso-positivo de AAGUIDs públicos do FIDO Alliance — confirmado, sem ação.
- `DEBUG_EXPOSE_SELF_PATH` — resolvido (ver #3).
- Sem ficheiros de código órfãos; lacuna de cobertura de teste — resolvida (ver Eixo A).

---

## Perguntas — todas respondidas

1. Cloudflare Access ainda bloqueia produção? → **Não**, desligada/ajustada.
2. Regra WAF de CI migrada? → **Sim**, já no dashboard.
3. `DEBUG_EXPOSE_SELF_PATH` — diagnóstico concluído? → Sem resposta sobre a causa em si, mas irrelevante: revertido por mudança de premissa, como já previsto em `dynamic/PLAN.md`. Reabrir se as violações self/self reaparecerem.
4. `arquitetura-editorial-este-site.md` aceite ou abandonada? → Sem confirmação de aceitação — tratada como proposta em aberto, `docs/proposals/`.
5. `honeypot-analise-evolucao.md`/`pagina-mapeamento-controlos.md` — alguma parte aceite? → Idem, `docs/proposals/`.
6. `home-revisao-editorial.md` — arquivar como está ou extrair nota? → Arquivar como está.
7. Relatórios de 2026-07-30 ainda servem? → Não, blocantes absorvidos nesta sessão — arquivados.
8. `security-review-2026-07.md` mover para archive? → Sim.
9. `prompt-*.md` serão reutilizados? → Movidos para `docs/prompts/`; continuam disponíveis se forem reutilizados.
10. `public-repo-decision.md` fundir ou manter? → Manter como está.
11. Certificação FCP Security Operations renovada ou descontinuada? → Descontinuada — entrada removida de `content/certs.json`.
12. Foto EXIF demo — provenance? → Confirmada como própria/autorizada.
