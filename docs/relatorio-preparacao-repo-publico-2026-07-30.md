# Relatório — preparação do repositório para público (2026-07-30)

Execução de [`prompt-repo-publico.md`](prompt-repo-publico.md), na branch
`claude/execute-public-repo-prompt-3th3el`. Três decisões preliminares foram
confirmadas com o dono do repo antes de qualquer alteração (ver §3).

---

## 1. O que foi alterado, por fase

### Fase 1 — bloqueadores

- **Email pessoal.** `static/src/config.ts:27` (`daniel_malaco@hotmail.com`)
  → `me@danielmala.co`, alias confirmado pelo dono como já ativo. Mesma troca
  em `docs/dns-tls.md:23` (registo CAA `iodef`). `docs/cloudflare-deploy.md:249`
  marcado `[x]`.
- **`.mcp.json`.** Removido `cloudflare-bindings` (único servidor de
  escrita — cria/apaga KV, D1, R2). Ficam os seis de leitura
  (`cloudflare-audit-logs`, `cloudflare-graphql-analytics`,
  `cloudflare-dns-analytics`, `cloudflare-observability`, `cloudflare-builds`,
  `cloudflare-docs`), confirmados como leitura pela análise já registada em
  `dynamic/PLAN.md` (achado N6, agora marcado resolvido).
- **Post de exemplo.** `content/blog/{pt,en}/hello-world.md` removidos —
  decisão do dono foi assumir o blog vazio em vez de publicar ou reescrever.
  `README.md` corrigido para não referenciar mais o ficheiro; o estado vazio
  já estava tratado no design (`BlogIndexPage.astro:25`, `dict.blog.empty`).
  Novo warning de build, inofensivo e esperado: `[glob-loader] No files found
  matching "**/*.md" in directory "../content/blog"`.
- **Flag de debug CSP.** `dynamic/worker/src/lib/csp-report.js:132`
  (`DEBUG_EXPOSE_SELF_PATH`) **mantém-se `true`** — confirmado com o dono que
  o diagnóstico das violações `self/self` ainda está em curso. Decisão
  registada em `dynamic/PLAN.md` com data, para reavaliação antes do
  repositório ficar público de facto (a mitigação assume produção atrás da
  Cloudflare Access).
- **`expected-headers.json`.** Mantém-se `SET-ME` — decisão confirmada:
  via (b), esperar a Access ser desligada na Fase 3 do lançamento. Registado
  em `docs/cloudflare-deploy.md:236-248`.

### Fase 2a — README

Reescrito em inglês com nota em português (decisão confirmada: EN principal
+ secção PT, não dois ficheiros separados). Correções factuais: 11
ferramentas (não 4), painel em `/perimetro/`+`/en/perimeter/` (não
`/honeypot`, rota que não existe), `dynamic/` em produção (não "roadmap
futuro"), lista dos JSON de `content/` que alimentam páginas reais, contagem
de testes atualizada (191, não 186). Acrescentado: diagrama de arquitetura +
três decisões mais interessantes com link para os ADRs (0004 zero-PII, 0001
CSP sem inline, 0003 rate limit KV), parágrafo "porquê tanto para um site
pessoal", divulgação de uso de IA (uma vez, sem pedir desculpa), nota sobre
os decoys do honeypot serem públicos por desenho.

### Fase 2b — docs/ (delegado a agente, achados aplicados por mim)

- **Duplicação das revisões de segurança.** Decisão confirmada: `-07.md`
  passa a log histórico de rondas, `-07-29.md` fica o retrato atual. Nota
  cruzada acrescentada nos dois topos.
- **Contradição real entre documentos, não apenas números desatualizados:**
  `docs/architecture.md` e `docs/threat-model.md` descreviam o deploy do
  Worker como manual (`wrangler deploy` a partir do laptop); `docs/cloudflare-deploy.md`
  §4 e `dynamic/worker/README.md` confirmam que é automático via **Cloudflare
  Workers Builds** desde há algum tempo. Corrigido nos dois primeiros — o
  achado H3 (`docs/security-review-2026-07-29.md`) continua aberto, mas pela
  falta de proveniência/gate de revisor, não pela falta de automação.
- Contagens corrigidas em `docs/threat-model.md`: 12 endpoints GET (não 11),
  5 rotas-isco (não 6).
- `dynamic/PLAN.md`: achado N6 marcado resolvido (decisão já executada na
  Fase 1).
- `dynamic/worker/README.md`: tabela de endpoints tinha 3 rotas em falta
  (`/api/pwned-range`, `/api/threat-intel`, `/api/vitals` GET+POST) —
  acrescentadas.
- `CLAUDE.md` lido como estranho pelo agente — sem achados, fica como está.
- Nenhum link markdown partido encontrado em `docs/`, `README.md`,
  `CLAUDE.md`, `.github/SECURITY.md`, `dynamic/PLAN.md`,
  `dynamic/worker/README.md`.

### Fase 2c — consistência textual (delegado a agente, 3 correções aplicadas por ele + 2 por mim)

- `static/src/i18n/ui.ts`: removida menção a `Reporting-Endpoints` (header
  removido em 2026-07, contradizia `static/public/_headers`); corrigida a
  contagem de ferramentas com servidor em dois sítios (3: pwned/self-scan/
  mirror — faltava "mirror").
- **`SITE.repo` nunca era usado** apesar do comentário em `config.ts`
  prometer "deep-links verificáveis (commit, workflows) na página Provas" —
  eram texto simples. Implementado em
  `static/src/components/pages/EvidencePage.astro`: hash do commit liga a
  `{repo}/commit/{hash}`, cada workflow liga à sua página de execuções no
  GitHub Actions.
- `content/projects/{pt,en}/{homelab,honeypot}.md`: uniformizado o texto de
  âncora do link para a página ATT&CK ("heatmap ATT&CK" em vez de "Attack"
  solto, inconsistente com `sobre.md`/`about.md`).
- Paridade PT/EN em `ui.ts` verificada programaticamente pelo agente: 0
  divergências em 828 chaves. Paridade de `content/pages`, `content/projects`
  confirmada. Nenhum deslize de PT-BR encontrado.

### Fase 2d — leitura crítica de código (delegado a agente)

- Único achado: `export { SECURITY_HEADERS }` em
  `dynamic/worker/src/index.js:926` (agora removido, com o import não usado
  em `index.js:29`) — reexport especulativo "para testes de fumo, se
  necessário", nunca consumido em lado nenhum.
- Sem comentários com contexto interno, sem código morto adicional, sem
  restos de debug (além do já tratado na Fase 1), sem TODOs esquecidos.

---

## 2. O que já estava correto (verificado, sem alteração)

- Histórico git completo (377 commits, sem shallow) sem segredos —
  confirmado com `gitleaks detect -v --log-opts="--all"`.
- `.gitleaksignore` contém só o baseline documentado (3 fingerprints, AAGUIDs
  públicos do FIDO MDS em `passkeys.js`).
- IPs privados encontrados (`192.168.1.10`, `10.0.0.1`, etc.) são todos
  exemplos deliberados em ferramentas (subnet calculator, email-header tool)
  ou nos seus testes — não são fugas.
- `wrangler.toml`: `CF_ZONE_TAG`/`CF_ACCOUNT_ID` são identificadores, não
  credenciais, já documentados como tal no próprio ficheiro.
- Todas as actions pinadas por SHA, `permissions: {}`, sem
  `pull_request_target`.
- Coerência factual pessoal (nome, cargo, email, domínio, percurso,
  certificações, CTFs) — tudo bate certo entre `sobre.md`/`about.md`,
  `content/awards.json`, `content/certs.json`, `home.journey`, `home.meta` e
  `config.ts`.
- Todos os deep-links internos do site (bloco `layers`, cross-links entre
  páginas) resolvem contra `routes.ts`.
- Todas as afirmações verificáveis testadas contra o código real: 191 testes
  (72 static + 119 worker), 6 workflows, 11 ferramentas (8 client-side + 3
  com servidor), 8 cabeçalhos pontuados no self-scan, 5 paths-isco = 5 regras
  Sigma, "nenhum IP guardado" no honeypot (confirmado por teste), 14
  táticas/40 técnicas ATT&CK, 31 certificações (12 verificáveis), 4 CTFs, 29
  páginas bilingues + `404`.
- `docs/arquitetura-editorial-este-site.md` e
  `docs/pagina-mapeamento-controlos.md` mencionam rotas que não existem
  (`/detecoes/`, `/telemetria/`) — mas são propostas explicitamente
  autoconscientes disso ("a rota deixou de existir", "*(rota nova)*"), não
  erros.

---

## 3. Decisões tomadas com o dono (antes de agir)

1. **Email:** alias `me@danielmala.co` já existe e recebe correio → trocado.
2. **Flag de debug CSP:** diagnóstico ainda em curso → mantém-se `true`.
3. **`.mcp.json`:** reduzir a todos os de leitura → `cloudflare-bindings`
   removido.
4. **`expected-headers.json`:** via (b), Access desliga na Fase 3 do
   lançamento → mantém-se `SET-ME`.
5. **Post `hello-world`:** remover e assumir blog vazio → removido.
6. **Idioma do README:** EN principal + secção PT → aplicado.
7. **Duplicação das revisões de segurança:** `-07.md` histórico, `-07-29.md`
   atual, com nota cruzada → aplicado.
8. **Issues/CONTRIBUTING:** desligar Issues → **não é trabalho de
   repositório**, fica na checklist da Fase 5 abaixo.

## 4. Decisões que ficam por tomar / por fazer (não são trabalho de repositório)

Nada ficou bloqueado além do que já é, por natureza, ação de dashboard/conta
— ver checklist completa na secção seguinte.

---

## 5. Checklist — só o dono pode fazer

**Antes do flip**
- [ ] Rodar `RATE_SALT` e `CF_API_TOKEN` (procedimento em `wrangler.toml`).
- [ ] Rever secrets do GitHub Actions: nenhum obsoleto, nenhum com âmbito a
      mais.
- [ ] CAA, HSTS preload, DNSSEC, redirect HTTP→HTTPS — checklist em
      `docs/dns-tls.md` (ações de dashboard Cloudflare + submissão externa
      para o preload).
- [ ] Confirmar se o diagnóstico de `DEBUG_EXPOSE_SELF_PATH` concluiu; se
      sim, reverter a flag e os 2 testes associados
      (`dynamic/worker/test/logic.test.mjs` ~496, 547, 558) e fechar a
      entrada em `dynamic/PLAN.md`.
- [ ] Decidir sobre o token de deploy do Worker/H3 (ver §2b acima): o deploy
      já é automático via Workers Builds, mas continua sem proveniência
      verificável (`attest-build-provenance`) nem gate de revisor — decidir
      se vale a pena mover para um workflow de GitHub Actions com Environment
      protegido, ou aceitar o risco residual documentado.

**No flip**
- [ ] Lançamento (Fase 3 do site): desligar/ajustar a Cloudflare Access;
      confirmar que as regras WAF cobrem sozinhas.
- [ ] Apontar `.github/expected-headers.json` → `url` para produção, assim
      que a Access deixar de bloquear (decisão já tomada: via (b)).
- [ ] Tornar o repositório público.
- [ ] Ligar **secret scanning + push protection** (grátis em público).
- [ ] Ligar **CodeQL** (default setup) e o upload de SARIF em `security.yml`.
- [ ] Ligar **Dependency Review** nos PRs.
- [ ] Configurar **branch protection / rulesets** no `main`: CI obrigatório,
      sem force-push, sem apagar.
- [ ] **Issues:** desligar (decisão já tomada). **Discussions:** deixar
      desligadas.

**Depois do flip**
- [ ] Adicionar **OpenSSF Scorecard** + badge.
- [ ] Confirmar que o caminho de reporte do `SECURITY.md` funciona ponta a
      ponta com o repo já público.
- [ ] Reavaliar o achado H3 à luz do Workers Builds (ver acima) — decidir se
      fecha com um deploy via GitHub Actions com Environment protegido, ou
      se o risco residual atual é aceite.

---

## 6. Veredicto

**Sim, o repositório está pronto para se tornar público**, sujeito apenas às
ações de conta/dashboard listadas na secção 5 (nenhuma delas é trabalho de
repositório, e nenhuma é bloqueante para o código/conteúdo em si).

Ponto que se mantém, já sinalizado em `docs/public-repo-decision.md` §9 e
repetido aqui por ser o mais importante: **o site ainda está atrás da
Cloudflare Access — não carrega para ninguém.** Publicar o repositório antes
de lançar o site é metade de um portefólio. A ordem recomendada continua:
lançar o site, depois publicar o repositório, idealmente na mesma semana.

Nada foi encontrado que devesse impedir a publicação por si só — os dois
itens que mais se aproximavam disso (a contradição sobre o método de deploy
do Worker, e o export morto) já foram corrigidos nesta ronda.
