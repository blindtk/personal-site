# Auditoria de conteúdo e ficheiros — repositório público (2026-07-31)

> Relatório de **análise**, gerado a partir do prompt reutilizável em
> `docs/prompt-repo-publico.md` (nota: apesar do nome semelhante, este ficheiro
> é diferente do `docs/prompt-repo-publico.md` original — ver secção "meta"
> abaixo). Nada foi alterado nesta ronda: nenhum ficheiro foi apagado, movido
> ou reescrito. Toda a afirmação abaixo é ancorada em `caminho:linha` ou num
> comando reprodutível.

> **Atualização (2026-07-31, mesmo dia).** O dono do repo confirmou que a
> Cloudflare Access deixou de bloquear `danielmala.co`/`www.danielmala.co` —
> resposta à pergunta 1 no fim deste relatório. Isso resolveu o achado #1 do
> resumo executivo e, por decisão já pré-acordada em `dynamic/PLAN.md`,
> obrigou a reverter também o achado #3 (`DEBUG_EXPOSE_SELF_PATH`). Ambos
> foram executados nesta mesma ronda (ver marcas `[RESOLVIDO]` abaixo); os
> restantes achados continuam por decidir.

## Nota meta, antes de tudo

Este não é o primeiro ciclo desta tarefa. `docs/prompt-repo-publico.md` é,
com grande probabilidade, o prompt que gerou uma ronda anterior — tem uma
"Fase 0 — Inventário" e uma "Fase 2b — Documentação" que pedem exatamente
isto, e já existe um relatório de execução datado de um dia antes de hoje
(`docs/relatorio-preparacao-repo-publico-2026-07-30.md`). Muitas correções
óbvias (contagem de testes no README, DNSSEC em `dns-tls.md`) já foram feitas
nesse ciclo. Esta ronda usou como ponto de partida o estado *atual* do repo,
não o histórico — mas isso significa que grande parte do trabalho fácil já
está feito, e o que sobra é mais difícil: decisões editoriais por confirmar
com o dono, e dois achados operacionais que parecem ainda estar em aberto.

O próprio `docs/prompt-repo-publico.md` está no âmbito do Eixo B deste
relatório e é classificado como qualquer outro ficheiro (ver tabela).

---

## Resumo executivo — os 5 problemas que mais custam a quem chega de fora

Por ordem de impacto (impacto = o que um leitor cético, a fazer exatamente o
que o próprio README convida — "não acredites, verifica" — encontra em 5
minutos):

1. **[RESOLVIDO 2026-07-31]** A verificação diária de cabeçalhos de produção
   estava desligada por placeholder, e o comentário admitia que o site
   podia ainda estar atrás de Cloudflare Access — `.github/
   expected-headers.json` tinha `"url": "SET-ME: https://danielmala.co/"`.
   **O dono confirmou que a Access já não bloqueia `danielmala.co`/
   `www.danielmala.co`**; `url` foi atualizado para `https://danielmala.co/`
   e o `$comment` já não reproduz a premissa desatualizada.
2. **[RESOLVIDO 2026-07-31, confirmado pelo dono do repo]** Uma técnica de
   bypass de WAF ainda ativa estava documentada em claro num ficheiro
   público. `docs/cloudflare-deploy.md:150-172` explicava que a regra 2 do
   WAF fazia *match* por uma substring de User-Agent pública (não migrada
   para o header assinado `X-Ci-Waf-Token`, já implementado do lado do CI)
   — identificado como "achado de uma sessão de validação de lançamento" em
   2026-07-30. **A regra no dashboard já foi migrada** para verificar
   `X-Ci-Waf-Token` em vez do User-Agent; a documentação foi atualizada para
   refletir isso.
3. **[RESOLVIDO 2026-07-31]** Uma flag de debug que expunha pathnames de
   violações CSP continuava ligada, com o risco aceite a assentar numa
   premissa que a própria tarefa desta auditoria invalidou.
   `dynamic/worker/src/lib/csp-report.js:132` tinha
   `DEBUG_EXPOSE_SELF_PATH = true`; o `dynamic/PLAN.md:25-30` e os dois
   relatórios de 2026-07-30 aceitavam este risco com base em "produção
   continua atrás de Cloudflare Access". Como essa base deixou de valer,
   revertida para `false` (o próprio `dynamic/PLAN.md` já previa reverter
   primeiro neste cenário, antes de a causa das violações self/self estar
   confirmada) — 2 assertions em `dynamic/worker/test/logic.test.mjs`
   atualizadas e um terceiro teste (só testava o comportamento de debug)
   removido; total de testes do Worker passa de 119 para 118, e o total do
   repo de 191 para 190 (README atualizado).
4. **A build de produção não é limpa — viola o próprio critério do
   `CLAUDE.md`.** `content/blog/` não existe fisicamente, mas
   `getCollection('blog', ...)` é chamado em `BaseLayout.astro:29` (todas as
   páginas) e `HomePage.astro:22`. `cd static && npm run build` produz
   **68 avisos** `"The collection \"blog\" does not exist or is empty"` (um
   por página, confirmado eu próprio a correr o build — 59 páginas, exit 0
   mas não silencioso). O `CLAUDE.md` exige "sem erros nem warnings novos"
   antes de qualquer PR — hoje esse crivo já está sujo, o que esconde
   qualquer aviso genuinamente novo introduzido por um PR futuro.
5. **Três números diferentes de "quantos cabeçalhos de segurança" para o
   mesmo facto, e o próprio site convida a comparar.** A Home diz **8**
   (`HomePage.astro:65`, alinhado com `dynamic/worker/src/lib/scan.js`, que
   tem 8 entradas — falta `cross-origin-embedder-policy`); a tabela-contrato
   da página Provas mostra **9** (`.github/expected-headers.json`, que inclui
   COEP); a página Segurança lista **7** linhas em `ui.ts:213-221` (agrega 3
   cabeçalhos num só bullet). O tile "8" da Home liga precisamente para a
   página Provas, onde o leitor vê 9. E o self-scan ao vivo nunca avalia
   COEP, apesar de a página Segurança o descrever como coberto.

Achado adicional que quase entrou no top 5 mas é mais fácil de corrigir:
o README diz **"six CI workflows"** mas há **9 ficheiros** em
`.github/workflows/` (`ci`, `codeql`, `dependency-review`, `headers`,
`invariants`, `labeler`, `scorecard`, `security`, `supply-chain`) — os "6"
correspondem exatamente aos 6 badges no topo do README (Scorecard tem badge
próprio, fora da contagem; `dependency-review` e `labeler` não têm badge nem
menção). Não é uma falha de segurança, mas é exatamente o tipo de
inexatidão verificável que o próprio README diz não ter (*"todo o número
verificável é conferido contra o código, não afirmado de memória"*).
Comando: `ls .github/workflows/*.yml | wc -l` → 9.

---

## Eixo A — achados de texto (site)

Verificação: paridade PT/EN de `static/src/i18n/ui.ts` (1950 linhas) é
**100%** — nenhuma chave em falta de nenhum dos lados, comprimentos de array
idênticos, confirmado por comparação programática das duas árvores. Links
internos nas componentes e no conteúdo markdown estão todos corretos (zero
partidos). Não há brasileirismos no texto editorial do autor. Estes pontos
**não** entram na tabela abaixo por não serem achados — ficam registados
aqui como base positiva confirmada.

| # | Ficheiro:linha | O que está lá | O que devia estar | Gravidade | PT/EN/ambos |
|---|---|---|---|---|---|
| A1 | `HomePage.astro:65` vs `.github/expected-headers.json` vs `static/src/i18n/ui.ts:213-221` vs `dynamic/worker/src/lib/scan.js:11-19` | "8" cabeçalhos (Home) / 9 no contrato (Provas) / 7 linhas (Segurança) para o mesmo facto; self-scan nunca avalia COEP | Um único número, a mesma fonte de verdade nas 3 páginas, e o self-scan a cobrir os 9 cabeçalhos do contrato | Média-alta | Ambos |
| A2 | `static/src/components/tools/EncoderTool.astro:25` | `placeholder="olá, mundo"` fixo, sem depender de `lang` | Placeholder em inglês em `/en/tools/encoder/` | Média | EN |
| A3 | `content/projects/pt/star-organizer.md` / `en/star-organizer.md` (front-matter `description`) | "atualizado automaticamente" / "updated automatically" | O corpo do próprio ficheiro explica que, para este site, a atualização é manual (vendorizada à mão) — a description contradiz o corpo, igual nos dois idiomas | Média | Ambos |
| A4 | `static/src/pages/**` (todas, via `BaseLayout.astro:29` + `HomePage.astro:22`) | Build emite 68 avisos `"collection blog does not exist"` | Build limpo (mover a chamada a `getCollection('blog', ...)` para não correr quando a coleção não existe, ou criar `content/blog/.gitkeep` — decisão de implementação, não deste relatório) | Média (viola CLAUDE.md hoje) | Ambos |
| A5 | `.github/expected-headers.json` (`$comment`, `url`) | Admite que a Cloudflare Access pode ainda estar a bloquear produção; cron de verificação neutralizado por placeholder | Confirmar estado real e, se resolvido, preencher a URL real; se não resolvido, é bloqueador de lançamento (ver resumo executivo #1) | Alta (condicional a confirmação do dono) | Ambos |
| A6 | `static/src/components/tools/ExifTool.astro:229` | `a.download = 'sem-metadados.jpg'` fixo nos dois idiomas | Nome de ficheiro traduzido em EN | Baixa | EN |
| A7 | `static/src/components/tools/PasskeyLab.astro:12,159` | Domínio-isco `login-seguro.xyz` (PT) e RP name inglês fixos, independentemente do idioma | Coerência de idioma no identificador de demo | Baixa | EN |
| A8 | `.well-known/security.txt` | `Contact`/`Policy` só apontam para URLs PT, apesar de `Preferred-Languages: pt, en` | Apontar para as duas versões, ou aceitar que PT é a canónica (decisão, não bug) | Baixa | Ambos |
| A9 | `content/certs.json` (`FCP Security Operations`, `expires: 2025-09-08`) | Certificação já expirada face a hoje (2026-07-31); `CertificationsPage.astro` já mostra "expirado" corretamente | Confirmar com o dono se foi renovada/descontinuada — dado a atualizar, não bug de código | Baixa | Ambos |
| A10 | Perímetro/Deteções/Provas/ferramenta de cabeçalhos de email | Densidade técnica alta (ASN, Sigma, SIEM, CVE/KEV, SPF/DKIM/DMARC, k-anonimato) sem glossário, em contraste com o tom acessível da Home/Sobre | Nenhuma ação obrigatória — é um site dirigido a pares técnicos; sinalizado como observação de tom, não erro | Baixa | Ambos |

Achados **sem** ação recomendada, por serem intencionais e bem documentados:
a coleção `blog` fica escondida da nav por design quando vazia
(`blog/[...page].astro:5-9` explica isto explicitamente); `footer.pathLabel`
("Percurso:" / "Track record:") é tradução não-literal deliberada, coerente
com o conteúdo agrupado; `site.agoPrefix` vazio em EN é ordem de palavras,
não chave em falta.

---

## Eixo B — classificação de ficheiros de documentação

Nenhum dos 25 ficheiros de documentação lidos integralmente merece
**apagar** puro e simples — mesmo as quatro propostas mais longas têm
raciocínio editorial genuinamente reutilizável. Nenhum merece **reescrever**
no sentido de "está factualmente errado" — os erros concretos que existiam
(contagem de testes, DNSSEC) já foram corrigidos num ciclo anterior.

| Ficheiro | Decisão | Justificação | Custo de errar |
|---|---|---|---|
| `README.md` | **manter** | Porta de entrada, já corrigido na ronda de 30/07; só a contagem de workflows (achado do resumo executivo) precisa de ajuste | Baixo |
| `docs/architecture.md` | **manter** | Diagrama exato e pequeno | Baixo |
| `docs/arquitetura-editorial-este-site.md` | **arquivar** → `docs/proposals/` | Proposta de reorganização (Perímetro→3 páginas) **não implementada** — `PerimeterPage.astro:29-34` ainda tem as 5 tabs que o documento diagnostica como problema | Alto se lido como referência viva: um leitor pode concluir que o site está desatualizado, quando é a proposta que está por decidir |
| `docs/cloudflare-deploy.md` | **manter, com correção urgente** | Runbook real e valioso, mas contém a técnica de bypass WAF ativa (achado #2) | Alto — apagar perde o melhor runbook; não corrigir deixa a receita pública |
| `docs/dns-tls.md` | **manter** | Só 2 itens pendentes (CAA, preload), sem detalhe sensível; DNSSEC já corrigido | Baixo |
| `docs/home-revisao-editorial.md` | **arquivar** (ou comprimir para nota curta) | **Já implementado quase literalmente** — `ui.ts:482-506` e `HomePage.astro:8-51` citam o documento por nome nos comentários e seguem a copy proposta | Médio — é um rascunho publicado ao lado do produto final que já existe; apagar por completo perde o raciocínio ("porquê tirar stats pessoais da Home") |
| `docs/honeypot-analise-evolucao.md` | **arquivar** → `docs/proposals/` | 58k caracteres de análise; o próprio documento (linha 30) admite "nenhuma está implementada" — `content/honeypot-attack.json` ainda usa a taxonomia antiga | Alto — é o documento mais longo e mais fácil de confundir com estado real |
| `docs/pagina-mapeamento-controlos.md` | **arquivar** → `docs/proposals/` | Proposta com copy "pronta a implementar"; nenhuma rota/chave i18n/componente correspondente existe | Médio — título já se assume proposta, mas ainda vive na raiz de `docs/` |
| `docs/prompt-consistencia-textual.md` | **arquivar** → `docs/prompts/` | Prompt de execução reutilizável para agente, não referência para leitor humano | Baixo |
| `docs/prompt-repo-publico.md` | **arquivar** → `docs/prompts/`; **redigir email pessoal** | Já corrido (ver relatório associado); linha 99 tem `daniel_malaco@hotmail.com` em claro | Médio — é prova do processo AI-assisted que o README elogia; manter sem redigir republica PII já obsoleto mas evitável |
| `docs/prompt-validacao-lancamento.md` | **arquivar** → `docs/prompts/`, sinalizar como possivelmente ainda ativo | O checklist que gera continua parcialmente por fechar (`DEBUG_EXPOSE_SELF_PATH`) | Médio — arquivar cedo de mais obriga a recriar quando for preciso revalidar |
| `docs/public-repo-decision.md` | **fundir** num ADR curto, ou manter | Decision record de qualidade, já executado, sobreposto com o relatório de preparação | Baixo-médio — é o melhor texto em inglês para um recrutador ler primeiro; fundir perde esse ângulo se malfeito |
| `docs/relatorio-preparacao-repo-publico-2026-07-30.md` | **manter por agora** → `docs/archive/` quando a checklist fechar | Tem itens de checklist genuinamente abertos (rotação de segredos) | Baixo |
| `docs/relatorio-validacao-lancamento-2026-07-30.md` | **manter por agora**, mesma nota | O bloqueador que identifica (`DEBUG_EXPOSE_SELF_PATH`) continua por resolver hoje | Baixo |
| `docs/security-headers.md` | **manter** | Referência técnica precisa, espelha `_headers` real | Baixo |
| `docs/security-review-2026-07-29.md` | **manter** | Retrato atual, ligado do README, inglês por razão declarada | Baixo |
| `docs/security-review-2026-07.md` | **arquivar** → `docs/archive/` (manter link cruzado) | O documento **não** diz ser substituído — diz explicitamente "mantêm-se os dois" (linha 3-9), e o outro confirma "kept for the fix history, not superseded" (linha 11). Não é uma sobreposição por descuido, é decisão deliberada. A única questão é *onde* na árvore, não *se* deve existir | Médio — apagar destrói a melhor prova de honestidade do repo (auto-correção pública de pontuação, achado de CSP partida em produção); mover para archive resolve o peso sem perder o conteúdo |
| `docs/threat-model.md` | **manter** | "Vivo, rever a cada trimestre" — última revisão 29-30/07, hoje 31/07, não está em atraso | Baixo |
| `docs/adr/README.md` + `0001`–`0004` | **manter** | ADRs curtos e precisos — melhor documentação do repo | Baixo |
| `dynamic/PLAN.md` | **manter** (candidato a reescrever a médio prazo) | Exigido pelo CLAUDE.md; correto mas longo — separar decisões de ideias/roadmap ajudaria | Médio |
| `dynamic/worker/README.md` | **manter** | Referência de endpoints em dia | Baixo |
| `.github/SECURITY.md` | **manter** | Política padrão, correta | Baixo |
| `.github/pull_request_template.md` | **manter** | Pequeno, funcional | Baixo |
| `LICENSE` | **manter** | MIT padrão | Baixo |
| Este próprio ficheiro (`docs/auditoria-repo-publico-2026-07-31.md`) | **arquivar** → `docs/prompts/` ou `docs/archive/` assim que as perguntas abaixo forem respondidas e o plano executado | É ele próprio um artefacto de processo, não referência viva | Baixo |

---

## Achados de exposição/segredos (sem reproduzir valores)

- **Nenhum segredo real** (API key, token, chave privada, credencial) foi
  encontrado no código, configuração ou histórico de commits (`git log --all
  --oneline | wc -l` = 147 commits; grep amplo por padrões de segredo e por
  `password|secret|token|api_key` nas mensagens de commit só devolveu texto
  sobre o próprio trabalho de segurança do projeto, não incidentes).
  `Bearer ` só aparece via variável de ambiente (`CF_API_TOKEN`) ou em
  fixtures de teste.
- `dynamic/worker/wrangler.toml:41-42,68-69` expõe em claro o `id` do
  namespace KV e o `CF_ZONE_TAG`/`CF_ACCOUNT_ID` reais (identificadores, não
  segredos — corretamente tratados como tal pelo próprio autor em comentário).
- `docs/cloudflare-deploy.md:144-172` documenta a ordem exata das 5 regras
  WAF de produção e a política geográfica exata (só PT passa) — transparência
  deliberada, sem custo. A técnica de bypass que aqui vivia (achado #2,
  **resolvido**) já não está ativa.
- `static/public/ferramentas/exif-demo.jpg` tem EXIF real com GPS (câmara
  FUJIFILM X-T5, coordenadas de zona turística fora de Portugal) — usado
  deliberadamente como demo da ferramenta EXIF
  (`ExifTool.astro:80`), não parece ser uma fuga acidental, mas vale
  confirmar com o dono que a foto não é pessoal.
  `static/test/fixtures/exif-sample.jpg` tem GPS claramente fictício
  (`Make: TESTCAM`).
- `docs/prompt-repo-publico.md:99` e
  `docs/relatorio-preparacao-repo-publico-2026-07-30.md:13` têm o endereço
  pessoal antigo `daniel_malaco@hotmail.com` em texto simples e pesquisável
  — já está no histórico do git de forma irreversível, mas repetir em prosa
  facilita scraping sem necessidade.
- `.gitleaksignore` lista como falso-positivo aceite um mapa de AAGUIDs
  públicos do FIDO Alliance em `static/src/scripts/passkeys.js` — não são
  segredos, confirmado.
- `dynamic/worker/src/lib/csp-report.js:132` — `DEBUG_EXPOSE_SELF_PATH`,
  **[RESOLVIDO 2026-07-31]** revertido para `false` (achado #3 do resumo
  executivo).
- Nenhum ficheiro de código, script ou entrada `content/*.json` órfão —
  todos os 12 scripts em `static/src/scripts/` e os 7 JSON de `content/` têm
  importador confirmado. **Lacuna de teste** (não órfão, mas contradiz a
  convenção do CLAUDE.md de testar com vetores conhecidos): `encoding.js`,
  `geo.js`, `lab-terminal.js`, `md5.js`, `password.js`, `pwned.js` e
  `subnet.js` não têm ficheiro de teste correspondente em `static/test/`.

---

## Plano de execução — PRs pequenos e independentes, por prioridade

1. **[FEITO 2026-07-31]** ~~PR — corrigir o cron de verificação de
   headers~~ — `url` em `.github/expected-headers.json` atualizado para
   `https://danielmala.co/` depois de o dono confirmar que a Access já não
   bloqueia produção; `$comment` atualizado. `docs/cloudflare-deploy.md`
   (secções 3 e 7) e `dynamic/PLAN.md` também atualizados para refletir o
   estado atual.
2. **[FEITO 2026-07-31, confirmado pelo dono do repo]** ~~PR — migrar a
   regra WAF de CI para o header assinado~~ — já migrada no dashboard;
   `docs/cloudflare-deploy.md` §5/§7 atualizado para remover a nota "falta
   migrar".
3. **[FEITO 2026-07-31]** ~~PR — decidir e resolver
   `DEBUG_EXPOSE_SELF_PATH`~~ — revertido para `false` em
   `dynamic/worker/src/lib/csp-report.js`, decisão registada em
   `dynamic/PLAN.md`, testes atualizados em
   `dynamic/worker/test/logic.test.mjs` (118 testes, era 119).
   `cd dynamic/worker && node --test` confirmado: 118 pass, 0 fail.
4. **PR — build limpo (coleção `blog`)**. Toca em: código
   (`BaseLayout.astro`/`HomePage.astro`/`content.config.ts` — decisão de
   implementação entre criar `content/blog/` vazio com `.gitkeep`, tornar a
   chamada condicional, ou remover a coleção até haver conteúdo). Reconfirmar:
   `cd static && npm run build` sem avisos de `blog`.
5. **PR — unificar a contagem de cabeçalhos de segurança**. Toca em:
   conteúdo/código (`HomePage.astro`, `ui.ts`, `expected-headers.json`,
   `scan.js` — decidir uma única fonte de verdade, incluir COEP no
   self-scan). Reconfirmar: `npm run build` + `node --test` em `static/`.
6. **PR — corrigir a contagem "six CI workflows" no README**. Toca em:
   conteúdo (`README.md`, duas ocorrências). Reconfirmar: `npm run build`.
7. **PR — mover documentação de processo/proposta** (depende das respostas
   às perguntas abaixo): `arquitetura-editorial-este-site.md`,
   `home-revisao-editorial.md`, `honeypot-analise-evolucao.md`,
   `pagina-mapeamento-controlos.md` → `docs/proposals/`; os `prompt-*.md` e
   este relatório → `docs/prompts/`/`docs/archive/`; `security-review-2026-
   07.md` → `docs/archive/` com link cruzado mantido. Redigir o email
   pessoal em `prompt-repo-publico.md` e no relatório de preparação. Toca só
   em docs — sem build a reconfirmar, mas verificar que nenhum link interno
   (`README.md`, outros docs, comentários no código que citam estes
   ficheiros por caminho) fica partido.
8. **PR — corrigir strings hardcoded EN** (`EncoderTool.astro` placeholder,
   `ExifTool.astro` nome de ficheiro descarregado). Toca em: código. Testar
   manualmente `/en/tools/encoder/` e `/en/tools/exif/`.
9. **PR — cobertura de teste em falta** para `encoding.js`, `geo.js`,
   `lab-terminal.js`, `md5.js`, `password.js`, `pwned.js`, `subnet.js`
   (vetores conhecidos, conforme a convenção do CLAUDE.md). Toca em: código.
   Reconfirmar: `node --test` em `static/`.

---

## Perguntas cuja resposta muda o plano

1. ~~A Cloudflare Access ainda bloqueia produção?~~ **Respondido
   2026-07-31: não, já foi desligada/ajustada.** Executado (ver item 1 do
   plano).
2. ~~A migração da regra WAF (User-Agent → `X-Ci-Waf-Token`) já foi feita no
   dashboard?~~ **Respondido 2026-07-31: sim, já migrada.** Documentação
   atualizada. (`*.pages.dev` confirmado que continua atrás de Access, por
   desenho — sem ação necessária.)
3. ~~`DEBUG_EXPOSE_SELF_PATH` — o diagnóstico já concluiu?~~ **Sem resposta
   sobre o diagnóstico em si, mas irrelevante agora**: a premissa do risco
   aceite (Access a proteger tudo) mudou, por isso revertido primeiro, como
   já estava decidido em `dynamic/PLAN.md`. Se as violações self/self
   reaparecerem, reabrir o diagnóstico à luz do novo estado.
4. **`arquitetura-editorial-este-site.md` (separar Perímetro em 3 páginas) —
   foi aceite e está para implementar, ou abandonada?** Determina
   `docs/proposals/` (viva) vs `docs/archive/` (morta).
5. **`honeypot-analise-evolucao.md` e `pagina-mapeamento-controlos.md` —
   alguma parte foi aceite?**
6. **`home-revisao-editorial.md`, já implementado — arquivar tal como está,
   ou extrair primeiro uma nota curta do raciocínio editorial?**
7. **Os dois relatórios de 2026-07-30 ainda servem, ou já foram totalmente
   absorvidos?**
8. **`security-review-2026-07.md` — concordas em mover para
   `docs/archive/` mantendo o link cruzado, ou preferes mantê-lo na raiz tal
   como está?**
9. **Dos três `prompt-*.md` — algum vai ser reutilizado em breve?**
   (`prompt-validacao-lancamento.md` em particular, se o lançamento continuar
   bloqueado pelos achados #1-3.)
10. **`docs/public-repo-decision.md` — fundir num ADR curto, ou manter
    inteiro por ser o melhor texto em inglês para um recrutador?**
11. **A certificação "FCP Security Operations" (expirada em 2025-09-08) foi
    renovada ou descontinuada?**
12. **A foto `static/public/ferramentas/exif-demo.jpg` (EXIF com GPS de
    fora de Portugal) — é uma foto de stock/creative-commons, ou precisa de
    substituição por algo com proveniência mais clara?**
