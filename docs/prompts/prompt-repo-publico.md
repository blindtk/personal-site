# Prompt — preparar o repositório para ser público

Prompt de execução para dar a um agente (pensado para **Sonnet**) com dois
objetivos ligados:

1. **Fechar tudo o que está pendente dentro do repositório** antes de o tornar
   público (`blindtk/personal-site` está privado hoje).
2. **Rever todos os ficheiros e textos do site** — código, documentação e
   conteúdo — na perspetiva de quem vai ler isto pela primeira vez, sem
   contexto e com espírito crítico.

O que **não** está aqui: decisões e cliques que só o dono do repo pode fazer
(dashboard da Cloudflare, definições do GitHub, rotação de segredos). Esses
ficam listados na **Fase 5**, para o agente entregar como checklist — nunca
para inventar que os fez.

Contexto de partida já escrito e a ler antes de tocar em nada:
[`public-repo-decision.md`](../public-repo-decision.md) (a decisão e o porquê),
[`security-review-2026-07-29.md`](../security-review-2026-07-29.md) e
[`security-review-2026-07.md`](../archive/security-review-2026-07.md) (as duas revisões),
[`cloudflare-deploy.md`](../cloudflare-deploy.md) §7 (checklist de lançamento),
[`../../dynamic/PLAN.md`](../../dynamic/PLAN.md) (decisões registadas e pendências do
Worker) e [`../../CLAUDE.md`](../../CLAUDE.md) (regras do projeto, que continuam a
valer para tudo o que for alterado).

Copia o bloco abaixo como pedido ao agente.

---

## Prompt

> **Tarefa:** preparar o repositório `blindtk/personal-site` para deixar de ser
> privado, e rever todos os ficheiros e textos do site. Trabalho em fases, com
> entregáveis verificáveis. Segue as regras de `CLAUDE.md` em tudo o que
> alterares: bilingue PT/EN sempre aos pares, strings de UI só em
> `static/src/i18n/ui.ts`, dados pessoais só em `static/src/config.ts`, rotas
> novas em `static/src/i18n/routes.ts`, português europeu no conteúdo PT.
>
> ### Regras de trabalho (aplicam-se a todas as fases)
>
> 1. **Verifica antes de acreditar.** Os documentos em `docs/` descrevem o
>    estado em datas passadas e alguns já estão desatualizados. Trata cada
>    pendência listada aqui como *hipótese* e confirma no código antes de
>    agir. Se já estiver feito, di-lo e passa à frente — não "corrijas" o que
>    já está correto.
> 2. **Não inventes execução.** Tudo o que exige o dashboard da Cloudflare, as
>    definições do GitHub, rotação de segredos ou acesso à conta **não é teu
>    para fazer**. Regista na checklist da Fase 5 e segue.
> 3. **Não reescrevas história do git**, não faças squash e não crias
>    repositório novo — está decidido e fundamentado em
>    `docs/public-repo-decision.md` §4.
> 4. **Não acrescentes ferramentas novas** (scanners, dependências, serviços).
>    A regra do projeto exige decisão explícita do dono; o repositório já tem
>    seis scanners e a revisão diz explicitamente que um sétimo é a coisa de
>    menor valor disponível.
> 5. **Antes de fechar cada fase:** `cd static && npm run build` sem erros nem
>    warnings novos; `cd static && npm test`; `cd dynamic/worker && npm test`.
>    Regista os números de testes no relatório. (Alguns testes estáticos
>    exigem `npm run build` primeiro — é por desenho, a mensagem de falha
>    di-lo.)
> 6. **Organização em PRs:** um PR por fase, na ordem abaixo. A Fase 1 é
>    bloqueante — não avances para as seguintes sem ela fechada. Mantém um PR
>    aberto de cada vez; PR merged nunca recebe commits novos (regra do
>    projeto).
>
> ---
>
> ### Fase 0 — Inventário do estado real (só leitura, sem alterações)
>
> Antes de mexer, produz um retrato do que existe **hoje**:
>
> - Lista todos os ficheiros do repo por área (`content/`, `static/`,
>   `dynamic/`, `docs/`, `.github/`) e assinala os que não estão referenciados
>   em lado nenhum (órfãos).
> - Corre os três comandos de teste/build acima e regista o resultado.
> - Corre `gitleaks detect --no-git` e, se a ferramenta estiver disponível,
>   `gitleaks detect` sobre o histórico completo. Se não estiver instalada,
>   di-lo — não presumas limpo. Confirma que `.gitleaksignore` só contém o
>   baseline documentado (AAGUIDs públicos do FIDO MDS em
>   `static/src/scripts/passkeys.js`) e nada mais.
> - Procura, em todo o repo **e no histórico**, por: emails pessoais, caminhos
>   locais de máquina (`/Users/`, `/home/<nome>`), IPs privados, tokens,
>   nomes de terceiros, e qualquer coisa que não queiras num repo público.
>   Distingue **identificadores** (IDs de KV, `CF_ZONE_TAG`, `CF_ACCOUNT_ID` —
>   públicos por natureza, já documentados como tal no `wrangler.toml`) de
>   **credenciais** (que não devem existir).
>
> Entrega: um relatório curto com o inventário e os achados. **Não alteres
> nada nesta fase.**
>
> ---
>
> ### Fase 1 — Bloqueadores (tem de estar feito antes de tornar público)
>
> Cada ponto abaixo foi verificado no repo à data de escrita deste prompt.
> Confirma e resolve:
>
> 1. **Email pessoal exposto.** `static/src/config.ts:27` tem
>    `[endereço pessoal antigo removido]`, com um comentário no próprio ficheiro a
>    recomendar um alias. Também aparece em `docs/dns-tls.md`. Substitui pelo
>    alias de domínio (`hello@danielmala.co` ou o que o dono indicar) nos dois
>    sítios. **Nota importante a escrever no relatório:** trocar aqui não
>    remove o endereço do histórico do git — a mitigação real é o alias ser
>    rotável, e o dono tem de confirmar que o alias existe e entrega correio
>    antes do flip. Se o alias ainda não existir, **para e pergunta**; não
>    inventes um endereço.
> 2. **Flag de debug ligada em produção.** `DEBUG_EXPOSE_SELF_PATH = true` em
>    `dynamic/worker/src/lib/csp-report.js:132` expõe o pathname nas violações
>    CSP `self/self`. É explicitamente temporário — `dynamic/PLAN.md` diz
>    "reverter assim que a causa for confirmada", e o risco aceite assentava
>    em produção estar atrás da Cloudflare Access. **Se o site for lançado e o
>    repo público, as duas premissas caem.** Pergunta ao dono se o diagnóstico
>    já concluiu; por omissão, **repõe `false`** e reverte os dois testes que
>    dependem do path (`dynamic/worker/test/logic.test.mjs`, ~linhas 496, 547 e
>    558), atualizando a entrada em `dynamic/PLAN.md` com o desfecho.
> 3. **`README.md` desatualizado e só em português.** Ver Fase 2 — o README é
>    o artefacto que mais gente vai ler e tem erros factuais. É bloqueante.
> 4. **`.mcp.json` na raiz — decisão por tomar.** Regista sete servidores MCP
>    da Cloudflare de âmbito de projeto, portanto propostos a qualquer pessoa
>    ou agente que clone o repo. `cloudflare-bindings` é de **escrita** (cria
>    e apaga KV/D1/R2). `dynamic/PLAN.md` marca isto como achado aberto (N6) e
>    diz explicitamente que a decisão não foi tomada. Num repo público isto
>    passa a ser um convite versionado. Apresenta as três opções ao dono
>    (manter os sete / reduzir aos de leitura / mover `cloudflare-bindings`
>    para connector pessoal fora do repo) com uma recomendação, e executa a
>    escolhida. Se não houver resposta, **a opção segura é remover o
>    `cloudflare-bindings` do ficheiro versionado** e documentar porquê.
> 5. **`.github/expected-headers.json` com `url: "SET-ME"`.** Está assim de
>    propósito enquanto a Cloudflare Access bloquear produção — não mexas às
>    cegas. Confirma com o dono qual das duas vias vai ser usada (Access
>    Service Token no CI, já suportado por `check-headers.mjs`, ou desligar a
>    Access na Fase 3 do lançamento) e deixa o ficheiro coerente com essa
>    escolha. Se nenhuma estiver decidida, **mantém `SET-ME`** e escreve na
>    checklist da Fase 5.
> 6. **Post de exemplo por publicar.** `content/blog/pt|en/hello-world.md` tem
>    `draft: true` e é o único post — com o repo público e o site no ar, o
>    blog fica vazio. Pergunta: publicar (tirar `draft`), reescrever, ou
>    remover e assumir o blog como vazio? Não decidas sozinho o que vai ser
>    publicado em nome do dono.
> 7. **Varredura final de segredos.** Repete o passo da Fase 0 sobre o estado
>    já alterado e confirma limpo.
>
> ---
>
> ### Fase 2 — Revisão de todos os ficheiros e textos
>
> Esta é a parte grande. Divide-a nas quatro frentes abaixo e reporta cada uma
> em separado.
>
> #### 2a. README — reescrever
>
> O README é a porta de entrada de um repo público. O atual está em português
> apenas e tem erros factuais confirmados:
>
> - `README.md:180` (bloco "Estrutura do código") diz `tools/ ← as 4
>   ferramentas client-side` — existem **onze**
>   ferramentas em `/ferramentas/`, três das quais requerem servidor (`pwned`,
>   `self-scan`, `mirror`).
> - A tabela "Features de segurança" aponta o painel do honeypot e o mapa de
>   tráfego para `/honeypot`, **rota que não existe** em
>   `static/src/i18n/routes.ts` — o painel vive de facto em `/perimetro/`
>   (`PerimeterPage.astro`). Corrige, e verifica se o mesmo erro se repete
>   noutros documentos.
> - O bloco "Estrutura do código" diz `dynamic/ ← PLAN.md (roadmap da futura
>   app com backend)` — o Worker está **em produção** desde então.
> - A "Nota de quota" explica escolhas com base no repositório ser privado.
>   Deixa de ser verdade no dia do flip; reescreve para o estado novo.
> - A lista de conteúdo omite os JSON de `content/` que alimentam páginas
>   reais (`awards`, `attack`, `certs`, `detections`, `catalog`,
>   `honeypot-attack`).
>
> Além de corrigir, o README precisa de ganhar (ver
> `docs/public-repo-decision.md` §6, que fundamenta cada ponto):
>
> - **Inglês.** Um leitor internacional é a maioria do público-alvo. Decide
>   com o dono entre README em EN com secção PT, ou `README.md` + `README.pt.md`
>   — e diz qual recomendas.
> - **O parágrafo sobre o excesso aparente.** Um site pessoal com modelo de
>   ameaça, 4 ADRs, 5 workflows e ~190 testes é desproporcionado — a não ser
>   que o README diga que a desproporção *é o ponto*: é um artefacto de
>   demonstração de engenharia de segurança. Um parágrafo converte a maior
>   fraqueza aparente na tese.
> - **A divulgação de uso de IA.** Os nomes de branch (`claude/…`) estão em
>   ~130 merge commits; a escolha não é revelar ou esconder, é enquadrar ou
>   deixar inferir. Há uma redação sugerida em `public-repo-decision.md` §5 —
>   usa-a como base, adapta à voz do site, uma vez e sem pedidos de desculpa.
> - **As três decisões mais interessantes**, cada uma com link para o seu ADR,
>   e o diagrama de arquitetura em destaque (`docs/architecture.md`).
> - **Nota sobre os decoys do honeypot serem públicos por desenho** — um
>   honeypot cujo valor é *demonstrar* a técnica não perde nada por ser
>   explicado, e é uma posição defensável que vale a pena afirmar em vez de
>   esconder.
>
> #### 2b. Documentação (`docs/`, `CLAUDE.md`, `SECURITY.md`, `dynamic/`)
>
> Lê **todos** os ficheiros de `docs/` e:
>
> - **Resolve a duplicação das revisões de segurança.** Existem
>   `security-review-2026-07.md` (1563 linhas, PT) e
>   `security-review-2026-07-29.md` (1002 linhas, EN) — âmbito sobreposto,
>   idiomas diferentes, e o README só linka o segundo. Decide (com o dono) se
>   se mantêm os dois com nota a explicar a relação, se se funde, ou se um
>   passa a arquivo datado. Verifica também as referências cruzadas: há links
>   entre documentos que apontam para o nome errado do outro ficheiro.
> - **Verifica todos os links internos** de todos os `.md` — ficheiros que
>   mudaram de nome, âncoras partidas, links para páginas do site que não
>   existem em `routes.ts`.
> - **Confirma que cada afirmação verificável ainda é verdade**: contagens de
>   testes, número de workflows, número de ferramentas, estado "em produção"
>   vs "planeado", listas de endpoints. Um repo público torna cada uma delas
>   falsificável por qualquer estranho — é esse o valor e é esse o risco.
> - **Lê `CLAUDE.md` como um estranho.** Passa a ser público. A recomendação
>   registada é mantê-lo (demonstra desenho deliberado de workflow com IA) —
>   confirma que não contém nada que não devesse ser lido de fora.
> - **`docs/dns-tls.md`, `docs/cloudflare-deploy.md` §7 e `dynamic/PLAN.md`**
>   têm checklists com caixas por fechar. Reconcilia-as com a realidade: o que
>   já foi feito passa a `[x]` com data; o que continua aberto e **não é
>   trabalho de repositório** migra para a checklist da Fase 5.
> - Avalia se falta `CONTRIBUTING.md` e templates de Issue — num repo público
>   com Issues ligadas, é a diferença entre triagem e ruído. Propõe, não
>   presumas: a decisão registada inclui a hipótese de simplesmente **desligar
>   as Issues**.
>
> #### 2c. Textos do site (conteúdo e i18n)
>
> Executa integralmente o prompt de
> [`prompt-consistencia-textual.md`](prompt-consistencia-textual.md) — cobre
> `content/**`, `static/src/i18n/ui.ts` (~1950 linhas, onde vive a maior parte
> do texto de página), `static/src/config.ts` e as componentes de
> `src/components/pages/`. Verifica paridade PT/EN, coerência factual entre
> páginas, terminologia, ligações cruzadas, narrativa e tom (**português
> europeu**, nunca brasileiro).
>
> Ao contrário do que esse prompt assume por omissão, aqui **estás autorizado a
> corrigir**: gralhas, deslizes de PT-BR, chaves i18n em falta num dos idiomas,
> links partidos e contradições factuais. O que **não** corriges sozinho é
> alteração de substância editorial (o que o dono afirma sobre si próprio,
> claims de certificações, decisões de posicionamento) — isso propões.
>
> Duas verificações extra próprias do "vai ficar público":
>
> - **Todas as afirmações verificáveis do site** ("X testes", "N workflows",
>   "sem trackers", "nenhum IP guardado", listas de controlos) passam a ser
>   auditáveis contra o código que qualquer pessoa vai poder ler. Verifica uma
>   a uma. Uma afirmação falsa num site cujo tema é "não acredites, verifica"
>   é o pior falhanço possível — e o próprio modelo de ameaça já lista "as
>   afirmações de segurança do site" como ativo quebrável.
> - **Deep-links para o repositório** (`SITE.repo` em `config.ts`, usados na
>   página Provas): hoje dão 404 a qualquer visitante porque o repo é privado.
>   Confirma que todos resolvem depois do flip — commits, workflows, ficheiros
>   e linhas específicas.
>
> #### 2d. Código
>
> Sem reescrever o que funciona, faz uma passagem de leitura crítica sobre
> `static/src/`, `static/public/` e `dynamic/worker/src/` à procura de:
>
> - comentários com contexto interno, notas para o próprio, linguagem que não
>   quererias que um recrutador lesse, ou TODOs esquecidos;
> - código morto, ficheiros órfãos, restos de experiências;
> - divergência entre o que um comentário promete e o que o código faz;
> - qualquer resto de debug além do `DEBUG_EXPOSE_SELF_PATH` da Fase 1.
>
> **Não** refactorizes para "parecer mais escrito à mão" — está explicitamente
> desaconselhado (`public-repo-decision.md` §5): é risco de regressão numa base
> com ~190 testes a passar, para derrotar um sinal que os nomes de branch já
> dão de qualquer maneira.
>
> ---
>
> ### Fase 3 — Verificação final
>
> - `cd static && npm run build` limpo; `npm test` nos dois projetos.
> - Todos os links internos do site e da documentação resolvem.
> - Paridade PT/EN completa (nenhuma página, chave i18n ou ficheiro de conteúdo
>   só de um lado).
> - Varredura de segredos limpa, no working tree e no histórico.
> - Nenhum `SET-ME`, `TODO` ou flag de debug ativa que não esteja
>   deliberadamente documentada como tal.
>
> ---
>
> ### Fase 4 — Relatório
>
> Entrega um documento em `docs/` com:
>
> 1. O que foi alterado, por fase, com `ficheiro:linha`.
> 2. O que foi verificado e estava **já correto** (importa tanto como o resto —
>   evita que a próxima ronda repita trabalho).
> 3. **Decisões que ficaram por tomar** e o que está bloqueado nelas.
> 4. A checklist da Fase 5, pronta a executar pelo dono.
> 5. Um veredicto claro: *o repositório está pronto para ser público?* Sim ou
>    não, com a lista exata do que falta se for não.
>
> ---
>
> ### Fase 5 — Só o dono pode fazer (checklist para entregar, não para executar)
>
> Regista isto no relatório, agrupado e por ordem. **Nenhum destes pontos é
> trabalho de repositório** — não tentes fazê-los nem os dês como feitos:
>
> **Antes do flip**
> - Criar o alias de email no domínio e confirmar que entrega correio.
> - Rodar `RATE_SALT` e `CF_API_TOKEN` (procedimento já documentado no
>   `wrangler.toml`).
> - Rever os secrets do GitHub Actions: nenhum obsoleto, nenhum com âmbito a
>   mais, antes de o repo passar a legível.
> - Decidir o destino do `.mcp.json` (Fase 1.4).
> - Decidir sobre o post `hello-world` (Fase 1.6).
>
> **No flip**
> - Tornar o repositório público.
> - Ligar **secret scanning + push protection** (grátis em público).
> - Ligar **CodeQL** (default setup) e o upload de SARIF em `security.yml` — o
>   comentário que diz "requer GHAS" fica obsoleto nesse momento.
> - Ligar **Dependency Review** nos PRs.
> - Configurar **branch protection / rulesets** no `main`: CI obrigatório, sem
>   force-push, sem apagar.
> - **Issues:** desligar ou pôr templates. **Discussions:** deixar desligadas.
>
> **Depois do flip**
> - Adicionar **OpenSSF Scorecard** + badge (com actions pinadas por SHA e
>   `permissions: {}` já em vigor, a pontuação deve ser alta à partida).
> - Apontar `.github/expected-headers.json` para produção assim que a Access
>   deixar de bloquear (ou configurar o Access Service Token no CI).
> - Confirmar que o caminho de reporte do `SECURITY.md` funciona ponta a ponta
>   com o repo já público.
> - Fechar o achado H3: **deploy por CI** com token de âmbito reduzido em
>   Environment protegido. Num repo público, um token de deploy é alvo de
>   valor real — Environment protegido e revisor obrigatório não são opcionais.
>
> **Ordem recomendada, e o ponto mais importante deste documento:** o site
> ainda está atrás da Cloudflare Access — **não carrega para ninguém**. Um repo
> público a apontar para um site inacessível é meio portfólio. Lançar o site
> vem primeiro; publicar o repo, logo a seguir.
