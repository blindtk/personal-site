# Segurança de CI/CD do `blindtk/blindtk` — relatório (2026-07-30)

> Âmbito: o repositório de perfil `blindtk/blindtk` (`README.md` +
> `assets/*.svg` + workflows). Usa o `blindtk/personal-site` como catálogo
> de controlos já provados e decide, ferramenta a ferramenta, o que faz
> sentido copiar — nunca por reflexo. Ver o prompt de execução em
> [`docs/prompt-repo-publico.md`](prompt-repo-publico.md)-style (não
> commitado como prompt próprio; resumo aqui).

---

## 1. Modelo de ameaça do `blindtk/blindtk` (Fase 0)

Este repositório **não** é o `personal-site`: é um `README.md`, cinco SVGs
gerados (`assets/`), e dois — agora quatro — workflows. Não há build, não
há dependências de aplicação, não há lockfile. O modelo de ameaça é outro.

### Ativos

1. **A conta GitHub do dono e a sua reputação** — este README *é* a
   primeira coisa que um recrutador ou colega lê.
2. **O `GITHUB_TOKEN` com `contents: write`** que o workflow
   `update-profile-widgets.yml` recebia (por omissão, ao nível do
   workflow inteiro, antes desta revisão).
3. **O conteúdo do README** — a montra de um perfil de segurança;
   inconsistência entre o que se afirma e o que é verdade custa mais
   reputação aqui do que em qualquer outro sítio.
4. **Os SVGs commitados**, servidos pelo `camo` do GitHub a quem visita o
   perfil — se um deles carregar conteúdo ativo, é o próprio dono a
   distribuí-lo.

### Atacante realista

- Compromisso de uma das quatro dependências de terceiros que o workflow
  invoca (`stats-organization/github-readme-stats-action`,
  `ryo-ma/github-profile-trophy`, `denoland/setup-deno`, `img.shields.io`
  como fonte de conteúdo, não como action).
- Uma tag movida — `ryo-ma/github-profile-trophy@v1.0` era, antes desta
  revisão, uma tag mutável: quem a controlasse controlava o que corria.
- Um PR de um estranho num repo público (superfície pequena: o único
  workflow disparado por `pull_request`/`push` é o `lint-actions.yml`,
  que só lê).

### Pior caso concreto (cadeia, não lista)

Alguém compromete `ryo-ma/github-profile-trophy` (ou move a tag `v1.0`)
→ o código dele corre no runner via `deno run --allow-net --allow-env
--allow-read --allow-write` → esse comando via, **antes desta revisão**,
o `GITHUB_TOKEN` inteiro do workflow (que tinha `contents: write` ao
nível do workflow, herdado por todos os passos, incluindo este) → com
`--allow-net` e `--allow-env` sem âmbito, o código consegue ler o token e
enviá-lo para qualquer destino de rede → com esse token, consegue fazer
push direto para `main` sem revisão humana (o próprio job final do
workflow já faz `git push` sem gate nenhum). **Entre "upstream
comprometido" e "commit no `main` do perfil do dono" não havia nenhuma
fronteira de permissão nem de rede.** Esta é a cadeia mais curta do
repositório, e é a que a Fase 4 fecha.

### Inventário dos workflows (estado ANTES desta revisão)

**`update-profile-widgets.yml`** — `schedule` semanal + `workflow_dispatch`;
`permissions: contents: write` ao nível do workflow (um único job,
`update-widgets`, herda o write em todos os passos); sem segredos além do
`GITHUB_TOKEN` por omissão; quatro actions de terceiros não pinadas por
SHA (`actions/checkout@v4` ×2, `stats-organization/github-readme-stats-action@v2`
×2, `denoland/setup-deno@v2`) mais o `ryo-ma/github-profile-trophy` pinado
por **tag mutável** (`v1.0`), não SHA; código de terceiros (Deno) a correr
com o token e permissões sem âmbito; um `curl` que interpolava o token
diretamente num `run:`; conteúdo de `img.shields.io` escrito direto para
um SVG commitado sem validação; `git push` direto para `main` sem revisão.

**`lint-actions.yml`** — `push`/`pull_request` com `paths:
.github/workflows/**` + `workflow_dispatch`; `permissions: contents: read`
já correto ao nível do workflow; `zizmor` sem versão cravada e sem
`--min-severity`; só um `actions/checkout@v4` não pinado.

O commit `f369858` (30-07-2026, antes desta revisão) já tinha fechado dois
achados do zizmor (`persist-credentials: false` nos dois checkouts que não
fazem push; o token do contador de estrelas movido para `env:`) e deixado
seis achados de "unpinned-uses" explicitamente em aberto, por falta de
acesso de leitura aos repositórios externos nessa altura.

**Correção ao inventário:** o `CodeQL` que aparece nos checks do PR
(`CodeQL` / `Analyze (actions)`) não é um workflow deste repositório — é o
*default setup* nativo do GitHub (Security → Code scanning), que já estava
ligado antes desta revisão e cobre a linguagem "GitHub Actions" (as
próprias workflows). Não corre de um ficheiro em `.github/workflows/`, por
isso não entrava na contagem "dois — agora quatro — workflows" acima; é um
quinto controlo, mas configurado fora do YAML.

---

## 2. Tabela de decisão (Fase 1) — candidatos do `personal-site`

Ordenada por valor decrescente.

| # | Controlo | Superfície aqui? | Ameaça que fecha | Custo | Veredicto |
|---|---|---|---|---|---|
| 2 | Actions pinadas por SHA | Sim — 7 `uses:` sem pin (6 em `update-profile-widgets.yml`, 1 em `lint-actions.yml`) + 1 `ref:` de tag mutável | Fecha a cadeia inteira da Fase 0: tag/registo comprometido deixa de correr código diferente sem aviso | Zero em CI; manutenção passa para o Renovate (já adotado, item #10) | **ADOTAR** |
| 1 | `permissions: {}` no topo + mínimo por job | Sim — workflow inteiro herdava `contents: write` | Reduz o raio de explosão: o passo que corre código de terceiros (troféus) deixa de ter `write` nenhum, mesmo comprometido | Uma corrida extra de runner por execução semanal (~1 min/semana) | **ADAPTAR** — dividido em dois jobs (`generate`: `contents: read`; `commit`: `contents: write`, via artefacto) |
| 4 | Segredos por `env:`, nunca interpolados em `run:` | Sim — `curl -H "Authorization: bearer ${{ secrets.GITHUB_TOKEN }}"` ainda interpolado no `run:` da contagem de estrelas | Fecha injeção de template nesse passo especificamente | Zero | **ADOTAR** |
| 5 | zizmor `--min-severity medium`, versão cravada | Sim — é o próprio `lint-actions.yml` | Sem versão, corre uma versão diferente a cada execução (o `personal-site` já viu uma versão retirada do PyPI por advisory); sem `--min-severity`, o gate é "o que o zizmor decidir mostrar por omissão" | Zero | **ADOTAR** |
| 6 | gitleaks no CI (`fetch-depth: 0`) | Marginal — não há segredos de aplicação, mas o `GITHUB_TOKEN` passa por vários passos e alguém editando o README/workflow à mão pode colar um valor sem querer | Fecha a única classe de erro humano que resta neste repo: um segredo colado por engano num commit | ~15-20s por push/PR — repo tem pouquíssimo volume de commits | **ADOTAR** (só o job de CI; o hook `pre-commit` local fica de fora — não há fluxo de contribuição de terceiros a proteger, só o dono edita, e o CI já é a rede de segurança) |
| 10 | Renovate (`pinGitHubActionDigests`, `minimumReleaseAge`) em vez de Dependabot para actions | Sim — este repo só tem GitHub Actions como "dependência" | Mantém os SHAs pinados no #2 atualizados sem depender de disciplina manual; um único mecanismo de manutenção para as duas contas em vez de dois | Zero em CI; precisa da app Renovate instalada neste repo (Fase 6) | **ADOTAR** — substitui o `dependabot.yml` (que só cobria `github-actions`, sem pin por digest) |
| 3 | `persist-credentials: false` no checkout | Sim | Evita o token ficar em `.git/config` mais tempo do que o necessário nos passos que não fazem push | Zero | **ADOTAR/confirmar** — já correto nos checkouts que não fazem push (`f369858` + o checkout do gerador de troféus); o checkout do job `commit` fica com o valor por omissão (`true`) porque é o único que faz `git push` — justificado, ver zizmor abaixo |
| 13 | `SECURITY.md` com caminho de reporte privado | Sim | Barato e coerente com o `.well-known/security.txt` do site — este repo tem workflow privilegiado, é razoável ter um caminho de reporte | ~5 min, zero manutenção | **ADOTAR** |
| 14 | OpenSSF Scorecard + badge | Sim — repo público, os controlos que o Scorecard mede (pins, permissões) acabaram de ser implementados aqui | Sinal contínuo e verificável de que os controlos acima não regridem silenciosamente | ~2-3 min/semana, grátis em repo público | **ADOTAR** — `schedule` semanal + `workflow_dispatch`, nunca em `push` (o commit semanal do bot não precisa de disparar isto outra vez) |
| 15 | Definições do repo (allowlist de Actions, pin-SHA obrigatório, secret scanning, branch protection) | Sim, mas fora do YAML | Fecha o resto da cadeia da Fase 0 (revisão humana no `git push` final) | Cliques, não código | **INAPLICÁVEL aqui → Fase 6** |
| 7 | Semgrep (regras públicas + próprias) | **Não** — não há ficheiros `.js`/`.ts` de aplicação; o único "código" é YAML (coberto pelo zizmor) e um heredoc Python inline dentro do workflow | — | — | **INAPLICÁVEL** |
| 8 | OSV-Scanner sobre lockfiles | **Não** — sem `package-lock.json`, sem `requirements.txt` | — | — | **INAPLICÁVEL** |
| 9 | `npm ci --ignore-scripts`, SBOM CycloneDX, `npm audit signatures` | **Não** — sem `package.json` | — | — | **INAPLICÁVEL** |
| 11 | Verificação do artefacto publicado depois do deploy (`headers.yml`) | **Não** — não há deploy de site nem headers HTTP a verificar; o "artefacto" é uma página README renderizada pelo GitHub | — | — | **INAPLICÁVEL** |
| 12 | Invariantes em cron a abrir/fechar Issue | Fraca — o único sinal a monitorizar é o próprio `update-profile-widgets.yml` falhar, e isso **já** notifica o dono nativamente (GitHub avisa por email quando um `schedule` falha) | Nenhuma ameaça nova fechada: a "falha silenciosa" que o `invariants.yml` do `personal-site` resolve (dashboards só-PULL que nunca avisam) não existe aqui — este workflow falha alto por natureza (curl/deno/git push que não correm) | Complexidade extra (label, Issue, lógica de fecho automático) para replicar um sinal que já existe | **REJEITAR** — "boas práticas em geral" sem cadeia concreta nova |

### Nota de leitura

Dois avisos do prompt original, respeitados nos dois sentidos: não copiei
os seis scanners do `personal-site` de código de aplicação (Semgrep, OSV,
`npm audit`/SBOM) porque não há superfície nenhuma para eles lerem aqui —
seria teatro. Mas também não tratei "é só o repo do perfil" como desculpa:
é público, corre um workflow com escrita no repo e código de terceiros, e
é a montra do dono — por isso ADOTEI pins por SHA, permissões mínimas,
`env:` para segredos, zizmor calibrado, gitleaks, `SECURITY.md`, Renovate
e Scorecard. O critério em cada linha foi sempre a cadeia da Fase 0, nunca
o tamanho do repositório.

---

## 3. Achados confirmados e corrigidos (Fase 2)

Todos os pontos abaixo foram confirmados no ficheiro atual antes de
qualquer alteração (regra 2 do prompt).

### `update-profile-widgets.yml`

| # | Achado | Confirmado? | Correção aplicada |
|---|---|---|---|
| 1 | `permissions: contents: write` ao nível do workflow, um único job | **Confirmado** (linha 20-21 do ficheiro antigo) | Dividido em dois jobs: `generate` (`permissions: contents: read`, corre todo o código de terceiros) → `commit` (`permissions: contents: write`, só faz checkout+download do artefacto+push). O artefacto (`actions/upload-artifact`/`download-artifact`, pinados por SHA) é a única coisa que atravessa a fronteira. |
| 2 | Seis `uses:` sem pin por SHA | **Confirmado** — `actions/checkout@v4` ×2, `stats-organization/github-readme-stats-action@v2` ×2, `denoland/setup-deno@v2` | Todas pinadas por SHA com a versão em comentário (`@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0`, `@e856fc8de9d7729b463c468911e232cfbdc3d55e # v2.0.2`, `@22d081ff2d3a40755e97629de92e3bcbfa7cf2ed # v2.0.5`), resolvidas via `git ls-remote --tags` contra os repositórios públicos (regra 2 do prompt: os SHAs são públicos). Adicionadas também `actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2` (mesmo SHA já usado no `personal-site`) e `actions/download-artifact@018cc2cf5baa6db3ef3c5f8a56943fffe632ef53 # v6.0.0`. |
| 3 | `${{ secrets.GITHUB_TOKEN }}` interpolado num `run:` (contagem de repos com estrela) | **Confirmado** | Movido para `env: GH_TOKEN`, `run:` passa a usar `${GH_TOKEN}` (mesmo padrão do `headers.yml`). |
| 4 | Código de terceiros a correr com o token (`ryo-ma/github-profile-trophy@v1.0`, tag mutável, `deno run --allow-net --allow-env --allow-read --allow-write` sem âmbito) | **Confirmado** | Três correções: (a) `ref:` passa de `v1.0` para o SHA dereferenciado da tag (`2ba2fe648c4e9b17d66e01bec285e083ca1824d3`); (b) o `deno run` passa a `--allow-net=api.github.com --allow-env=GITHUB_TOKEN1,GITHUB_TOKEN2 --allow-read=. --allow-write=../assets` — lido o código-fonte de `render_svg.ts`/`GithubApiService.ts` na v1.0 para confirmar que é exatamente isto que o script usa (só chama `api.github.com/graphql`, só lê essas duas variáveis, só escreve dentro de `../assets`); (c) o job que corre este código (`generate`) só tem `contents: read` — mesmo que o token seja exfiltrado, não sabe escrever no repo. |
| 5 | `persist-credentials` depois de dividir em dois jobs | **Confirmado, resolvido pela divisão** | Checkout do `generate`: `persist-credentials: false` (nunca faz push). Checkout do `commit`: valor por omissão (`true`), com comentário a justificar — é o único job que faz `git push`. Zizmor local confirma que é o único achado que sobra, com confiança **baixa**. |
| 6 | Conteúdo externo (`img.shields.io`) escrito direto para SVG commitado, sem verificação | **Confirmado** | Adicionada validação antes de comitar: rejeita o ficheiro (falha o job) se não começar por `<svg` ou se contiver `<script`, um atributo `on*=`, `<foreignObject` ou `javascript:`. Não é sanitização completa — é um filtro proporcional a uma fonte conhecida (shields.io) que nunca deveria conter nada disto, documentado como tal no comentário. |
| 7 | `git push` direto para `main`, sem revisão, semanalmente | **Confirmado** | Não corrigido em código — é uma decisão de branch protection (Fase 6). Ver opções na secção 6. |

### `lint-actions.yml`

| # | Achado | Confirmado? | Correção aplicada |
|---|---|---|---|
| 8 | `pip install zizmor` sem versão | **Confirmado** | `pip install zizmor==1.28.0` — mesma versão cravada do `personal-site` (`security.yml`), mesmo motivo (1.27.0 retirada do PyPI por `GHSA-f42p-wjw5-97qh`). |
| 9 | Sem `--min-severity` | **Confirmado** | `zizmor --min-severity medium .github/workflows/` — mesmo gate do `personal-site`. |
| 10 | Gatilho só por `paths: .github/workflows/**` | **Confirmado** | Adicionado `schedule: "30 6 * * 1"` (semanal, a seguir aos outros workflows) — já tinha `workflow_dispatch`. |
| 11 | `permissions`/`persist-credentials` no job | **Já estava correto** — `permissions: contents: read` ao nível do workflow (não tinha o mínimo *por job*, adicionado agora) e `persist-credentials: false` no checkout já vinham do commit `f369858` | Adicionado `permissions: contents: read` explícito também ao nível do job `zizmor` (antes só existia ao nível do workflow). |

### Ausências avaliadas

| # | Item | Decisão | Justificação |
|---|---|---|---|
| 12 | `SECURITY.md` | **Adotado** | Ver tabela da Fase 1, #13. |
| 13 | `dependabot.yml` sem pin por digest | **Substituído por Renovate** | Ver tabela da Fase 1, #10. `dependabot.yml` removido (só cobria `github-actions`, sem digest pinning); `renovate.json5` novo cobre o mesmo com `pinGitHubActionDigests`. |
| 14 | CODEOWNERS, PR template, allowlist de Actions | **Fora deste PR** | CODEOWNERS/PR template não têm sinal aqui (repo de um só contribuidor, sem fluxo de PR externo real); allowlist de Actions é definição de repo → Fase 6. |

---

## 4. README e assets como superfície própria (Fase 3)

Todas as afirmações verificáveis do README sobre o `personal-site` foram
confirmadas contra o código atual (não corrigidas — porque estavam
corretas):

| Afirmação no README do `blindtk/blindtk` | Verificação | Resultado |
|---|---|---|
| "CSP com zero `unsafe-inline`" | `docs/security-review-2026-07-29.md` §6 + `astro.config.mjs` | **Confirmado** |
| "no IP is ever stored — only country, ASN, path, timestamped to nearest 5 minutes" | `dynamic/worker/src/index.js:47` — `ANON_WINDOW_MS = 5 * 60_000` | **Confirmado**, valor exato |
| "rate-limit key is a salted, rotating, truncated SHA-256" | `dynamic/worker/src/lib/ratelimit.js:33` (`clientHash`, SHA-256 truncado a 8 bytes) + `dailySalt` (rotação diária) | **Confirmado** |
| "a test enforces that the IP never reaches KV or the logs" | `dynamic/worker/test/logic.test.mjs` | **Confirmado**, teste existe |
| "Each decoy is tagged with its MITRE ATT&CK technique and cross-referenced against the CISA KEV catalog" | `dynamic/worker/src/lib/attack-map.js` (`techniqueForPath`, `techniquesForText`/`KEV_KEYWORDS`) | **Confirmado** |
| 5 decoys listados (`/wp-login.php`, `/.env`, `/.git/config`, `/admin`, `/phpmyadmin/`) | `dynamic/worker/src/lib/decoys.js:18` — `DECOYS` tem exatamente estes 5 | **Confirmado**, contagem exata |

**Nenhuma correção necessária** — as afirmações eram exatas antes mesmo de
o `personal-site` ficar público, o que só reforça o ponto: são verificáveis
por qualquer estranho a partir de agora.

### A contradição do `visitorbadge.io` (não decidida — apresentada)

O README tem, no fundo da página,
`https://api.visitorbadge.io/api/visitors?path=...` — um badge de
contagem de visitas de terceiro. É telemetria de visitantes deste perfil
enviada para um serviço externo, sem opt-out possível para quem visita.

A tensão: o `personal-site` associado (linkado no mesmo README) faz do
"zero trackers, zero PII" a sua tese central — CSP sem terceiros,
honeypot que nunca guarda IP, um site inteiro desenhado à volta dessa
promessa. Um badge de visitas de terceiro no README que aponta para esse
site é uma inconsistência visível para qualquer leitor técnico que preste
atenção aos dois ao mesmo tempo.

O precedente já existe: o banner (`assets/banner.svg`) foi self-hosted
precisamente para deixar de depender de um serviço externo
(`capsule-render.vercel.app`) que tinha um bug de renderização — mesma
categoria de decisão, motivo diferente (aqui é coerência de mensagem, não
um bug).

**Recomendação:** remover o badge do `visitorbadge.io`, ou substituí-lo
por uma contagem gerada pelo próprio `update-profile-widgets.yml` (ex.:
`traffic/views` da API do GitHub para o repo, que já está disponível ao
`GITHUB_TOKEN` do job `generate` com `contents: read`, sem chamar
nenhum terceiro). **Não implementado nesta PR** — é uma decisão de
posicionamento do dono, não uma correção de segurança, e o prompt pede
explicitamente para não a tomar sozinho.

O `streak-stats.demolab.com` (mencionado no README como "fica como
estava") não tem o mesmo problema: não é telemetria sobre o visitante, é
uma imagem gerada a partir de dados públicos do GitHub sobre o dono do
perfil — mais parecido com os `img.shields.io` (também dados públicos,
sem tracking do visitante).

---

## 5. O que já estava correto (não mexido)

- `persist-credentials: false` nos checkouts que não fazem push
  (corrigido no commit `f369858`, antes desta revisão).
- Template injection do contador de estrelas via `env:`
  (idem, `f369858`).
- `permissions: contents: read` ao nível do workflow em
  `lint-actions.yml`.
- `workflow_dispatch` já presente nos dois workflows.
- A separação em si entre "gerar widgets" (`update-profile-widgets.yml`) e
  "auditar workflows" (`lint-actions.yml`) — dois workflows de
  responsabilidade única, mesmo princípio do `ci.yml`/`security.yml` do
  `personal-site`.

---

## 6. `git push` direto para `main` — opções, não decisão

Fase 2, achado #7. Sem correção de código possível — é uma decisão de
branch protection (Fase 6). Três caminhos, cada um com um trade-off
diferente para o bot semanal:

1. **Ruleset "bypass list" para `github-actions[bot]`.** Branch protection
   liga-se para humanos, o bot continua a fazer push direto. Mais simples;
   mantém o risco de um `main` protegido na prática só para PRs humanos.
2. **O bot abre PR em vez de push direto**, com auto-merge se
   `lint-actions.yml`/`scorecard.yml` passarem. Fecha a lacuna de "zero
   revisão", mas o "revisor" é outro workflow automático, não uma pessoa —
   valor real depende de o CI conseguir mesmo detetar o que interessa (só
   deteta os SVGs mudarem, não se são os SVGs *certos*).
3. **Manter push direto, aceitar o risco.** Defensável dado o raio de
   explosão reduzido nesta revisão (job sem `contents: write` a correr
   código de terceiros) — mas é uma aceitação explícita, não silenciosa.

---

## 7. Custo total estimado (Actions, conta partilhada)

| Workflow | Gatilho | Estimativa |
|---|---|---|
| `update-profile-widgets.yml` | semanal | ~3-4 min/semana (2 jobs agora, era ~2-3 min num só) |
| `lint-actions.yml` | push/PR a `.github/workflows/**` + semanal | ~15-20s por evento + ~15-20s/semana |
| `gitleaks.yml` (novo) | push/PR a `main` | ~15-20s por evento — baixíssimo volume neste repo |
| `scorecard.yml` (novo) | semanal | ~2-3 min/semana |

Total adicional: **~2-3 min/semana**, nada em `push`/`pull_request` de alto
volume — a conta partilhada com o `personal-site` (que está perto da quota
por causa do seu próprio volume de PRs, não deste repo) não é afetada de
forma mensurável.

---

## 8. Veredito

**A via mais curta entre um atacante externo e um commit no
`blindtk/blindtk` era: comprometer/mover a tag `ryo-ma/github-profile-trophy@v1.0`
→ correr código com `--allow-net`/`--allow-env` sem âmbito → ler o
`GITHUB_TOKEN` com `contents: write` que o workflow inteiro herdava → push
direto para `main`.**

**Ficou fechada, e já está em `main`** (commit `59dc1d9`, ver Addendum 2).
Essa dependência está pinada por SHA (não por tag), o código dela corre
num job com `contents: read` (não `write`), e mesmo que o token dele seja
lido, as permissões do Deno estão reduzidas ao que o script realmente usa.
A escrita no repo (`contents: write`) está isolada num segundo job que não
corre nenhum código de terceiros, só faz checkout + download de
artefacto + commit + push.

**O que fica aberto, por decisão, não por descuido:** o `git push` final
continua sem revisão humana — o ruleset do `main` já existe mas ainda não
tem a regra de PR obrigatório (secção 6 e Addendum 2 — decisão do dono); o
badge do `visitorbadge.io` continua no README (secção 4 — decisão do
dono); e secret scanning/push protection/allowlist de Actions (Fase 6,
itens 2 e 3) continuam por confirmar/ligar fora deste PR.

---

## 9. Validação

`zizmor --min-severity medium --offline .github/workflows/` (versão
1.28.0, mesma cravada no `security.yml` do `personal-site`), corrido
localmente contra os quatro workflows do `blindtk/blindtk` depois das
alterações:

```
13 findings (12 suppressed, 1 unsafe fixes): 0 informational, 0 low, 1 medium, 0 high
```

O único achado que sobra é `artipacked` (confiança **baixa**) no checkout
do job `commit` de `update-profile-widgets.yml` — não tem
`persist-credentials: false` porque é o único checkout de todo o repo que
precisa das credenciais persistidas para fazer `git push`. Confirmado
intencional, não uma omissão.

Corrido com `--offline` porque este ambiente não tem um `GH_TOKEN` válido
para as auditorias online (ex.: deteção de commits impostores via API);
os workflows já passam `GH_TOKEN: ${{ github.token }}` para o zizmor em
CI, onde essas auditorias vão correr normalmente.

**Não corrido end-to-end:** este ambiente não tem `deno` instalado, por
isso a alteração ao `deno run --allow-net=... --allow-env=... ...` (achado
#4) foi validada por leitura do código-fonte de
`ryo-ma/github-profile-trophy@v1.0` (`render_svg.ts`,
`GithubApiService.ts`, `utils.ts` — confirma que só chama
`api.github.com/graphql`, só lê `GITHUB_TOKEN1`/`GITHUB_TOKEN2`, só
escreve dentro de `../assets`), não por execução real. **Recomenda-se
correr `workflow_dispatch` manualmente depois do merge** para confirmar
que os cinco SVGs continuam a ser gerados antes de confiar no cron
semanal — é exatamente o aviso do prompt: "um workflow endurecido que
deixou de funcionar é uma regressão, não um controlo."

### Addendum: dois problemas reais só apanhados pelo CI real

A validação local (`--offline`, sem `GH_TOKEN`) não é o CI real, e o CI do
PR apanhou dois problemas que a validação local não conseguia ver:

1. **Pin errado por confundir tag anotada com commit.** O SHA usado para
   `github/codeql-action/upload-sarif@…` em `scorecard.yml` era o *objeto*
   da tag anotada `v3.37.4` (`dfbc6164…`), não o commit para onde ela
   aponta (`a2983b8b…`) — só a auditoria `ref-version-mismatch`, que
   precisa de rede/`GH_TOKEN` para consultar a API, apanhou isto. `uses:`
   tem de apontar para o commit, não para o objeto da tag; confirmado com
   `git ls-remote --tags` a olhar para a linha `^{}` de deref (que a
   verificação inicial, com um `grep` demasiado apertado, tinha ignorado
   para este caso específico). Corrigido no commit `e5c7952`.
2. **O achado `artipacked` aceite conscientemente (checkout do job
   `commit`, credenciais persistidas de propósito) fazia o zizmor sair
   sempre com erro** — o `--min-severity medium` não distingue "achado por
   rever" de "achado revisto e aceite". Sem uma exceção documentada, o
   check `zizmor` ficaria vermelho para sempre por um risco já entendido,
   o que ensina a ignorar o check em vez de o ler — exatamente o
   contrário do que uma revisão de segurança deve produzir. Corrigido com
   um `.github/zizmor.yml` novo (mesmo padrão do `osv-scanner.toml`/
   `.semgrep/` deste repo: exceção datada e justificada, não silenciosa),
   commit `cea5eec`. Confirmado localmente: `zizmor` passa a sair com
   código 0 ("1 ignored, 12 suppressed").

Depois destas duas correções, os quatro checks do PR do `blindtk/blindtk`
(`zizmor`, `gitleaks`, `CodeQL`, `Analyze (actions)` — os dois últimos já
existiam antes desta revisão, código scanning nativo do GitHub) estão
verdes.

### Addendum 2: merge, PRs automáticas reconciliadas, e o ruleset já em vigor

**Merge:** `blindtk/blindtk#2` foi integrado em `main` (squash, commit
`59dc1d9`). Todas as alterações desta secção estão em produção.

**PRs automáticas pendentes, verificadas e resolvidas** (o dono pediu para
confirmar isto antes do merge — não estava coberto pelo âmbito original da
Fase 1/2, mas é consequência direta da decisão #10 da tabela):

- **Dependabot #1 — "Bump actions/checkout from 4 to 7".** Fechada sem
  merge. Duas razões: (a) fica superseded pela remoção do
  `dependabot.yml` nesta PR (a ecossistema `github-actions` passa a ser
  gerido só pelo Renovate); (b) mesmo que não fosse, um salto de major
  (`v4` → `v7`, com mudanças de comportamento documentadas — defaults
  novos de `pull_request_target`, `allow-unsafe-pr-checkout`) não é uma
  decisão para tomar na mesma PR que está a reduzir superfície de ataque —
  fica para uma PR do Renovate à parte, quando o dono quiser avaliar.
- **Renovate #3 — "Configure Renovate" (onboarding).** Isto revelou um
  facto que corrige o item #4 da checklist original da Fase 6: **a app
  Renovate já estava instalada neste repositório antes desta revisão** —
  não precisava de ser instalada, só não tinha nenhum `renovate.json`/
  `renovate.json5` para trabalhar a partir de, por isso o Renovate abriu a
  PR de onboarding com a sua config genérica por omissão. Fechada sem
  merge (mergear criaria um segundo ficheiro de config, `renovate.json`, a
  conflituar com o `renovate.json5` desta PR, já em `main`). O Renovate
  deve reconhecer o config existente na próxima execução agendada.

**Ruleset do `main` — confirmado pelo dono, avaliado:**

```json
{
  "name": "Main",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "rules": [{ "type": "deletion" }, { "type": "non_fast_forward" }],
  "bypass_actors": []
}
```

Só tem `deletion` (impede apagar o `main`) e `non_fast_forward` (impede
force-push/reescrever história). **Isto não fecha o achado #7 da Fase
2/secção 6** — não há regra "Require a pull request before merging", por
isso um push direto e fast-forward (exatamente o que o job `commit` de
`update-profile-widgets.yml` faz todas as semanas) continua a passar sem
qualquer revisão. É proteção real contra dois cenários (apagar o branch,
reescrever história), mas não contra o cenário que a Fase 0 desenhou
(escrita não revista). Para fechar isso falta acrescentar a regra de PR
obrigatório — o que, por sua vez, obriga a escolher uma das três opções da
secção 6 para o push semanal do bot (hoje `bypass_actors` está vazio; sem
um bypass para `github-actions[bot]`, ativar essa regra parte o workflow).
Decisão do dono, não tomada aqui.

**Configurações de segurança do repositório (secret scanning, push
protection, Dependabot alerts):** não verificadas nesta revisão — as
ferramentas disponíveis nesta sessão não expõem `Settings → Code security`
por API. Ficam por confirmar pelo dono (item 2 da checklist abaixo).

**Sobre a lista de workflows de "Code scanning" do GitHub (perguntada
antes do merge):** nenhum se aplica além do que já foi decidido nesta
revisão. `CodeQL Analysis` já está ativo (default setup nativo, ver nota
na Fase 0). `OSSF Scorecard` está coberto pelo `scorecard.yml` desta PR —
**não ativar também o template do GitHub para o mesmo**, duplicaria o
SARIF publicado, um dos dois sem pin. Todo o resto da lista (Snyk,
SonarQube, Checkmarx, Trivy, Bandit, RuboCop, ESLint, tfsec, Fortify,
Veracode, …) é scanner de linguagem/IaC sem superfície neste repositório —
mesma lógica de INAPLICÁVEL da tabela da Fase 1.

---

## 10. Fase 6 — só o dono pode fazer

Checklist, por ordem de valor. Estado atualizado depois do merge.

1. **Branch protection / ruleset no `main`** — **parcialmente feito**. O
   ruleset "Main" já existe (`deletion` + `non_fast_forward`), mas falta a
   regra de PR obrigatório para fechar o achado #7; e falta decidir uma
   das três opções da secção 6 para o push do bot semanal antes de a
   ativar (ver Addendum 2).
2. **Secret scanning + push protection** — grátis em repositório público;
   compensa o gitleaks local com deteção nativa do GitHub. **Não
   verificado** nesta revisão (sem acesso de API a `Settings → Code
   security` nesta sessão) — confirmar manualmente.
3. **Allowlist de Actions + "pin por SHA obrigatório"** nas definições do
   repositório — sem isto, nada impede que uma alteração futura reintroduza
   uma action sem pin. O `personal-site` já tem os dois ligados; ver o
   comentário do job `osv-scanner` em `security.yml` para o efeito prático
   (obrigou a chamar a action do OSV diretamente em vez do workflow
   reutilizável oficial, que traz dependências transitivas sem pin).
4. ~~Confirmar/instalar a app Renovate neste repositório~~ — **já estava
   instalada** (confirmado pela PR de onboarding #3, ver Addendum 2); só
   faltava o ficheiro de configuração, que esta PR já adiciona. Sem ação
   pendente aqui.
5. **Rever o âmbito por omissão do `GITHUB_TOKEN`** nas definições da conta
   (read-only por omissão, subindo só onde declarado — já é o que os
   workflows fazem explicitamente, isto é a rede de segurança se algum dia
   um workflow novo esquecer o `permissions:`).
6. **Confirmar se a mesma conta tem outros repositórios públicos com
   workflows privilegiados** — as conclusões desta revisão (pins por SHA,
   permissões mínimas por job, segredos por `env:`) aplicam-se a qualquer
   um deles.
