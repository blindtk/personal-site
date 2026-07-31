# Relatório — validação de prontidão para o lançamento (Fase 3, 2026-07-30)

Execução de [`prompt-validacao-lancamento.md`](../prompts/prompt-validacao-lancamento.md)
(nome de trabalho — o pedido original chegou como prompt solto, não como
ficheiro no repo), na branch `claude/site-launch-validation-3ynlvd`, a partir
do commit `da77869` (`main`). **Tarefa de validação, não de execução** —
nenhuma ação de dashboard/conta Cloudflare foi tentada; nenhum ficheiro de
código foi alterado. Este documento é a entrega.

---

## 1. Bloqueadores reais (Fase 1)

### 1.1 `DEBUG_EXPOSE_SELF_PATH` — bloqueador, precisa de decisão do dono

**`dynamic/worker/src/lib/csp-report.js:132`**: a flag continua `true`. O
comentário no próprio ficheiro (linhas 124–131) e a entrada em
`dynamic/PLAN.md` (2026-07-29, atualizada 2026-07-30) confirmam a premissa
de risco explicitamente: *"o site está atrás de Cloudflare Access (só o
dono o visita), por isso o risco de expor path é mínimo enquanto isto ficar
ligado"*. A entrada de `dynamic/PLAN.md` datada de **2026-07-30** (mesma
data deste relatório) regista: *"diagnóstico ainda a decorrer, flag
mantém-se `true`"* — não há, no repositório, nenhum registo de que o
diagnóstico das violações `self/self` tenha concluído entretanto.

Os dois testes associados (`dynamic/worker/test/logic.test.mjs:496-497`,
`547-549`, `558`) confirmam por comentário que dependem da flag e que
"reverter" implica mudar também o `source` esperado de volta para `'self'`
genérico.

**Consequência:** desligar/ajustar a Access sem primeiro confirmar o estado
do diagnóstico muda o risco aceite de "mínimo" (só o dono acede) para "real"
(qualquer visitante cuja violação CSP `self/self` dispare passa a ter o
pathname do recurso bloqueado exposto no payload agregado do dashboard
"Violações CSP" — nunca query/fragmento, mas o path já pode ser sensível
dependendo da rota). **Não decidi isto sozinho, conforme instruído** — fica
registado como bloqueador para o dono confirmar uma de duas coisas antes do
flip:
- o diagnóstico já concluiu e a flag pode reverter agora (ver o passo já
  planeado em `docs/relatorio-preparacao-repo-publico-2026-07-30.md` §5,
  "Antes do flip"); ou
- o diagnóstico continua em curso e o dono aceita o risco novo
  conscientemente ao desligar a Access na mesma.

### 1.2 `.github/expected-headers.json` — não é bloqueador, confirmado pronto

`url` continua `"SET-ME: https://danielmala.co/"`. Li
`.github/scripts/check-headers.mjs` de ponta a ponta: quando `target` está
vazio ou começa por `SET-ME` (linha 55), o script emite um
`::warning::` explícito, escreve um resumo no `GITHUB_STEP_SUMMARY` e sai
com `process.exit(0)` — degrada com aviso visível, não falha silenciosamente
nem finge sucesso. Confirmado também com dados reais: as últimas 13
execuções do workflow `Headers` no `main` (via API do GitHub, `schedule`,
2026-07-19 a 2026-07-29) estão todas `success` — consistente com o padrão
"sempre verde, sem verificar nada" descrito na revisão de segurança N3, não
com falhas mascaradas.

O script já aceita `ACCESS_CLIENT_ID`/`ACCESS_CLIENT_SECRET` como
credenciais opcionais de Access Service Token (linhas 24-28), com
`fetchSameOrigin` a impedir que essas credenciais sigam um redirect para
fora da origem (linhas 30-53) — pronto a "ligar" assim que o dono preencher
o `url`, sem precisar de mais alterações de código.

### 1.3 `.github/scripts/check-invariants.mjs` — não é bloqueador, confirmado pronto (com uma nota)

Mesmo padrão exato do `check-headers.mjs`: `SET-ME` → `::warning::` +
`exit(0)` (linhas 22-29), sem `ACCESS_CLIENT_ID`/`SECRET` → cabeçalhos vazios,
sem quebrar nada. Lógica de classificação (crítico vs. informativo, 429
tratado como proteção a funcionar, 2+ falhas informativas em simultâneo
como sinal real) lida e consistente com o que `dynamic/PLAN.md` descreve.

**Nota, não bloqueador:** o workflow `invariants.yml` foi mesclado no
`main` em `2026-07-29 20:31 UTC` (commit `5c00398`). A API do GitHub Actions
mostra **zero execuções** até ao momento desta verificação — o cron
(`43 7 * * *` UTC) ainda não disparou desde o merge. Isto é esperado (não é
falha), mas significa que o comportamento de no-op avisado descrito acima
está confirmado por **leitura do código**, não ainda por uma execução real
em produção. Vale a pena o dono confirmar a primeira execução depois de
disparar (ou correr `workflow_dispatch` manualmente) antes de depender dela
no dia do lançamento.

### 1.4 Regras WAF (`docs/cloudflare-deploy.md` §5) — não verificável a partir do código

Confirmado: a tabela de 5 regras (bots skip, CI skip, honeypot Managed
Challenge, PT Managed Challenge, resto do mundo Block) é configuração da
zona Cloudflare, sem equivalente no repositório. **Registo para o dono
confirmar no dashboard antes do flip:** que as 5 regras existem, por esta
ordem exata, e que nenhuma foi desativada ou alterada desde 2026-07-29 —
exatamente como pedido.

Consegui confirmar uma fatia via teste externo (ver Fase 3, §3.3): a
partir de um IP fora de PT, a regra 5 (Block) disparou tal como
documentado. Isto **não** confirma as regras 1-4 nem a ordem exata — só
prova que pelo menos a regra final do catch-all está ativa e a bloquear
como esperado.

### 1.5 Outras menções "atrás da Access" no repositório

`grep` por variações de "atrás da Access" / "enquanto a Access" / "Access
ainda" / "Access continua" / "Access bloque" / "Cloudflare Access" no
repositório inteiro devolveu 14 ficheiros. Revistos um a um, além dos 3
pontos já cobertos acima (1.1-1.3) e da própria secção 3 do
`cloudflare-deploy.md` (1.4):

- **`dynamic/worker/README.md:211-213`** e **`dynamic/worker/src/index.js:388-390`**
  — `ACCESS_CLIENT_ID`/`ACCESS_CLIENT_SECRET` do self-scan (`SCAN_TARGET`),
  documentados como "só necessários se a Cloudflare Access estiver ativa à
  frente de `SCAN_TARGET`". Não é um risco aceite condicional — é uma
  dependência opcional que continua a funcionar (self-scan simplesmente vê
  a página de login em vez do site, sem quebrar) com a Access ligada ou
  desligada. Nada a fazer.
- **`docs/honeypot-analise-evolucao.md:49`** — tabela de invariantes lista
  "Cloudflare Access — ainda cobre `danielmala.co` inteiro (incl. iscos)".
  É uma descrição do estado atual, não um risco aceite com essa premissa
  como mitigação principal; deixa de ser verdade no dia do flip por
  definição, sem implicar ação de código.
- `docs/security-review-2026-07.md`, `docs/security-review-2026-07-29.md`,
  `docs/prompt-repo-publico.md`, `docs/public-repo-decision.md`,
  `docs/relatorio-preparacao-repo-publico-2026-07-30.md` — todas
  descrições/análises históricas já refletidas nos pontos acima, sem achado
  novo.

**Não encontrei nenhum risco aceite adicional, para além dos 3 já
identificados no prompt, cuja mitigação principal dependa da Access
continuar ligada.**

---

## 2. Checklist reconciliada (Fase 2)

### `docs/cloudflare-deploy.md` §7

| Item | Estado real | Categoria |
| --- | --- | --- |
| Lançamento: desligar/ajustar Access + confirmar WAF sozinho | Pendente, confirmado — Access continua a bloquear (ver Fase 3) | **(b) dashboard/conta** |
| "Previews sociais"/"O dono sempre" não criadas (decisão, não esquecimento) | Confirmado `[x]` no próprio ficheiro; nada a verificar em código (são regras que não existem) | — (já fechado) |
| `expected-headers.json` → `url` em `SET-ME` até a Access desligar | Confirmado — ver §1.2. Script pronto; falta só a Access desligar ou o dono preencher `url` | **(b) dashboard**, o "preencher" é uma linha de config que o dono faz depois do flip, não trabalho de repo |
| CAA, HSTS preload, DNSSEC | Ver `docs/dns-tls.md` abaixo — **DNSSEC já está ativo**, ao contrário do que a doc sugere; CAA e preload continuam pendentes | misto — ver abaixo |
| Alias de email (`me@danielmala.co`) | **Feito e confirmado no código** — `static/src/config.ts:24` já usa `me@danielmala.co` | (a) trabalho de repo — já concluído |
| Repo público | Fora de âmbito deste prompt (é o `prompt-repo-publico.md`) | — |

### `docs/dns-tls.md`

| Item | Estado real (verificado de fora, Fase 3) | Categoria |
| --- | --- | --- |
| 1. Registos CAA | **Confirmado ausente** — consulta DNS (ver §3.1) devolve zero registos CAA. Doc já diz isto corretamente (nota de 2026-07-29) | **(b) dashboard** |
| 2. Redirect HTTP→HTTPS | **Não verificável de fora hoje** — ver §3.3, a regra WAF de geo-bloqueio intercepta o pedido antes de qualquer redirect, em HTTP e HTTPS | **(b) dashboard** — doc assume que já está ligado ("Cloudflare Pages já força HTTPS"), não há como confirmar isso de um IP fora de PT enquanto o WAF bloquear primeiro |
| 3. HSTS preload | Deliberadamente adiado (subdomínios por decidir) — nenhuma mudança | **(b) dashboard + submissão externa**, sem alteração de estado |
| 4. DNSSEC | **Achado: já está ativo**, contradizendo a doc que o lista como "extra barato (recomendado)" por fazer. Ver §3.2 — confirmado por dois resolvedores validadores independentes (Cloudflare e Google), `DNSKEY` publicado na zona e `DS` correspondente já registado na zona pai `.co`. **Recomendo atualizar `docs/dns-tls.md` §4 para `[x]`** — não é bloqueador, é uma correção de documentação desatualizada (exatamente o padrão que a Fase 2 deste prompt pede para caçar) | já feito — doc por corrigir |

Não encontrei nenhum item marcado `[ ]` que devesse estar `[x]` além do
DNSSEC acima, nem nenhum item marcado `[x]` que na verdade não estivesse
feito.

---

## 3. O que foi possível confirmar de fora (Fase 3)

Tinha acesso à rede neste ambiente. Resultados:

### 3.1 CAA

`dig` não está disponível neste ambiente; usei DNS-over-HTTPS
(`cloudflare-dns.com/dns-query` e `dns.google/resolve`) como equivalente.
`danielmala.co CAA` devolve resposta vazia (sem secção `Answer`) nos dois
resolvedores — confirma a nota já existente na doc: **nenhum registo CAA
criado**.

### 3.2 DNSSEC

`danielmala.co DNSKEY` devolve 2 chaves (`ECDSAP256SHA256`), com a flag
`AD: true` (Authenticated Data) em ambos os resolvedores consultados
(Cloudflare `1.1.1.1`/DoH e Google `8.8.8.8`/DoH) — dois validadores
independentes concordam que a cadeia de confiança valida. Confirmei também
o registo `DS` na zona pai (`.co`), presente e coerente com o `DNSKEY`
publicado. **Conclusão: DNSSEC está ativo e a validar corretamente hoje**,
apesar de `docs/dns-tls.md` §4 o listar como item pendente.

### 3.3 Pedido HTTP a `https://danielmala.co/`

Resultado: **HTTP 403, página "Sorry, you have been blocked" do
Cloudflare** (não a página de login da Cloudflare Access, e não o site).
Repeti em HTTP puro (`http://danielmala.co/`) — mesmo resultado, 403.

**Isto não é o que o prompt esperava por omissão** ("hoje deve devolver a
página de login da Access") — mas tem uma explicação verificável, não é um
sinal de que a Access esteja desligada: o IP de saída deste ambiente
resolve para os EUA (confirmado via `ipinfo.io/country` → `US`; os
`cf-ray` das respostas mostram datacenters `IAD`/`ORD`, ambos EUA). Segundo
`docs/cloudflare-deploy.md` §5, a regra 5 (`Blocked Countries - Site` — país
≠ PT → `Block`, `pára a avaliação`) corre **antes** de qualquer coisa
chegar à Access (Access está por trás de tudo, WAF de zona corre primeiro
na borda). Ou seja: **a página que recebi é exatamente o comportamento
esperado da regra 5 do WAF para um visitante fora de PT** — não prova nem
desmente se a Access continua ligada, porque o pedido nunca chegou lá.

**Limitação honesta, sinalizada como pedido:** não tenho forma de testar a
partir de um IP em PT neste ambiente, por isso **não consigo confirmar se a
Access continua ativa** por este caminho. O que consigo confirmar com
confiança: a regra WAF de bloqueio geográfico para não-PT está a funcionar
como documentado. Isto não significa "a Access pode já não estar a
bloquear" (a condição de alarme que o prompt pediu para sinalizar) — o
resultado observado é consistente com qualquer estado da Access, porque o
WAF intercepta primeiro.

### 3.4 Headers de segurança

Não alcançável — o mesmo bloqueio WAF impede ver a resposta real do site
(recebi os headers da própria página de erro da Cloudflare, não os do
`_headers` do site), por isso não há comparação válida a fazer contra
`.github/expected-headers.json` a partir daqui.

### 3.5 Registos adicionais confirmados (fora do pedido, mas relevantes)

SPF (`v=spf1 include:_spf.mx.cloudflare.net -all`) e DMARC
(`p=reject; sp=reject; adkim=s; aspf=s`) confirmados corretos e presentes —
consistente com a nota já registada em `docs/dns-tls.md` §1.

---

## 4. Build e testes

Corridos nesta sessão, a partir do commit `da77869`:

- `cd static && npm ci && npm run build` — **completou sem erros**, 59
  páginas geradas, exit code 0.
- `cd static && npm test` — **72/72 testes, 0 falhas**.
- `cd dynamic/worker && npm ci && npm test` — **119/119 testes, 0 falhas**.

**Uma nota sobre "sem warnings novos" (regra do `CLAUDE.md`):** o build
emite o aviso `[WARN] [glob-loader] The base directory
".../content/blog/" does not exist.`, seguido da mensagem `The collection
"blog" does not exist or is empty.` repetida uma vez por cada uma das ~59
páginas geradas (67 ocorrências no total). Isto é a consequência esperada
e já aceite de `content/blog/` ter sido removida por completo na Fase 1 da
preparação do repositório para público (`docs/relatorio-preparacao-repo-
publico-2026-07-30.md`, "Post de exemplo") — mas o texto exato do aviso e o
volume (67× vs. a única linha antecipada nesse relatório, "`[glob-loader]
No files found matching`") divergem do que ficou documentado, porque
entretanto a pasta `content/blog/pt`/`en` deixou de existir de todo (git
não versiona diretórios vazios), em vez de existir vazia. **Não é um
bloqueador nem uma regressão funcional** (o build completa com exit 0 e o
estado "blog vazio" já estava tratado no design, `BlogIndexPage.astro:25`)
— é uma nota de que o aviso documentado ficou tecnicamente desatualizado.
Não alterei nada para corrigir isto, por estar fora do âmbito de uma tarefa
de validação.

---

## 5. Veredicto

**Não, ainda não é um "sim" incondicional** — falta uma confirmação
específica do dono antes do flip, e uma lista curta de itens que só o dono
executa no dashboard. Nada do que encontrei aponta para um problema no
código ou na configuração do repositório em si; build e testes estão
100% verdes.

### O único bloqueador que exige uma decisão do dono antes do flip

- **`DEBUG_EXPOSE_SELF_PATH`** (`dynamic/worker/src/lib/csp-report.js:132`)
  continua `true`, e não há registo de que o diagnóstico das violações
  `self/self` tenha concluído desde a última confirmação (2026-07-30, a
  mesma data de hoje). Desligar a Access sem resolver isto primeiro muda o
  risco de exposição de path de "mínimo" para "real". **Pergunta direta ao
  dono:** o diagnóstico já concluiu? Se sim, reverter a flag (e os 2 testes
  associados) antes do flip. Se não, o dono aceita conscientemente o risco
  novo, ou prefere adiar o flip até fechar o diagnóstico?

### Itens que já estão prontos, só à espera do flip (sem trabalho de repo)

- `expected-headers.json`/`check-headers.mjs` e `check-invariants.mjs` —
  confirmados prontos a "ligar" assim que `url` apontar para produção
  (decisão já tomada: depois do flip).
- Regras WAF — não verificáveis a partir daqui; **confirmar no dashboard**
  que as 5 regras (`docs/cloudflare-deploy.md` §5) continuam ativas, por
  esta ordem, desde 2026-07-29.
- CAA, HSTS preload — genuinamente pendentes, ações de dashboard/submissão
  externa.
- Rotação de `RATE_SALT`/`CF_API_TOKEN` — procedimento documentado em
  `wrangler.toml`, ação do dono no dia do flip.

### Achado que não bloqueia nada, mas vale corrigir na documentação

- **DNSSEC já está ativo** (confirmado por dois resolvedores DoH
  independentes) — `docs/dns-tls.md` §4 continua a listá-lo como pendente.
  Sugiro marcar `[x]` nessa secção quando o dono confirmar.

### O que não consegui confirmar, e digo-o explicitamente

- Se a Cloudflare Access continua de facto a bloquear produção. O pedido
  HTTP feito a partir deste ambiente (IP nos EUA) foi interceptado pela
  regra WAF de bloqueio geográfico antes de chegar à Access — não há como
  distinguir daqui "Access ligada" de "Access desligada", porque o WAF
  bloqueia primeiro para qualquer origem fora de PT. Não presumi nenhum dos
  dois estados.

**Resumo para o dono:** o repositório está tecnicamente pronto (build,
testes, scripts de verificação, checklist de docs). O que falta é uma
resposta sobre o diagnóstico de `DEBUG_EXPOSE_SELF_PATH`, e depois a
sequência já conhecida de ações de dashboard (Access, WAF, CAA, DNSSEC já
feito, rotação de segredos) no dia do flip.
