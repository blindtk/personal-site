# Revisão de postura de segurança — 2026-07

> Avaliação crítica do repositório e da infraestrutura, na perspetiva de
> *Principal AppSec / DevSecOps*. Âmbito: `static/` (Astro no Pages),
> `dynamic/worker/` (Cloudflare Worker), `.github/` (CI/CD) e a zona
> Cloudflare. **Premissa assumida em todo o documento: isto é um site
> pessoal, não um SaaS.** Ferramenta a mais é ruído a mais, e ruído
> ignorado é pior do que ferramenta nenhuma — porque cria a ilusão de
> cobertura.

**Resumo em duas linhas:** a base é invulgarmente boa — melhor do que a
esmagadora maioria dos repositórios pessoais e do que muitos repositórios
de empresa. Os problemas que restam **não são falta de scanners**: são
duas ou três lacunas concretas de *execução* (testes que nunca correm,
um lockfile que ninguém analisa, um cron que não verifica nada) e **um
bug real de lógica de negócio** que nenhuma das ferramentas propostas
apanharia.

---

## Estado das correções (follow-up, mesma revisão)

As lacunas de risco alto e várias de risco médio identificadas abaixo foram
corrigidas num PR de seguimento, com testes a comprovar cada uma. Resumo:

| Lacuna | Estado | Como foi verificado |
|---|---|---|
| #1 rate limiter esgota a quota do KV | **Corrigido** — cap global diário (`RATE_LIMIT_WRITE_CAP`, mesmo padrão do honeypot/CSP/vitals) | 2 testes novos (`node --test`) |
| #2 nenhum teste corre em CI | **Corrigido** — `npm run test`/`npm test` em jobs próprios (`build` e `worker` novo) | 105 testes do Worker + 68 do static, verdes |
| #3 lockfile do Worker não é analisado | **Corrigido** — OSV a cobrir os dois lockfiles; `npm audit` também no job `worker` | Ver achado extra abaixo — encontrou uma vulnerabilidade real |
| #4 cron de headers não verifica nada | **Corrigido** — `url` no `expected-headers.json` já não é `SET-ME` | — |
| #5 `RATE_SALT` falha em silêncio | **Corrigido** — `console.error('rate_salt_missing', …)` quando o segredo falta | 1 teste novo |
| #6 `compatibility_date` de 18 meses | **Corrigido**, com aviso — bump para `2026-01-01`; precisa da validação via deploy da branch (já documentada no `CLAUDE.md`) antes do merge | `wrangler deploy --dry-run` valida a config; o runtime real só se confirma com deploy |
| #7 sem observabilidade no Worker | **Corrigido** — `[observability] enabled = true` | `wrangler deploy --dry-run` confirma que o TOML continua válido |
| HSTS ausente nas respostas do Worker | **Corrigido** — adicionado a `RESPONSE_SECURITY_HEADERS` | testes existentes continuam verdes |
| `wrangler deploy --dry-run` como gate de CI | **Adicionado** — funciona sem nenhum segredo da Cloudflare | Confirmado neste ambiente, sem credenciais |
| `astro check` em CI | **Corrigido (ronda 2, PR #128)** — 37 erros reais resolvidos, script ligado ao `ci.yml` | 0 erros/0 warnings/0 hints, com reinstalação limpa |
| Semgrep só a `ERROR` | **Corrigido (ronda 3)** — triagem completa feita, gate sobe para `ERROR` + `WARNING` | Scan sem filtro de severidade: 16 achados (2 ERROR / 8 WARNING / 6 INFO) → 0 depois da triagem; ver secção abaixo |

### Dois achados que não estavam na lista original

A correção expôs dois problemas reais e atuais que a revisão inicial não
tinha apanhado (não são hipotéticos — reproduzidos neste ambiente):

1. **`dynamic/worker/package-lock.json` tinha uma vulnerabilidade high
   real** (não um falso positivo): `sharp` `<0.35.0`, herdada via
   `miniflare`/`wrangler` (GHSA-f88m-g3jw-g9cj, CVEs de libvips). Corrigido
   com uma atualização real e dentro do range (`wrangler@4.112.0` →
   `4.115.0`, ainda satisfaz `^4.0.0`), não com uma exceção — é exatamente o
   caso que o `renovate.json5` já previa ("sharp/libvips puxado pelo
   wrangler"), só que ninguém o estava a verificar até agora.
2. **`zizmor==1.27.0`, a versão fixada em `security.yml`, foi retirada do
   PyPI por um advisory de segurança** (GHSA-f42p-wjw5-97qh) — descoberto ao
   tentar reproduzir o job localmente para validar as alterações. O
   `renovate.json5` já tem um `customManager` para isto (regex + datasource
   `pypi`, mesmo padrão do semgrep), mas ainda não tinha aberto PR. Corrigido
   para `1.28.0` diretamente neste PR.

Também descoberto: `npm audit --audit-level=high` já estava a falhar no
`main` *antes* de qualquer alteração deste PR, pelo mesmo falso positivo do
`astro@7.1.0` já documentado em `osv-scanner.toml` (MAL-2026-10726) — só que
o `npm audit` não tem mecanismo de exceção próprio, ao contrário do
OSV-Scanner. Corrigido com `.github/scripts/check-npm-audit.mjs` +
`.github/npm-audit-allowlist.json`, que replica o padrão do
`osv-scanner.toml` (justificação + `ignoreUntil`) para esta gate.

### Ronda 2 (PR #128): validação direta no dashboard + `astro check` fechado

Depois da ronda 1, o dono do repo validou diretamente três pontos no
dashboard da Cloudflare/GitHub que eu só tinha conseguido apontar, não
confirmar — e isso apanhou uma regressão real que a ronda 1 tinha
introduzido:

- **Deploy automático confirmado**: Workers Builds está ligado
  (`blindtk/personal-site`, root `dynamic/worker`, branch `main`) — as
  correções de código chegam a produção sozinhas a cada push, à
  semelhança do Pages. Ajuste: o "Build watch paths" está em `*`
  (dispara em qualquer commit ao repo, não só em `dynamic/worker/**`) —
  fica como sugestão de afinação, não correção.
- **Branch protection confirmado ausente**: nem o sistema clássico nem
  os Rulesets se aplicam neste repo (privado, conta pessoal) — GitHub
  exige Team/Enterprise para isso em repos privados. Não é um erro de
  configuração; é um limite da plataforma que só se resolve tornando o
  repo público ou pagando o upgrade.
- **Regressão apanhada a tempo**: o PR #126 tinha apontado o `url` do
  `expected-headers.json` para produção, partindo do princípio de que o
  site era publicamente acessível. Confirmado que a **Cloudflare Access
  continua ativa** — o cron diário do `Headers` ia falhar sempre contra
  a página de login da Access, não por regressão de headers real.
  Revertido para `SET-ME`, com as duas formas de o ativar antes do
  lançamento documentadas em `docs/cloudflare-deploy.md`.
- **WAF fechado por decisão explícita**: as regras "Previews sociais" e
  "O dono sempre" do desenho original nunca existiram, confirmado nos
  screenshots — Known Bots (regra 1) já cobre os crawlers de preview
  social, e só PT passar com Managed Challenge é o desenho final aceite
  (mesmo sujeitando o dono a Block fora de PT). Documentado.

Depois disso, `astro check` foi corrigido: 37 erros reais (não 36 —
o número exato depende de qual commit se conta), quase todos por 5-6
causas raiz repetidas (`parseExif()` sem `@returns` a esconder todos os
campos EXIF reais; chaves i18n na secção errada do dicionário —
`dict.security` em vez de `dict.evidence`, que causava texto
"**undefined**" real na página self-scan em produção; tuplos e uniões
de literais alargados para tipos genéricos por falta de anotação).
Ligado ao `ci.yml`. Resultado: 0 erros, 0 warnings, 0 hints.

### Ronda 3: triagem do Semgrep e subida do gate para `WARNING`

Fecha o item **#8** (*Semgrep só a `ERROR`*). O scan foi corrido sem filtro
de severidade, contra exatamente o mesmo âmbito do CI (regras públicas de
JS/TS + `.semgrep/`, mesmo conjunto de ficheiros: 205 alvos, 203 regras).

**Volume real: 16 achados — 2 ERROR, 8 WARNING, 6 INFO — em 6 regras.**

| Regra | Sev. | N.º | Onde | Veredito |
|---|---|---|---|---|
| `typescript.lang.correctness.useless-ternary` | ERROR | 2 | `lab-terminal.js` | **Verdadeiro positivo — corrigido** |
| `javascript.lang.correctness.no-replaceall` | WARNING | 5 | `worker/src/lib/sanitize.js` | Não aplicável |
| `javascript.lang.security.html-in-template-string` | WARNING | 2 | `lab-terminal.js` | Falso positivo |
| `javascript.lang.security.audit.detect-non-literal-regexp` | WARNING | 1 | `worker/src/lib/ct.js` | Falso positivo |
| `javascript.audit.detect-replaceall-sanitization` | INFO | 4 | `worker/src/lib/sanitize.js` | Não aplicável |
| `javascript.lang.correctness.missing-template-string-indicator` | INFO | 2 | `worker/src/lib/notfound.js` | Falso positivo |

**Os dois ERROR eram defeitos a sério**, não ruído: dois ternários mortos
com os dois ramos literalmente iguais (`pt ? X : X`) — a mensagem do `sudo`
(citação literal do `sudo(8)`, que fica em inglês nos dois idiomas) e a
linha do `hash` no `help`. Corrigidos no código, não suprimidos: os
ternários desapareceram e o comportamento é idêntico.

Os restantes 14 foram suprimidos com `// nosemgrep: <rule-id>` no sítio,
cada um com a justificação por cima (mesmo padrão de exceção do
`osv-scanner.toml` e do `.github/npm-audit-allowlist.json`, mas **sem data
de expiração** — não são vulnerabilidades de terceiros à espera de patch,
são regras que não se aplicam a este código):

- **`no-replaceall` / `detect-replaceall-sanitization`** (9 dos 14, todos na
  mesma função `escapeHtml`): a primeira avisa que `replaceAll` falta em
  browsers antigos — este ficheiro só corre no workerd e no Node dos testes;
  a segunda pede DOMPurify/sanitize-html — o Worker não tem DOM, e `escapeHtml`
  não é limpeza por lista de tags permitidas, é o escape completo dos cinco
  caracteres. Trocar isto por uma dependência seria mais superfície, não menos.
- **`html-in-template-string`**: `` `${cmd} <base64|url|hex> <texto>` `` não é
  HTML — é notação de uso do terminal, apanhada só porque `<b` parece uma tag.
  As linhas do terminal são impressas com `div.textContent`; não há sink.
- **`detect-non-literal-regexp`**: o taint vem de `key`, parâmetro de uma
  closure chamada só com `'O'` e `'CN'`. O texto do crt.sh é o *assunto* do
  match, não o padrão, e o padrão é linear — não há ReDoS.
- **`missing-template-string-indicator`**: os `{…}` são blocos de CSS dentro
  do HTML estático do 404; o template não interpola nada.

**Depois da triagem: 0 achados a qualquer severidade.**

**Decisão: o gate sobe de `ERROR` para `ERROR` + `WARNING`.** Os números
justificam-no dos dois lados:

- O bucket WARNING tem 8 achados no repositório inteiro — triagem de uma
  tarde, feita, e agora a zero. O custo marginal de o incluir é **zero
  hoje**, e o custo de o manter é uma supressão justificada por caso novo.
- 3 dos 8 WARNING são de categoria *security* (`html-in-template-string`,
  `detect-non-literal-regexp`) — exatamente a classe de achado que o gate
  existe para apanhar. Com `--severity ERROR` estavam a ser deitados fora
  em silêncio: o Semgrep classifica a maioria das suas regras de XSS/injeção
  em modo *audit* abaixo de ERROR, por serem confidence LOW/MEDIUM.
- O ruído recorrente concentra-se numa única regra não-security
  (`no-replaceall`, 5 dos 8) e num único sítio do código.

**INFO fica de fora do gate** (continua a aparecer no relatório, sem falhar
o build): as 6 ocorrências vêm de regras *audit* com confidence LOW cuja
recomendação típica é acrescentar uma dependência de sanitização. Não é
sinal que justifique parar um PR.

Duas notas operacionais que saíram desta passagem:

1. **`--severity` é um filtro de igualdade, não um mínimo.** Passar só
   `--severity WARNING` faria os achados ERROR deixarem de contar — o gate
   ficaria mais fraco, não mais forte. Daí as duas flags no `security.yml`.
2. **`// nosemgrep` só suprime se o marcador estiver na linha imediatamente
   anterior ao achado.** Num comentário de várias linhas, a justificação vai
   primeiro e o `nosemgrep:` fica na última — não ao contrário. Para suprimir
   duas regras no mesmo sítio, separam-se por vírgula na mesma linha.

*Ressalva de método:* o scan de triagem foi corrido com as regras de JS/TS
do repositório aberto `semgrep/semgrep-rules` (o registo `semgrep.dev` não
era alcançável do ambiente onde a triagem correu), ou seja um **superconjunto**
dos packs `p/typescript` + `p/javascript`. A prova de que é superconjunto:
`useless-ternary` é ERROR na origem e as duas linhas que apanhou estavam no
`main` desde o PR #74 com o job `semgrep` sempre verde — logo o pack do
registo ou não traz essa regra, ou trá-la abaixo de ERROR. O risco residual
era o inverso: uma regra que só existisse no registo podia aparecer como
WARNING no primeiro CI depois desta mudança.

**Confirmado no CI do PR #130:** o job `semgrep` com o gate novo passou
verde à primeira, e o log dá a dimensão real dos packs — **76 regras (74 do
registo + 2 nossas, de `.semgrep/`)** contra as 203 do superconjunto usado
na triagem, com **0 achados**. A triagem foi portanto conservadora por uma
margem larga: o que o CI corre é um subconjunto do que foi analisado à mão.

### CAA — confirmado em falta (verificação DNS ao vivo)

Consulta direta aos registos DNS de produção (2026-07-29): **SPF e
DMARC estão excelentes** (`v=spf1 ... -all`; DMARC com `p=reject;
sp=reject; adkim=s; aspf=s` — mais estrito do que a maioria dos sites
profissionais) e o MX confirma uma Cloudflare Email Routing real (não
precisa de "null MX", ao contrário do que a ronda 1 sugeriu como
opção condicional). **Mas não existe nenhum registo CAA** — a consulta
devolve sem resposta, apesar de `docs/dns-tls.md` já ter os registos
prontos a copiar. Enquanto isto ficar por fazer, qualquer CA
publicamente confiada pode emitir um certificado para o domínio, sem
restrição nenhuma. É uma ação de dashboard (DNS → Records → Add
record → CAA, sete linhas), não de código — documentado com a data da
confirmação em `docs/dns-tls.md`.

---

## 1. Maturidade atual

| Área | Nota | Uma linha |
|---|---|---|
| Gestão de segredos | **8/10** | Sem segredos no repo, sem token da Cloudflare no GitHub. Falha silenciosa no `RATE_SALT`. |
| Segurança de dependências | **7/10** | Boa cobertura… do `static/`. O lockfile do Worker não é analisado por nada. |
| Cadeia de fornecimento | **8/10** | Pins por SHA, `minimumReleaseAge`, zizmor. Deploy do Worker fora do CI. |
| Análise estática | **6/10** | Semgrep bem apontado, mas 6 ficheiros de teste **nunca correm em CI**. |
| Segurança de CI/CD | **8/10** | Decil de topo. Falta o *gate* de testes e o cron de headers está morto. |
| Específico da Cloudflare | **6/10** | CSP exemplar; runtime com `compatibility_date` velho, sem observabilidade e com um caminho de auto-DoS. |
| Segurança em runtime | **5/10** | Nenhuma retenção de logs, nenhum alerta, verificação pós-deploy meio ligada. |
| Revisão de lógica de negócio | **6/10** | Raciocínio excelente e *documentado*; sem rede de segurança automática — e já falhou uma vez em produção. |
| **Postura global** | **7/10** | Sólida. O que falta compra-se com ~1 dia de trabalho, não com 8 ferramentas novas. |

### Justificação

**Gestão de segredos — 8.** Não há segredos versionados; gitleaks corre em
pre-commit *e* em CI com `fetch-depth: 0` (história completa, não só o
último commit). Os segredos do Worker vivem em `wrangler secret`, e o
`wrangler.toml` documenta cada um. Detalhe que quase ninguém acerta: **não
existe nenhum token da Cloudflare nos segredos do GitHub** — o Pages faz
deploy pela integração Git, portanto um comprometimento do GitHub Actions
não dá acesso à conta Cloudflare. Isso vale muito.

Desconto: `dailySalt(secret)` em `lib/ratelimit.js` cai em `'rotate-me'`
quando `RATE_SALT` não está definido. Se o segredo alguma vez faltar em
produção, o rate limiting *continua a funcionar* e nada avisa — o salt é
apenas público e previsível. Uma falha de configuração que não faz barulho
é uma falha que dura meses. Além disso, a rotação semanal está escrita num
comentário e depende de memória humana.

**Dependências — 7.** A combinação Renovate (*version updates*) +
Dependabot (só *security*, para transitivas) está corretamente pensada e
comentada — muita gente liga os dois e depois vive em guerra de PRs.
`minimumReleaseAge: '3 days'` é uma defesa real contra pacotes npm
comprometidos e retirados pouco depois. O `osv-scanner.toml` exige
justificação **e** data de expiração por exceção.

Desconto, e é concreto: o `security.yml` corre
`--lockfile=./static/package-lock.json`. O `dynamic/worker/package-lock.json`
(89 pacotes resolvidos, a árvore do `wrangler`) **não é analisado por
ninguém** — nem pelo OSV, nem pelo `npm audit`, que só corre com
`working-directory: static`. É `devDependencies`, o que baixa o impacto, mas
é código que corre na tua máquina com acesso ao token da Cloudflare.

**Cadeia de fornecimento — 8.** Todas as actions pinadas por commit SHA com
o Renovate a manter os digests; `persist-credentials: false` em todos os
checkouts; zizmor a auditar os próprios workflows com auditorias online
ligadas (deteção de commits impostores). Isto é postura de empresa madura.

Desconto: o Worker faz deploy **à mão**, com `npx wrangler deploy` do
portátil. É a razão pela qual não há token no GitHub (bom), mas significa
que **não há garantia de que o que está em produção corresponda ao `main`**
— nenhum scanner, teste ou revisão fica entre o teu editor e o edge. Para
metade dinâmica do site, o CI é decorativo.

**Análise estática — 6.** O Semgrep está bem apontado: rulesets públicos de
TS/JS mais regras próprias em modo `generic` para os `<script>` dos `.astro`
(que o Semgrep não parseia nativamente) — isso é uma solução criativa e
correta para um problema real.

Descontos, dois:
1. `--severity ERROR` descarta tudo o que é `WARNING`, e nas regras públicas
   a maioria das regras de *taint* (o que realmente encontra injeção) é
   `WARNING`. Estás a correr o Semgrep essencialmente como um *linter* de
   padrões, não como SAST.
2. **Nenhum teste corre em CI.** Existem 6 ficheiros de teste
   (`static/test/csp-lint|email-headers|exif|observability|passkeys` e
   `dynamic/worker/test/logic.test.mjs`) e nenhum workflow os invoca. O
   `pull_request_template.md` pede ao humano que marque uma caixa a dizer que
   os correu. Isso não é um controlo, é uma intenção. O `astro check` também
   existe em `package.json` e também nunca corre — 16,8% do repo é
   TypeScript que nunca é verificado.

**CI/CD — 8.** `permissions: {}` por omissão com cada job a declarar o
mínimo; valores externos passados por `env:` em vez de interpolados no
`run:` (com o comentário a explicar porquê); jobs separados por
responsabilidade. Nota alta merecida.

Descontos: não há *gate* de testes/tipos (acima), e o cron diário de headers
não verifica nada — ver a lacuna #4 abaixo.

**Cloudflare — 6.** A CSP é do melhor que se vê: `require-trusted-types-for
'script'`, `trusted-types 'none'`, zero `unsafe-inline`, zero inline no site
inteiro garantido por dois *levers* de build explícitos, COOP/COEP/CORP,
`form-action 'none'`, `base-uri 'none'`. O truque do `!` para o CORP das
imagens OG mostra que houve depuração a sério.

Do lado do Worker, o desenho é limpo: lógica pura separada de rede, sem PII,
sem SSRF em lado nenhum (o `/api/scan` usa uma *var* fixa, o `/api/pwned-range`
valida 5 hex a ferro, o `/api/ct` tem query fixa, o `/api/mirror` não aceita
input). Não existe um único ponto onde input de visitante escolha um destino
de `fetch` — é exatamente isso que separa este código de 90% dos "Workers com
uma API".

Descontos: `compatibility_date = "2025-01-01"` está 18 meses atrasada; não há
bloco `[observability]` (portanto os `console.error` não vão a lado nenhum);
não há `[limits]`; e existe o caminho de auto-DoS descrito na lacuna #1.

**Runtime — 5.** É a nota mais baixa e é a certa. O `headers.yml` é uma boa
ideia — verificar em produção o que se promete no repo — mas metade não
funciona. Não há retenção de logs no Worker, não há alerta nenhum, não há
monitorização sintética dos `/api/*`. Se o Worker começar a devolver 502 às
03:00, descobres quando abrires o site.

**Lógica de negócio — 6.** O `dynamic/PLAN.md` é excecional: decisões
datadas, com justificação, com o custo registado e com correções de
conclusões erradas anteriores. Isso é melhor documentação de decisão do que
a maioria das equipas produz.

Mas: a única classe de bug que realmente te ameaça aqui é a interação entre
quotas do plano Free e o caminho de escrita — e ela **já falhou em
produção** (o alerta dos 50% do teto diário do KV, registado no PLAN). Os
caps `underCap` foram a resposta. Continuam incompletos — ver a seguir.

---

## 2. Análise de lacunas

### Risco alto

**#1 — O rate limiter é ele próprio um amplificador de escritas no KV
(auto-DoS de todas as features de segurança).**

`rateLimit()` em `src/index.js:380` faz `env.KV.put()` em **cada pedido
permitido**. Ao contrário do honeypot, do recetor CSP e dos vitals, **não
passa por `underCap`** — não tem teto global.

Fazendo as contas com os limites que estão no código:

| Rota | Máx. por minuto/IP | Escritas KV/dia, 1 só IP sustentado |
|---|---|---|
| `/api/mirror` | 30 | **43 200** |
| `/api/vitals` (POST) | 30 | 43 200 |
| `/api/pwned-range` | 20 | 28 800 |
| `/api/csp-report` | 10 | 14 400 |

O teto do plano Free é ~**1 000 escritas/dia para a conta inteira**. Um
único IP, dentro dos limites que tu próprio definiste, esgota o orçamento
diário de escrita da conta em **cerca de 35 minutos** — sem sequer ser
bloqueado, porque está a respeitar o rate limit.

Consequência: durante o resto do dia o honeypot deixa de registar eventos,
os vitals param, as violações CSP perdem-se e o snapshot diário da firewall
(`fw:<dia>`, o que constrói a janela de 7 dias) não é escrito. **O ataque
desliga precisamente as features que existem para o detetar**, e fá-lo sem
disparar nada, porque os caps do honeypot só protegem o honeypot.

O agravante é a ironia: os caps foram apertadíssimos (60 eventos de honeypot
por dia!) para poupar orçamento que o rate limiter gasta a 43× a velocidade.

*Correção certa* — mover o rate limiting para fora do KV. A Cloudflare tem
uma **Rate Limiting API** com *binding* nativo no Worker, gratuita, em
memória por colo, que não toca no KV:

```toml
[[ratelimit]]
binding = "RL_MIRROR"
namespace_id = "1001"
simple = { limit = 30, period = 60 }
```

```js
const { success } = await env.RL_MIRROR.limit({ key: id });
```

Perde-se a precisão global (é por colo) e ganha-se: zero escritas KV, zero
latência de KV no caminho quente, e a `dailySalt`/`clientHash` mantêm-se
para a chave (a propriedade zero-PII fica intacta). Alternativa mais barata
de escrever, se quiseres manter o KV: envolver o `put` do rate limiter num
`underCap` global, o que degrada o rate limiting sob abuso mas salva o
orçamento. Alternativa complementar e melhor ainda: **uma regra de Rate
Limiting da zona** (1 grátis no Free) à frente de `/api/*` — bloqueia no
edge, antes de o Worker sequer ser invocado, e por isso também não gasta
invocações.

**#2 — Nenhum teste e nenhuma verificação de tipos corre em CI.**

Seis ficheiros de teste, zero execuções. `sanitize.js`, `normalizeVitals`,
`parseRanges`, `gradeFromHeaders`, `underCap`, `nextState` — toda a lógica
pura que constitui as tuas garantias de segurança — pode regredir sem que
nada falhe. O `CLAUDE.md` manda correr `node --test` antes de qualquer PR
que toque em `dynamic/`; o CI não o verifica. Um controlo que depende de
disciplina não é um controlo.

**#3 — O lockfile do Worker não é analisado por nenhuma ferramenta.**
Detalhado acima. Correção: uma linha no `scan-args` do OSV.

**#4 — A verificação diária de headers não verifica nada.**

`.github/expected-headers.json` tem `"url": "SET-ME: https://<projeto>.pages.dev/"`.
O `check-headers.mjs` faz explicitamente:

```js
if (!target || target.startsWith('SET-ME')) { /* notice */ process.exit(0); }
```

Ou seja, o cron `17 6 * * *` corre todos os dias e sai **verde sem testar
nada**. Só os eventos `deployment_status` verificam de facto (via
`environment_url`). Perdeste a rede de segurança que apanha *derivas fora de
deploy*: alguém a mexer nas Transform Rules da Cloudflare, uma regra de zona
a remover um header, o `_headers` a exceder um limite do Pages. É uma
correção de um caractere e devolve o controlo mais valioso que tens.

### Risco médio

**#5 — `RATE_SALT` falha em silêncio.** Adicionar uma verificação no
arranque (ou no `/api/health`) que assinale `RATE_SALT` em falta, e
automatizar a rotação semanal (uma Routine/cron que te lembre, ou um
workflow `workflow_dispatch` documentado). Hoje é memória humana.

**#6 — `compatibility_date` de 2025-01-01.** 18 meses de correções de
runtime e defaults por adotar. Subir para uma data recente e correr os
testes; é barato e o Renovate não trata disto.

**#7 — Sem observabilidade no Worker.** Os `console.error('honeypot_write_failed', …)`,
`csp_report_write_failed`, `request_failed` não são retidos em lado nenhum.
Escreveste *logging* de incidente e depois deitaste-o fora. Correção de três
linhas:

```toml
[observability]
enabled = true
head_sampling_rate = 1
```

**#8 — Semgrep só a ERROR.** Subir para `WARNING` numa passagem, ver o
volume real, e usar `.semgrepignore`/`nosemgrep` para o que for ruído. Se o
volume for insuportável, voltar a ERROR — mas com dados, não por omissão.

**#9 — Deploy manual do Worker.** Não te digo para pôr um token da
Cloudflare no GitHub (isso troca um risco por outro pior). Alternativa: um
job de CI com `wrangler deploy --dry-run` para provar que o Worker *compila
e valida* a cada PR, mantendo o deploy manual. Ganhas o gate sem o segredo.

### Nice-to-have

- `CODEOWNERS` (auto-atribuição de revisão; sinal de organização num repo
  público).
- `step-security/harden-runner` nos jobs — controlo de egress dos runners.
  Genuinamente útil contra actions comprometidas; custo quase zero.
- Lista de *decoys* duplicada entre `wrangler.toml` (`routes`) e `DECOYS` em
  `index.js`. Vão divergir. Gerar uma da outra ou pelo menos um teste que
  compare as duas.
- Sem HSTS nas respostas do Worker (só `nosniff` + `default-src 'none'`).
  Se a zona tem "Always Use HTTPS" é cosmético, mas um scanner externo vai
  apontá-lo — e o teu site é literalmente sobre isso.
- **DMARC / SPF / MX nulo.** O `docs/dns-tls.md` cobre CAA, DNSSEC e HSTS
  muito bem, mas não menciona email. Um domínio de portfólio sem
  `v=DMARC1; p=reject` é *spoofable* para phishing em teu nome. Se não
  envias email do domínio: `MX .` (null MX, RFC 7505), `v=spf1 -all`,
  `_dmarc` com `p=reject`. Custo: 10 minutos. Fecha uma classe inteira de
  abuso e é conteúdo bom para o site.
- Validação de esquema do `content/*.json` (zod nas content collections do
  Astro) — hoje um JSON malformado só se descobre no build, na melhor das
  hipóteses.

---

## 3. Avaliação de cada ferramenta proposta

| Ferramenta | Problema que resolve | Sobreposição | Manutenção | Falsos positivos | Valor aqui | Classificação |
|---|---|---|---|---|---|---|
| **Strix** | Pentest autónomo com IA: explora a app a correr, encadeia falhas, testa authz/lógica | Nenhuma real | Média (revisar achados) | Baixa-média | Baixo — não há modelo de autorização para quebrar | **Opcional** |
| **Trivy** | Contentores, IaC, SBOM, ficheiros | Total com OSV nas deps | Baixa | Média | ~Zero — não há Dockerfile, K8s nem Terraform | **Não vale a pena** |
| **Nuclei** | Templates de CVEs/misconfig contra alvo vivo | Parcial com o self-scan | Média-alta (tuning) | **Alta** por omissão | Baixo-médio, e com um efeito colateral mau | **Opcional** |
| **OWASP ZAP** | DAST (passivo + ativo) | **Total** com `check-headers.mjs` + `/api/scan` | Média | Alta no ativo | Negativo — duplica um controlo teu melhor afinado | **Não vale a pena** |
| **CodeQL** | Dataflow interprocedural real | Complementa o Semgrep | Baixa | **Baixa** | Alto *se o repo for público* | **Recomendado (condicional)** |
| **CodeRabbit** | Revisão de PR com IA | Com o Copilot Review | Baixa | Média | Médio | **Opcional** |
| **Copilot Code Review** | Revisão de PR com IA | Com o CodeRabbit | Muito baixa | Média | Médio | **Recomendado se já pagas Copilot** |
| **Playwright** | Testes E2E / regressão de CSP em runtime | Nenhuma | Baixa-média | **Muito baixa** | **Alto** — cobre a tua fragilidade nº1 | **Recomendado, a roçar Essencial** |

### Notas por ferramenta

**Strix.** A superfície é 12 endpoints GET e 2 POST, sem autenticação, sem
base de dados, sem contas de utilizador, sem sessões, sem uploads
persistidos. Strix brilha em IDOR, escalamento de privilégios e
encadeamento de authz — nada disso existe aqui. O que *poderia* encontrar é
abuso de lógica (tipo a lacuna #1) e é precisamente por isso que não o
descarto de todo. Mas não por PR. Ver secção 8.

**Trivy.** Sê honesto sobre o que ele faz: `trivy fs` para dependências
(já tens OSV, que usa a mesma base OSV.dev), `trivy image` (não há imagens),
`trivy config` para IaC (não há IaC — `wrangler.toml` não é suportado).
Sobra a geração de SBOM, que podes fazer com `npm sbom` sem instalar nada.
**Adicionar o Trivy aqui é adicionar um job para não encontrar nada.**

**Nuclei.** Avisos concretos, porque quase ninguém os antecipa:
1. A esmagadora maioria dos ~9 000 templates é para software que não corres
   (WordPress, Jira, Confluence, painéis expostos). Correr o conjunto todo
   contra o teu domínio é ~15 minutos de pedidos para produzir ruído.
2. **Vai poluir o teu próprio honeypot.** O Nuclei testa `/.env`,
   `/wp-login.php`, `/.git/config`, `/admin` — que são exatamente os teus
   *decoys*. Cada varredura injeta eventos falsos no teu Threat
   Intelligence *e* consome do teu cap de 60 eventos/dia. O teu painel
   público passa a mostrar "ataques" que és tu.
3. Se o usares: subconjunto apertado (`-t http/misconfiguration/ -t ssl/ -t
   dns/`), a partir de um IP que excluas, e nunca no caminho de PR.

Valor real: baixo em deteção, **médio em narrativa de portfólio** ("corro
Nuclei semanalmente contra o meu próprio domínio" lê-se bem). Decide com
esse critério, não com o de segurança.

**OWASP ZAP.** Esta é a que eu recuso com mais convicção. O *baseline scan*
passivo do ZAP verifica headers de segurança, cookies, fuga de informação —
tu já fazes isso com o `check-headers.mjs` contra uma lista versionada de
substrings obrigatórias, com zero falsos positivos e uma mensagem de erro
que diz exatamente qual header regrediu. **O teu controlo é melhor do que o
do ZAP para o teu caso.** O *active scan* injeta payloads em formulários e
parâmetros; tens um formulário que faz `preventDefault()` e nunca submete.
Adicionar o ZAP acrescenta ~5 minutos de CI, um relatório HTML que ninguém
lê, e alertas informativos que vais aprender a ignorar — o que é o começo de
ignorares alertas em geral.

**CodeQL.** É a única da lista que encontra classes de bugs que o teu
Semgrep estruturalmente não encontra: análise de fluxo de dados
interprocedural (source num handler → sink noutro módulo, através de duas
chamadas). Num Worker com `index.js` a chamar 13 libs, isso é exatamente a
forma do teu código.

**Mas há um bloqueio, e está documentado no teu próprio `security.yml`:** o
comentário do job OSV diz que a publicação de SARIF exige GitHub Advanced
Security, "indisponível neste repo". Code scanning é **gratuito em
repositórios públicos** e pago em privados. Portanto:
- Repo **público** → CodeQL é gratuito, integra-se nativamente, **liga já**.
- Repo **privado sem GHAS** → não consegues publicar resultados; ficas com
  correr o CLI e falhar o job pelo código de saída, o que é desconfortável e
  perde o triagem. **Não vale a pena nessas condições.**

Isto é a decisão que muda a resposta: é a mesma razão pela qual o CodeRabbit
(free tier para repos públicos) e o próprio valor de portfólio dependem
todos do mesmo interruptor. Se o repo ainda é privado, **torná-lo público é
a decisão de maior alavancagem deste documento inteiro** — desbloqueia
CodeQL grátis, CodeRabbit grátis e transforma todo este trabalho em prova
visível.

**CodeRabbit vs. Copilot Code Review.** Ver secção 4. A regra é: **escolhe
um.** Dois revisores de IA no mesmo PR produzem comentários sobrepostos, e a
resposta humana a comentários sobrepostos é parar de os ler.

**Playwright.** Esta é a recomendação que quero que leves mesmo, e é a que a
maior parte das listas descarta por "não ser uma ferramenta de segurança".

A tua CSP é *load-bearing* e **frágil por construção**, e tu próprio
documentaste porquê: o "zero inline" não é automático, depende de dois
*levers* (`build.inlineStylesheets: 'never'` e `vite.build.assetsInlineLimit: 0`)
mais um hash SHA-256 escrito à mão para o bloco JSON-LD. Uma atualização do
Astro que mude o comportamento de *hoisting*, ou uma alteração ao
`SITE.name` no `config.ts`, quebra isto — e **o `check-headers.mjs` não
apanha**, porque o header continuaria perfeitamente correto. É a *página*
que passa a violá-lo. O sintoma é os painéis deixarem de funcionar em
produção, silenciosamente. Já aconteceu uma vez (está no comentário do
`astro.config.mjs`).

O teste que falta é de ~40 linhas:

```js
// para cada rota do routes.ts, PT e EN:
const violations = [];
page.on('console', m => { /* … */ });
await page.addInitScript(() => {
  document.addEventListener('securitypolicyviolation',
    e => window.__csp ??= [] && window.__csp.push(e.violatedDirective));
});
await page.goto(url);
expect(await page.evaluate(() => window.__csp ?? [])).toEqual([]);
// e o lever, diretamente:
expect(await page.$$eval('script:not([src])',
  els => els.filter(e => e.type !== 'application/ld+json').length)).toBe(0);
```

Isto é um teste de **regressão de controlo de segurança**, não um teste E2E
qualquer. Cobre a fragilidade concreta que a tua arquitetura tem, com falsos
positivos praticamente nulos. Corre em ~30s. Se adicionares uma só coisa
desta lista, adiciona esta.

---

## 4. Comparação dos três revisores com IA

| | **Strix** | **CodeRabbit** | **Copilot Code Review** |
|---|---|---|---|
| Natureza | Agente de pentest (executa e explora) | Revisor de PR (lê o diff) | Revisor de PR (lê o diff) |
| Capacidade de segurança | **Alta** — valida explorabilidade a sério | Média — heurística + regras | Média-baixa |
| Qualidade de revisão de código | N/A (não é o objetivo) | **Alta** — a melhor das três | Média |
| Raciocínio sobre lógica de negócio | **Alta**, mas precisa de estado para explorar | Média-alta com contexto | Baixa |
| Suporte TypeScript | Bom | **Excelente** | Excelente |
| Suporte Cloudflare Workers | Fraco — sem `wrangler dev --remote`, não há `request.cf`, nem KV realista | Razoável (lê como JS) | Razoável |
| Custo | Tokens Anthropic por execução | Grátis em repo público; ~$12-24/mês privado | Incluído na subscrição Copilot |
| Ruído | Baixo | Médio (verboso; dá para configurar) | Médio-baixo |

**Sobre o suporte a Workers, que é o critério decisivo:** nenhuma das três
compreende bem o teu modelo de ameaça real. A lacuna #1 deste documento — o
rate limiter a esgotar a quota de KV — exige saber (a) que o plano Free tem
~1 000 escritas/dia, (b) que o limite é da *conta*, não do namespace, e (c)
que o `underCap` existe noutros caminhos mas não neste. Isso é conhecimento
de domínio, não análise de código. **Nenhum dos três encontraria isto de
forma fiável**, e é honesto dizê-lo antes de gastares dinheiro à espera do
contrário.

**Maior ROI: Copilot Code Review**, se já pagas Copilot — custo marginal
zero, atrito zero, apanha os deslizes normais. Se não pagas: **CodeRabbit em
repo público** (grátis, e é o melhor revisor dos três). **Strix não é um
revisor** e não deve ser comparado com estes dois em cadência de PR — é uma
ferramenta de campanha, não de rotina.

---

## 5. Revisão específica da Cloudflare

### O que já está certo (não mexer)

- `workers_dev = false` + `preview_urls = false` — fecha o bypass de
  `*.workers.dev` à Access e ao WAF de zona. **A maioria das pessoas não
  sabe que este bypass existe.**
- Worker em rotas do próprio domínio, mantendo `connect-src 'self'`.
- CORS: allowlist explícita, eco da origem só se estiver na lista,
  `Vary: Origin` sempre presente, sem `Allow-Credentials`, só `GET, OPTIONS`.
  Implementação correta — o erro comum (`Access-Control-Allow-Origin: *` com
  credenciais, ou eco cego da origem) não está cá.
- Zero SSRF: nenhum `fetch` com destino derivado de input.
- Zero-PII coerente: o IP nunca chega ao KV, só como hash salteado com
  rotação diária. O arredondamento do timestamp a 5 min para impedir
  correlação é um detalhe que quase ninguém pensa.
- `RESPONSE_SECURITY_HEADERS` com `default-src 'none'` em respostas JSON.
- CAA, DNSSEC e HSTS documentados e planeados em `docs/dns-tls.md`.

### O que corrigir

1. **`compatibility_date`** → data recente + correr testes.
2. **`[observability] enabled = true`** — sem isto não tens *incident
   response*, tens adivinhação.
3. **Rate limiting fora do KV** (lacuna #1) — *binding* nativo de rate
   limiting e/ou uma regra de zona à frente de `/api/*`.
4. **`[limits] cpu_ms`** — um teto explícito impede que um caminho patológico
   (o fan-out de 168 buckets do threat-intel, por exemplo) consuma tempo a
   mais.
5. **Cache API em vez de KV para o que é cache.** O teu `cached()` guarda em
   KV, o que gasta o recurso escasso (escritas) para fazer o trabalho de um
   recurso abundante (`caches.default` não tem quota diária). Para
   `cache:ticker`, `cache:scan`, `cache:ct`, `cache:cfstats` — dados
   públicos, não-pessoais, com TTL — o Cache API é o sítio certo e alivia
   diretamente a pressão que gerou os caps agressivos. **Atenção ao usá-lo:**
   a chave é o URL completo, portanto parâmetros não-keyed permitem
   *poisoning*; usa uma chave sintética (`new Request('https://cache.local/ticker')`)
   e nunca o `request` original.
6. **HSTS nas respostas do Worker** — juntar ao `RESPONSE_SECURITY_HEADERS`.
7. **`wrangler deploy --dry-run` em CI** — o gate sem o segredo.

### Comummente esquecido (e aplicável a ti)

- **`request.cf` é `undefined` em `wrangler dev` local** (sem `--remote`).
  O `mirror.js` e o `recordHoneypot` já tratam disso com defaults, mas
  qualquer feature nova que dependa de `cf.asn` vai parecer partida em dev e
  funcionar em prod, ou pior, o contrário.
- **Ordem de rotas Worker vs. Pages** — uma rota do Worker ganha ao Pages
  para o mesmo path. Se algum dia criares uma página `/admin` no site, o
  *decoy* do honeypot intercepta-a. Vale um comentário no `_headers` ou no
  `routes.ts`.
- **Limites de KV que não são o que se pensa:** o teto de escrita é da
  **conta**, partilhado por todos os namespaces e Workers. Se um dia
  adicionares um segundo Worker (as ferramentas de DNS/WHOIS do PLAN),
  compete pelo mesmo orçamento.
- **Secrets Store da Cloudflare** (segredos ao nível da conta, em vez de por
  Worker) — relevante quando existir um segundo Worker a precisar do mesmo
  `CF_API_TOKEN`. Hoje ainda não.
- **CAA cobre emissão; o teu vigia CT cobre observação.** Tens os dois
  planeados, o que é raro — mas repara que são complementares e não
  redundantes: o CAA *impede* CAs não autorizadas, o CT *deteta* o que
  passou na mesma. Vale a pena dizê-lo assim no site.
- **Email spoofing** — ver nice-to-have na secção 2. É a lacuna mais óbvia
  que resta na tua superfície de domínio.

### Para o futuro (D1 / R2 / Durable Objects)

Quando chegarem as ferramentas de DNS/WHOIS do `PLAN.md`:

- **D1** — usar sempre *prepared statements* com `.bind()`; nunca template
  strings. É SQLite: uma query mal construída sobre input de utilizador é
  injeção SQL a sério, e o teu Semgrep atual não tem regras para a API do D1.
  Se adicionares D1, adiciona uma regra própria em `.semgrep/`.
- **R2** — nunca expor um bucket com acesso público direto; servir sempre
  através do Worker com validação. Presigned URLs com TTL curto.
- **Durable Objects** — é a resposta *certa* para rate limiting com estado
  forte, se um dia precisares de garantias globais em vez de por colo. Mas
  não vale o custo hoje: o binding nativo de rate limiting resolve o teu
  problema com uma fração da complexidade.
- **DNS/WHOIS aceitam input de utilizador — é a primeira feature tua com
  SSRF real.** Hoje não tens nenhum caminho de `fetch` controlado pelo
  visitante; um resolvedor de DNS/WHOIS destrói essa propriedade. Antes de a
  construíres: allowlist de esquemas, rejeitar IPs privados/link-local/IPv6
  mapeado, sem seguir redirects, timeout curto, e um teste com vetores
  (`127.0.0.1`, `169.254.169.254`, `[::ffff:127.0.0.1]`, `0.0.0.0`,
  `metadata.google.internal`). **Regista esta decisão no PLAN.md antes de
  escrever a primeira linha.**

---

## 6. Pipeline de CI/CD recomendado

Princípio: o caminho de PR tem de continuar rápido, porque um caminho de PR
lento é um caminho de PR que se contorna.

### Por Pull Request (alvo: < 4 min)

| Passo | Porquê | Tempo | Manutenção |
|---|---|---|---|
| `npm ci && npm run build` (static) | Já existe | ~90s | — |
| **`npm run test` (static)** | **Novo.** Os testes existem e nunca correm | ~10s | Nula |
| **`node --test` (dynamic/worker)** | **Novo.** Idem | ~5s | Nula |
| **`npx astro check`** | **Novo.** 16,8% de TS por verificar | ~30s | Baixa |
| Gitleaks (`fetch-depth: 0`) | Já existe | ~20s | Nula |
| Semgrep (subir para WARNING) | Já existe, mal calibrado | ~60s | Média no 1.º triagem |
| OSV (**+ lockfile do worker**) | Já existe, incompleto | ~30s | Nula |
| zizmor | Já existe | ~15s | Nula |
| `npm audit --audit-level=high` (ambos) | Já existe, só no static | ~10s | Nula |
| **`wrangler deploy --dry-run`** | **Novo.** Gate sem segredo | ~20s | Nula |
| **Playwright: regressão de CSP** | **Novo.** A adição de maior valor | ~40s | Baixa |
| Copilot/CodeRabbit review | Assíncrono, não bloqueia | — | Baixa |

Correr em paralelo: o total de *wall clock* fica nos ~2-3 minutos.

### Merge para `main`

Tudo o do PR, mais:
- **`headers.yml` via `deployment_status`** — já tens, e funciona. Manter.

Não duplicar mais nada: o `main` só recebe o que passou no PR.

### Noturno (`schedule`)

| Passo | Porquê | Tempo |
|---|---|---|
| **`headers.yml` com o `url` corrigido** | Apanha deriva *fora* de deploy — regras de zona, Transform Rules | ~10s |
| OSV + `npm audit` no `main` | Advisories novas aparecem sem commits novos | ~40s |
| *Smoke* dos `/api/*` (curl + `jq`) | Deteta o Worker em 502 antes de o descobrires a olho | ~20s |

O *smoke test* dos endpoints é o que te falta em runtime e custa 15 linhas
de `bash`.

### Semanal

| Passo | Porquê | Tempo |
|---|---|---|
| Renovate (segunda de manhã) | Já configurado | — |
| Lembrete de rotação do `RATE_SALT` | Hoje é memória humana | 1 min manual |
| *(opcional)* Nuclei, subconjunto tuned, IP excluído do honeypot | Valor de narrativa | ~5 min |

### Release / Mensal

- `lockFileMaintenance` do Renovate (já configurado, dia 1).
- **Strix, manualmente ou mensal, só em `dynamic/**`** — ver secção 8.
- Revisão do `osv-scanner.toml`: alguma exceção expirou? (o `ignoreUntil` do
  MAL-2026-10726 é 2026-10-01 — está a ~2 meses).

---

## 7. Modelo de ameaça (leve)

**Ativos, por valor real:** (1) a tua reputação profissional — este site *é*
o argumento; (2) o controlo da conta Cloudflare e do domínio; (3) o
repositório GitHub; (4) a integridade dos dados públicos do painel; (5) a
promessa de privacidade zero-PII que fazes explicitamente aos visitantes.

Repara que **os dados não são um ativo** — não há dados pessoais, por
desenho. Isso elimina de uma vez a maior parte do modelo de ameaça de uma
app web, e é a decisão de segurança mais forte do projeto inteiro.

| Ameaça | Probabilidade | Impacto | Estado |
|---|---|---|---|
| Varrimento automatizado de massa (`/.env`, `/wp-login.php`) | **Certa, contínua** | Nulo | Coberto — é literalmente o *feature* |
| **Esgotamento da quota de escrita do KV** | **Média** | **Alto** — desliga honeypot, vitals, CSP, firewall 7d | **Descoberto** — lacuna #1 |
| Vandalismo de dados: poluir os painéis públicos com eventos falsos | **Média** | Médio — mina a credibilidade, que é o ativo | Parcial: cap de 60/dia limita o volume, mas não a *composição* (um só ASN pode dominar o "top ASN" com 60 pedidos) |
| XSS via feeds de terceiros (CISA KEV / NVD comprometido ou envenenado) | Baixa | Alto | **Bem coberto** — `sanitize.js` + `textContent` + `trusted-types 'none'` |
| Regressão de CSP por atualização do Astro | **Média-alta** | Médio-alto — painéis partidos, silenciosamente | **Não coberto** — é o argumento do Playwright |
| Comprometimento de dependência npm | Baixa | Alto | Bem coberto — `minimumReleaseAge`, OSV, Dependabot, superfície minúscula |
| Action do GitHub comprometida | Baixa | **Alto** — mas sem token da Cloudflare, o estrago limita-se ao repo | Bem coberto — pins por SHA, `permissions: {}`, zizmor |
| Takeover da conta Cloudflare | Muito baixa | **Crítico** — domínio, DNS, tudo | **Verificar: MFA com chave de hardware, não TOTP.** Não é verificável a partir do repo |
| Phishing por spoofing de email do domínio | Média | Médio-alto — reputação | **Não coberto** — sem DMARC |
| Fuga de PII por regressão de código | Baixa | **Alto** — quebra uma promessa pública explícita | Parcial: a disciplina está documentada, mas nada impede um PR futuro de persistir `cf-connecting-ip` |
| DoS ao Worker (esgotar invocações) | Baixa | Médio | Parcial: WAF de zona planeado; o rate limiting está no sítio errado |

**Ataque mais provável:** varrimento de massa. Já está a acontecer, e não te
faz mal nenhum. Ignora-o.

**Ataque de maior impacto:** takeover da conta Cloudflare. Não é código, é
higiene de conta — **MFA com chave de hardware (WebAuthn), não TOTP por SMS
nem por app**. Se ainda não estiver, é a coisa mais importante deste
documento que não custa uma linha de código.

**Abuso mais realista:** alguém que leia o teu site, perceba que os painéis
são alimentados por endpoints públicos sem autenticação, e decida ver o que
acontece se martelar `/api/mirror`. Não é malícia sofisticada — é
curiosidade, que é exatamente o público que este site atrai. **O teu site
convida ativamente o teste que o parte.** Isso é o argumento mais forte para
tratar a lacuna #1 primeiro.

**Vale a pena registar:** contra um PR futuro que quebre a promessa de
zero-PII, o controlo certo não é um scanner — é uma regra Semgrep própria
que proíba `cf-connecting-ip` em qualquer caminho que termine em `KV.put`,
com uma exceção anotada para o `ratelimit.js`. Cinco linhas em `.semgrep/`,
no mesmo estilo das que já lá tens.

---

## 8. Custo-benefício: Strix por PR?

**Não. Claramente não.** Três razões, por ordem de peso:

1. **A maior parte dos teus PRs não tem superfície de ataque.** Pelo teu
   próprio labeler, os PRs dividem-se em `content`, `static`, `dynamic`,
   `documentation`, `ci`. Um PR que adiciona um post em markdown ou corrige
   uma string de i18n não tem nada para um agente de pentest explorar.
   Gastar tokens nele é gastar por gastar.
2. **Não há modelo de autorização.** Strix ganha o seu valor em IDOR,
   escalamento de privilégios e encadeamento de authz. Não tens autenticação
   nenhuma — não há privilégio para escalar. O melhor da ferramenta não se
   aplica.
3. **O ambiente é hostil ao agente.** Sem `wrangler dev --remote` não há
   `request.cf`, o KV é local e vazio, e os limites de quota — a tua ameaça
   real — não existem em dev. Strix estaria a testar uma coisa que não é o
   teu sistema.

### Cadência recomendada

**Por evento, não por calendário.** Concretamente:

```yaml
on:
  pull_request:
    paths: ['dynamic/**']     # já tens este recorte no labeler
  workflow_dispatch:
  schedule:
    - cron: '0 5 1 * *'       # mensal, contra produção
```

- **Em PRs que tocam `dynamic/**`** — é onde vive a lógica que pode ter
  bugs de abuso. Na tua cadência, isto são talvez 2-4 PRs por mês, não 30.
- **Mensal contra produção**, onde o KV é real, o `request.cf` existe e as
  quotas são as verdadeiras. É a única configuração em que Strix teria uma
  hipótese honesta de encontrar algo como a lacuna #1.
- **`workflow_dispatch`** antes de cada feature dinâmica nova — em especial
  **antes de lançar as ferramentas de DNS/WHOIS**, que são a primeira vez
  que aceitas um destino de rede controlado pelo utilizador. Essa sim é uma
  campanha de pentest que se justifica, e vale mais do que 12 meses de
  execuções por PR.

Custo estimado nesta cadência: uma pequena fração do que custaria por PR,
com maior probabilidade de achado por execução — porque cada execução
acontece onde há algo para encontrar.

---

## 9. Recomendações finais

### Top 5 — maior ROI de segurança

1. **Corrigir o esgotamento da quota de KV pelo rate limiter** (lacuna #1).
   *Binding* nativo de rate limiting da Cloudflare + regra de zona. É o único
   problema explorável a sério do sistema, e desliga precisamente as tuas
   defesas.
2. **Correr os testes e o `astro check` em CI.** ~10 linhas de YAML. Ativa
   seis ficheiros de teste que já escreveste e que hoje não valem nada.
3. **Corrigir o `url` no `expected-headers.json`** e adicionar o lockfile do
   Worker ao OSV. Duas linhas, duas lacunas fechadas.
4. **MFA com chave de hardware na Cloudflare e no GitHub, e DMARC
   `p=reject` + null MX no domínio.** Fora do código, maior impacto por
   minuto investido do que qualquer scanner desta lista.
5. **`[observability] enabled = true` no Worker.** Sem retenção de logs não
   há resposta a incidentes — só reconstituição a partir de nada.

### Top 5 — maior valor de portfólio

1. **Tornar o repositório público** (se ainda não é). Desbloqueia CodeQL
   grátis, CodeRabbit grátis, e — mais importante — transforma esta CI toda
   em prova visível. O `security.yml` que escreveste é melhor argumento de
   contratação do que qualquer post de blog.
2. **Testes Playwright de regressão de CSP.** "Tenho um teste E2E que falha
   se alguma página violar a minha própria CSP" é uma frase que muito poucos
   engenheiros conseguem dizer, e é *verdadeiramente* uma boa prática, não
   teatro.
3. **CodeQL** (condicional a #1). Selo reconhecível, sinal real, manutenção
   quase nula.
4. **Publicar este próprio documento** — ou a sua narrativa — na secção
   Segurança do site. Uma revisão de postura que encontra um bug real no teu
   próprio sistema e o corrige em público vale mais do que uma lista de
   *badges*. Vale especialmente a lacuna #1: é uma história de segurança
   genuinamente interessante (o rate limiter que consome a quota que protege
   o detetor).
5. **Escrever a página "modelo de ameaça" a partir da secção 7.** Encaixa
   perfeitamente na estética do site e demonstra a competência que
   diferencia — modelar ameaças, não correr scanners.

### Ferramentas a evitar

- **Trivy** — não tens contentores, IaC nem imagens. Zero achados, um job a
  mais.
- **OWASP ZAP** — duplica, pior, um controlo que já tens (`check-headers.mjs`).
  Adicioná-lo é treinar-te a ignorar alertas.
- **Nuclei no caminho de PR** — e, se o usares de todo, com subconjunto
  apertado e IP excluído, senão poluis o teu próprio honeypot.
- **CodeRabbit *e* Copilot Review ao mesmo tempo** — escolhe um.
- **Strix por PR** — ver secção 8.
- **Mais qualquer scanner de SAST ou de dependências.** Estás **saturado**
  nessas duas áreas: OSV + Dependabot + Renovate + `npm audit` cobrem
  dependências com folga, e Semgrep + (eventualmente) CodeQL cobrem SAST. Se
  te apetecer adicionar alguma coisa a essas áreas nos próximos 12 meses, a
  resposta certa é quase de certeza não.

### Pontuação global: **72/100**

| Área | Peso | Nota |
|---|---|---|
| Segredos & cadeia de fornecimento | 20 | 16 |
| Dependências | 15 | 11 |
| Análise estática & testes | 20 | 11 |
| CI/CD | 15 | 12 |
| Runtime & Cloudflare | 20 | 12 |
| Modelação de ameaças & documentação | 10 | 10 |

Contexto para o número: 72 num site pessoal é muito alto. A média nesta
categoria anda nos 25-35 (sem CI de segurança nenhuma). O que impede este
projeto de estar nos 85+ não é ferramenta nenhuma da tua lista — é que
**controlos que já escreveste não estão ligados** (testes, o cron de
headers, o lockfile do Worker) e há **um bug de lógica por corrigir**.
Fechar essas quatro coisas leva-te a ~85 sem instalar praticamente nada.
Nota máxima na modelação de ameaças e documentação: o `PLAN.md`, com
decisões datadas, custos registados e correções de conclusões erradas, é
melhor do que o que a maioria das equipas produz.

### Reavaliação — ronda 1 (PR #126): 87/100 → ronda 2 (PR #128): **94/100**

| Área | Peso | Inicial | Ronda 1 | Ronda 2 | Porquê mudou na ronda 2 |
|---|---|---|---|---|---|
| Segredos & cadeia de fornecimento | 20 | 16 | 18 | **19** | MFA confirmado (Yubikey principal + backup, Cloudflare e GitHub) |
| Dependências | 15 | 11 | 14 | **14** | Sem alterações nesta ronda — já perto do máximo |
| Análise estática & testes | 20 | 11 | 15 | **19** | `astro check` fechado: 37 erros reais corrigidos (incluindo um bug real de UI, texto "undefined" em produção), 0 erros/warnings/hints, ligado ao `ci.yml`. (Ronda 3 fechou também a triagem do Semgrep — ver secção acima) |
| CI/CD | 15 | 12 | 14 | **14** | Sem alterações — branch protection continua bloqueada pelo plano GitHub (privado, conta pessoal), confirmado no dashboard, não é um erro de configuração |
| Runtime & Cloudflare | 20 | 12 | 16 | **18** | Deploy automático confirmado (Workers Builds); WAF fechado por decisão explícita e documentada; uma regressão real (Access + `expected-headers.json`) apanhada e corrigida antes de causar dano. Desconto: CAA confirmado em falta por consulta DNS ao vivo |
| Modelação de ameaças & documentação | 10 | 10 | 10 | **10** | Sem alterações — já estava no máximo |

**94/100.** O que falta para os últimos 6 pontos, por ordem de esforço: CAA
(sete linhas no DNS, cinco minutos — o mais barato de todos) e branch
protection/rate limiting nativo da zona (bloqueados por plano — Cloudflare
Free não tem rate limiting de zona grátis além de 1 regra, GitHub privado
não aplica proteção sem Team/Enterprise). A triagem do Semgrep, que estava
nesta lista, foi feita na ronda 3 e o gate já cobre `WARNING`. Nenhum dos
que restam é um problema de ferramenta em falta; são uma tarefa de cinco
minutos e duas decisões de plano/custo que só o dono do repo pode tomar.

### Roteiro a 12 meses

**Mês 1 — fechar o que já está escrito (esforço: ~1 dia)**
Rate limiting fora do KV · testes + `astro check` em CI · `url` dos headers
· lockfile do Worker no OSV · `[observability]` · `compatibility_date` ·
MFA por hardware · DMARC/SPF/null MX.
→ **Isto sozinho leva-te de 72 a ~85.**

**Mês 2-3 — cobrir a fragilidade estrutural**
Playwright para regressão de CSP · decidir sobre repo público → CodeQL ·
escolher **um** revisor de IA · ~~Semgrep a `WARNING` com triagem única~~
(feito, ronda 3) · regra Semgrep própria anti-PII (`cf-connecting-ip` →
`KV.put`) ·
`wrangler deploy --dry-run` em CI.

**Mês 4-6 — runtime e conteúdo**
*Smoke test* noturno dos `/api/*` · migrar as caches puras de KV para Cache
API · `harden-runner` · `CODEOWNERS` · publicar a página de modelo de
ameaça e o *writeup* da lacuna #1.

**Mês 7-9 — antes das ferramentas de DNS/WHOIS**
Registar no `PLAN.md` a decisão e as defesas anti-SSRF **antes** de
escrever código · vetores de teste de SSRF a acompanhar a implementação ·
campanha Strix de `workflow_dispatch` sobre a feature nova, em produção ·
reavaliar o rate limiting (Durable Objects só se as garantias por colo se
revelarem insuficientes).

**Mês 10-12 — manutenção e consolidação**
Rever o `osv-scanner.toml` (exceções expiradas) · reavaliar se o revisor de
IA escolhido continua a dar valor ou virou ruído — **e desligá-lo se virou**
· Strix mensal se as execuções anteriores produziram achados, descontinuar
se não · rever esta revisão.

**Nota final, e é a mais importante:** a tendência natural daqui em diante é
adicionar. Resiste. Este projeto já tem mais cobertura de segurança do que
precisa em duas das seis áreas, e menos execução do que devia em três. O
próximo ano deve ser sobre **ligar, calibrar e desligar**, não sobre
instalar. Se em julho de 2027 tiveres exatamente as mesmas ferramentas de
hoje mais o Playwright e o CodeQL, e todas com sinal que leias de facto,
esta foi a decisão certa.
