# Home — revisão editorial: de stats pessoais para stats do site

Análise editorial da zona inicial da Home (`/` e `/en/`). **Não contém código.**
Toda a copy proposta destina-se a `static/src/i18n/ui.ts` (chaves `home.*`, nos
dois blocos de idioma: PT ~linha 479, EN ~linha 1439).

Números verificados a 2026-07-28, a partir de `content/`, de `routes.ts` e de um
build real (`npm run build` — 59 páginas).

---

## 0) Factos apurados (base da análise)

| Facto | Valor | Fonte |
|---|---|---|
| Páginas HTML no build | 59 | `dist/` |
| Pares bilingues (PT+EN) | **29** | 29 EN + 29 PT + 1 `404` só PT |
| Ferramentas | **11** (8 client-side, 3 com servidor) | `ToolsIndexPage.astro` |
| Ferramentas listadas na Home | 6 | `HomePage.astro` |
| Projetos | 4 por idioma | `content/projects/` |
| **Posts publicados** | **0** (1 rascunho por idioma) | `draft: true` em `hello-world.md` |
| Pares de rotas | 16 | `routes.ts` |
| Camadas "Este site" | 4 + visão geral | `SiteLayers` |
| Regras Sigma | 5 | `content/detections.json` |
| Paths-isco (decoys) | 5 | `DECOYS` + `content/honeypot-attack.json` |
| Cabeçalhos pontuados no self-scan | 8 | `dynamic/worker/src/lib/scan.js` |
| Táticas / técnicas ATT&CK | 14 / 40 | `content/attack.json` |
| Certificações | 31 total, 12 verificáveis | `content/certs.json` |
| CTFs vencidos | 4 | `content/awards.json` |

Três incoerências que esta mudança deve resolver (ver §7):

1. **`meta` diz "6+ anos em segurança", o widget diz "9+ anos em redes &
   segurança".** Ambos são defensáveis (segurança desde 2020; redes+segurança
   desde 2017), mas estão a 200 px um do outro no mesmo ecrã. Lidos juntos,
   parecem um erro.
2. **A secção da Home chama-se "Ferramentas · client-side" e lista 6**, quando
   há 8 client-side e 11 no total. Se o widget novo disser "11 ferramentas", a
   contradição fica visível no mesmo ecrã.
3. **Não há posts publicados.** A secção "Últimos posts" não renderiza de todo.

---

## 1) Diagnóstico editorial

### Faz sentido remover o widget de stats pessoais? Sim.

O argumento mais forte não é "há números a mais" — é **redundância de eixo**. A
zona inicial da Home tem hoje dois blocos lado a lado que dizem a mesma coisa:

- bloco de identidade → "quem sou" (nome, papel, bio, meta, chips);
- widget de stats → "quem sou, mas com números maiores".

Dois painéis, um só eixo. E imediatamente abaixo vem o **Percurso**, que é a
terceira versão da mesma mensagem — desta vez a versão boa, porque é concreta e
datada (5 paragens, 5 países, empregadores nomeados). O widget de stats é o elo
mais fraco dos três: é o único que afirma sem mostrar.

Há um segundo problema, de registo. `9+`, `31`, `12`, `4` em números grandes é a
gramática visual do *pitch*, não a de quem documenta trabalho. O resto do site
segue a lógica oposta ("não acredites, verifica"): `/provas/`, `/certificacoes/`,
a galeria de coins dos CTFs, o commit SHA no rodapé de `/este-site/`. O widget é
o único sítio onde o site pede que se acredite num número por ele ser grande.

### O que se ganha

- **A Home passa a ter dois eixos em vez de um.** Esquerda: quem sou. Direita: o
  que é este site. É a diferença entre um cartão de visita e um índice.
- **Coerência de tom.** Sai o único bloco genuinamente promocional da Home.
- **O Percurso deixa de competir.** Sem o widget a antecipar "9+ anos", a
  timeline volta a ser a prova, em vez de ilustração de um número já dado.
- **Resolve a incoerência 6+/9+** por construção: passa a haver um número só.

### O que se perde (e é preciso ser honesto)

- **Densidade imediata de credibilidade.** Um recrutador que aterre na Home 8
  segundos via LinkedIn apanhava "31 certificações" sem scroll. Isso é uma perda
  real, não imaginária.
  *Mitigação:* a informação não desaparece — desce para a linha de credenciais do
  bloco de identidade (§5), ainda acima da dobra, mas em peso tipográfico de
  facto e não de anúncio.
- **O contraste visual da grelha de 4.** Os números grandes davam ritmo à
  coluna direita.
  *Mitigação:* o widget novo herda a mesma grelha e o mesmo peso — o ritmo
  mantém-se, muda a substância.
- **`12 verificáveis · Credly` era o melhor stat do conjunto** (é o único
  auditável por terceiros num clique) e perde protagonismo.
  *Mitigação:* mantê-lo com ligação a `/certificacoes/` na linha de credenciais.

### Esta informação fica melhor no bloco de identidade? Fica — com uma condição.

Fica melhor porque **muda de género**: deixa de ser métrica e passa a ser
qualificador. "31 certificações" isolado num painel é uma afirmação de escala;
"31 certificações, 12 verificáveis no Credly" numa linha discreta por baixo da
meta é uma nota de rodapé factual. Mesmo número, registo oposto.

A condição: **não pode entrar tudo na prosa.** Se os quatro números forem para a
bio, a bio vira parágrafo de CV.

### Como evitar que o bloco fique pesado / promocional / "CV"

Quatro regras concretas:

1. **Uma camada, um tipo de informação.** Prosa = o que faço. Meta = coordenadas
   (onde, desde quando, formação). Chips = etiquetas de domínio. Linha de
   credenciais = os números auditáveis. Nunca repetir um facto em duas camadas.
2. **Nenhum número novo na prosa.** A bio proposta em §6 não ganha um único
   algarismo. Os números vivem em `meta`, `chips` e na linha de credenciais.
3. **Um número por conceito.** Não coexistem "6+ anos" e "9+ anos"; não coexistem
   "31 certificações" na meta e nos chips.
4. **Todo o número tem destino.** Se um número não puder ligar a uma página que o
   prove, não pertence ao bloco de identidade — pertence ao CV.

---

## 2) Novo papel da Home

Depois da mudança, a Home deve responder a três perguntas, por esta ordem, e a
mais nenhuma:

1. **Quem é esta pessoa?** → bloco de identidade (nome, papel, bio, meta, chips,
   credenciais).
2. **O que é este sítio e o que é que ele tem lá dentro?** → widget de stats do
   site.
3. **Por onde entro?** → Percurso, posts, projetos, ferramentas.

O modelo mental certo é **capa de documentação técnica**, não landing page: uma
identificação sóbria em cima, um sumário do que a coisa contém, e depois os
pontos de entrada. Um `README.md` bem escrito, essencialmente.

A mudança de eixo é esta:

| Antes | Depois |
|---|---|
| "Eu tenho 31 certificações" | "Eu faço isto; este site é parte disso" |
| Home = vitrine de números pessoais | Home = índice de um sistema vivo |
| Prova = o tamanho do número | Prova = a ligação para a página que o mostra |

O widget novo é o que faz a dobradiça: é o primeiro sítio onde o site fala de si
próprio como objeto técnico, e passa naturalmente o testemunho a `/este-site/`.

**Limite importante:** a Home mostra a **estrutura** do sistema (o que existe,
quanto existe). O **estado operacional** (versão, commit, deploy, saúde do
Worker) já vive em `/este-site/` e deve continuar lá. Se a Home duplicar o painel
de estado, fica com um mini-dashboard redundante e um segundo sítio para as
coisas ficarem dessincronizadas. Esta separação é o critério central de §3.

---

## 3) Widget de stats do site — análise métrica a métrica

Grelha de avaliação: **força editorial** (diz algo verdadeiro sobre o site?),
**estabilidade** (muda de forma legível ou salta?), **útil vs. gimmick**, **sítio
certo**.

### Recomendadas

**Páginas bilingues — 29 pares**
Forte. O bilinguismo é uma decisão de arquitetura do projeto (regra 1 do
CLAUDE.md), não um extra: cada rota existe em PT e EN com paridade real. Um
número que mostra disciplina estrutural, não volume.
Estável (cresce devagar, monotonicamente). Útil. Sítio certo: Home.
*Nota:* dizer "29 páginas, cada uma em PT e EN" é mais honesto e mais impressivo
do que "58 páginas" — 58 sobrevaloriza, e o par é que é o facto interessante.

**Ferramentas — 11 (8 no browser, 3 com servidor)**
Forte. É a coisa mais concretamente útil que o site oferece a um estranho, e a
divisão client-side/servidor é exatamente a distinção de privacidade que o site
já faz questão de assinalar por badge.
Estável. Útil. Sítio certo: Home.
*Bloqueio a resolver primeiro:* a secção logo abaixo diz "Ferramentas ·
client-side" e lista 6. Ou o widget diz 11 e a secção passa a "Ferramentas"
com nota "6 de 11", ou há contradição visível no mesmo ecrã.

**Cabeçalhos de segurança verificados — 8**
Forte, e o mais alinhado com o tom do site: não é "somos seguros", é "há 8
controlos e podes correr o scanner tu próprio". Liga a `/provas/` e à ferramenta
self-scan.
Estável. Útil (não gimmick — é auditável em tempo real por qualquer visitante).
Sítio certo: Home, com ligação a `/provas/`.
*Ressalva de implementação:* o número vive em `dynamic/worker/src/lib/scan.js`,
que o site estático não importa. Fica manual, com risco de deriva — ver §7.

**Paths-isco → regras Sigma — 5 → 5**
Forte, e é o número mais distintivo do site inteiro. Não diz "tenho um
honeypot"; diz que existe um *pipeline* fechado (isco → técnica ATT&CK → regra
de deteção), com um teste no Worker a garantir a sincronização. É o stat que
melhor justifica a frase "o site é um sistema vivo".
Estável (derivável de `content/`). Útil. Sítio certo: Home — é a única métrica da
lista que um visitante não esperaria, e liga a `/perimetro/` e `/lab/`.

### Rejeitadas — e porquê

**Posts — 0 publicados. Rejeitada, sem hesitação.**
Neste momento o único post é `draft: true` nos dois idiomas, a secção "Últimos
posts" não renderiza e não existe `/blog/` no build. Um widget que anuncie "0
posts" documenta um site vazio; omitir a métrica e manter a secção do blog
oculta é mais honesto. **Reavaliar a partir de ~5 posts publicados** — aí passa a
métrica forte, porque cadência editorial é sinal real.

**Projetos — 4. Rejeitada por redundância.**
O número é honesto, mas os 4 projetos estão listados por extenso a meio da mesma
página. Contar o que está visível dois ecrãs abaixo não acrescenta informação —
gasta um tile dos quatro.

**Técnicas ATT&CK — 40. Rejeitada, com aviso.**
Editorialmente arriscada. "40 técnicas" numa grelha de stats do site lê-se como
alegação de cobertura defensiva, e a maior parte de `attack.json` descreve
controlos do trabalho na Ascendi, não deste site. É a métrica mais próxima de
inflação da lista toda. Fica bem onde já está: `/attack/`, com o contexto do
heatmap a qualificá-la.

**Estado operacional / saúde do Worker. Rejeitada nesta forma.**
Duplica exatamente o painel de `/este-site/`, exige fetch no cliente e introduz a
possibilidade de a Home mostrar um ponto vermelho como primeira impressão do
site. Um badge ao vivo na Home é a definição de dashboard aleatório.

**Último deploy / commit / versão. Rejeitada como tile; aproveitável como
microcopy.**
Como tile é volátil e semanticamente pobre (um `n` que é uma data não é um `n`).
Como linha discreta de rodapé do widget — "estado ao vivo em Este site →" — faz
o trabalho todo sem gastar um tile e sem duplicar dados.

**Secções do site. Rejeitada por vagueza.**
"Secções" não tem definição estável: 16 pares de rotas? 4 camadas? 7 itens de
nav? Uma métrica cuja definição é discutível não é auditável, e este site
vende-se em auditabilidade.

**Eventos do honeypot / ataques bloqueados. Rejeitada para a Home.**
Volátil por natureza (um scanner faz saltar o número numa tarde) e vaidosa na
substância — "1.284 ataques" mede a internet, não o site. Já vive bem em
`/perimetro/`, com janela temporal explícita, que é o contexto que a torna
legítima.

**Total de repos do catálogo GitHub — 550.** Já rejeitada pelo próprio código
(comentário em `HomePage.astro`: "sinais de competência, não de consumo"). O
julgamento mantém-se: é métrica de consumo. Fica em `/links/`.

---

## 4) Recomendação final para o widget

**Quatro métricas.** Não três, não seis. Quatro mantém a grelha 2×2 existente
(zero trabalho de layout), e há exatamente quatro métricas que passam os quatro
critérios — a quinta melhor candidata já é claramente mais fraca.

| # | Valor | Métrica | Liga a |
|---|---|---|---|
| 1 | 29 | páginas, cada uma em PT e EN | `/este-site/` |
| 2 | 11 | ferramentas · 8 no browser | `/ferramentas/` |
| 3 | 8 | cabeçalhos de segurança verificados | `/provas/` |
| 4 | 5 | paths-isco → regras Sigma | `/perimetro/` |

**A lógica do conjunto** — e é isto que impede o widget de parecer aleatório: os
quatro tiles contam uma frase, por esta ordem.

> O site é bilingue por construção **(1)**, dá ferramentas que funcionam sem te
> pedir dados **(2)**, defende-se a si próprio de forma verificável **(3)**, e
> transforma o que o ataca em deteções **(4)**.

Estrutura → utilidade → postura → sistema vivo. Um dashboard aleatório é um
conjunto de números que partilham uma grelha; isto é uma sequência argumentativa
onde cada tile justifica o seguinte. É o teste a aplicar a qualquer métrica que
se queira acrescentar no futuro: **cabe na frase?** Se não couber, não entra.

**Tom: técnico-estrutural, não operacional.** O widget descreve o que o site *é*
e *tem* — inventário, não telemetria. O operacional (versão, commit, deploy,
saúde) fica em `/este-site/`, e o widget aponta para lá numa linha de microcopy.
Esta é a fronteira que evita a duplicação, e deve ser mantida explicitamente.

**Três regras de execução:**

- **Cada tile liga à página que o prova.** É a continuação direta do padrão que
  o widget atual já usa nos stats de certificações, e é o que distingue este
  widget de uma infografia: cada número é o início de um caminho, não o fim.
- **Nenhum número redondo ou arredondado.** 29, 11, 8, 5. Números pequenos e
  exatos são mais credíveis do que números grandes e vagos — e são a razão pela
  qual este widget não se lê como marketing.
- **Nenhum número inventado ou "a crescer".** Se uma métrica não for derivável
  hoje de `content/` ou do build, ou é assumida como manual com comentário (caso
  dos 8 cabeçalhos), ou não entra.

---

## 5) Bloco de identidade — como absorver a informação

Cinco camadas, cada uma com um trabalho, nenhum facto repetido:

| Camada | Trabalho | O que absorve do widget |
|---|---|---|
| `bio` (prosa) | o que faço, e que este site faz parte disso | **nada** — zero números |
| `meta` | coordenadas: onde, desde quando, formação | **anos de experiência** |
| linha de credenciais (nova) | os números auditáveis | **certificações + verificáveis** |
| `chips` | etiquetas de domínio | **CTFs vencidos** |
| Percurso (abaixo) | a prova dos anos | — |

### Onde integrar "anos de experiência" → `meta`

A `meta` já tem o item, só está com o número errado do ponto de vista da
coerência. Substituir `6+ anos em segurança` por `9+ anos em redes & segurança`
resolve a incoerência com o widget antigo e alarga corretamente o âmbito — o
Percurso, logo abaixo, mostra 2017–18 em Doha e Santos, que é trabalho de redes.

*Alternativa a considerar:* `redes & segurança desde 2017` nunca fica
desatualizado, enquanto `9+` exige lembrar de o bumpar. Fica a repetição de
"desde" com o item da Ascendi, mas ganha-se um facto que nunca envelhece — e
"desde 2017" é mais auditável do que "9+ anos", que obriga o leitor a confiar
numa conta. **Recomendo `9+ anos` por fluidez de leitura, mas a variante `desde
2017` é editorialmente superior** e a escolha é legítima nos dois sentidos.

### Onde integrar "certificações" → linha curta separada

Não na prosa (vira CV). Não nos chips (os chips são domínios, não contagens —
e 31 num chip lê-se como troféu). Não na `meta` a par das coordenadas, porque
são dois números e a `meta` ficaria com quatro itens desequilibrados.

**Uma linha curta própria, imediatamente abaixo da `meta`, com ligação a
`/certificacoes/`.** Junta os dois números num só facto legível e mantém o
convite à verificação. É a camada que o widget deixa vaga, e é discreta por
posição e por peso tipográfico — não por esconder informação.

### "Credenciais verificáveis" — discreto, mas ligado

**Discreto, sim; escondido, não.** É a única credencial auditável por terceiros
e o gesto que define o tom do site. A forma certa é `12 verificáveis no Credly`
dentro da linha de credenciais, com a linha inteira a ligar a `/certificacoes/`
(que por sua vez liga ao Credly). No texto principal seria promocional; fora da
Home seria desperdiçar o melhor argumento.

### "CTFs vencidos" — sim, mas nos chips

Merece ficar na Home: é resultado, é datado, tem prova fotográfica na página
Sobre. Mas não na prosa nem na meta.

**Nos chips, substituindo `CTF Winner '22` por `4 CTFs vencidos`.** O chip já lá
está a fazer este trabalho com um só evento; passar a contagem absorve o stat sem
acrescentar uma camada nova. Os chips são o registo certo — etiquetas de baixo
peso, sem números grandes.

### Como manter curto e natural

A bio ganha **uma** frase, não duas, e essa frase existe por razão estrutural:
apresenta o site como parte do trabalho, o que dá cobertura editorial ao widget
que está mesmo ao lado. Sem ela, o widget de stats do site aparece sem
introdução. Com ela, o painel da direita passa a ser a resposta à última frase do
painel da esquerda — os dois blocos passam a conversar em vez de coexistir.

Contagem final do bloco: 3 frases de prosa, 3 itens de meta, 1 linha de
credenciais, 5 chips. Todos os números do widget antigo continuam presentes; a
Home deixa de os anunciar.

---

## 6) Copy final — pronta a usar

### `home.bio`

**PT**
> Planeio e opero segurança de redes em infraestrutura crítica — e construo as
> ferramentas que uso para o fazer. Foco em threat intelligence, forense digital
> e resposta a incidentes. Este site faz parte do trabalho: as ferramentas, o
> perímetro e as deteções estão públicos.

**EN**
> I plan and operate network security for critical infrastructure — and I build
> the tools I use to do it. Focused on threat intelligence, digital forensics,
> and incident response. This site is part of the work: the tools, the perimeter,
> and the detections are public.

*(As duas primeiras frases mantêm-se inalteradas. A terceira é a ponte para o
widget. "deteções" — grafia europeia pós-AO90, consistente com o resto do
repositório.)*

### `home.meta`

**PT** — `@ Ascendi · desde 2020` · `MSc · FEUP` · `9+ anos em redes & segurança`
**EN** — `@ Ascendi · since 2020` · `MSc · FEUP` · `9+ years in networking & security`

*Variante sem prazo de validade (ver §5):*
PT `redes & segurança desde 2017` — EN `networking & security since 2017`

### Linha de credenciais (nova)

**PT** — `31 certificações · 12 verificáveis no Credly`
**EN** — `31 certifications · 12 verifiable on Credly`

*Ligação:* linha inteira → `/certificacoes/` · `/en/certifications/`.
*Se for preciso um rótulo de ligação separado:* PT `ver todas →` · EN `see all →`

### `home.chips`

**PT** — `Fortinet NSE 4/5/6/7` · `SANS SEC504` · `4 CTFs vencidos` · `ISO 27001` · `MITRE ATT&CK`
**EN** — `Fortinet NSE 4/5/6/7` · `SANS SEC504` · `4 CTFs won` · `ISO 27001` · `MITRE ATT&CK`

*(Única alteração: `CTF Winner '22` → contagem. Os restantes quatro mantêm-se.)*

### Título do widget (`home.statsLabel`)

**PT** — `stats do site`
**EN** — `site stats`

Renderiza como `// stats do site`, mantendo o padrão `phead` existente.
*Alternativa mais sóbria, se `stats` parecer herdado do widget antigo:*
PT `estrutura` — EN `structure`.

### Tiles do widget

| # | `n` | `d` PT | `d` EN | tom |
|---|---|---|---|---|
| 1 | `29` | `páginas · cada uma em PT e EN` | `pages · each in PT and EN` | green |
| 2 | `11` | `ferramentas · 8 no browser` | `tools · 8 in-browser` | green |
| 3 | `8` | `cabeçalhos de segurança verificados` | `security headers verified` | blue |
| 4 | `5` | `paths-isco → regras Sigma` | `decoy paths → Sigma rules` | amber |

Tons segundo a convenção existente (`green` / `blue` / `amber`), com âmbar
reservado ao tile do honeypot — coerente com o uso de âmbar para Lab/avisos.

*Se as etiquetas 3 e 4 forem longas de mais para a grelha em mobile:*
PT `cabeçalhos verificados` / `paths-isco → Sigma`
EN `headers verified` / `decoys → Sigma`

### Microcopy de rodapé do widget

**PT** — `Números do build, não escritos à mão. Estado ao vivo em Este site →`
**EN** — `Numbers from the build, not hand-typed. Live status on This site →`

Faz três coisas de uma vez: declara a proveniência dos números (que é o
argumento de credibilidade), dá saída para `/este-site/`, e mantém o estado
operacional fora da Home. **Só usar a primeira frase se as métricas forem de
facto derivadas** — ver a ressalva dos cabeçalhos em §7.

---

## 7) Implementação no projeto

### Onde

**Tudo em `static/src/i18n/ui.ts`**, nos dois blocos de idioma (`pt` ~479,
`en` ~1439), por regra 2 do CLAUDE.md — zero strings nos componentes.

### Chaves da Home a mudar

| Chave | Ação |
|---|---|
| `home.bio` | reescrever (PT + EN) — +1 frase |
| `home.meta` | 3.º item: `6+ anos em segurança` → `9+ anos em redes & segurança` |
| `home.chips` | 3.º chip: `CTF Winner '22` → `4 CTFs vencidos` / `4 CTFs won` |
| `home.statsLabel` | `stats` → `stats do site` / `site stats` |
| `home.statsStatic` | substituir os 4 itens; trocar as chaves `certsTotal`/`certs`/`awards` por `pages`/`tools`/`headers`/`decoys` |
| `home.credentials` | **nova** — linha de credenciais |
| `home.statsNote` | **nova** — microcopy de rodapé do widget |
| `home.featuredTools` | rever: "Ferramentas · client-side" com 6 listadas vs. "11 ferramentas" no widget |

### O widget pessoal desaparece por completo?

**O conceito, sim; o painel, não.** O `<section class="panel">` da direita, a
grelha `stats-grid`, os tiles `n`/`l` e os tons mantêm-se tal como estão — o
layout não muda. O que é integralmente substituído é a *semântica*: nenhuma
métrica pessoal deve sobrar no painel, nem sequer uma. Um painel com três stats
do site e um "31 certificações" perdido no canto é pior do que qualquer das duas
versões puras, porque destrói a frase de §4.

Comentários a atualizar em `HomePage.astro` (o bloco "Stats: sinais de
competência, não de consumo") — passam a descrever critério estrutural, não de
competência.

### O que deve passar a ser derivado

**Derivar (recomendado):**
- **Ferramentas (11 / 8 client-side)** — derivável da mesma lista que
  `ToolsIndexPage.astro` já usa, contando por `kind`. Elimina a deriva entre o
  widget e o índice de ferramentas, que é a mais provável de todas.
- **Paths-isco e regras Sigma (5 / 5)** — deriváveis de
  `content/honeypot-attack.json` e `content/detections.json`. `content/` é fonte
  de verdade por convenção do projeto, e já há um teste no Worker a garantir que
  os dois ficheiros estão sincronizados.
- **Certificações (31 / 12)** — **já são derivadas** de `content/certs.json` com
  o critério `verified !== false`. A lógica atual em `HomePage.astro` não deve
  ser apagada: migra do widget para a linha de credenciais do bloco de
  identidade, mantendo o mesmo critério da página Certificações.

**Manual, com comentário obrigatório:**
- **Cabeçalhos verificados (8)** — a lista pontuada vive em
  `dynamic/worker/src/lib/scan.js`, que o site estático não importa (fronteira
  `static/` ↔ `dynamic/`). Fica um número manual com risco real de deriva se
  alguém acrescentar um cabeçalho ao scan. Mitigação mínima: comentário na chave
  a apontar para `scan.js`. Em alternativa, mover a lista para
  `content/security-headers.json` e passar os dois lados a lê-la — decisão de
  arquitetura, fora do âmbito desta revisão editorial.
- **Páginas bilingues (29)** — derivável em teoria a partir de `routes.ts` +
  coleções, mas a contagem exata depende de rotas dinâmicas (ferramentas,
  projetos, posts) e o cálculo seria frágil e pouco legível. **Recomendo manual,
  com comentário**, e revisão sempre que se acrescentem rotas. É um número que
  muda poucas vezes por ano.

**Nota:** `awards.length` deixa de alimentar o widget, mas o valor `4` passa para
o chip. Ou o chip fica manual (aceitável — muda uma vez por ano, no máximo), ou
mantém-se derivado de `content/awards.json` como está hoje.

### Ordem sugerida de execução

1. Resolver a contradição das ferramentas (§0.2) — determina se o tile diz 11.
2. Confirmar a contagem de páginas com um build no momento de implementar.
3. Aplicar a copy de §6 em `ui.ts` (PT + EN em simultâneo).
4. Ligar cada tile à respetiva página.
5. `cd static && npm run build` — sem erros nem warnings novos.
6. Reler a Home nos dois idiomas em mobile, com atenção às etiquetas 3 e 4.

---

## 8) Avisos honestos

- **A métrica dos posts é a única fraqueza estrutural exposta por esta análise.**
  Zero posts publicados num site que tem blog, RSS e uma secção "Últimos posts"
  não é um problema do widget — é um problema de conteúdo que o widget tornaria
  visível. Omitir a métrica é a decisão certa hoje; publicar o `hello-world` (ou
  outro post) é a decisão certa a seguir.
- **Os 8 cabeçalhos são o número mais frágil do widget recomendado**, por
  atravessar a fronteira `static/`↔`dynamic/`. Está declarado acima; se a deriva
  incomodar, a alternativa é substituir o tile por "4 camadas documentadas"
  (`/seguranca/`, `/provas/`, `/perimetro/`, `/este-site/performance/`) — mais
  fraco editorialmente, mas 100% derivável de `routes.ts`.
- **"29 páginas" é um número que envelhece em silêncio.** Não rebenta o build
  nem dá erro — apenas fica errado. Vale um comentário na chave a lembrar de o
  rever quando se acrescentam rotas.
- **A perda de impacto imediato para recrutadores é real.** Se essa audiência
  for prioritária, a linha de credenciais deve ficar acima da dobra em mobile —
  o que é uma decisão de layout, não de copy, e vale a pena verificar no browser.
- **Não foi tocada a página Sobre**, por indicação explícita. Vale notar que os
  quatro números pessoais têm lá o seu lugar natural e completo; esta mudança
  não os elimina do site, apenas deixa de os anunciar na Home.
