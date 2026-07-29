# Arquitetura editorial — secção «Este Site»

Análise da subpágina **Perímetro** e proposta de reorganização. Documento
editorial: não contém código, componentes nem TypeScript. Todo o texto citado
aqui vive (ou passará a viver) em `static/src/i18n/ui.ts`, PT e EN lado a lado.

Estado auditado: `PerimeterPage.astro` (1066 linhas), `SiteLayers.astro`,
`BaseLayout.astro`, `routes.ts`, `ui.ts`.

---

## 0) Estado real, antes de discutir

Três correções ao enunciado, verificáveis no repositório:

1. **«Deteções» não é uma página.** É a 2.ª tab de Perímetro, fundida no commit
   `7f1c1a2` («Funde Deteções em Perímetro como 5ª tab»). A rota `/detecoes/`
   deixou de existir. As tabs atuais são **cinco**: Honeypot · Deteções ·
   Cloudflare · Tendências (7d) · Logs.
2. **A secção «Este Site» tem cinco páginas**, não oito: Visão Geral,
   Segurança, Perímetro, Provas, Performance. ATT&CK e Certificações estão
   fora de propósito — o racional está escrito em `BaseLayout.astro:50-54` e no
   cabeçalho de `SiteLayers.astro`: não são sobre o site, são sobre percurso
   pessoal.
3. **As URLs da secção não são coerentes.** Só Performance está aninhada
   (`/este-site/performance/`). Segurança (`/seguranca/`), Perímetro
   (`/perimetro/`) e Provas (`/provas/`) são de topo. A secção é um agrupamento
   de navegação, não uma hierarquia de URLs.

Volume relativo dos componentes de página da secção:

| Página | Linhas | Superfícies live |
|---|---:|---|
| Perímetro | 1066 | ~25 widgets + 8 stat cards + heatmap + mapa + ticker + tabela paginada |
| Performance | 243 | 2 tabs |
| Provas | 228 | build-time + 2 blocos live |
| Visão Geral | 200 | 2 widgets de estado |
| Segurança | 111 | nenhuma |

---

## 1) Diagnóstico

### O problema estrutural

**Perímetro não é uma página. É uma secção disfarçada de página.** Carrega cinco
trabalhos editoriais distintos sob um único `<h1>`, e usa a barra de tabs para
esconder que são distintos.

### Sim, mistura quatro níveis de leitura

| Nível | O que é | Onde está hoje | Frequência de leitura |
|---|---|---|---|
| **Conceptual** | o que é um endpoint-isco, porquê existe, o contrato de privacidade | tab Honeypot (prosa) + 3 notas de rodapé | lê-se uma vez |
| **Metodológico** | pipeline isco → ATT&CK → Sigma, 5 regras completas, `sigma-cli` | tab Deteções | lê-se uma vez, consulta-se depois |
| **Dados agregados ao vivo** | Cloudflare da zona, tendências 7d, heatmap, mapa de tráfego | tabs Cloudflare + Tendências | muda a cada visita |
| **Evidência bruta** | tabela pesquisável e paginada, sem IP | tab Logs | consulta-se, não se lê |

E ainda um quinto trabalho, transversal: **navegação**. Três pontes (ATT&CK,
projeto Honeypot, Deteções→ATT&CK) espalhadas por tabs diferentes, duas delas a
apontar para o mesmo destino.

### Porque é que isto confunde

- **A barra de tabs iguala coisas desiguais.** «Honeypot» (uma explicação) e
  «Logs» (uma tabela de dados) aparecem como pares. Não são. A tab bar declara
  paridade que o conteúdo não tem.
- **As tabs escondem a hierarquia real.** Deteções é *a jusante* de Honeypot.
  Tendências (7d) é *a mesma coisa* que Honeypot (24h), noutra janela. Nada na
  interface diz isso; a leitura lateral sugere quatro assuntos paralelos onde
  há um assunto com quatro profundidades.
- **A página tem dois sujeitos, não um.** O *honeypot deste site* (instrumentação
  própria, dados próprios, contrato de privacidade próprio) e a *zona Cloudflare*
  (telemetria de infraestrutura, que não é honeypot nenhum). Só partilham a
  página porque ambos são «tráfego hostil». O sinal está no código: a tab
  Cloudflare consome as chaves `site.*` de `ui.ts` — o mesmo bloco de strings da
  página **Performance**. O vocabulário já classificou aqueles dados como
  telemetria de zona, não como honeypot.
- **Quebra o contrato documental.** Uma página documental é estável e citável.
  Metade de Perímetro muda a cada minuto. Não é possível citar «o Perímetro»
  sem ambiguidade temporal.
- **Não há deep-link.** Não se pode apontar para uma regra Sigma específica nem
  para as tendências de 7 dias — só para `/perimetro/` mais a instrução «carrega
  na tab X». Numa página cujo argumento é *verifica tu*, isto é caro.
- **O modo de falha é 80% da página.** Sem o Worker publicado, quatro das cinco
  tabs ficam vazias. A explicação e as regras Sigma — que continuam válidas —
  são arrastadas para dentro do mesmo estado de indisponibilidade.
- **Custo de manutenção.** 1066 linhas é a única página da secção que não se lê
  de cima a baixo. Qualquer mudança editorial obriga a navegar lógica de
  fetch, render de tabelas e paginação.

### O que *não* é o problema

O conteúdo. Cada uma das cinco tabs está bem escrita e é honesta — inclusive nas
notas de indisponibilidade. O problema é de arrumação, não de qualidade.

---

## 2) Papel editorial de cada página

Uma frase por página. Se a página não responde à sua pergunta, o conteúdo está
no sítio errado.

| Página | Pergunta a que responde | Registo | Dados live? |
|---|---|---|---|
| **Visão Geral** | «O que é este site e está de pé?» | mapa + estado | estado de componentes, sim |
| **Segurança** | «Que defesas existem, e porquê?» | prosa declarativa | não, por desenho |
| **Provas** | «Como verifico o que ele diz?» | audit trail, gerado no build | build-time, determinístico |
| **Performance** | «Funciona bem para quem visita?» | painel | sim, tráfego legítimo |
| **Perímetro** | «O que é que a Internet tenta contra este site, e o que isso prova?» | ensaio curto com evidência | mínimo |
| **Deteções** | «Como é que isso vira deteção?» | metodologia + artefactos | contadores, marginal |

Nota: Perímetro tem hoje quatro papéis. Deteções não tem papel nenhum, porque
não tem página.

### Onde cada coisa deve viver

| Conteúdo | Destino | Razão |
|---|---|---|
| Explicação do honeypot | **Perímetro**, em prosa, no topo | é a tese da página |
| Dashboards live (Cloudflare, honeypot 24h) | **página de telemetria** | mudam a cada visita; não são texto |
| Tendências 7d | **página de telemetria** | é a mesma série, outra janela |
| Logs pesquisáveis | **página de telemetria**, último bloco | ferramenta de consulta, não leitura |
| Explicação da privacidade | versão longa em **Segurança** (já lá está, `security.privacyTitle`); contrato curto de 2 frases em **Perímetro**; nota de uma linha em cada superfície com dados | dito uma vez a sério, repetido curto onde é preciso |
| Ponte para ATT&CK | **Perímetro** (uma vez) e **Deteções** (uma vez) | hoje aparece três vezes em Perímetro |
| Ponte para Sigma / Deteções | **Perímetro**, no fim | é o passo seguinte da narrativa |
| Ponte para o projeto Honeypot | **Perímetro**, no fim, junto à anterior | ambas são «continuar a ler» |
| Mapa de tráfego hostil | **página de telemetria** | é um painel |
| Ticker CISA KEV / NVD | **página de telemetria** | feed externo, muda sozinho |
| Correlação KEV («explorada agora») | **Perímetro** — é argumento, não painel | sustenta a tese com uma frase |

---

## 3) Opções de reorganização

### Opção A — Minimalista (zero rotas novas)

Tirar a prosa de dentro das tabs e pô-la no corpo da página. A tab bar passa a
conter só superfícies de dados.

- **Ficam como estão:** Visão Geral, Segurança, Provas, Performance.
- **Muda de papel:** Perímetro. Passa a *página com cabeçalho editorial +
  painel anexo*. As tabs reduzem-se a quatro: Deteções, Cloudflare, Tendências,
  Logs. O que era a tab «Honeypot» sobe para o corpo, acima da tab bar, com os
  4 stat cards e a correlação KEV.
- **Nova página:** não.
- **Dashboards:** ficam onde estão, mas deixam de competir com a explicação.
- **Vantagens:** uma tarde de trabalho; nav intacta; sem URLs novas; sem
  redirects; resolve o pior sintoma (o leitor deixa de ter de carregar numa tab
  para saber o que a página é).
- **Desvantagens:** a página continua com 1066 linhas e dois sujeitos; Cloudflare
  continua a ser telemetria de zona dentro de uma página sobre o honeypot;
  continua sem deep-link para regras Sigma; o modo de falha continua a levar a
  página quase toda.

### Opção B — Intermédia (uma rota nova)

Devolver Deteções a página própria e mandar a Cloudflare para junto da restante
telemetria de zona.

- **Ficam como estão:** Visão Geral, Segurança, Provas.
- **Mudam de papel:** Perímetro (fica honeypot: explicação + tendências + logs);
  Performance (ganha 3.ª tab «Ameaças» com os dados Cloudflare — que já usam as
  strings `site.*` desta página).
- **Nova página:** sim, **Deteções** (`/detecoes/` ↔ `/en/detections/`) —
  tecnicamente uma reversão da fusão, com conteúdo já escrito em `ui.ts`.
- **Dashboards:** honeypot fica em Perímetro; Cloudflare vai para Performance.
- **Vantagens:** cada página passa a ter um sujeito; a Cloudflare reencontra o
  vocabulário a que já pertence; deep-link para cada regra Sigma; a nav cresce
  só um item.
- **Desvantagens:** Performance deixa de significar «velocidade» e passa a
  significar «telemetria de zona» — o nome fica a apertar, e a página cresce
  para três tabs de peso desigual. Perímetro continua a misturar ensaio com
  painel, só que com menos painéis. É meia-solução.

### Opção C — Ideal (duas rotas novas)

Três páginas, três papéis, sem sobreposição.

- **Ficam como estão:** Visão Geral, Segurança, Provas, Performance.
- **Muda de papel:** Perímetro. Passa a página **editorial e estável**: o que é
  o honeypot, o que é medido, com que garantias, o que os dados mostram. Sem
  painéis — exceto uma tira de quatro números (ver §4).
- **Novas páginas:** duas.
  - **Deteções** (`/detecoes/` ↔ `/en/detections/`) — metodologia e regras.
  - **Telemetria** (`/telemetria/` ↔ `/en/telemetry/`) — todos os painéis ao
    vivo: honeypot 24h/7d, Cloudflare da zona, tendências, mapa, ticker, logs.
- **Dashboards:** todos em Telemetria, em tabs — que aí fazem sentido, porque
  passam a separar coisas do mesmo tipo (painéis) e não coisas de tipos
  diferentes.
- **Vantagens:** cada página tem um registo só e um modo de falha só; Perímetro
  volta a ser citável; as tabs de Telemetria são finalmente homogéneas; a
  indisponibilidade do Worker afeta uma página em vez de quatro quintos de uma;
  o argumento («scan automático apanha até um site pessoal») fica legível sem
  depender de rede.
- **Desvantagens:** o dropdown «Este Site» cresce de 5 para 7 itens — é o custo
  real desta opção e não é pequeno; `SiteLayers` passa a listar 7 entradas;
  duas rotas novas × 2 idiomas = 4 ficheiros de rota; há duas páginas de
  painéis no site (Performance e Telemetria), que é preciso justificar em texto.

#### Variante C2, para registo

Fundir Performance dentro de Telemetria (tabs: Tráfego · Core Web Vitals ·
Honeypot · Cloudflare · Tendências · Logs). Nav volta a 5 itens e só existe uma
página de painéis. **Não recomendado agora:** recria o problema de Perímetro
numa escala maior, e mistura tráfego legítimo com tráfego hostil — que é
precisamente a distinção que dá valor às duas leituras.

---

## 4) Recomendação final

**Opção C.**

Razão principal: é a única que separa *registo* de leitura, e não apenas
assuntos. A Opção A arruma a página; a B arruma os assuntos; só a C arruma
aquilo que está realmente misturado — texto que se lê uma vez e números que
mudam sozinhos. Um site que se declara documental não pode ter a sua página
mais argumentativa a mudar de conteúdo a cada minuto.

Razão secundária: alinha a secção com a lógica que ela já usa. «Este Site» está
organizado por conceito — arquitetura, postura, prova, desempenho. «Perímetro»
é o único nome que descreve um *lugar* em vez de um conceito, e foi por isso
que atraiu tudo o que era vagamente fronteiriço.

### Respostas diretas

**Perímetro deve continuar a ter dashboards?**
Não. Com uma exceção deliberada: **os quatro stat cards** (tentativas 24h, path
mais tentado, países 7d, tempo até ao 1.º scan) **ficam**, mais a faixa de
correlação KEV. Não são um painel — são a evidência que sustenta a tese da
página. Sem eles a afirmação «até um site pessoal apanha scan automático» fica
por provar. Trade-off assumido: reintroduz-se um pouco de dado live numa página
que se quer estável. Aceita-se porque degradam bem («—») e porque são quatro
números, não vinte e cinco widgets.

**Os dashboards devem ir para uma página nova?**
Sim. Todos os restantes: Cloudflare, tendências 7d, heatmap, mapa de tráfego,
ticker.

**Qual deve ser o nome dessa página?**
**Telemetria** / **Telemetry**.

O argumento decisivo não é estético: **a palavra já está em `ui.ts`**. A intro
do bloco `layers` diz «Segurança, provas e telemetria são faces do mesmo
projeto». O vocabulário da secção já prevê esta página — só não existia a página.

Alternativas ponderadas e rejeitadas:
- *Observabilidade* — jargão de SRE; promete SLOs e alertas que não existem.
- *Painéis* / *Dashboards* — descreve o formato, não o assunto; o segundo é
  anglicismo, fora do registo do site.
- *Sinais* — vago.
- *Tráfego hostil* — bom mas fecha demais: a página inclui ticker de threat
  intel e métricas de zona que não são todas hostis.

**Os logs devem ficar nessa página ou noutra?**
Em **Telemetria**, como último bloco. Considerei Provas e rejeitei: Provas tem
um contrato — *tudo gerado no build, determinístico, reproduzível por quem lê*.
Os logs são runtime, não reproduzíveis e efémeros. Pô-los lá dilui o contrato
que dá valor a Provas. Trade-off: quem procura «evidência» pode ir primeiro a
Provas; resolve-se com uma linha em Provas a apontar para Telemetria.

---

## 5) Estrutura proposta

### 5.1 Perímetro — `/perimetro/` ↔ `/en/perimeter/`

**Objetivo editorial:** explicar o que este site mede na fronteira, com que
garantias, e o que os dados mostram. Legível de cima a baixo, sem tabs, sem
rede. Estável e citável.

**Headings principais**

1. `<h1>` Perímetro / Perimeter
2. `<h2>` Os endpoints-isco / The decoy endpoints
3. `<h2>` O que é registado / What is recorded
4. `<h2>` O que os números dizem / What the numbers say — *(4 stat cards + KEV)*
5. `<h2>` A seguir / What comes next — *(pontes: Deteções, Telemetria, projeto)*

**Entra:** prosa do honeypot; contrato de privacidade em duas frases; os 4 stat
cards; a faixa de correlação CISA KEV; nota metodológica sobre os limites do
painel; três pontes, agrupadas no fim.

**Sai:** tab bar; tab Cloudflare; tab Tendências; tab Logs; mapa de tráfego
hostil; ticker; toda a lógica de fetch exceto a dos 4 números; as regras Sigma
e o pipeline (vão para Deteções); as notas de rodapé dispersas (consolidam-se).

**Ordem ideal:** tese → mecanismo → contrato → evidência → continuação. Nunca o
inverso: os números não abrem a página, sustentam-na.

### 5.2 Deteções — `/detecoes/` ↔ `/en/detections/` *(rota nova)*

**Objetivo editorial:** mostrar como um toque num isco se torna deteção
utilizável por terceiros. É a página que transforma observação em artefacto.

**Headings principais**

1. `<h1>` Deteções / Detections
2. `<h2>` O pipeline / The pipeline — *(3 passos, já escritos em `ui.ts`)*
3. `<h2>` As regras / The rules — *(um `<h3>` por regra, cada uma com `id`
   próprio para deep-link)*
4. `<h2>` Converter para a tua plataforma / Convert for your platform
5. `<h2>` A seguir / What comes next — *(ATT&CK, Perímetro)*

**Entra:** conteúdo atual da tab Deteções, praticamente intacto; contador de
7 dias por regra (é marginal e degrada para «—»); bloco `sigma-cli`.

**Sai:** nada de substancial — ganha um `<h1>` e uma URL. Sai a dependência de
estar dentro de uma tab de outra página.

**Ordem ideal:** pipeline → regras → conversão → pontes. O leitor precisa do
modelo mental antes do YAML.

### 5.3 Telemetria — `/telemetria/` ↔ `/en/telemetry/` *(rota nova)*

**Objetivo editorial:** os números, ao vivo, sem argumentação. A página não
explica — mostra. Quem quer o porquê vai a Perímetro.

**Headings principais**

1. `<h1>` Telemetria / Telemetry
2. Intro curta + nota de indisponibilidade *(uma vez, no topo, para toda a página)*
3. Tab bar homogénea, quatro superfícies do mesmo tipo:
   - `Honeypot` — contadores 24h, mapa de tráfego hostil, ticker
   - `Cloudflare` — ameaças da zona, países, estados, firewall
   - `Tendências (7d)` — heatmap, horas, atacantes novos/recorrentes, técnicas
   - `Logs` — tabela pesquisável e paginada
4. `<h2>` Notas metodológicas / Methodology notes — *(fora das tabs, no fim:
   privacidade, janelas e cache, limites)*

**Entra:** tudo o que hoje é live em Perímetro exceto os 4 stat cards e a
correlação KEV.

**Sai (nunca entra):** explicação do honeypot; regras Sigma; pipeline; qualquer
argumento. Se uma frase aqui explica *porquê*, pertence a Perímetro.

**Ordem ideal:** mais próximo → mais distante. Honeypot (instrumentação própria)
antes de Cloudflare (infraestrutura de terceiros); janela curta antes de longa;
agregados antes de bruto. Notas metodológicas no fim, sempre visíveis,
independentes da tab aberta.

---

## 6) Texto editorial (PT / EN)

Todas as chaves abaixo vivem em **`static/src/i18n/ui.ts`**, nos blocos PT e EN,
com a mesma estrutura dos dois lados.

### 6.1 Intro de Perímetro — `perimeter.intro`

**PT**
> Este site serve endpoints-isco: páginas de login e ficheiros que nenhum
> visitante humano procura. Quem lhes toca fica registado — país, ASN e path,
> nunca o IP. Esta página explica o que é medido e com que garantias. Os
> painéis ao vivo estão em Telemetria; as regras que apanhariam cada ataque
> estão em Deteções.

**EN**
> This site serves decoy endpoints: login pages and files no human visitor looks
> for. Whoever touches them is recorded — country, ASN and path, never the IP.
> This page explains what is measured and under what guarantees. The live panels
> are in Telemetry; the rules that would catch each attack are in Detections.

### 6.2 CTA para os painéis — `perimeter.telemetryBody` / `perimeter.telemetryCta`

**PT**
> Contadores, tendências de 7 dias e o log pesquisável, ao vivo.
> **Ver a Telemetria →**

**EN**
> Counters, 7-day trends and the searchable log, live.
> **See the Telemetry →**

### 6.3 CTA para Deteções — `perimeter.detectionsBody` / `perimeter.detectionsCta`

**PT**
> Cada classe de ataque apanhada aqui tem uma regra Sigma que a detetaria num
> SIEM.
> **Ver as Deteções →**

**EN**
> Each class of attack caught here has a Sigma rule that would detect it in a
> SIEM.
> **See the Detections →**

### 6.4 Intro da página de Telemetria — `telemetry.intro`

**PT**
> Os números, ao vivo. Duas fontes: o honeypot deste site (endpoints-isco, só
> metadados) e a Cloudflare, que vê a zona inteira. Nada aqui é editorial — é o
> que os contadores dizem no momento em que abriste a página. O porquê está em
> Perímetro.

**EN**
> The numbers, live. Two sources: this site's honeypot (decoy endpoints,
> metadata only) and Cloudflare, which sees the whole zone. Nothing here is
> editorial — it is what the counters say at the moment you opened the page. The
> why is in Perimeter.

### 6.5 Intro de Deteções — `detections.intro`

Reaproveitar a que já existe em `ui.ts`, com um ajuste: deixa de poder dizer «o
passo a seguir ao honeypot» como se estivesse ao lado dele numa tab.

**PT**
> O passo a seguir ao isco. Cada classe de ataque que este site apanha vem com a
> regra Sigma que a detetaria num SIEM e o ID MITRE ATT&CK correspondente. As
> regras são vendor-neutral. O contador ao lado de cada uma são toques reais dos
> últimos 7 dias nos endpoints-isco deste site.

**EN**
> The step after the decoy. Each class of attack this site catches comes with the
> Sigma rule that would detect it in a SIEM and the matching MITRE ATT&CK ID. The
> rules are vendor-neutral. The counter next to each one is real hits over the
> last 7 days on this site's decoy endpoints.

### 6.6 Notas metodológicas

#### Privacidade — `telemetry.notePrivacy` (e versão curta em `perimeter.privacyNote`)

**PT**
> Nenhum IP é armazenado. De cada pedido guardam-se três campos: país, ASN e
> path. A anonimização acontece no Worker, antes da escrita, e é verificável no
> código (`dynamic/worker/`).

**EN**
> No IP is stored. Three fields are kept per request: country, ASN and path.
> Anonymisation happens in the Worker, before the write, and is verifiable in
> the code (`dynamic/worker/`).

#### Dados ao vivo — `telemetry.noteLive`

**PT**
> Os contadores são lidos quando abres a página. As janelas apresentadas são de
> 24 horas e de 7 dias. O ticker de threat intel (CISA KEV, NVD) tem cache de
> uma hora.

**EN**
> Counters are read when you open the page. The windows shown are 24 hours and
> 7 days. The threat intel ticker (CISA KEV, NVD) is cached for one hour.

#### Limites do painel — `telemetry.noteUnavailable`

**PT**
> Estes painéis dependem de o Worker (`dynamic/worker/`) estar publicado nas
> rotas do domínio. Se não estiver, os contadores ficam em «—» e as tabelas
> vazias. O texto do Perímetro, as regras de Deteções e a garantia de
> privacidade não dependem disso.

**EN**
> These panels depend on the Worker (`dynamic/worker/`) being published on the
> domain routes. If it is not, counters show “—” and tables stay empty. The
> Perimeter text, the Detections rules and the privacy guarantee do not depend
> on it.

#### Nota curta em Perímetro, junto aos 4 números — `perimeter.statsNote`

**PT**
> Quatro números, lidos ao vivo. Se ficarem em «—», o Worker não está publicado
> — o resto desta página continua válido.

**EN**
> Four numbers, read live. If they show “—”, the Worker is not published — the
> rest of this page still holds.

---

## 7) Implementação editorial

### 7.1 Onde vive o texto

**Todo o texto desta secção vive em `static/src/i18n/ui.ts`**, PT e EN no mesmo
ficheiro e com estrutura idêntica. Zero strings nos componentes (regra 2 do
`CLAUDE.md`). Blocos afetados:

- `perimeter.*` — encolhe: saem `tabHoneypot`, `tabDetections`, `tabCloudflare`,
  `tabTrends`, `tabLogs`; entram `telemetryBody`, `telemetryCta`,
  `detectionsBody`, `detectionsCta`, `statsNote`.
- `detections.*` — mantém-se quase todo; ganha `metaTitle` (hoje não tem, porque
  não era página).
- **`telemetry.*` — bloco novo.** Recebe as chaves de painel que hoje estão
  emprestadas em `site.*` (`cardThreats`, `tiHeatmap`, `logsSearch`,
  `logColPath`, …). Decisão a tomar: mover ou partilhar. **Recomendo mover** o
  que é exclusivo de tráfego hostil e deixar em `site.*` só o que Performance
  também usa — caso contrário `site.*` continua a ser o saco de tudo.
- `layers.*` — passa a listar 7 entradas; a descrição de `perimeter` deixa de
  dizer «honeypot, deteções e Cloudflare» e passa a descrever só o perímetro.
- `nav.*` e `footer.*` — dois rótulos novos.

### 7.2 Rotas novas

Em `static/src/i18n/routes.ts`, dois pares:

```
detections : /detecoes/    ↔  /en/detections/
telemetry  : /telemetria/  ↔  /en/telemetry/
```

Ficheiros de rota: `pages/detecoes.astro`, `pages/telemetria.astro`,
`pages/en/detections.astro`, `pages/en/telemetry.astro` — finas, 3 linhas
(regra 1 do `CLAUDE.md`).

**Nota sobre aninhamento:** as novas rotas ficam de topo, como a maioria da
secção (`/seguranca/`, `/perimetro/`, `/provas/`). A anomalia é
`/este-site/performance/`, que é a única aninhada. Uniformizar tudo sob
`/este-site/` seria mais coerente, mas quebra URLs publicadas e obriga a
redirects — **trata-se como decisão separada**, não como parte desta.

### 7.3 Coerência com o resto de «Este Site»

- **Ordem canónica**, a mesma em `SiteLayers.astro`, no dropdown do
  `BaseLayout.astro` e na lista de Visão Geral: Visão Geral → Segurança →
  Perímetro → Deteções → Telemetria → Provas → Performance. Mantém o princípio
  já documentado no `BaseLayout.astro` (o que está a acontecer antes do «não
  acredites, verifica»), com Deteções e Telemetria a entrar como continuação
  natural de Perímetro.
- **ATT&CK e Certificações continuam fora.** Nada nesta reorganização mexe
  nessa decisão, e Deteções liga a ATT&CK em prosa — não a promove a camada.
- **Regra editorial nova, para não voltar ao mesmo sítio:** *uma página, um
  registo*. Se uma página tem texto que se lê uma vez e números que mudam
  sozinhos, os números vão para Telemetria. Vale para páginas futuras.
- **A palavra «telemetria» já está em `layers.intro`** — a nova página torna
  verdadeira uma frase que já existe.
- **Antes de fechar:** `cd static && npm run build` sem erros nem warnings
  novos; página nova nas duas versões PT + EN; par registado em `routes.ts`.

### 7.4 Ordem de execução sugerida

1. Extrair Deteções para página própria (é conteúdo já escrito — risco baixo,
   ganho imediato).
2. Criar Telemetria e mover Cloudflare + Tendências + Logs + mapa + ticker.
3. Reescrever Perímetro como página linear, com os 4 números e as pontes.
4. Atualizar `layers`, nav e rodapé.

Cada passo é entregável sozinho. Se parares no passo 1, o site fica melhor do
que está.

---

## 8) Trade-offs em aberto

Ficam explícitos, para decisão do dono do repo — nenhum se resolve por estilo:

1. **Menos páginas vs. clareza.** A Opção C leva o dropdown de 5 para 7 itens.
   Sete é muito para um menu. A alternativa honesta é a Opção B (6 itens), que
   deixa Perímetro a meio caminho. Não há solução com 5 itens e registos
   separados — é preciso escolher qual dos dois se sacrifica.
2. **Duas páginas de painéis.** Performance e Telemetria são ambas dashboards.
   Justifica-se pela distinção tráfego legítimo / tráfego hostil, mas essa
   distinção tem de estar escrita nas intros das duas, ou parece duplicação.
3. **Os 4 números em Perímetro.** Contradizem parcialmente a regra «uma página,
   um registo». Mantêm-se porque sem eles o argumento da página não é
   verificável. Se preferires pureza, tiram-se e a frase passa a remeter para
   Telemetria — a página fica mais limpa e menos convincente.
4. **Logs em Telemetria vs. Provas.** Escolhi Telemetria para não diluir o
   contrato build-time de Provas. Quem procura evidência pode bater primeiro em
   Provas; mitiga-se com uma linha de ponte, não com uma mudança de sítio.
