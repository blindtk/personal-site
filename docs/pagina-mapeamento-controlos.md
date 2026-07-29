# Proposta — subpágina «Mapeamento de controlos» (secção Este Site)

Análise editorial, recomendação e **copy final PT/EN pronta a implementar** para
uma nova subpágina dentro da secção *Este Site* / *This Site*.

Âmbito: **só** o próprio site (controlos, arquitetura, postura, evidência
pública). Fora de âmbito: a página *Sobre*, e o tema «frameworks aplicados no
percurso profissional» (tratado noutro sítio, ver `/attack/` e `/certificacoes/`).

Nada aqui é código. É texto e estrutura.

---

## 0. Correções de premissa (estado real do repositório)

Duas coisas do enunciado não correspondem ao que está no código hoje:

1. **«Deteções» não é uma página autónoma.** Foi fundida em `/perimetro/` como
   *tab* (`PerimeterPage.astro`, slot `detections`, alimentada por
   `content/detections.json`). Logo, esta nova página distingue-se de *uma*
   página — o Perímetro — e não de duas.
2. **`/attack/` está deliberadamente fora da secção «Este Site».** Tanto
   `BaseLayout.astro` como `SiteLayers.astro` o excluem por comentário
   explícito: é o *heatmap pessoal* («o meu CV»), sobre credenciais e percurso,
   não sobre este site. Isto condiciona como o ATT&CK pode ser ligado aqui
   (ver §6).

---

## 1. Recomendação editorial

**Faz sentido?** Sim, com uma condição: a página só se justifica se **não
introduzir um único facto novo**. Se for só uma camada de tradução — controlos
que já existem, lidos no vocabulário de frameworks públicos, cada linha a
apontar para a página onde a evidência já vive — acrescenta valor real a um
leitor técnico externo (recrutador técnico, auditor, par) que pensa em
«OWASP A05» e não em «cabeçalhos e porquê». Se começar a alegar controlos que
não estão noutro lado, torna-se pseudo-auditoria e contamina a credibilidade das
outras quatro páginas.

**Papel exato na arquitetura editorial:** é a **camada de indexação**. As outras
páginas produzem factos; esta indexa-os por vocabulário externo. A regra de ouro,
que resolve toda a sobreposição: *cada célula da tabela ou aponta para outra
página deste site, ou não entra*.

**Como se distingue:**

| Página | Pergunta a que responde | Registo |
|---|---|---|
| Segurança | **Porquê** existe cada controlo (modelo de ameaça, razão de ser) | prosa explicativa |
| Provas | **Prova-me** — artefactos gerados no build ou lidos ao vivo | máquina, sem prosa |
| Perímetro (com tab Deteções) | **O que tenta entrar agora** e que regra o apanharia | telemetria ao vivo |
| Projeto «Este site» | **Que decisões** levaram a esta arquitetura | narrativa de projeto |
| **Mapeamento (nova)** | **Como é que isto se chama** na linguagem das frameworks, e **até onde vai a alegação** | tabela de referência |

**Como evitar sobreposição com «Sobre»:** duas regras mecânicas.

- O sujeito de todas as frases é **o site**, nunca «eu». Zero primeira pessoa
  aplicada a experiência, certificações ou percurso.
- Zero menções a credenciais, empregadores, anos de experiência ou ferramentas
  usadas profissionalmente. Se uma frase continuasse a fazer sentido caso o site
  mudasse de dono, pode ficar. Se não, é conteúdo do *Sobre*.

---

## 2. Nome da subpágina

### Cinco opções

| # | PT | EN | Nota |
|---|---|---|---|
| 1 | **Mapeamento de controlos** | **Control mapping** | Descritivo, técnico, honesto quanto ao que é |
| 2 | Frameworks e controlos | Frameworks and controls | Claro, mas põe a framework antes do facto |
| 3 | Alinhamento com frameworks | Framework alignment | Bom, mas «alinhamento» já é meia-alegação |
| 4 | Controlos observáveis | Observable controls | Excelente rigor, fraco como entrada de nav |
| 5 | Referências e cobertura | References and coverage | «Cobertura» arrisca leitura de completude |

**«Conformidade» / «Compliance» fica rejeitado como título**, e vale a pena
dizer porquê: é a única palavra da lista que descreve um *estado atestado por
terceiros*. Usá-la no `<h1>` obrigaria o resto da página a passar a vida a
desmentir o próprio título. A palavra só deve aparecer no corpo da página, e só
pela negativa («isto não é conformidade formal»).

### Escolha

**PT: «Mapeamento de controlos» · EN: «Control mapping».**

Porquê: diz exatamente o que a página faz (mapear), não o que ela prova; nomeia
o objeto certo (*controlos* — o que o site tem — e não *frameworks* — o que é de
outros); e é neutro quanto ao grau de cobertura, que é depois qualificado linha
a linha. Como entrada de nav reduz-se a uma palavra — **«Mapeamento» / «Mapping»**
— coerente com «Visão Geral», «Segurança», «Perímetro», «Provas», «Performance».

### Subtítulo (intro, não um `<h2>`)

- PT: *Os controlos deste site, lidos à luz de frameworks públicos de segurança web.*
- EN: *This site's controls, read against public web-security frameworks.*

---

## 3. Estrutura da página

### Formato: **híbrido — tabela principal + notas curtas por framework**

- **Tabela**, sim: é o formato que já carrega a informação densa desta secção
  (`security.headers`, `evidence.contract`, `evidence.pipeline` usam todos
  `result-table`). Uma tabela com coluna «Limite da alegação` obriga a escrever
  o limite em todas as linhas — o rigor fica imposto pela estrutura, não pela
  boa vontade de quem escreve.
- **Cards, não.** Cards com ícone de framework leem-se como selos de
  conformidade. É exatamente a leitura a evitar.
- **Heatmap, não.** Já existem dois heatmaps no site (`/attack/` e a tab
  Tendências). Um terceiro, aplicado a frameworks, implicaria uma escala de
  cobertura — quantificação que esta página não pode sustentar sem se tornar
  auto-auditoria.
- **Notas curtas por framework**, sim: a tabela não tem espaço para dizer
  *porque é que* a framework é ou não adequada a este site. Três a cinco frases
  por framework, abaixo da tabela.

### Esqueleto de headings

```
H1  Mapeamento de controlos                    | Control mapping
    intro (2 frases)
H2  Como ler esta página                       | How to read this page
H2  Mapa de controlos                          | Control map
    [tabela principal]
H2  Por framework                              | Framework by framework
    H3  OWASP Top 10
    H3  CIS Controls
    H3  CISA CPG
    H3  MITRE ATT&CK
H2  Frameworks fora do eixo desta página       | Frameworks outside this page's axis
    H3  ISO/IEC 27001
    H3  NIS2
H2  Limites                                    | Limits
    [componente SiteLayers — cross-links da secção]
```

---

## 4. Framework mapping (análise)

> **Nota de implementação, a resolver antes de publicar:** fixar e escrever a
> versão de cada framework na página. Este documento assume **OWASP Top 10 (2021)**,
> **CIS Controls v8.1**, **CISA CPG v1.0.1** e **ATT&CK Enterprise** na versão
> que alimenta `content/attack.json`. Confirmar se se quer mapear contra a
> edição mais recente do OWASP Top 10 antes de publicar.
>
> As referências CIS ficam ao nível de **controlo** (1–18), nunca de salvaguarda
> (`x.y`); as CISA CPG ficam ao nível de **nome de objetivo** e função
> (Identificar/Proteger/Detetar/Responder), não de identificador alfanumérico —
> os identificadores só devem entrar depois de verificados na versão publicada
> do CPG. Referenciar ao detalhe daria à página o ar de auditoria que ela
> declaradamente não é.

### OWASP Top 10 — **eixo principal**

- **Porquê faz sentido:** é a única das quatro frameworks cuja unidade de
  análise é uma *aplicação web*. Todos os controlos deste site são
  aplicacionais.
- **O que se pode mapear:** A03 (CSP estrita sem `unsafe-inline`, Trusted Types,
  render por `textContent`, SAST de sinks DOM-XSS); A05 (contrato de cabeçalhos
  verificado em produção); A06 (OSV-Scanner, `npm audit`, Renovate); A08
  (Actions pinadas por digest, lockfile, Gitleaks, zizmor, zero terceiros); A09
  (relatórios CSP, telemetria honeypot, vigia CT).
- **O que não alegar:** A01 e A07 **não são controlos — são não-aplicáveis**.
  Não há contas, sessões nem área privada. Escrever «não aplicável», nunca
  «coberto»: ausência de superfície não é controlo implementado. A04 (design
  inseguro) não é verificável por terceiros e não deve entrar. A02 e A10 só
  entram se houver algo concreto a apontar.
- **Evidência que suporta:** `/seguranca/` (cabeçalhos e porquê), `/provas/`
  (contrato de cabeçalhos, scan ao vivo, workflows), `static/public/_headers`.
- **Formulação curta:** PT — «Os riscos do Top 10 que têm superfície neste site,
  e o controlo que lhes corresponde.» EN — «The Top 10 risks that have surface
  on this site, and the control that answers each.»

### CIS Controls — **eixo secundário, ao nível de controlo**

- **Porquê faz sentido:** dá vocabulário de higiene operacional (dependências,
  configuração, registos) que o OWASP não cobre.
- **O que se pode mapear:** 2 (inventário de software: lockfile + Renovate), 3
  (proteção de dados: sem cookies/analytics/BD), 4 (configuração segura:
  cabeçalhos, HSTS, Permissions-Policy), 7 (gestão de vulnerabilidades:
  OSV-Scanner, `npm audit`), 8 (registos: honeypot, firewall, relatórios CSP —
  **parcial**), 16 (segurança aplicacional: Semgrep, Gitleaks, zizmor, rate
  limiting e sanitização no Worker).
- **O que não alegar:** nenhum *Implementation Group* (IG1/IG2/IG3) — são
  perfis organizacionais e este site não é uma organização. Nada de 5/6 (contas
  e acessos), 14 (formação), 17 (resposta a incidentes) ou **18 (teste de
  intrusão — não existe)**. Nunca citar salvaguardas `x.y`.
- **Evidência que suporta:** `/provas/` (workflows, pipeline), `/perimetro/`
  (tab Logs), `/seguranca/` (privacidade e dados), repositório público.
- **Formulação curta:** PT — «Higiene operacional, ao nível do controlo. Um site
  não é uma organização: só entra o subconjunto que faz sentido para um ativo
  único.» EN — «Operational hygiene, at control level. A site is not an
  organisation: only the subset that makes sense for a single asset applies.»

### CISA CPG — **eixo secundário, por objetivo**

- **Porquê faz sentido:** o CPG é escrito em objetivos de resultado, não em
  requisitos documentais, o que se lê bem sem invocar um programa de segurança
  inteiro. E há um cruzamento genuíno: o ticker do site correlaciona técnicas
  observadas com o catálogo **KEV da própria CISA**.
- **O que se pode mapear:** *Identificar* — mitigar vulnerabilidades conhecidas
  (CI + correlação KEV); *Proteger* — criptografia forte (HTTPS/HSTS) e ausência
  de serviços administrativos expostos; *Detetar* — recolha de registos e
  deteção de TTP relevantes (honeypot, Sigma); *Responder* — divulgação de
  vulnerabilidades (`security.txt`, RFC 9116).
- **O que não alegar:** MFA, gestão de credenciais, formação, segmentação de
  rede, cópias de segurança e planos de resposta — ou não têm sujeito neste
  contexto, ou não têm evidência pública. O CPG foi desenhado para operadores de
  infraestrutura crítica; dizer que um site pessoal «cumpre CPG» é erro de
  categoria.
- **Evidência que suporta:** `/.well-known/security.txt`, `/perimetro/`
  (correlação KEV, deteções), `/este-site/` (estado dos componentes: edge, DNS,
  TLS, Worker), `/provas/`.
- **Formulação curta:** PT — «Objetivos do CPG que têm tradução direta num site:
  vulnerabilidades conhecidas, cifra, deteção e canal de divulgação.» EN — «CPG
  goals that translate directly to a website: known vulnerabilities, encryption,
  detection and a disclosure channel.»

### MITRE ATT&CK — **só onde há deteção**

- **Porquê faz sentido (com limite):** o site já produz dados ATT&CK reais —
  `content/honeypot-attack.json` associa cada URL-isco a uma técnica,
  `content/detections.json` publica regras Sigma com o campo `technique`, e o
  Perímetro liga cada evento à técnica correspondente.
- **O que se pode mapear:** exclusivamente as técnicas que já constam desses
  dois ficheiros, e só na leitura «observado no isco → regra que o apanharia».
- **O que não alegar:** cobertura de táticas, percentagem de cobertura, ou
  qualquer sugestão de que o ATT&CK descreve a *defesa* do site. E — importante —
  **não confundir com `/attack/`**, que é o heatmap pessoal e está deliberadamente
  fora desta secção. Se `/attack/` for referido, tem de ser com etiqueta
  explícita («heatmap pessoal, não do site»).
- **Evidência que suporta:** `/perimetro/` → tab Deteções (regras Sigma
  copiáveis, com contadores de 7 dias ao vivo).
- **Formulação curta:** PT — «ATT&CK entra só onde há deteção: o que foi
  observado nos URLs-isco e a regra Sigma que o apanha.» EN — «ATT&CK appears
  only where detection exists: what was observed on the decoy URLs and the Sigma
  rule that catches it.»

### ISO/IEC 27001 — **não deve ser o eixo**

- **Porquê não:** a unidade de certificação é um **sistema de gestão** (ISMS) de
  uma **organização** — âmbito, política, avaliação de risco, Declaração de
  Aplicabilidade, auditoria interna, revisão pela gestão, organismo certificador.
  Nada disso tem sujeito num site pessoal. Além disso, a maioria dos controlos do
  Anexo A é organizacional, de pessoas e físico: mapeá-los obrigaria a inventar
  processos ou a deixar 80% da tabela vazia — e uma tabela quase vazia é, ela
  própria, uma afirmação sobre o site.
- **A razão editorial mais forte:** a moeda desta página é **evidência
  observável do exterior**. A evidência da ISO 27001 é documental e interna, por
  natureza não verificável por um visitante. Uma framework cuja evidência não é
  publicamente verificável não pertence ao eixo desta página.
- **Menção secundária legítima:** como *vocabulário* — o Anexo A é uma forma
  reconhecida de agrupar controlos, e alguns temas (gestão de vulnerabilidades
  técnicas, segurança no desenvolvimento) descrevem bem partes do que existe.
  Menção metodológica, uma frase, sem número de controlo e sem a palavra
  «conformidade».
- **Formulação curta:** PT — «A ISO 27001 certifica um sistema de gestão numa
  organização, não um site. Fica de fora do eixo desta página; serve, quando
  muito, como vocabulário.» EN — «ISO 27001 certifies a management system in an
  organisation, not a website. It stays off this page's axis; at most it serves
  as vocabulary.»

### NIS2 — **não deve ser o eixo**

- **Porquê não:** a NIS2 é uma **diretiva**, com âmbito definido por setor e
  dimensão de entidade (entidades essenciais e importantes) e transposta para o
  direito de cada Estado-Membro. Um site pessoal não é uma entidade abrangida —
  não há sujeito jurídico a quem as obrigações se apliquem. «Alinhado com a
  NIS2» é, aqui, erro de categoria antes de ser exagero.
- **Menção secundária legítima:** as medidas do artigo 21.º funcionam como
  *lista de temas* (análise de risco, tratamento de incidentes, segurança da
  cadeia de fornecimento, divulgação de vulnerabilidades) e alguns desses temas
  têm eco real neste site — cadeia de CI e `security.txt`. Dizê-lo em uma frase,
  deixando claro que o eco é temático e não jurídico.
- **Formulação curta:** PT — «A NIS2 aplica-se a entidades de certos setores e
  dimensões, não a sites pessoais. Alguns dos temas do artigo 21.º têm eco aqui;
  a obrigação legal não.» EN — «NIS2 applies to entities of certain sectors and
  sizes, not to personal websites. Some of the Article 21 themes echo here; the
  legal obligation does not.»

---

## 5. Copy final — **PT**

> Texto para `static/src/i18n/ui.ts` (ver §7). Nenhum destes textos deve ficar
> escrito à mão numa componente.

**Meta title:** `Mapeamento de controlos — alinhamento com frameworks`

**Page title (H1):** `Mapeamento de controlos`

**Intro:**

> Os controlos técnicos deste site, lidos à luz de frameworks públicas de
> segurança web. É um mapeamento, não uma auditoria: cada linha aponta para
> evidência já publicada noutra página e diz onde a alegação acaba.

**H2 · Como ler esta página** (nota metodológica)

> Só entram controlos observáveis: algo que possas verificar de fora — um
> cabeçalho servido, um workflow público, um ficheiro no repositório — ou que
> esteja documentado noutra página deste site. Nenhuma linha introduz factos
> novos. As referências ficam ao nível do controlo, nunca ao nível da
> salvaguarda ou da cláusula: mapear ao detalhe daria a esta página um ar de
> auditoria que ela não tem. Onde a cobertura é parcial, está escrito parcial.
> Onde não se aplica, está escrito não aplicável — ausência de superfície não é
> controlo implementado.
>
> Versões usadas: OWASP Top 10 (2021), CIS Controls v8.1, CISA CPG v1.0.1,
> MITRE ATT&CK Enterprise.

**H2 · Mapa de controlos**

| Framework | Área | Controlo observado no site | Evidência pública | Limite da alegação |
|---|---|---|---|---|
| OWASP Top 10 | A03 · Injeção (XSS) | CSP estrita: `script-src 'self'`, `style-src 'self'`, sem `unsafe-inline`; `require-trusted-types-for 'script'`; zero scripts de terceiros | Segurança → Cabeçalhos; Provas → scan ao vivo | Fecha a via principal de XSS. Não é prova de ausência de XSS. |
| OWASP Top 10 | A05 · Configuração incorreta | Contrato de cabeçalhos versionado e verificado em produção a cada push | Provas → Contrato de cabeçalhos | Cobre a resposta HTTP servida. Não cobre a configuração da conta de infraestrutura. |
| OWASP Top 10 | A06 · Componentes vulneráveis | OSV-Scanner sobre o lockfile, `npm audit` a falhar o build em high/critical, Renovate | Provas → Workflows | Cobre vulnerabilidades conhecidas e publicadas. Não cobre 0-day nem o código próprio. |
| OWASP Top 10 | A08 · Integridade de software e dados | GitHub Actions pinadas por digest SHA, lockfile, Gitleaks, zizmor, sem CDN de terceiros | Provas → Workflows; hash do último commit | Cobre a cadeia de build deste repositório. Não há assinatura de artefactos. |
| OWASP Top 10 | A09 · Registo e monitorização | Relatórios de violação de CSP, telemetria do honeypot, vigia de Certificate Transparency | Provas → Violações CSP e Vigia CT; Perímetro | Parcial. Sem SIEM, sem alerta contínuo, sem retenção longa. |
| OWASP Top 10 | A01 e A07 · Acesso e autenticação | Site estático: sem contas, sem sessões, sem área privada | Segurança → Modelo de ameaça; projeto «Este site» | **Não aplicável.** Ausência de superfície, não controlo implementado. |
| CIS Controls | 2 · Inventário de software | Lockfile versionado e atualizações geridas pelo Renovate | Repositório público | Inventário de um ativo, não de um parque. |
| CIS Controls | 3 · Proteção de dados | Sem cookies, sem analytics, sem scripts de terceiros, sem base de dados; ferramentas client-side processam tudo no browser | Segurança → Privacidade e dados | Não cobre os logs de conexão da infraestrutura, que estão documentados. |
| CIS Controls | 4 · Configuração segura | Cabeçalhos de segurança, HSTS a dois anos, Permissions-Policy a desligar APIs não usadas | Provas → cabeçalhos ao vivo | Aplica-se a um único ativo publicado. |
| CIS Controls | 7 · Gestão contínua de vulnerabilidades | Análise de dependências a cada push e janela semanal de atualização | Provas → Workflows | Sem varrimento autenticado nem gestão formal de exceções. |
| CIS Controls | 8 · Registos de auditoria | Eventos do honeypot e do firewall agregados; relatórios de CSP | Perímetro → Logs e Tendências | Parcial e por decisão de privacidade: agregado, sem IP, retenção curta. |
| CIS Controls | 16 · Segurança de software aplicacional | SAST nos scripts de cliente, deteção de segredos, auditoria dos workflows, rate limiting e sanitização no Worker | Provas → Workflows; repositório | Sem revisão externa. O controlo 18 (teste de intrusão) não é alegado. |
| CISA CPG | Identificar · Mitigar vulnerabilidades conhecidas | Dependências analisadas em CI; ticker a correlacionar técnicas observadas com o catálogo KEV da CISA | Provas → Workflows; Perímetro → correlação KEV | Correlação informativa. Não substitui gestão de vulnerabilidades. |
| CISA CPG | Proteger · Cifra forte e superfície exposta | HTTPS forçado por HSTS, TLS gerido pelo edge; superfície publicada limitada ao site estático e a um Worker isolado | Visão Geral → estado dos componentes; Provas | Descreve a superfície publicada. Não é varrimento de infraestrutura. |
| CISA CPG | Detetar · Registos e deteção de TTP | Honeypot com URLs-isco e regras Sigma publicadas, com contagem ao vivo | Perímetro → Deteções | Deteção limitada à superfície-isco. Sem cobertura de endpoint ou de rede. |
| CISA CPG | Responder · Divulgação de vulnerabilidades | `security.txt` (RFC 9116) com política de contacto publicada | `/.well-known/security.txt`; Segurança → Como reportar | Canal documentado. Sem SLA de resposta e sem programa de recompensas. |
| MITRE ATT&CK | Deteção | Cada URL-isco está associado a uma técnica; cada regra Sigma publicada refere o ID da técnica | Perímetro → Deteções | Descreve o observado no isco e a regra que o apanha. Não é cobertura defensiva do site. |

**H2 · Por framework**

*H3 · OWASP Top 10*

> É a única destas frameworks cuja unidade de análise é uma aplicação web, e por
> isso é o eixo desta página. Cinco das dez categorias têm superfície aqui e
> estão na tabela acima. Duas — controlo de acesso e autenticação — não têm
> sujeito: um site estático sem contas nem sessões não implementa esses
> controlos, apenas não tem onde os aplicar. A distinção é deliberada e está
> escrita em cada linha.

*H3 · CIS Controls*

> Cobrem a higiene operacional que o OWASP não descreve: dependências,
> configuração, registos. O mapeamento fica ao nível do controlo (1 a 18) e
> nunca ao nível da salvaguarda — um site é um ativo único, não uma organização
> com parque, contas e equipa. Por isso não se invoca nenhum Implementation
> Group, e os controlos de pessoas, acessos e resposta a incidentes ficam de
> fora. O controlo 18, teste de intrusão, não é alegado: não existe.

*H3 · CISA CPG*

> Os CPG estão escritos em objetivos de resultado, o que se lê bem sem invocar
> um programa de segurança inteiro. Quatro têm tradução direta num site:
> vulnerabilidades conhecidas, cifra, deteção e canal de divulgação. Há aqui um
> cruzamento real, e não retórico: o ticker deste site correlaciona as técnicas
> observadas no honeypot com o catálogo KEV publicado pela própria CISA. Os
> restantes objetivos foram escritos para operadores de infraestrutura crítica e
> não têm sujeito neste contexto.

*H3 · MITRE ATT&CK*

> ATT&CK entra apenas onde existe deteção. Cada URL-isco do honeypot está
> associado a uma técnica, e cada regra Sigma publicada no Perímetro refere o ID
> dessa técnica — com contagem de acertos ao vivo. É o que foi observado e a
> regra que o apanharia; não é uma medida de cobertura defensiva deste site.
> (O heatmap ATT&CK pessoal é outra coisa e vive fora desta secção.)

**H2 · Frameworks fora do eixo desta página**

*H3 · ISO/IEC 27001*

> A ISO 27001 certifica um sistema de gestão de segurança da informação numa
> organização — âmbito, política, avaliação de risco, declaração de
> aplicabilidade, auditoria interna, organismo certificador. Nada disso tem
> sujeito num site pessoal, e a maior parte dos controlos do Anexo A é
> organizacional, de pessoas ou física. Há ainda uma razão editorial: a evidência
> da ISO é documental e interna, e esta página só trabalha com evidência que um
> visitante consiga verificar de fora. Fica como vocabulário, quando é útil para
> nomear um grupo de controlos. Não como alegação.

*H3 · NIS2*

> A NIS2 é uma diretiva europeia com âmbito definido por setor e dimensão da
> entidade, transposta para o direito de cada Estado-Membro. Um site pessoal não
> é uma entidade abrangida: não há a quem as obrigações se apliquem. Alguns dos
> temas do artigo 21.º — cadeia de fornecimento, tratamento de incidentes,
> divulgação de vulnerabilidades — têm eco no que está documentado neste site,
> e é só isso que se afirma. O eco é temático; a obrigação legal não existe.

**H2 · Limites**

> Isto é um mapeamento técnico feito por quem mantém o site, não uma avaliação
> independente nem uma declaração de conformidade. Não há certificação, auditoria
> externa, teste de intrusão nem declaração de aplicabilidade. Nenhuma das
> frameworks citadas foi implementada como programa: são vocabulário público
> usado para organizar controlos que já existiam por outras razões. As
> frameworks mudam de versão; esta página fixa a versão que usa e pode ficar
> desatualizada em relação à edição mais recente. E se algo aqui divergir do que
> a produção serve, a produção é que manda — as Provas mostram-na ao vivo.

---

## 5. Copy final — **EN**

**Meta title:** `Control mapping — framework alignment`

**Page title (H1):** `Control mapping`

**Intro:**

> This site's technical controls, read against public web-security frameworks.
> It is a mapping, not an audit: every row points to evidence already published
> elsewhere on the site, and states where the claim stops.

**H2 · How to read this page**

> Only observable controls appear here: something you can check from the outside
> — a served header, a public workflow, a file in the repository — or something
> documented on another page of this site. No row introduces new facts.
> References stay at control level, never at safeguard or clause level: mapping
> that finely would give this page the air of an audit it is not. Where coverage
> is partial, it says partial. Where something does not apply, it says not
> applicable — absent surface is not an implemented control.
>
> Versions used: OWASP Top 10 (2021), CIS Controls v8.1, CISA CPG v1.0.1, MITRE
> ATT&CK Enterprise.

**H2 · Control map**

| Framework | Area | Control observed on this site | Public evidence | Limit of the claim |
|---|---|---|---|---|
| OWASP Top 10 | A03 · Injection (XSS) | Strict CSP: `script-src 'self'`, `style-src 'self'`, no `unsafe-inline`; `require-trusted-types-for 'script'`; no third-party scripts | Security → Headers; Evidence → live scan | Closes the main XSS path. Not proof that no XSS exists. |
| OWASP Top 10 | A05 · Security misconfiguration | Versioned header contract, verified against production on every push | Evidence → Header contract | Covers the served HTTP response. Does not cover infrastructure account settings. |
| OWASP Top 10 | A06 · Vulnerable and outdated components | OSV-Scanner over the lockfile, `npm audit` failing the build on high/critical, Renovate | Evidence → Workflows | Covers known, published vulnerabilities. Not 0-day, not first-party code. |
| OWASP Top 10 | A08 · Software and data integrity failures | GitHub Actions pinned by SHA digest, lockfile, Gitleaks, zizmor, no third-party CDN | Evidence → Workflows; latest commit hash | Covers this repository's build chain. There is no artefact signing. |
| OWASP Top 10 | A09 · Security logging and monitoring | CSP violation reports, honeypot telemetry, Certificate Transparency watch | Evidence → CSP violations and CT watch; Perimeter | Partial. No SIEM, no continuous alerting, no long retention. |
| OWASP Top 10 | A01 and A07 · Access and authentication | Static site: no accounts, no sessions, no private area | Security → Threat model; “This site” project | **Not applicable.** Absent surface, not an implemented control. |
| CIS Controls | 2 · Software asset inventory | Versioned lockfile, updates handled by Renovate | Public repository | Inventory of one asset, not of an estate. |
| CIS Controls | 3 · Data protection | No cookies, no analytics, no third-party scripts, no database; client-side tools process everything in the browser | Security → Privacy and data | Does not cover the infrastructure's connection logs, which are documented. |
| CIS Controls | 4 · Secure configuration | Security headers, two-year HSTS, Permissions-Policy switching off unused APIs | Evidence → live headers | Applies to a single published asset. |
| CIS Controls | 7 · Continuous vulnerability management | Dependency scanning on every push and a weekly update window | Evidence → Workflows | No authenticated scanning, no formal exception process. |
| CIS Controls | 8 · Audit log management | Aggregated honeypot and firewall events; CSP reports | Perimeter → Logs and Trends | Partial and by privacy decision: aggregated, no IPs, short retention. |
| CIS Controls | 16 · Application software security | SAST on client scripts, secret detection, workflow auditing, rate limiting and sanitisation in the Worker | Evidence → Workflows; repository | No external review. Control 18 (penetration testing) is not claimed. |
| CISA CPG | Identify · Mitigating known vulnerabilities | Dependencies scanned in CI; ticker correlating observed techniques with CISA's own KEV catalog | Evidence → Workflows; Perimeter → KEV correlation | Informative correlation. Not a substitute for vulnerability management. |
| CISA CPG | Protect · Strong encryption and exposed surface | HTTPS forced via HSTS, TLS managed at the edge; published surface limited to the static site and one isolated Worker | Overview → component status; Evidence | Describes the published surface. Not an infrastructure scan. |
| CISA CPG | Detect · Log collection and TTP detection | Honeypot decoy URLs and published Sigma rules, with live hit counts | Perimeter → Detections | Detection limited to the decoy surface. No endpoint or network coverage. |
| CISA CPG | Respond · Vulnerability disclosure | `security.txt` (RFC 9116) with a published contact policy | `/.well-known/security.txt`; Security → How to report | Documented channel. No response SLA, no bounty programme. |
| MITRE ATT&CK | Detection | Each decoy URL maps to a technique; each published Sigma rule carries the technique ID | Perimeter → Detections | Describes what was observed on the decoys and the rule that catches it. Not defensive coverage of the site. |

**H2 · Framework by framework**

*H3 · OWASP Top 10*

> It is the only one of these frameworks whose unit of analysis is a web
> application, which is why it is this page's axis. Five of the ten categories
> have surface here and appear in the table above. Two — access control and
> authentication — have no subject: a static site with no accounts and no
> sessions does not implement those controls, it simply has nowhere to apply
> them. The distinction is deliberate and is written into every row.

*H3 · CIS Controls*

> These cover the operational hygiene OWASP does not describe: dependencies,
> configuration, logs. The mapping stays at control level (1 to 18) and never at
> safeguard level — a website is a single asset, not an organisation with an
> estate, accounts and a team. No Implementation Group is invoked, and the
> people, access and incident-response controls stay out. Control 18,
> penetration testing, is not claimed: it does not exist here.

*H3 · CISA CPG*

> The CPGs are written as outcome goals, which reads well without invoking an
> entire security programme. Four translate directly to a website: known
> vulnerabilities, encryption, detection and a disclosure channel. There is a
> real crossover here rather than a rhetorical one: this site's ticker
> correlates techniques observed in the honeypot with the KEV catalog published
> by CISA itself. The remaining goals were written for critical-infrastructure
> operators and have no subject in this context.

*H3 · MITRE ATT&CK*

> ATT&CK appears only where detection exists. Each honeypot decoy URL maps to a
> technique, and each Sigma rule published on the Perimeter carries that
> technique's ID — with live hit counts. It is what was observed and the rule
> that would catch it; it is not a measure of this site's defensive coverage.
> (The personal ATT&CK heatmap is a different thing and lives outside this
> section.)

**H2 · Frameworks outside this page's axis**

*H3 · ISO/IEC 27001*

> ISO 27001 certifies an information security management system inside an
> organisation — scope, policy, risk assessment, statement of applicability,
> internal audit, certification body. None of that has a subject on a personal
> website, and most Annex A controls are organisational, people-related or
> physical. There is also an editorial reason: ISO evidence is documentary and
> internal, and this page only works with evidence a visitor can verify from the
> outside. It stays as vocabulary, where that helps name a group of controls.
> Not as a claim.

*H3 · NIS2*

> NIS2 is a European directive whose scope is defined by an entity's sector and
> size, transposed into each Member State's law. A personal website is not a
> covered entity: there is nobody for the obligations to apply to. Some Article
> 21 themes — supply chain, incident handling, vulnerability disclosure — echo
> what is documented on this site, and that is all that is being said. The echo
> is thematic; the legal obligation does not exist.

**H2 · Limits**

> This is a technical mapping written by the person who maintains the site, not
> an independent assessment and not a statement of compliance. There is no
> certification, no external audit, no penetration test and no statement of
> applicability. None of the frameworks cited was implemented as a programme:
> they are public vocabulary used to organise controls that already existed for
> other reasons. Frameworks change version; this page pins the version it uses
> and may lag the most recent edition. And if anything here diverges from what
> production serves, production wins — Evidence shows it live.

---

## 6. Ligações internas

Todas as ligações de saída, e nada a entrar de fora (a página não deve ser
destino obrigatório de ninguém — é uma leitura opcional).

| Destino | Onde | Formulação PT | Formulação EN |
|---|---|---|---|
| Visão Geral `/este-site/` | bloco `SiteLayers` no fim | (já existente) | (já existente) |
| Segurança `/seguranca/` | intro + célula «Evidência» das linhas OWASP A03/A05 e CIS 3 | «O porquê de cada controlo está na Segurança.» | “The reason for each control is on Security.” |
| Provas `/provas/` | célula «Evidência» da maioria das linhas; deep-links `#h-workflows`, `#h-headers` | «A prova de cada linha está nas Provas.» | “The proof behind each row is on Evidence.” |
| Perímetro `/perimetro/` | linhas ATT&CK, CPG Detetar, CIS 8 | «Ver o Perímetro →» | “See the Perimeter →” |
| Deteções | **como âncora de tab dentro do Perímetro**, não como página | «Perímetro → Deteções» | “Perimeter → Detections” |
| Projeto «Este site» `/projetos/este-site/` | linha «não aplicável» do OWASP e nota metodológica | «As decisões de arquitetura por trás disto estão no projeto.» | “The architecture decisions behind this are in the project.” |
| `/.well-known/security.txt` | linha CPG Responder | «security.txt (RFC 9116)» | “security.txt (RFC 9116)” |
| `/attack/` | **opcional, com etiqueta obrigatória** | «Heatmap ATT&CK pessoal — cobertura de percurso, não deste site.» | “Personal ATT&CK heatmap — career coverage, not this site's.” |

Sobre `/attack/`: a recomendação é **não ligar diretamente** e deixar o
Perímetro fazer essa ponte, que já a faz (`/attack/#T…`). O risco de um leitor
ler o heatmap pessoal como se fosse cobertura do site é exatamente o tipo de
ambiguidade que esta página existe para eliminar. Se for mesmo ligado, tem de
ser com a etiqueta acima, na nota da secção ATT&CK e nunca dentro da tabela.

---

## 7. Onde deve viver o texto

**Recomendação: `static/src/i18n/ui.ts`, numa nova chave `mapping`.** Não em
`content/`.

Porquê:

1. **Regra 2 do `CLAUDE.md`** — todas as strings de UI vivem em `ui.ts`, PT e EN
   na mesma estrutura, zero strings escritas à mão em componentes.
2. **Isto é dado estruturado, não prosa.** A tabela principal é um array de
   objetos com cinco campos fixos. É exatamente o padrão de `security.headers`,
   `evidence.contract` e `evidence.pipeline` — todos em `ui.ts`.
3. **`content/` tem outro papel neste repositório:** ou coleções de prosa longa
   (`blog/`, `projects/`, `pages/`), ou JSON partilhado com o Worker e validado
   por testes (`attack.json`, `detections.json`, `honeypot-attack.json`). Esta
   página não é prosa longa nem dado que o Worker leia.
4. **Paridade PT/EN fica garantida pela forma do dicionário** — divergência de
   estrutura entre idiomas parte o build, o que é a verificação que esta página
   mais precisa.

**Exceção que justificaria `content/`:** se um dia se quiser um teste que
verifique que cada célula de «Evidência pública» aponta para uma rota que existe
de facto — cruzando com `routes.ts` — então o padrão correto é
`content/mapping.json` mais um teste em `node --test`, tal como
`detections.json` já é cruzado com os DECOYS reais do Worker. Recomendação:
começar em `ui.ts`; migrar só se e quando esse teste for escrito.

**Além do texto, a implementação toca em (só para registo, não é código):**

- `static/src/i18n/routes.ts` — novo par `mapping: /este-site/mapeamento/` +
  `/en/this-site/mapping/`, seguindo o precedente do `performance` (subpágina
  real de `/este-site/`, ao contrário de Segurança/Perímetro/Provas, que estão
  na raiz).
- `static/src/layouts/BaseLayout.astro` — entrada no `siteGroup`, entre Provas e
  Performance: a página lê as Provas, por isso vem depois delas; a Performance é
  outro eixo e fecha o grupo.
- `static/src/components/SiteLayers.astro` — nova `LayerKey` e nova entrada, com
  string em `layers`:
  - PT: «Mapeamento — os controlos deste site à luz de frameworks públicas»
  - EN: “Mapping — this site's controls against public frameworks”
- Etiqueta de nav: **«Mapeamento» / “Mapping”** (uma palavra, como as irmãs).
- Duas rotas finas (PT/EN) + uma componente partilhada em
  `src/components/pages/`, ambas a passar apenas `lang`.

---

## 8. Verificação das restrições

| Restrição | Estado |
|---|---|
| Sem código Astro | cumprido |
| Sem TypeScript | cumprido |
| Sem controlos inventados | cumprido — cada linha da tabela corresponde a algo presente em `_headers`, `.github/workflows/`, `dynamic/worker/src/lib/` ou `content/` |
| Sem conformidade inventada | cumprido — «conformidade» só aparece pela negativa |
| Sem linguagem de marketing | cumprido |
| Português europeu | cumprido |
| Frases curtas e auditáveis | cumprido |
| PT e EN | cumprido |
| «Compliance» fora do título | cumprido, com justificação em §2 |
| Fora do âmbito: Sobre, percurso profissional | cumprido — regra do sujeito em §1 |

### Duas decisões a confirmar antes de implementar

1. **Versão do OWASP Top 10.** Esta proposta mapeia contra a edição de 2021. Se
   se quiser mapear contra a edição mais recente, os identificadores das linhas
   têm de ser revistos — e a página deve sempre escrever a edição que usa.
2. **Identificadores numéricos das CISA CPG.** Esta proposta refere os objetivos
   **por nome e por função** (Identificar/Proteger/Detetar/Responder) e não por
   identificador alfanumérico. Acrescentar os identificadores é possível, mas só
   depois de os verificar na versão publicada do CPG — inventar um identificador
   errado numa página cujo argumento é o rigor seria o pior falhanço possível.
