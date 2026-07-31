# Proposta — subpágina «Mapeamento de controlos» (secção Este Site)

> **Proposta, não implementada (confirmado 2026-07-31).** Nenhuma rota, chave
> `ui.ts` ou componente correspondente existe — ver
> `docs/archive/auditoria-repo-publico-2026-07-31.md`. Movido para `docs/proposals/`
> para não ser lido como estado atual do site.

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

> **Versões fixadas nesta proposta:** **OWASP Top 10:2025** (edição final,
> decidida pelo dono do repo), **CIS Controls v8.1**, **ATT&CK Enterprise** na
> versão que alimenta `content/attack.json`. As **CISA CPG** são referidas por
> **nome de objetivo e função** (Identificar/Proteger/Detetar/Responder), sem
> identificador alfanumérico — decisão tomada: os identificadores ficam para
> mais tarde, depois de verificados na versão publicada do CPG.
>
> As referências CIS ficam ao nível de **controlo** (1–18), nunca de salvaguarda
> (`x.y`). Referenciar ao detalhe daria à página o ar de auditoria que ela
> declaradamente não é.
>
> **O que a edição de 2025 muda para este site:** «Componentes vulneráveis e
> desatualizados» deixou de ser categoria própria e foi absorvida por **A03 ·
> Falhas na cadeia de fornecimento de software**, que passou a terceiro risco da
> lista — é onde este site concentra mais controlos automatizados. O antigo A09
> passou a chamar-se registo **e alerta**, o que torna explícito um limite que já
> existia. E o SSRF, que era categoria própria (A10:2021), está agora dentro do
> **A01**.

### OWASP Top 10:2025 — **eixo principal**

- **Porquê faz sentido:** é a única das quatro frameworks cuja unidade de
  análise é uma *aplicação web*. Todos os controlos deste site são
  aplicacionais.
- **O que se pode mapear:** A02 (contrato de cabeçalhos verificado em produção);
  A03 (OSV-Scanner, `npm audit`, Renovate, Actions pinadas por digest, zero
  terceiros); A04 (HSTS, k-anonimato no verificador de passwords, hash com salt
  diário no rate limiting); A05 (CSP estrita sem `unsafe-inline`, Trusted Types,
  render por `textContent`, SAST de sinks DOM-XSS, sanitização no Worker); A08
  (hash do commit publicado, Gitleaks, zizmor, verificação da CSP servida); A09
  (relatórios CSP, telemetria honeypot, vigia CT); A10 (degradação explícita
  quando o Worker falha). No A01 entra apenas a parte de **SSRF**: os pedidos de
  saída do Worker vão para destinos fixos e a rota do verificador de passwords
  só aceita 5 caracteres hexadecimais — o próprio código a documenta como «não
  reutilizável como proxy aberto».
- **O que não alegar:** a parte de *controlo de acesso* do A01 e o A07 **não são
  controlos — são não-aplicáveis**. Não há contas, sessões nem área privada.
  Escrever «não aplicável», nunca «coberto»: ausência de superfície não é
  controlo implementado. A06 (design inseguro) não é verificável por terceiros e
  fica de fora da tabela. No A09, não alegar deteção ativa: há registo, não há
  alerta — e o nome da categoria em 2025 obriga a dizê-lo.
- **Evidência que suporta:** `/seguranca/` (cabeçalhos e porquê), `/provas/`
  (contrato de cabeçalhos, scan ao vivo, workflows, hash do commit),
  `static/public/_headers`, `dynamic/worker/src/lib/` (`pwned.js`, `scan.js`,
  `ratelimit.js`, `sanitize.js`).
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
> Versões usadas: OWASP Top 10:2025, CIS Controls v8.1, MITRE ATT&CK
> Enterprise. As CISA CPG são referidas por objetivo e função, sem
> identificador.

**H2 · Mapa de controlos**

| Framework | Área | Controlo observado no site | Evidência pública | Limite da alegação |
|---|---|---|---|---|
| OWASP Top 10:2025 | A01 · Controlo de acesso | Site estático: sem contas, sem sessões, sem área privada | Segurança → Modelo de ameaça; projeto «Este site» | **Não aplicável.** Ausência de superfície, não controlo implementado. |
| OWASP Top 10:2025 | A01 · SSRF (categoria própria até 2021, hoje aqui dentro) | Os pedidos de saída do Worker vão para destinos fixos, definidos em configuração; a rota do verificador de passwords só aceita cinco caracteres hexadecimais, o que a impede de servir de proxy aberto | Repositório: `dynamic/worker/src/lib/pwned.js` e `scan.js` | Leitura do código publicado, não resultado de teste. Cobre as rotas que existem hoje. |
| OWASP Top 10:2025 | A02 · Configuração incorreta | Contrato de cabeçalhos versionado e verificado em produção a cada push | Provas → Contrato de cabeçalhos | Cobre a resposta HTTP servida. Não cobre a configuração da conta de infraestrutura. |
| OWASP Top 10:2025 | A03 · Falhas na cadeia de fornecimento de software | OSV-Scanner sobre o lockfile (vulnerabilidades conhecidas e pacotes maliciosos), `npm audit` a falhar o build em high/critical, Renovate, GitHub Actions pinadas por digest SHA, zero scripts ou CDN de terceiros | Provas → Workflows | Cobre o que é conhecido e publicado. Não cobre 0-day nem comprometimento a montante ainda não divulgado. |
| OWASP Top 10:2025 | A04 · Falhas criptográficas | HTTPS forçado por HSTS a dois anos; o verificador de passwords usa k-anonimato — o browser envia cinco caracteres do hash, nunca a password; os identificadores do rate limiting são hash com salt rotativo diário e não são associados a eventos | Segurança → Cabeçalhos e Privacidade; repositório | O TLS é gerido pelo edge, não por este repositório. Sem revisão criptográfica externa. |
| OWASP Top 10:2025 | A05 · Injeção | CSP estrita: `script-src 'self'`, `style-src 'self'`, sem `unsafe-inline`; `require-trusted-types-for 'script'`; render sempre por `textContent`; SAST sobre sinks de DOM XSS; sanitização de todo o dado externo no Worker | Segurança → Cabeçalhos; Provas → scan ao vivo e Workflows | Fecha a via principal de XSS. Não é prova de ausência de XSS. |
| OWASP Top 10:2025 | A07 · Falhas de autenticação | Não existe autenticação: sem contas, sem sessões, sem recuperação de palavra-passe | Segurança → Modelo de ameaça | **Não aplicável**, pela mesma razão do A01. |
| OWASP Top 10:2025 | A08 · Falhas de integridade de software e dados | Hash do commit publicado e verificável, deteção de segredos sobre a história do PR, auditoria dos próprios workflows, verificação de que a CSP servida não diverge da versionada | Provas → último commit e Workflows | Não há assinatura de artefactos nem proveniência de build. |
| OWASP Top 10:2025 | A09 · Falhas de registo e alerta | Relatórios de violação de CSP recolhidos, telemetria do honeypot, vigia de Certificate Transparency | Provas → Violações CSP e Vigia CT; Perímetro | **Parcial, e do lado certo da fronteira:** há registo, não há alerta. Sem SIEM e sem notificação automática. |
| OWASP Top 10:2025 | A10 · Tratamento de condições excecionais | Quando o Worker falha, as secções que dependem dele degradam para um estado explícito em vez de partir a página; o honeypot devolve sempre um 404 indistinguível; o cap de escritas descarta em silêncio em vez de falhar | Projeto «Este site»; Perímetro, com o Worker em baixo | Comportamento observável, sem testes de falha sistemáticos. |
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

*H3 · OWASP Top 10:2025*

> É a única destas frameworks cuja unidade de análise é uma aplicação web, e por
> isso é o eixo desta página. A edição de 2025 mudou três coisas que importam
> aqui. «Componentes vulneráveis» deixou de ser categoria própria e passou a
> estar dentro do A03, cadeia de fornecimento, que subiu a terceiro risco da
> lista — é onde este site concentra mais controlos automatizados. O SSRF, que
> tinha categoria própria, está agora dentro do A01. E o antigo A09 passou a
> chamar-se registo **e alerta**, o que torna explícito um limite que já existia:
> aqui há registo, não há alerta.
>
> Duas áreas não têm sujeito. Sem contas nem sessões, o controlo de acesso e a
> autenticação não são controlos implementados — apenas não têm onde se aplicar,
> e está escrito assim em cada linha. O A06, design inseguro, fica fora da
> tabela: não é verificável de fora, e esta página só trabalha com o que é.

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
> Versions used: OWASP Top 10:2025, CIS Controls v8.1, MITRE ATT&CK Enterprise.
> The CISA CPGs are referenced by goal and function, without identifiers.

**H2 · Control map**

| Framework | Area | Control observed on this site | Public evidence | Limit of the claim |
|---|---|---|---|---|
| OWASP Top 10:2025 | A01 · Access control | Static site: no accounts, no sessions, no private area | Security → Threat model; “This site” project | **Not applicable.** Absent surface, not an implemented control. |
| OWASP Top 10:2025 | A01 · SSRF (its own category until 2021, now folded in here) | The Worker's outbound requests go to fixed, configured destinations; the password-checker route accepts only five hexadecimal characters, which stops it working as an open proxy | Repository: `dynamic/worker/src/lib/pwned.js` and `scan.js` | A reading of published code, not a test result. Covers the routes that exist today. |
| OWASP Top 10:2025 | A02 · Security misconfiguration | Versioned header contract, verified against production on every push | Evidence → Header contract | Covers the served HTTP response. Does not cover infrastructure account settings. |
| OWASP Top 10:2025 | A03 · Software supply chain failures | OSV-Scanner over the lockfile (known vulnerabilities and malicious packages), `npm audit` failing the build on high/critical, Renovate, GitHub Actions pinned by SHA digest, no third-party scripts or CDN | Evidence → Workflows | Covers what is known and published. Not 0-day, not an undisclosed upstream compromise. |
| OWASP Top 10:2025 | A04 · Cryptographic failures | HTTPS forced by two-year HSTS; the password checker uses k-anonymity — the browser sends five characters of the hash, never the password; rate-limiting identifiers are hashed with a daily rotating salt and never tied to events | Security → Headers and Privacy; repository | TLS is managed at the edge, not by this repository. No external cryptographic review. |
| OWASP Top 10:2025 | A05 · Injection | Strict CSP: `script-src 'self'`, `style-src 'self'`, no `unsafe-inline`; `require-trusted-types-for 'script'`; rendering always via `textContent`; SAST over DOM XSS sinks; sanitisation of all external data in the Worker | Security → Headers; Evidence → live scan and Workflows | Closes the main XSS path. Not proof that no XSS exists. |
| OWASP Top 10:2025 | A07 · Authentication failures | There is no authentication: no accounts, no sessions, no password recovery | Security → Threat model | **Not applicable**, for the same reason as A01. |
| OWASP Top 10:2025 | A08 · Software or data integrity failures | Published, verifiable commit hash, secret detection across the PR's history, auditing of the workflows themselves, and a check that the served CSP does not diverge from the versioned one | Evidence → latest commit and Workflows | No artefact signing and no build provenance. |
| OWASP Top 10:2025 | A09 · Security logging and alerting failures | CSP violation reports collected, honeypot telemetry, Certificate Transparency watch | Evidence → CSP violations and CT watch; Perimeter | **Partial, and on the right side of the line:** there is logging, there is no alerting. No SIEM, no automatic notification. |
| OWASP Top 10:2025 | A10 · Mishandling of exceptional conditions | When the Worker fails, the sections that depend on it degrade to an explicit state instead of breaking the page; the honeypot always returns an indistinguishable 404; the write cap drops silently rather than failing | “This site” project; Perimeter, with the Worker down | Observable behaviour, without systematic failure testing. |
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

*H3 · OWASP Top 10:2025*

> It is the only one of these frameworks whose unit of analysis is a web
> application, which is why it is this page's axis. The 2025 edition changed
> three things that matter here. “Vulnerable components” stopped being its own
> category and now sits inside A03, supply chain, which rose to third on the
> list — that is where this site concentrates most of its automated controls.
> SSRF, previously its own category, now sits inside A01. And the old A09 was
> renamed logging **and alerting**, which makes explicit a limit that already
> existed: there is logging here, there is no alerting.
>
> Two areas have no subject. With no accounts and no sessions, access control
> and authentication are not implemented controls — they simply have nowhere to
> apply, and every row says so. A06, insecure design, stays out of the table: it
> is not verifiable from the outside, and this page only works with what is.

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

### Decisões tomadas

1. **Versão do OWASP Top 10 — resolvido: edição 2025.** É a edição final mais
   recente (`owasp.org/Top10/2025/`). Todas as linhas foram remapeadas: o antigo
   A03 Injeção é hoje **A05**, o antigo A05 Configuração é hoje **A02**, o antigo
   A06 Componentes vulneráveis foi absorvido pelo **A03 · cadeia de
   fornecimento**, o SSRF passou a viver dentro do **A01**, e o A09 ganhou a
   palavra *alerta* no nome. A página escreve sempre a edição que usa.
2. **Identificadores numéricos das CISA CPG — adiado por decisão.** Os objetivos
   ficam referidos **por nome e por função** (Identificar/Proteger/Detetar/
   Responder). Os identificadores alfanuméricos podem ser acrescentados mais
   tarde, depois de verificados na versão publicada do CPG — inventar um
   identificador errado numa página cujo argumento é o rigor seria o pior
   falhanço possível.

### Ponta solta menor (não bloqueia)

- **`CIS Controls v8.1`** — os *nomes* dos controlos 1 a 18 usados aqui são
  estáveis entre v8 e v8.1, por isso o mapeamento é válido em qualquer das duas.
  Confirmar o número de versão exato a escrever na página quando se
  implementar; se houver dúvida, escrever apenas «CIS Controls v8».
