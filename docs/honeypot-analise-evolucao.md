# Honeypot — análise técnica e editorial, e proposta de evolução

Análise ao honeypot (`dynamic/worker/`) e às páginas que o explicam
(`/perimetro/`, `/attack/`, projeto Honeypot). **Não contém código, nem
expressões WAF prontas a usar, nem payloads.** É desenho, taxonomia, critérios
de decisão e copy.

Toda a copy proposta indica o destino:
- **copy de página live** → `static/src/i18n/ui.ts` (chaves `perimeter.*`,
  `detections.*`, nos dois blocos de idioma: PT ~linha 419, EN ~linha 1387);
- **copy do projeto** → markdown em `content/projects/pt/honeypot.md` e
  `content/projects/en/honeypot.md`.

Nada aqui toca na página Sobre.

Factos apurados a 2026-07-29 por leitura do repositório. Não há números de
tráfego real nesta análise — o painel ainda não está exposto (ver §0).

---

## 0) Factos apurados (a base de tudo o resto)

| Facto | Valor | Fonte |
|---|---|---|
| Paths-isco | 5 | `DECOYS` em `dynamic/worker/src/index.js` |
| Rotas do Worker | 6 (1 de API + 5 exatas de isco) | `wrangler.toml` |
| Campos por evento | `ts` (arredondado a 5 min), `country`, `asn`, `path`, `technique` | `recordHoneypot()` |
| Escritas KV por evento | 4 (`recent`, bucket hora, bucket dia, cap) | `recordHoneypot()` |
| Cap de eventos do honeypot | **60/dia** (≈240 escritas/dia) | `HONEYPOT_WRITE_CAP` |
| Orçamento KV do plano Free | ~1.000 escritas/dia **para a conta inteira** | `dynamic/PLAN.md` |
| Regras WAF personalizadas em uso | 5 | `docs/cloudflare-deploy.md` §5 |
| Ação `Log` em Custom Rules no Free | **não disponível** | idem |
| Regra WAF #5 | *Managed Challenge* a tudo fora de 27 países da UE | idem |
| Cloudflare Access | ainda cobre `danielmala.co` inteiro (incl. iscos) | idem §3 |
| Resposta dos iscos | 404 HTML byte-a-byte igual ao 404 real | `lib/notfound.js` |
| `robots.txt` | `Allow: /`, sem `Disallow` | `static/src/pages/robots.txt.ts` |
| Regras Sigma publicadas | 5 (1:1 com os iscos) | `content/detections.json` |

**Cinco restrições estruturais** decorrem daqui, e condicionam tudo o que se
segue. Vale a pena lê-las antes de qualquer ideia de expansão:

1. **O honeypot já está saturado à escrita, não à leitura.** O cap é de 60
   eventos/dia. Acrescentar paths-isco **não gera mais dados** — gera os mesmos
   60 eventos/dia repartidos por mais paths, com o resto descartado em silêncio.
   Qualquer expansão de cobertura tem de começar por resolver o orçamento de
   escrita, não pela lista de paths.
2. **O WAF não pode ser camada de observação neste plano.** São 5 regras
   personalizadas, as 5 já estão ocupadas, e o Free não tem ação `Log`. Uma
   regra WAF no Free ou **atua** (bloqueia/desafia) ou não existe. Não há
   "detetar no edge sem afetar tráfego".
3. **A regra WAF #5 corta o honeypot antes de ele ver seja o que for.** Um
   *Managed Challenge* a todo o tráfego fora da UE apanha a esmagadora maioria
   do scanning automático da Internet — que vem de redes de cloud e botnets fora
   da UE. O honeypot, tal como o perímetro está configurado, vai ver sobretudo
   **o que a UE lhe manda**, e isso é um enviesamento que a página tem de
   declarar (ver §7). É a diferença entre "o que a Internet tenta contra este
   site" e "o que passou a política geo e depois tentou".
4. **Enquanto a Access estiver ligada, o honeypot vê zero.** É o primeiro passo
   operacional de qualquer coisa nesta análise: excluir os paths-isco da Access
   (ou desligá-la no lançamento) — caso contrário todo o resto é teoria.
5. **A discrição dos iscos não é sustentável.** A lista está no `wrangler.toml`,
   no `index.js`, no `content/honeypot-attack.json`, no `detections.json` e no
   texto do projeto. Se o repositório passar a público, a lista é pública. Logo:
   **não desenhar nada que dependa de os paths serem secretos.** O valor do
   honeypot está no volume automático e indiscriminado, não em enganar quem
   leu o repositório.

---

## 1) Diagnóstico do honeypot atual

### O que está bem — e deve ficar como está

- **Sensor, não teatro.** Os iscos registam e devolvem 404. O Worker não serve
  conteúdo falso, não guarda corpo de pedido, não interage. É a postura correta
  para um site pessoal e é o que torna a promessa de privacidade defensável.
- **O 404 uniforme é a melhor decisão de realismo do desenho atual.** O
  comentário no topo de `lib/notfound.js` está certo: um 404 diferente dos
  outros é um *tell*. Hoje um scanner não consegue distinguir `/wp-login.php` de
  qualquer path inexistente. Isto é realismo a sério — e é gratuito.
- **Privacidade por construção, com prova.** Sem IP, timestamp arredondado a 5
  min, chave de rate-limit derivada com salt rotativo e nunca ligada aos
  eventos, tudo coberto por teste. Esta é a parte mais forte do projeto e a que
  melhor justifica a existência da página.
- **Lógica pura separada e testada** (`aggregate.js`, `attack-map.js`), com
  teste de sincronização entre o Worker e `content/`. Escala bem para uma
  taxonomia maior sem virar espaguete.
- **Degradação graciosa.** Worker em baixo ⇒ painel mostra fallback, site
  estático não nota.
- **Caps de escrita dimensionados ao orçamento real**, com o trade-off escrito
  no código. Raro e correto.

### O que hoje é demasiado básico ou previsível

- **Cinco paths exatos é uma amostra, não uma superfície.** Cobrem quatro
  famílias e deixam de fora as que hoje dominam o scanning automático: leftovers
  de cloud/CI, ficheiros de backup, APIs mal expostas, endpoints de
  configuração. Um scanner típico percorre centenas de paths; este honeypot
  regista uma fração e, do resto, não fica sinal nenhum.
- **`/admin` sem barra e `/.env` só na raiz.** As rotas são exatas. Um scanner
  que peça `/admin/`, `/administrator/`, `/api/.env` ou `/backend/.env` não
  toca em nada. Isto empobrece o sinal sem qualquer ganho.
- **O evento é pobre para o que custa.** Cada evento custa 4 escritas e guarda
  5 campos. **Acrescentar campos ao mesmo evento é gratuito** (é o mesmo `put`)
  e hoje deita-se fora sinal de graça: método HTTP, presença de query string,
  versão de protocolo, presença/ausência de cabeçalhos que um browser real
  sempre envia. Ver §6.
- **O mapeamento ATT&CK está a sobre-declarar.** `/wp-login.php → T1110 (Brute
  Force)` só se sustenta se houver de facto tentativa de credenciais. O Worker
  não regista o método, e um `GET` a uma página de login é enumeração
  (`T1595.003 — Wordlist Scanning`), não *credential access*. O mesmo vale para
  `/.env → T1592`: o que se observa é o *pedido*, não a recolha. Um honeypot
  passivo vive quase todo em **Reconnaissance (TA0043)** e, no limite, em
  `T1190`. Ver §3 e §6.
- **Uma regra Sigma por path** não escala. Com 30 paths seriam 30 regras
  quase iguais e a página deixava de se ler. As regras devem passar a ser **por
  família** (ver §3).
- **Não existe noção de sequência.** Um pedido isolado a `/.env` e uma varredura
  de 40 paths em 20 segundos aparecem exatamente iguais no painel. É a diferença
  analítica mais óbvia que falta.

### O que já é excesso para um site pessoal

- **A tab "Logs" com 200 eventos crus, paginada e pesquisável.** É a parte mais
  cara em KV (o `recent` reescreve-se inteiro a cada evento) e a que menos diz:
  200 linhas de `país + ASN + path` sem identidade nem sequência não se
  "investigam". Ou se reduz a lista, ou se assume que é uma amostra ilustrativa
  e se diz isso na página.
- **Threat Intel com "atacantes novos vs. recorrentes" por ASN.** Com um teto de
  60 eventos/dia e agrupamento por ASN — em que uma cloud inteira é um só ASN —
  "recorrente" quer dizer "a mesma cloud outra vez". A palavra promete mais do
  que o dado sustenta. Manter o dado, mudar o rótulo.
- **Cinco tabs na mesma página**, com três fontes de verdade diferentes
  (KV do honeypot, GraphQL da zona, `content/detections.json`). Não é excesso de
  funcionalidade, é excesso de *página*. Ver §8.

---

## 2) Realismo — análise crítica ideia a ideia

Antes das tabelas, o critério. Há duas coisas diferentes a chamar-se
"realismo":

- **Realismo de sensor:** o isco é indistinguível do resto do site. Mede-se
  pela *ausência de tells* — mesma resposta, mesmos cabeçalhos, mesma latência,
  mesmo comportamento perante métodos e variantes de path. **É este que
  interessa, e é aqui que ainda há trabalho por fazer.**
- **Realismo cénico:** o isco imita a interface de outra aplicação. Mede-se pelo
  quanto se parece com o WordPress. **Não produz sinal analítico adicional** —
  um scanner que recebe 200 e um que recebe 404 registam-se exatamente da mesma
  maneira — e traz custos que a seguir se detalham.

O erro fácil é comprar o segundo a pensar que se está a comprar o primeiro.

### 2.1 Servir páginas "verdadeiras" em vez de 404

| | |
|---|---|
| **Benefício** | Praticamente nenhum para deteção. O evento registado é o mesmo. |
| **Risco** | Alto. O Worker passa a servir HTML de aplicações que o site não corre; um scanner que receba `200` num `/wp-login.php` marca o domínio como "WordPress vivo" e **promove-o** para listas de alvos mais agressivos. O tráfego sobe, o orçamento de KV e de invocações esgota-se mais depressa, e o site fica com uma superfície declarada que não tem. |
| **Manutenção** | Alta e permanente. HTML falso envelhece (versões, temas, textos), tem de passar a CSP do Worker, e cada página é mais código não testado numa área que hoje é 100% lógica pura testada. |
| **Valor de deteção** | **Nulo** face ao 404, sem interação. Só ganha valor se se capturar o que é submetido — e isso é a linha que não se deve atravessar (ver 2.2). |
| **Faz sentido aqui?** | **Não.** Classificação: *excesso cénico sem valor analítico*. |

### 2.2 Imitar interfaces reais (WordPress login, phpMyAdmin, painéis)

Trata-se em separado porque tem um problema próprio, e sério.

Uma página de login falsa convida ao envio de credenciais. As credenciais que
os scanners injetam **são de pessoas reais** — vêm de listas de fugas e de
*credential stuffing*. Servir um formulário significa passar a receber, na tua
infraestrutura, passwords de terceiros. Mesmo descartando-as no instante
seguinte:

- entra em contradição direta com a garantia central do projeto ("nenhum IP é
  armazenado", "só metadados") — passa a existir uma classe de dados muito mais
  sensível do que um IP a atravessar o Worker;
- qualquer erro de log, qualquer `console.error` com o corpo do pedido, e o dano
  é irreversível e não é teu para reparar;
- em RGPD, dados de autenticação de terceiros são categoria de risco elevado; o
  facto de terem sido enviados por um bot não te dá base legal para os tratar,
  e a defesa "não guardei" tem de ser provada.

> **Risco legal e ético — recomendação explícita:** não servir formulários de
> autenticação falsos, nem aceitar corpo de pedido nos iscos, em nenhuma
> variante. O ganho analítico é marginal; o risco não é.

| Variante | Veredicto |
|---|---|
| Login WordPress / phpMyAdmin / painel admin com formulário | *Risco desnecessário* — não fazer |
| Painel "admin" só de leitura, sem formulário | *Excesso cénico* — custo de manutenção sem sinal novo |
| Dashboards falsos | *Excesso cénico* |
| Ficheiros "expostos" com conteúdo falso (`.env` com chaves inventadas) | *Excesso cénico*, com um risco adicional: chaves falsas circulam, aparecem em scanners de segredos de terceiros e geram ruído para outros. Não fazer. |
| Endpoints de backup / API / metadata a devolver JSON falso | *Excesso cénico*; e um `/api/*` falso colide com a API real do Worker |

**Uma exceção defensável, e só uma:** *canary tokens* — um ficheiro-isco cujo
conteúdo é inerte mas único, que sinaliza quando alguém o **usa** noutro sítio.
É honesto e sem interação. Mas exige um serviço terceiro ou um endpoint de
retorno, e para este site não paga o que custa. Registar como ideia, não
construir.

### 2.3 O que aumenta realismo *a sério* (e que se deve fazer)

Isto sim é realismo de sensor, e é barato:

1. **Variantes de path.** `/admin` e `/admin/`; `/.env` na raiz e em prefixos
   comuns; `/phpmyadmin/` e as suas grafias habituais. Um scanner que testa 5
   variantes deixa de encontrar 4 buracos.
2. **Coerência de métodos.** Hoje um `POST` a um isco cai no mesmo ramo e
   recebe o mesmo 404 — o que está certo, mas o método não é registado. Deve
   ser: distingue enumeração de tentativa e é o que salva o mapeamento ATT&CK
   (§3).
3. **Coerência de cabeçalhos e latência.** O 404 do Worker e o 404 do Pages
   devem ser indistinguíveis não só no HTML mas nos cabeçalhos de resposta e na
   ordem de grandeza da latência. Hoje o Worker responde de imediato e o Pages
   serve de cache — uma diferença sistemática e mensurável de latência é um
   *tell*. Verificar depois do lançamento; se houver diferença notória, é a
   única "encenação" que vale a pena: alinhar a resposta, não inventar
   conteúdo.
4. **O `robots.txt` como parte do desenho.** Ver §4 — é a peça em falta com
   melhor relação sinal/custo do projeto inteiro.

### 2.4 Distinguir tipos de isco (ficheiro / login / painel / API / diretório / trap)

**Sim — mas como *classificação do evento*, não como comportamentos
diferentes.** A resposta mantém-se uniforme (404); o que muda é a etiqueta que
o Worker anexa ao evento. Custo: zero escritas adicionais. Ganho: as
agregações, as regras Sigma e a página passam a falar em famílias em vez de
paths soltos, e a taxonomia cresce sem que a página cresça.

Servir respostas diferentes por tipo de isco seria reintroduzir o *tell* que o
`notfound.js` foi escrito para eliminar. Não fazer.

---

## 3) Taxonomia de paths-isco

Regras de desenho antes da tabela:

- **A unidade passa a ser a família, não o path.** Um path pertence a uma
  família; a família tem técnica ATT&CK, regra Sigma e valor analítico. Os paths
  crescem sem que nada mais cresça.
- **Padrões, não lista exata.** O Worker deve classificar por prefixo/sufixo
  (ex.: qualquer path terminado em `/.env`, qualquer coisa sob `/.git/`), para
  que variantes não escapem.
- **As rotas do `wrangler.toml` passam a ser poucas e por prefixo.** Uma rota
  exata por path não escala e há teto de rotas por zona — confirmar o valor
  atual no dashboard antes de desenhar. A alternativa "encaminhar o site todo
  para o Worker" resolve a cobertura mas põe o Worker no caminho crítico de
  todas as visitas: **não recomendado** neste plano.
- **Nunca reclassificar um path que o site sirva de verdade.** Antes de
  adicionar uma família, confirmar contra as rotas reais (`routes.ts`,
  `/ferramentas/*`).

### Famílias propostas

| # | Família | Exemplos de padrão (ilustrativos) | Quem procura | ATT&CK | Classe de evento / Sigma | Valor |
|---|---|---|---|---|---|---|
| 1 | **CMS / WordPress** | `/wp-login.php`, `/wp-admin/*`, `/xmlrpc.php`, `/wp-content/*` | botnets de massa, o tráfego mais volumoso da Internet | `T1595.003` (GET) · `T1110` **só** em POST | `cms_probe` — 1 regra com lista de padrões | **Alto** (volume) |
| 2 | **DB admin** | `/phpmyadmin/*` e grafias equivalentes, `/adminer*` | scanners à procura de consolas esquecidas | `T1595.002`; `T1190` se houver POST/query de exploração | `dbadmin_probe` | **Alto** |
| 3 | **Git / segredos / config** | `/.git/*`, `/.env` e variantes por prefixo, ficheiros de config em raiz | recolectores de segredos, automação de "secret scanning" ofensivo | `T1595.003`; `T1592.002` quando o alvo é software/versão | `secret_leak_probe` | **Alto** (fidelidade máxima: nunca é legítimo) |
| 4 | **Ficheiros de backup / dumps** | sufixos de arquivo e de dump em raiz, `backup*`, nomes derivados do domínio | scanners oportunistas | `T1595.003` | `backup_probe` | **Alto** (barato, comum, zero falsos positivos) |
| 5 | **Portais de administração** | `/admin`, `/admin/`, `/administrator*`, `/manager*`, `/console*` | wordlists genéricas | `T1595.003` | `adminpanel_probe` | **Médio** (mais ruidoso; pode existir em estates reais) |
| 6 | **Leftovers de cloud / infra** | endpoints de metadata de cloud pedidos por engano ao host, paths de orquestração/painéis de infra | scanners de SSRF e de configuração exposta | `T1595.002` · `T1190` | `cloud_leftover_probe` | **Médio-alto** (bom indicador de scanner moderno vs. botnet antiga) |
| 7 | **Leftovers de CI/CD** | ficheiros de pipeline em raiz, diretórios de artefactos, endpoints de runner | scanners orientados a *supply chain* | `T1595.003` | `cicd_probe` | **Médio** |
| 8 | **Package / dependências** | manifestos e lockfiles de ecossistemas em raiz, diretórios de dependências | scanners de inventário e de versão | `T1592.002` | `inventory_probe` | **Médio** (útil para separar recon de exploração) |
| 9 | **APIs mal expostas** | prefixos de API versionada que o site não serve, endpoints de documentação de API, GraphQL | scanners de API, alguns já com IA no meio | `T1595.002` | `api_probe` | **Médio** — **cuidado:** o site tem `/api/*` real, tem de haver separação estrita |
| 10 | **Recon genérico / fingerprinting** | pedidos de ficheiros de identificação de servidor, sondas de versão, `HEAD` a paths de assinatura | qualquer scanner na fase 1 | `T1595.001` · `T1592` | `fingerprint_probe` | **Baixo-médio** (muito ruído, valor sobretudo como denominador) |
| 11 | **Crawler traps / conformidade robots** | um único path declarado `Disallow` no `robots.txt` | crawlers que ignoram `robots.txt` | `T1595` | `robots_violation` | **Alto por unidade de esforço** — ver §4 |

Notas de fidelidade:

- Famílias 3 e 4 são as de maior fidelidade: não há tráfego legítimo nenhum.
  Merecem `level: high` em Sigma e disparo ao primeiro toque.
- Família 5 é a de menor fidelidade e a regra atual já o reconhece
  (`level: low`, condicionada a `sc-status: 404`). Manter assim.
- Família 9 é a única com risco de auto-colisão. Se for adotada, a fronteira
  tem de ser explícita no código e verificada por teste — um isco que apanhe
  a API real transforma visitantes em "eventos hostis" e corrompe todo o
  painel.

### Correção ao mapeamento ATT&CK

Proposta concreta, para `content/honeypot-attack.json` +
`attack-map.js` (mantendo o teste de sincronização):

| Observação | Técnica hoje | Proposta |
|---|---|---|
| `GET` a path de login | `T1110` | `T1595.003` |
| `POST` a path de login | `T1110` | `T1110` (mantém — passa a ser verdade) |
| Pedido a ficheiro de segredos/config | `T1592` | `T1595.003` |
| Pedido a painel admin | `T1595` | `T1595.003` |
| Pedido com padrão de exploração a app conhecida | `T1190` | `T1190` (mantém) |

E uma nota editorial que hoje falta e devia estar na página: **um honeypot
passivo observa reconhecimento.** Ver as suas técnicas quase todas em
Reconnaissance não é uma limitação envergonhada, é o que ele é. Dizê-lo torna a
página mais credível, não menos.

---

## 4) Spider traps e crawler traps

### O que não fazer, e porquê

**Geração infinita** — calendários sem fim, paginação infinita, árvores de links
que se expandem, parâmetros combinatórios, texto gerado para prender bots:

- **Paga-o o teu Worker, não o bot.** Cada página gerada é uma invocação e CPU
  teus. Uma armadilha "infinita" é um convite explícito a que um bot consuma o
  teu orçamento — no plano Free, o mesmo orçamento de que depende a API do
  site. A armadilha pode derrubar o painel que ela existe para alimentar.
- **Apanha o alvo errado.** Bots de arquivo, leitores de acessibilidade,
  agregadores e investigação académica seguem links. Não distinguem "armadilha"
  de "site".
- **É postura ofensiva, não defensiva.** Consumir deliberadamente recursos de
  terceiros por tempo indefinido é *tarpitting*. Pode ser legítimo em contexto
  de investigação, com âmbito e autorização; num site pessoal que se apresenta
  como sóbrio e auditável, é uma contradição.
- **Custo de SEO real.** Mesmo com `noindex`, gasta-se orçamento de rastreio em
  lixo e arrisca-se sinal de conteúdo fino/*doorway*.

Veredicto: *risco desnecessário de manutenção, SEO e ambiguidade ética.*
**Não implementar.**

### "Os Lusíadas" e variantes de conteúdo gerado

Duas coisas, e vale a pena separá-las porque a premissa da pergunta não se
confirma:

- **Direitos de autor: não é o problema.** *Os Lusíadas* (1572) é domínio
  público. O que pode ter direitos é uma *edição* concreta — notas, fixação de
  texto, prefácio. Usar o texto base não levanta questão legal.
- **O problema é outro, e é decisivo: o tom.** Todas as outras páginas do site
  dizem "não acredites, verifica" e sustentam-no. Uma armadilha que despeja
  estrofes num loop é uma piada — e uma piada que gera páginas a sério, com
  URLs a sério, num domínio cuja tese é a seriedade documental. Enfraquece o
  resto por associação, e é a primeira coisa que um leitor técnico vai usar para
  desvalorizar tudo o resto.

**Recomendação: não usar.** Se houver vontade de uma marca portuguesa, o sítio
certo é o 404 (que já tem uma piada de terminal) ou uma frase original na página
do projeto — não conteúdo gerado.

### A versão que vale mesmo a pena

**Um path declarado `Disallow` no `robots.txt`, que não é ligado de lado
nenhum, servido pelo mesmo Worker com o mesmo 404, e registado como qualquer
outro isco.**

Porque funciona:

- **O sinal é limpo por construção.** Quem chega àquele path leu o
  `robots.txt` (é a única forma de saber que existe) e decidiu ignorá-lo. Não
  é inferência, é dedução. Nenhum outro isco dá um sinal desta qualidade.
- **Custo: uma linha no `robots.txt` e uma entrada na tabela de famílias.**
- **Risco de SEO: nenhum.** Não está no sitemap, não está ligado, está
  explicitamente excluído. Os crawlers que interessam nunca lá vão — e é
  precisamente por isso que quem lá vai interessa.
- **Ética: limpa.** Não se consome nada de ninguém; devolve-se um 404. Quem
  fica registado escolheu ignorar uma instrução pública.
- **Manutenção: zero** depois de criado.

Duas notas de execução:

- Acrescentar `X-Robots-Tag: noindex, nofollow` na resposta dos iscos (via
  `_headers` não dá — os iscos são do Worker; é nos cabeçalhos de resposta do
  Worker). Barato e correto.
- **Não** ligar o path a partir de nenhuma página, nem sequer com
  `rel="nofollow"` e escondido. Um link escondido é o que separa "canário de
  conformidade" de "armadilha", e a partir daí todas as objeções acima voltam.

### Resumo

| Variante | Veredicto |
|---|---|
| Path `Disallow` no `robots.txt`, não ligado, 404 | **Fazer** — *isco credível e útil* |
| Árvore de links profunda / paginação infinita / calendário | *Risco desnecessário* — não fazer |
| Parâmetros infinitos | *Risco desnecessário* (e envenena as próprias métricas) |
| Texto gerado para prender crawlers | *Excesso cénico* + custo de SEO |
| Conteúdo literário português em loop | *Excesso cénico* — não fazer |
| Link escondido para o path-isco | *Risco desnecessário* — anula a limpeza do sinal |

---

## 5) Arquitetura de deteção — papel de cada camada

O princípio que arruma tudo: **cada camada deve fazer o que as outras não
conseguem, e nada mais.** Duas camadas a detetar a mesma coisa não é
redundância defensiva, é dupla contabilidade — e é o que produz painéis que se
contradizem.

### Cloudflare WAF (edge)

- **Papel: política. Não é sensor** — e neste plano não pode ser (sem ação
  `Log`, 5 regras, todas ocupadas).
- **Deve conter:** o que nunca deve chegar ao Worker (abuso volumétrico,
  política geográfica, exceções de bots verificados). O que já lá está.
- **Não deve conter:** classificação de iscos. Uma regra WAF que bloqueie
  scanners de iscos **destrói o sensor** — é exatamente o efeito que a regra #5
  já tem hoje, sem intenção.
- **A decisão explícita que falta:** o honeypot e a regra geo são incompatíveis
  em objetivo. Ou se aceita que o honeypot mede tráfego pós-política (e a
  página di-lo), ou se cria uma exceção para os paths-isco (que ficam
  acessíveis ao mundo, com o cap de escrita como travão). **Recomendação:
  aceitar e declarar**, na fase 1. Abrir os iscos ao mundo é a fase 2 e exige
  primeiro resolver o orçamento de escrita.

### Cloudflare Worker

- **Papel: o único ponto de decisão.** Classifica (path → família → técnica),
  enriquece o evento, aplica o cap, devolve sempre o mesmo 404.
- **Princípio de custo:** *enriquecer* um evento é gratuito, *criar* um evento
  custa 4 escritas. Todo o desenho de deteção deve empurrar sinal para os
  campos do evento, não para eventos novos.
- **Fronteira:** nada de estado por cliente ao ritmo dos pedidos (ver KV).

### Workers KV

- **Papel: contadores e uma janela curta de eventos.**
- **Regra publicável, e boa:** *no KV só entra o que não cresce com o número de
  clientes.* Contadores por família/país/ASN/hora — sim. Estado por
  cliente/sessão — não.
- **Consequência honesta:** correlação por sequência de pedidos do mesmo
  cliente **não cabe no KV** neste plano. Alternativa sem custo de KV: memória
  efémera do edge (Cache API), que é *best-effort*, local ao datacenter e não
  garante consistência — serve para marcar "este cliente já tocou noutro isco
  nos últimos minutos", não para contabilidade. Se a resposta a "quantos paths
  tentou" tiver mesmo de ser fiável, isso é Durable Objects — **ferramenta
  nova, exige decisão do dono do repo** (`CLAUDE.md`) e não se justifica ainda.

### Camada de agregação

- **Papel: transformar contadores em leituras**, on-read, pura e testada. Já é
  assim (`aggregate.js`); manter.
- **É aqui que vive o *scoring*** (§6): calcular no momento da leitura custa
  zero armazenamento e permite mudar a heurística sem migrar dados. Guardar um
  score no evento seria congelar uma opinião.

### Página Perímetro

- **Papel: estado.** O que está a acontecer, agora, e o que a Cloudflare já
  parou. Números, janelas, tendências.
- **Não é** o sítio para explicar desenho, taxonomia ou o porquê da
  privacidade — só um resumo curto com link.

### Página Deteções

- **Papel: portabilidade.** Traduzir o que se observa em regras que funcionam
  noutro sítio. Uma regra por **família**, com o contador ao vivo ao lado. É a
  página que prova que o honeypot serve para alguma coisa fora deste site.

### Página ATT&CK

- **Papel: cobertura pessoal.** Cuidado com a colisão de significados: em
  `/attack/` "coberto" quer dizer *o que eu sei fazer*; no honeypot quer dizer
  *o que tentaram contra mim*. São coisas diferentes e a página não as deve
  fundir. Os links do honeypot devem apontar para lá; as contagens do honeypot
  não devem acender células do heatmap pessoal.

### Fluxo, em uma linha

`WAF (política) → Worker (classifica + enriquece + 404) → KV (contadores) →
agregação (deriva sinais e score) → Perímetro (estado) / Deteções (regras
portáveis) / ATT&CK (referência)`

---

## 6) Mais deteções

Ordenadas por relação valor/custo. "Custo" é sobretudo **escritas KV**, que é o
recurso escasso.

| # | Proposta | Valor analítico | Custo | Risco de ruído | Publicar? |
|---|---|---|---|---|---|
| 1 | **Método HTTP no evento** | Alto — separa enumeração de tentativa; corrige o ATT&CK | Nulo (campo no mesmo `put`) | Nulo | **Sim** |
| 2 | **Família do path no evento** | Alto — todas as agregações passam a ser por família | Nulo | Nulo | **Sim** |
| 3 | **Presença de query string / de fragmento suspeito** (booleano, nunca o conteúdo) | Alto — distingue recon de tentativa de exploração | Nulo | Baixo | **Sim** (como booleano) |
| 4 | **Classe de User-Agent** (balde: vazio / ferramenta conhecida / semelhante a browser / biblioteca) | Médio-alto — separa botnet antiga de scanner moderno | Nulo | Médio (UA é falsificável — dizê-lo) | **Sim**, com a ressalva |
| 5 | **Sinais de "não-browser"** (ausência de `Accept-Language`, versão de protocolo HTTP/1.1, ausência de `Accept` credível) | Alto em conjunto — é o melhor discriminador barato que existe | Nulo | Baixo | **Sim**, agregado |
| 6 | **Score de confiança derivado na leitura** (soma dos sinais 1–5 + fidelidade da família) | Alto — dá ordem ao painel sem inventar categorias | Nulo (calculado on-read) | Médio (é heurística — tem de se dizer) | **Sim**, com os critérios visíveis |
| 7 | **Correlação de ritmo por ASN dentro da janela** (quantos eventos do mesmo ASN na mesma hora) | Médio — já é derivável dos buckets | Nulo | Médio (ASN ≠ ator) | Sim, com rótulo honesto |
| 8 | **Correlação com o que a Cloudflare bloqueou antes** (país/ASN presentes nos dois lados) | Médio — mostra as duas camadas a falar | Nulo (dados já existem) | Alto de interpretação: são amostras e janelas diferentes; somar seria errado | Sim, **como comparação, nunca como soma** |
| 9 | **Deteções compostas em Sigma** (regras de correlação: N famílias distintas do mesmo cliente numa janela; contagem de eventos por janela) | Alto — é o que um SOC a sério escreve | Baixo (é conteúdo, não runtime) | Baixo | **Sim** — e é a melhor forma de mostrar sequência sem a implementar no Worker |
| 10 | **Sequência real por cliente no Worker** | Alto se fiável | **Alto** — estado por cliente; ou KV (não cabe) ou ferramenta nova | Médio | **Não agora** |
| 11 | **Taxonomia de atores em 4 classes** (bot burro / crawler agressivo / scanner massivo / probing focado) | **Baixo com os dados atuais** | Baixo | **Alto** | **Não publicar** — ver abaixo |

**Sobre a #11, explicitamente:** sem identidade por cliente, sem sequência e com
60 eventos/dia, "probing focado" não é distinguível de "duas botnets a bater no
mesmo minuto". Publicar quatro classes de ator é afirmar mais do que o dado
sustenta — precisamente o erro que o resto do site evita. Alternativa honesta e
igualmente interessante: publicar **os sinais** (família, método, classe de UA,
sinais de não-browser) e deixar a leitura ao visitante. Mostra mais competência
do que uma classificação inventada.

**Sobre a #9,** é a jogada mais elegante disponível: o Sigma tem regras de
correlação. Publicar uma regra de correlação — "o mesmo cliente toca em N
famílias distintas dentro de uma janela" — demonstra o raciocínio de deteção
composta **sem** obrigar o Worker a manter estado. A regra é verdadeira e útil
num SIEM que tenha IPs; o honeypot, que não os tem, di-lo na nota de rodapé.
Isto é vantagem editorial, não desculpa.

---

## 7) Páginas do site — o que pertence a cada uma

### Diagnóstico do que está repetido hoje

| Conteúdo | Onde aparece | Problema |
|---|---|---|
| "Só metadados, nunca IPs" | `perimeter.intro`, `perimeter.privacyNote`, `perimeter.honeypotIntro`, `detections.pipelineSteps[0]`, projeto md, README do Worker | Repetido 5×. Uma vez em cada sítio com propósito diferente basta. |
| Lista dos 5 paths | projeto md, `honeypotIntro`, `detections.pipelineSteps[0]`, `detections.json` | Com uma taxonomia por famílias, a lista literal deixa de fazer sentido na copy — passa a exemplo. |
| "Cada path tem uma técnica ATT&CK" | `perimeter.techNote`, `detections.pipelineSteps[1]`, projeto md | 3×. Fica na tab Deteções e no projeto. |
| Explicação do Worker vs. estático | projeto md, README, `perimeter.projectNote` | Correto assim: a página remete, o projeto explica. |

### Regra de arrumação proposta

| Assunto | Destino | Porquê |
|---|---|---|
| Números ao vivo, janelas, tendências | **Perímetro** (`ui.ts`) | é estado |
| O que cada número significa e **não** significa | **Perímetro** (`ui.ts`), nota curta | limites junto ao dado |
| Enviesamento da política geo | **Perímetro** (`ui.ts`) — **novo, em falta** | sem isto o painel induz em erro |
| Famílias de paths (conceito + exemplos) | **Deteções** (via `content/detections.json`) | é a unidade das regras |
| Lista exaustiva de paths | **repositório**, mais nenhum sítio | não é conteúdo editorial |
| Regras Sigma e conversão | **Deteções** | já está |
| Regras de correlação (compostas) | **Deteções** | é o passo seguinte natural |
| Papel de cada camada (WAF/Worker/KV) | **projeto Honeypot** (`content/`) | é arquitetura |
| Porquê 404 uniforme e não páginas falsas | **projeto Honeypot** (`content/`) — **novo** | é a decisão mais interessante do projeto e não está escrita |
| Porquê não há tarpits | **projeto Honeypot** (`content/`) — **novo** | idem |
| Orçamento de KV e cap de eventos | **projeto Honeypot** (`content/`) — **novo** | explica o teto e antecipa a pergunta |
| Privacidade: prova, não promessa | **projeto Honeypot** (`content/`) + nota curta no Perímetro | já está, só desduplicar |
| Cobertura ATT&CK pessoal | **ATT&CK** | não misturar com o honeypot |

### Página nova?

**Não.** Uma quinta página ("Spider traps", "Taxonomia") repartiria ainda mais
um assunto que já está esticado por quatro sítios. O canário de `robots.txt` é
**uma família na tabela + dois parágrafos no projeto**. Se um dia a taxonomia
crescer ao ponto de merecer página própria, o candidato natural é promover
**Deteções** de tab a página outra vez — mas isso já foi feito e desfeito
(`_redirects` tem os 301), e mexer nos URLs uma terceira vez é pior do que o
problema que resolve.

---

## 8) Estrutura editorial proposta

### Projeto Honeypot — `content/projects/{pt,en}/honeypot.md`

**Objetivo editorial:** explicar o desenho e, sobretudo, **o que foi
deliberadamente não construído**. É a peça de engenharia; é aqui que a decisão
de não servir logins falsos vale mais do que qualquer painel.

**Headings propostos:**

1. *(intro sem heading)* — o que é, em 4 linhas, com link para o Perímetro
2. `## O que o honeypot é — e o que não é` **(novo)** — sensor vs. encenação;
   sem interação, sem formulários, sem conteúdo falso
3. `## Porque vive no Worker, não no site estático` — mantém
4. `## Famílias de isco` **(novo)** — a taxonomia em prosa curta, com exemplos,
   sem lista exaustiva
5. `## O 404 é o produto` **(novo)** — porque a resposta uniforme é a decisão de
   realismo mais importante
6. `## Privacidade por construção` — mantém, encurtado (é a única secção que
   pode remeter para o teste)
7. `## Limites deliberados` **(novo)** — cap de escritas do plano Free;
   enviesamento da política geo; sem sequência por cliente; sem tarpits, e
   porquê
8. `## Correlação: honeypot ↔ ATT&CK ↔ KEV` — mantém, com a correção de
   técnicas de §3

**Sai:** a lista literal dos 5 paths na intro (vira "famílias, por exemplo…").
**Links internos:** Perímetro, `/attack/`, projeto "Este site".

### Perímetro — `static/src/i18n/ui.ts`, chave `perimeter.*`

**Objetivo editorial:** responder a "o que está a chegar a este site, agora, e o
que já foi travado antes de chegar". Nada de arquitetura.

**Tabs propostas** — reordenadas por *pergunta*, não por fonte de dados:

| Tab hoje | Proposta | Nota |
|---|---|---|
| Honeypot | **O que chega** | stats + mapa + correlação KEV; ganha a nota de enviesamento geo |
| Deteções | **Como se deteta** | mover para depois de "O que a Cloudflare travou" — é o passo seguinte, não o segundo |
| Cloudflare | **O que já foi travado** | inalterado |
| Tendências (7d) | **Tendências (7d)** | inalterado; renomear "atacantes recorrentes" → "redes recorrentes" |
| Logs | **Amostra de eventos** | o nome "Logs" promete investigação; é uma amostra |

**Entra:** nota de enviesamento (geo + cap), uma linha, junto às stats.
**Sai:** repetição da promessa de privacidade em três sítios — fica uma.

### Deteções — tab do Perímetro, conteúdo em `content/detections.json`

**Objetivo editorial:** provar portabilidade.

**Estrutura:** intro → pipeline (3 passos, mantém) → **regras por família**
(substitui as 5 por path) → **regras de correlação** (novo, 1–2) → conversão com
`sigma-cli` → link para ATT&CK.

**Sai:** uma regra por path. **Entra:** contador por família e a nota de que a
correlação por cliente pressupõe um SIEM com IPs, que este honeypot não tem.

### ATT&CK

Sem alterações estruturais. Uma frase a separar os dois sentidos de "cobertura"
(ver §5).

---

## 9) Copy editorial (PT + EN)

Frases curtas. Sem linguagem de marketing. Nada aqui afirma números.

### 9.1 Intro do projeto Honeypot → `content/projects/pt/honeypot.md` e `content/projects/en/honeypot.md`

**PT**
> Alguns paths deste site existem só para serem tentados. Não servem nada, não
> respondem nada de especial: devolvem o mesmo 404 que qualquer caminho
> inexistente. A diferença é que a tentativa fica registada — só país, rede e
> caminho pedido, nunca o IP. Quem lhes toca não é gente: é automação a varrer a
> Internet inteira. O estado ao vivo está no [Perímetro](/perimetro/).

**EN**
> A few paths on this site exist only to be tried. They serve nothing and answer
> nothing special: they return the same 404 as any path that never existed. The
> difference is that the attempt is recorded — country, network and requested
> path only, never the IP. Whoever touches them is not a person: it is
> automation sweeping the whole Internet. The live state is on the
> [Perimeter](/en/perimeter/) page.

### 9.2 Bloco "Como funciona" → markdown do projeto (`content/`)

**PT**
> O pedido chega ao edge da Cloudflare e, se a política de zona o deixar passar,
> a um Cloudflare Worker. O Worker reconhece o caminho, classifica-o numa
> família de isco, anexa a técnica ATT&CK correspondente e escreve um evento
> agregado no KV. Depois devolve o 404 — o mesmo HTML, os mesmos cabeçalhos, o
> mesmo aspeto do 404 real do site. Nada distingue um isco de um caminho que
> nunca existiu. Essa indistinção é o desenho, não um detalhe.

**EN**
> The request reaches Cloudflare's edge and, if the zone policy lets it through,
> a Cloudflare Worker. The Worker recognises the path, classifies it into a
> decoy family, attaches the matching ATT&CK technique and writes an aggregated
> event to KV. Then it returns the 404 — same HTML, same headers, same look as
> the site's real 404. Nothing tells a decoy apart from a path that never
> existed. That indistinguishability is the design, not a detail.

### 9.3 Bloco "O que é detetado" → markdown do projeto (`content/`)

**PT**
> O que se deteta é o pedido, não o ataque. É uma distinção importante: um
> honeypot passivo observa reconhecimento — enumeração de caminhos conhecidos,
> procura de ficheiros de configuração, varrimento de painéis de administração.
> Por isso quase todas as técnicas mapeadas vivem na tática *Reconnaissance* do
> ATT&CK. Só quando o pedido traz método ou forma de exploração é que passa a
> ser outra coisa, e só nesse caso é classificado como tal.

**EN**
> What gets detected is the request, not the attack. The distinction matters: a
> passive honeypot observes reconnaissance — enumeration of known paths, hunting
> for configuration files, sweeping for admin panels. That is why almost every
> mapped technique sits under ATT&CK's *Reconnaissance* tactic. Only when a
> request carries an exploitation method or shape does it become something else,
> and only then is it classified as such.

### 9.4 Bloco "Privacidade e limites" → markdown do projeto (`content/`)

**PT**
> Nenhum IP é guardado. Cada evento tem país, rede (ASN), caminho e um
> timestamp arredondado a cinco minutos — o arredondamento é anonimização, não
> arrumação. Há um teste que falha se um IP aparecer no armazenamento ou nos
> logs.
>
> Os limites são igualmente parte do desenho. O plano usado tem um teto diário
> de escritas, por isso o honeypot descarta eventos acima de um cap — sob
> varrimento intenso perde-se granularidade, nunca o site. A política de zona
> desafia tráfego de fora da Europa antes de chegar aqui, o que enviesa a origem
> do que se observa. E sem IP não há sequência por cliente: sabe-se o que foi
> tentado, não quem tentou o quê a seguir a quê. Nada disto se resolve com mais
> paths.

**EN**
> No IP is stored. Each event holds country, network (ASN), path and a timestamp
> rounded to five minutes — the rounding is anonymisation, not tidiness. A test
> fails if an IP ever appears in storage or in the logs.
>
> The limits are part of the design too. The plan in use has a daily write
> ceiling, so the honeypot drops events above a cap — under heavy scanning you
> lose granularity, never the site. The zone policy challenges traffic from
> outside Europe before it gets here, which biases the origins observed. And
> without an IP there is no per-client sequence: you know what was tried, not
> who tried what after what. None of this is fixed by adding more paths.

### 9.5 Intro da página Perímetro → `static/src/i18n/ui.ts`, `perimeter.intro`

**PT**
> O que a Internet tenta contra este site, e o que é travado antes de chegar.
> Duas fontes: os endpoints-isco servidos por um Worker próprio, e o que a
> Cloudflare vê na zona inteira. Só agregados e metadados — nunca IPs.

**EN**
> What the Internet tries against this site, and what gets stopped before it
> arrives. Two sources: the decoy endpoints served by a dedicated Worker, and
> what Cloudflare sees across the whole zone. Aggregates and metadata only —
> never IPs.

### 9.6 Nota de enviesamento (nova) → `ui.ts`, chave nova `perimeter.biasNote`

Esta é a adição de copy mais importante desta análise.

**PT**
> Estes números não são uma amostra neutra da Internet. A política da zona
> desafia tráfego de fora da Europa antes de chegar ao isco, e o registo tem um
> teto diário de eventos. O que se vê aqui é o que passou o perímetro e coube no
> teto — não tudo o que foi tentado.

**EN**
> These numbers are not a neutral sample of the Internet. The zone policy
> challenges traffic from outside Europe before it reaches the decoy, and
> logging has a daily event ceiling. What you see here is what got past the
> perimeter and fit under the ceiling — not everything that was tried.

### 9.7 Intro da página Deteções → `static/src/i18n/ui.ts`, `detections.intro`

**PT**
> O passo a seguir ao isco: cada família de caminho que este site apanha vem com
> a regra Sigma que a apanharia num SIEM. As regras são vendor-neutral e
> convertem-se com o `sigma-cli`. O contador ao lado de cada uma são toques
> reais nos últimos sete dias — quando o painel está ligado; quando não está,
> fica a traço e a regra continua tão válida.

**EN**
> The step after the decoy: every path family this site catches comes with the
> Sigma rule that would catch it in a SIEM. The rules are vendor-neutral and
> convert with `sigma-cli`. The counter beside each one is real hits over the
> last seven days — when the panel is wired up; when it is not, it stays a dash
> and the rule is just as valid.

### 9.8 Nota sobre o canário de `robots.txt` → markdown do projeto (`content/`)

Deve existir publicamente? **Sim** — explicar o mecanismo não o enfraquece
(quem o quisesse evitar bastava-lhe respeitar o `robots.txt`, que é o
comportamento desejado), e é a ideia mais interessante do conjunto.

**PT**
> Um dos caminhos está declarado como proibido no `robots.txt` e não está
> ligado a partir de lado nenhum. Só se chega lá lendo o `robots.txt` e
> decidindo ignorá-lo. Não é uma armadilha: devolve o mesmo 404 que tudo o
> resto, não gera páginas, não prende ninguém. É um canário de conformidade —
> mede quem lê as regras e passa à frente.

**EN**
> One of the paths is declared off-limits in `robots.txt` and is linked from
> nowhere. The only way to reach it is to read `robots.txt` and decide to ignore
> it. It is not a trap: it returns the same 404 as everything else, generates no
> pages, holds no one. It is a compliance canary — it measures who reads the
> rules and walks past them.

---

## 10) Recomendação final

### Fazer — vale mesmo a pena

| # | O quê | Porquê |
|---|---|---|
| 1 | **Excluir os iscos da Access (ou lançar).** | Sem isto, nada do resto produz um único evento. |
| 2 | **Método HTTP + família no evento; classificação por padrão em vez de path exato.** | Custo zero em KV, corrige o ATT&CK e desbloqueia tudo o resto. |
| 3 | **Corrigir o mapeamento ATT&CK** (`T1595.003` onde hoje há `T1110`/`T1592`). | É a correção de rigor mais visível para quem percebe do assunto. |
| 4 | **Rotas do `wrangler.toml` por prefixo, poucas.** | Deixa a taxonomia crescer em código e não em infraestrutura. |
| 5 | **Famílias 1–5 da tabela de §3** (CMS, DB admin, segredos, backups, painéis). | Cobre a esmagadora maioria do scanning real com 5 famílias. |
| 6 | **Canário de `robots.txt`.** | Melhor sinal por unidade de esforço do projeto inteiro. |
| 7 | **Nota de enviesamento no Perímetro (§9.6).** | Sem ela o painel afirma mais do que sabe. É a correção editorial mais importante. |
| 8 | **Regras Sigma por família + 1 regra de correlação.** | Mostra deteção composta sem construir estado no Worker. |
| 9 | **Secções novas no markdown do projeto** (§8): "o que não é", "o 404 é o produto", "limites deliberados". | A decisão de não encenar é o melhor conteúdo disponível e hoje não está escrita em lado nenhum. |
| 10 | **`X-Robots-Tag: noindex, nofollow` nas respostas dos iscos.** | Uma linha, elimina qualquer risco de indexação. |

### Não fazer — parece boa ideia e não compensa

- **Páginas falsas de login/painel/phpMyAdmin.** Sem ganho analítico; e receber
  credenciais de terceiros contradiz a garantia central do site (§2.2).
- **Ficheiros-isco com conteúdo falso** (chaves inventadas). Poluem scanners de
  terceiros.
- **Spider traps com geração infinita, calendários, paginação sem fim.** Pagas
  tu o custo; postura ofensiva; risco de SEO (§4).
- **Conteúdo literário em loop.** Não é problema de direitos de autor — *Os
  Lusíadas* é domínio público. É problema de tom, e esse é pior.
- **Taxonomia publicada de "tipos de atacante" em 4 classes.** Os dados não a
  sustentam (§6, #11).
- **Lista exaustiva de paths na copy.** Vira wordlist e envelhece mal.

### Manter simples

- O 404 uniforme, sem exceções, sem variações por família.
- Um Worker, um namespace KV, agregação on-read pura e testada.
- Uma página de estado (Perímetro), uma explicação (projeto), uma tradução
  (Deteções). Sem páginas novas.

### Segunda fase

- **Abrir os iscos à política geo** (exceção no WAF) — só depois de resolver o
  orçamento de escrita, porque o volume sobe de forma não trivial.
- **Famílias 6–9** (cloud, CI/CD, inventário, APIs) — a 9 só com fronteira
  testada contra `/api/*` real.
- **Score de confiança visível** com os critérios expostos.
- **Sequência por cliente** — só com Durable Objects e **decisão explícita do
  dono do repo**; registar em `dynamic/PLAN.md` antes de qualquer código.
- **Reduzir a lista `recent`** se o KV apertar: é a maior escrita por evento.

### O que não publicar de forma explícita

- A lista completa e atual de paths-isco na copy (famílias e exemplos, sim).
- A fórmula exata do score, se vier a existir — os critérios, sim; os pesos,
  não (evita afinação trivial contra o sensor).
- O caminho concreto do canário de `robots.txt` no texto do projeto. Está no
  `robots.txt`, que é público por definição — não precisa de ser repetido em
  prosa, e mencioná-lo de passagem ("um dos caminhos") é mais elegante.
- Qualquer coisa que dependa de segredo: o repositório pode tornar-se público
  (§0, ponto 5).

### Uma nota final, honesta

A tentação natural é medir a evolução do honeypot em número de paths. Com o cap
de 60 eventos/dia e a política geo à frente, **mais paths não dão mais dados** —
dão os mesmos dados repartidos por mais rótulos. As três coisas que mudam
mesmo o que este projeto consegue dizer são, por ordem: tornar os iscos
alcançáveis, enriquecer o evento que já se escreve, e declarar os limites do que
se mede. Nenhuma delas é encenação, e é isso que as torna consistentes com o
resto do site.
