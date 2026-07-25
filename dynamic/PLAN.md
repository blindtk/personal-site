# dynamic/ — plano da app dinâmica ("Lab")

> **Estado: em produção.** `dynamic/worker/` (Worker das features de
> segurança do site — honeypot, mapa de tráfego hostil, self-scan de
> cabeçalhos, ticker SOC e pipeline de violações CSP) está deployado nas
> rotas do domínio `danielmala.co`. Deploy, gotchas e infraestrutura
> (Access, WAF) documentados em `dynamic/worker/README.md` e
> `docs/cloudflare-deploy.md`.
> As ferramentas de rede abaixo (DNS/whois/…) continuam por fazer; a página
> `/lab/` ("em construção") apontará para elas quando existirem.

## Decisões registadas

- **2026-07 — Secção "Este Site" (observabilidade) — fases 2/3** (aprovado pelo
  dono do repo, na sequência do pedido "Este Site"): três adições ao Worker
  para alimentar a Threat Intelligence, os Logs e a Performance da nova secção.
  Todas **zero-PII** e **best-effort** (nunca derrubam o núcleo):
    1. **Threat Intelligence do honeypot** (`/api/threat-intel`, cache 5 min,
       aquecida no cron). Os buckets do honeypot passam a acumular também
       **byAsn** e **byTech** (a par de country/path — ver `aggregate.js`), e os
       buckets horários passam a reter **8 dias** (era 2) para dar um **heatmap
       dia×hora** e "ataques por hora do dia". Agrega localmente: top país/ASN/
       técnica/path, hora de pico. **Atacantes agrupados por ASN, NUNCA por IP**
       — os eventos do honeypot nunca tiveram IP. O `recent` sobe de 30→200
       eventos para a **tabela de Logs** (pesquisa/paginação no cliente).
    2. **Acumulação de firewall 7d** (a "fase 2" já antevista abaixo): o cron
       fotografa a repartição de firewall das últimas 24h num snapshot diário
       (`fw:<dia>`, TTL 8d) e o `/api/threat-intel` funde os 7 dias. É assim que
       se estende a janela de 24h (limite do dataset cru no Free) para 7 dias,
       só com contadores por ação/origem. **Cron ativado** (`*/30 * * * *`) —
       era opcional; agora é preciso para acumular.
    3. **RUM first-party de Core Web Vitals** (`POST/GET /api/vitals`,
       `lib/vitals.js` + `static/public/js/vitals.js`). O browser mede LCP/CLS/
       INP/TTFB com `PerformanceObserver` e envia **uma vez** via `sendBeacon`;
       o Worker acumula **histogramas diários** e devolve o **p75** (o percentil
       da Google) por métrica. **Só agregados**: nunca a amostra individual,
       nem IP, nem UA, nem URL — mesma defesa em camadas do recetor CSP
       (Content-Type restrito, corpo ≤2KB, rate limit, cap de escritas). Porquê
       first-party e não o RUM da Cloudflare: o beacon deles é **script de
       terceiros**, incompatível com a CSP estrita e com o "sem trackers" do
       site. **Para desligar**: remover `<script src="/js/vitals.js">` do
       `BaseLayout.astro` (o resto do site não depende dele).

- **2026-07 — Detalhe por código HTTP no painel "Estado da Cloudflare"**
  (aprovado pelo dono do repo): o card "ameaças bloqueadas (WAF/edge)" mostrava
  só um contador cego (`threats` do `httpRequests1dGroups`), sem dizer *o que* a
  proteção fez. Passa a haver uma tabela **"pedidos rejeitados por código HTTP ·
  7d"** (só 4xx/5xx: 403 bloqueado, 429 rate limit, 503 desafio/indisponível…),
  a partir do **`responseStatusMap`** do `httpRequests1dGroups` — campo irmão do
  `countryMap` que já usamos. Só agregados, nunca IPs. Fica no **pedido-núcleo**
  (não é best-effort separado): é um campo tão estável como o `countryMap`.
  Lógica pura em `cf-analytics.js` (`blockedByStatus`), testada; UI
  (`CfAnalytics.astro`) + i18n (`statusLabels`, com fallback ao código cru).

  **Porquê o código HTTP e não a "origem/ação" da regra WAF (a escolha óbvia):**
  o detalhe real — `firewallEventsAdaptiveGroups` (action `block`/`skip`, source
  `firewallCustom`/`ratelimit`…) — é **Pro+**. Provado por eliminação contra a
  zona real (Free), não por documentação:
    - permissões: o token tem `Account Analytics:Read` + `Zone Analytics:Read` +
      `Zone Logs:Read` e o dataset continua a dar `"does not have access to the
      path"`;
    - janela: no Free os datasets adaptativos limitam-se a 24h (o
      `httpRequestsAdaptiveGroups` devolveu literalmente *"cannot request a time
      range wider than 1d"*); reduzida a query de firewall para 24h, **continua**
      barrada, enquanto o `httpRequestsAdaptiveGroups` — mesmo token, mesma
      janela — **devolve** dados. Logo: não é permissão nem janela, é o **plano**.
    - O `threatPathingMap` (Free, mecanismo por ameaça) foi testado e é esparso
      ao ponto de inútil (1 em ~676), por isso também caiu.

  **Custo desta decisão:** custou muitas iterações e vários PRs (o dataset de
  firewall foi tentado e revertido). Fica registado o desfecho: no plano Free, a
  via honesta e rica para "o que a proteção faz" é o **código HTTP das respostas
  do edge**; o detalhe por regra WAF exige Pro+. Se a zona um dia passar a Pro,
  reabre-se o `firewallEventsAdaptiveGroups` (com janela ≤ retenção do plano).

- **2026-07 — CORREÇÃO: eventos de firewall SÃO acessíveis no Free (dataset
  cru)** (fase 1 aprovada pelo dono do repo): a conclusão anterior ("firewall é
  Pro-only") estava **errada** — confundi os dois datasets. O
  `firewallEventsAdaptive**Groups**` (agregado) é Pro+, mas o
  `firewallEventsAdaptive` (**cru**, eventos individuais) **funciona no Free**
  (retenção 24h), com o token a ter as permissões de leitura de firewall (Zone
  Firewall Services:Read, Zone WAF:Read, Account Firewall Access Rules:Read).
  Provado em produção: o cru devolveu eventos reais (`managed_challenge` de
  `firewallCustom`), enquanto o agregado continuou a dar "no access". Como o
  agregado é Pro, a **agregação por ação/origem faz-se no Worker** a partir do
  cru (`firewallBreakdown`). Pedido separado e **best-effort** (nunca derruba o
  painel-núcleo). O painel passa a ter duas tabelas — **por ação** e **por
  origem · 24h** — a par do "por código HTTP · 7d" (que se mantém, é sinal
  complementar). Etiquetas i18n (`actionLabels`/`sourceLabels`) com fallback ao
  valor cru; nunca se pede nem guarda o IP. **Fase 2 (planeada, ainda não
  feita):** como o cru só tem 24h no Free, um **cron diário** coleta o agregado
  do dia para KV e acumula uma janela de **7 dias** — a ideia de "coletar e
  guardar" do dono do repo, que aqui faz todo o sentido.

- **2026-07 — CORREÇÃO 2: o texto do painel "Tráfego" sobre IP/URL/user-agent/
  ASN estava errado; adicionado detalhe por URL, user-agent e ASN** (pedido
  direto do dono do repo): o `planNote` da tab Tráfego dizia que "detalhe por
  IP, URL, user-agent e ASN de todo o tráfego exige o dataset
  `firewallEventsAdaptiveGroups` (Pro+)". Isso confundia outra vez os dois
  datasets do ponto acima — só o AGREGADO é Pro+; o CRU (já em uso para
  ação/origem/país desde a correção anterior) sempre teve os campos
  `clientRequestPath`, `userAgent` e `clientAsn` disponíveis no Free. Corrigido
  o texto e adicionado o que ele dizia faltar: três tabelas novas na tab
  Tráfego — **URLs mais visadas**, **user-agents mais vistos** e **redes (ASN)
  mais vistas**, todas pelo firewall nas últimas 24h (limite de retenção do
  cru). Implementação:
    - `CF_FIREWALL_DETAIL_QUERY` — pedido GraphQL **separado** de
      `CF_FIREWALL_QUERY` (mesmo dataset, campos diferentes), para isolar o
      risco: uma deriva de schema nestes três campos novos nunca apaga as
      tabelas de ação/origem/país que já funcionam em produção (mesmo
      princípio best-effort de sempre).
    - `firewallDetailBreakdown` em `cf-analytics.js` — pesa por
      `sampleInterval` (mesma amostragem que `firewallBreakdown`), sanitiza
      path/user-agent com `sanitizeText` e valida o ASN com `normalizeAsn`.
    - **`clientIP` continua fora** — está disponível neste dataset (é
      literalmente o que prova que o texto antigo estava errado), mas nunca é
      pedido nem processado. Zero-PII é escolha do site, não limitação do
      Free — o `planNote` corrigido diz isto explicitamente.
    - Sem acumulação a 7 dias para estas três tabelas (ficam a 24h, ao
      contrário de ação/origem/país que já têm o snapshot diário da fase 2
      acima) — manter o KV/`snapshotFirewall` a acumular path/user-agent
      aumentaria a pegada de dados retidos sem pedido explícito para isso;
      revisitar só se o dono do repo pedir.

- **2026-07 — Dependabot security-only a par do Renovate** (decisão do dono do
  repo): o Renovate faz todos os *version updates* (rotina agrupada + majors),
  mas fica ligado também o **Dependabot security updates** — só para
  vulnerabilidades. Não é contradição com o "substitui o Dependabot" da config:
  o Renovate, por design, só abre PRs de segurança para dependências **diretas**
  (as do `package.json`); as **transitivas** (fundo do `package-lock.json`) não
  são alcançadas por ele — nem com `osvVulnerabilityAlerts`. O Dependabot
  security-only tapa esse buraco porque analisa o lock file inteiro. Caso que
  motivou a decisão: `sharp`/`libvips` (High, CVE-2026-33327/33328/35590/35591),
  transitiva puxada pelo `wrangler` (devDependency) em `dynamic/worker/` — o
  Renovate nunca a listaria. O que **não** se liga: Dependabot *version updates*
  (colidiria com o Renovate) e as *Dependabot rules* de auto-dismiss
  (a "dismiss low-impact dev-scoped" dispensaria alertas como o do sharp e
  anularia o próprio security update; malware nunca se auto-dispensa). Config do
  Renovate marca os CVEs com label `security` (`vulnerabilityAlerts`).

- **2026-07 — Verificador de passwords comprometidas (k-anonimato)** (aprovado
  pelo dono do repo): ferramenta educativa que verifica se uma password aparece
  em fugas conhecidas via *range API* do Have I Been Pwned, **sem a password
  alguma vez sair do browser**. O cliente calcula o SHA-1 localmente
  (WebCrypto), envia só os 5 primeiros hex do hash ao Worker (`GET
  /api/pwned-range?prefix=XXXXX`), recebe ~800 sufixos que partilham esse
  prefixo e faz a correspondência localmente — o Worker (e o HIBP) nunca sabem
  que password foi testada. O Worker atua como *relay* anonimizador (o HIBP vê o
  IP de egress da Cloudflare, não o do visitante) e envia `Add-Padding: true`
  para uniformizar o tamanho das respostas. Lógica pura em
  `dynamic/worker/src/lib/pwned.js` (parse) e `static/src/scripts/pwned.js`
  (split/match), ambas testadas com vetores conhecidos. Princípios: validação
  estrita do prefixo (`^[0-9A-F]{5}$` — não é reutilizável como proxy aberto),
  rate limit desde o dia 1, cache 24h por prefixo (dataset público), zero
  logs de prefixos. A UI, em estilo de log de terminal, torna o protocolo de
  k-anonimato *visível* — é esse o produto, não o resultado da consulta.
  **Atualização 2026-07 (ver entrada abaixo): já não vive só na página
  Segurança — tem página própria em `/ferramentas/pwned/`.**

- **2026-07 — Pipeline de violações CSP** (aprovado pelo dono do repo):
  `report-uri`/`report-to` na camada de header da CSP → `POST
  /api/csp-report` no Worker (validação estrita, rate limit, só agregados
  anónimos — nunca o URL completo) → painel "Violações CSP" na página
  Segurança. Papel duplo: canário de regressão da CSP (zero inline,
  script-src/style-src 'self') + observatório do ruído que uma CSP estrita
  apanha. Rodagem: calibrar os
  buckets de ruído com dados reais antes de dar destaque ao painel.

- **2026-07 — Vigia CT (monitor de Certificate Transparency do próprio
  domínio)** (aprovado pelo dono do repo): o Worker consulta os logs públicos
  de CT via crt.sh (duas queries — apex e `%.domínio`, porque um certificado
  emitido só para um subdomínio nunca apareceria na query do apex), deduplica
  pré-certificado/folha pelo serial e compara cada emissão dos últimos 90
  dias com a allowlist `CT_EXPECTED_ISSUERS` (por omissão Let's Encrypt +
  Google Trust Services, o par primário/backup da Cloudflare). Emissões fora
  da allowlist aparecem como "inesperado" — o primeiro sinal de um takeover
  de DNS/registrar. Painel na página Segurança (padrão CspViolations:
  fallback sem Worker, stats + banner + tabela), endpoint `GET /api/ct` com
  cache 6 h + stale-while-revalidate e warm no cron. **Distinto da
  "verificação de certificados TLS" do roadmap** (essa é para hosts
  arbitrários com input do utilizador; isto é observabilidade defensiva do
  próprio ativo, sem qualquer input de visitantes — não é reutilizável como
  proxy nem precisa de rate limit próprio). Lógica pura em
  `dynamic/worker/src/lib/ct.js`, testada com vetores realistas do crt.sh.

- **2026-07 — Reversão: ferramentas com backend passam a viver em
  `/ferramentas/`** (decisão do dono do repo): as duas entradas acima diziam
  que o verificador de passwords e o self-scan viviam só na página Segurança
  "porque o índice `/ferramentas/` é 100% client-side". Deixou de ser assim —
  ambos têm agora página própria (`/ferramentas/pwned/`,
  `/ferramentas/self-scan/`) e aparecem no índice com um badge "requer
  servidor" (verde "client-side" para as restantes), em vez de client-side
  ser um contrato implícito e absoluto do índice. A página Segurança mantém a
  narrativa (o porquê de cada ferramenta) e passa a linkar para a ferramenta
  em vez de a embeber — mesmo padrão já usado lá para o heatmap ATT&CK e as
  Provas. A página **Provas continua a embeber o self-scan diretamente**
  (é o próprio propósito dessa página: prova ao vivo, não um link).

- **2026-07 — Três ferramentas novas** (aprovadas pelo dono do repo, após
  proposta com mockups):

  - **Analisador de CSP** (`/ferramentas/csp/`, **100% client-side**): cola-se
    uma `Content-Security-Policy` e recebe-se uma leitura crítica, diretiva a
    diretiva — `unsafe-inline`/`unsafe-eval`, wildcards contornáveis (host com
    `*.`, JSONP/CDN), esquemas nus, e diretivas em falta (`base-uri`,
    `object-src`, `frame-ancestors`, `form-action`). Nota por letra
    determinística. Lógica pura em `static/src/scripts/csp-lint.js` (parse +
    heurísticas CSP L3 + bypasses públicos conhecidos), testada com vetores
    (`static/test/csp-lint.test.mjs`); as mensagens são IDs traduzidos no i18n.
    Sem rede, sem abuso; complementa o self-scan (que diz *se* o header existe;
    isto diz *se o valor presta*).

  - **Espelho** (`/ferramentas/mirror/`, **requer servidor**): o simétrico do
    honeypot — mostra ao próprio visitante o que qualquer servidor aprende dele
    no handshake (TLS/cipher, HTTP, país/ASN, User-Agent, Accept-Language) num
    painel, e o que o browser revela localmente (ecrã, fuso, núcleos, tema) no
    outro. Endpoint `GET /api/mirror` **sem input de visitante** (não é proxy),
    **sem qualquer escrita de estado** (só o rate limit toca no KV) e que
    **nunca devolve o IP** (visível ao Worker, mas não ecoado nem guardado).
    Lógica pura em `dynamic/worker/src/lib/mirror.js` (`serverView`), testada —
    incluindo a garantia dura de que o IP não aparece no corpo. Rate limit
    30/min por cliente; resposta per-request (`no-store`).

  - **Laboratório de passkeys** (`/ferramentas/passkeys/`, **100%
    client-side**): cria uma passkey de demonstração real (WebAuthn), disseca o
    `authenticatorData` byte a byte (rpIdHash, flags UP/UV/BE/BS/ED, signCount,
    AAGUID identificado, chave pública COSE via `getPublicKey`) e verifica a
    assinatura da asserção com WebCrypto — mostrando, ao repetir contra um
    domínio-isco, porque é que o browser recusa (resistência a phishing = o
    autenticador assina a origem que o browser viu). Lógica pura em
    `static/src/scripts/passkeys.js` (parse binário, flags, AAGUID, DER→raw da
    assinatura ECDSA), testada com vetores. Sem rede, sem estado no servidor; a
    passkey criada é real e fica no gestor do utilizador (aviso de limpeza).

- **2026-07 — Cache do cron alinhada ao intervalo (evita reconstruir o
  threat-intel a cada tick)** (pedido direto do dono do repo — "faz o que
  achares mais adequado para reduzir o consumo de API", plano Free): mesmo
  alerta "50% of your daily Workers KV operation limit reached" da entrada
  abaixo (reporting CSP), mas desta vez com o site **ainda por publicar** e
  só o dono a aceder via Zero Trust Access — a Access cobre `danielmala.co`
  inteiro (incl. `/api/*` e os paths-isco), logo nenhum visitante real ou
  scanner consegue lá chegar. A fonte tinha de ser algo que corre sem
  pedidos HTTP: o **cron** (`*/30 * * * *`, `scheduled()` em `src/index.js`),
  que dispara direto do runtime da Cloudflare, fora do alcance da Access.
  Duas causas identificadas por inspeção do código (sem acesso ao breakdown
  exato do dashboard):
    1. `cache:threatintel` tinha TTL de 5 min — menor que o intervalo do
       cron (30 min). Cada um dos 48 ticks/dia encontrava a cache sempre
       "stale" e reconstruía o fan-out completo de `readThreatBuckets`
       (`THREAT_INTEL_HOURS`=168 + 7 dias + `recent` = ~176 GETs) +
       `readFirewall7d` (7 GETs) — **~183 leituras + 1 escrita por tick,
       48×/dia (~8.800 leituras/dia)**, para um valor que na prática nunca
       chegava a ficar em cache do ponto de vista do cron. Corrigido: TTL
       subido para 6h, alinhado com scan/ct/cf-stats (mesmo padrão já usado
       nesta rota).
    2. `snapshotFirewall` corria encadeado a seguir a **todo** o
       `cached('cache:cfstats', ...)`, não só quando a cache de facto
       refrescava — nos ticks em que `cached()` devolvia o valor já em
       cache (a maioria, TTL 6h), a fotografia diária (`fw:<dia>`) era
       reescrita com os mesmos dados, sem qualquer ganho de frescura (o
       cf-stats só muda quando `fetchCfStats` corre mesmo, ~4×/dia).
       Corrigido: o snapshot passou para dentro do producer do `cached()`,
       só corre quando os dados são de facto novos — de 48 escritas/dia
       para ~4/dia nessa chave.
  Nada mudou no dado que os visitantes veem (mesmo TTL de 6h já usado por
  scan/ct/cf-stats) — só deixou de se pagar KV a reconstruir o mesmo valor
  em ticks onde nada tinha mudado. `npm test` (lógica pura) continua a
  passar; não há teste automatizado para `scheduled()`/o router em si
  (best-effort, degradação graciosa por desenho). Se o alerta persistir
  depois disto, o passo seguinte é olhar para o dashboard (Storage &
  Databases → KV → Metrics) para ver a repartição real leituras/escritas —
  sem esses números, esta correção parte do fan-out mais óbvio no código,
  não de uma medição direta.

- **2026-07 — Reporting CSP: de automático (`report-uri`/`report-to`) para
  manual (botão)** (pedido direto do dono do repo, motivado por um alerta real
  da Cloudflare — "50% of your daily Workers KV operation limit reached" no
  plano Free): o reporting automático mandava um POST a `/api/csp-report` por
  cada violação de QUALQUER visitante — na prática, sobretudo ruído de
  extensões de browser (ver painel "Violações CSP", stat `ruído de
  extensões`), e cada POST aceite custa escritas no KV (rate-limit + bucket +
  cap, ~3 writes/POST), partilhadas com honeypot/vitals/cron no mesmo teto
  diário. Removidos `report-uri`, `report-to` e o cabeçalho
  `Reporting-Endpoints` de `static/public/_headers` (+ espelhos nginx/Caddy em
  `docs/security-headers.md`, + `.github/expected-headers.json`). No lugar:
  captura 100% local — `static/public/js/csp-report.js`, o primeiro recurso
  de `<head>` (sem `defer`, de propósito: liga o listener
  `securitypolicyviolation` antes de qualquer script/link que pudesse violar
  a CSP, para não perder o sinal de regressão da própria build) — guarda em
  `sessionStorage` (dedup por diretiva+origem, teto de 20). Nada sai daí sem
  um clique: `CspViolations.astro` (página Provas) lê a fila e manda um
  botão "Reportar" que envia tudo num único POST no formato batch
  `application/reports+json` já suportado por `parseReports()` — zero
  mudança no Worker além dos comentários. **Trade-off aceite conscientemente:**
  perde-se a deteção automática de regressões reais em produção — só se sabe
  se alguém (tipicamente o próprio dono, a testar após um deploy) visitar a
  página Provas e clicar. Revisitar se o teto do KV deixar de ser
  problema (upgrade de plano, ou amostragem em vez de corte total).

## Ideias guardadas (apresentadas, **não aprovadas** para implementação)

Propostas de 2026-07 que ficaram na gaveta por decisão do dono do repo —
registadas para não se perderem, não para serem construídas sem nova decisão:

- **Desmonta-Link (triagem de URLs de phishing)** — 100% client-side em
  `static/`: cola-se um URL suspeito e a ferramenta desmonta-o *sem nunca o
  visitar* — domínio registável verdadeiro vs. subdomínio-isco
  (`paypal.com.conta-segura.xyz`), punycode/homóglifos, redirects embutidos
  em parâmetros, truque do `@` no authority, TLDs de abuso frequente.
  Veredicto por "sinais", nunca binário seguro/inseguro. Sem rede, sem
  riscos de abuso; esforço pequeno-médio (heurísticas + subset da Public
  Suffix List embebido).

- **Sigma Playground** — client-side em `static/`: o visitante cola uma
  linha de log nginx/apache e um mini-motor Sigma (subset declarado:
  `selection`, `contains/startswith/endswith`, `condition` AND/OR/NOT) corre
  as mesmas regras publicadas em /deteções, mostrando campo a campo o que
  disparou, com link para a técnica ATT&CK. Fecha o ciclo "honeypot → regras
  → experimenta tu"; regras partilhadas com /deteções via `content/` (single
  source of truth). Logs nunca saem do browser; esforço médio.

## O que vai ser

A parte do site que precisa de backend: ferramentas de rede e segurança que
não podem correr só no browser (porque exigem consultas a partir de um
servidor, acesso a portas arbitrárias, ou chaves de API privadas).

## Ferramentas planeadas

| Prioridade | Ferramenta | Porque precisa de backend |
| --- | --- | --- |
| 1 | **DNS lookup** (A, AAAA, MX, TXT, NS, CNAME, SOA) | consultas DNS diretas a resolvers arbitrários; DoH do browser não cobre todos os tipos/resolvers |
| 2 | **Whois** de domínios e IPs | o protocolo whois (porta 43) não é acessível a partir do browser |
| 3 | **Análise de headers de segurança HTTP** | CORS impede o browser de inspecionar headers de sites terceiros |
| 4 | **Verificação de blacklists de IP** (DNSBL) | exige consultas DNS reversas a listas como Spamhaus |
| — | (ideias futuras) traceroute visual, verificação de certificados TLS, port check | acesso raw à rede |

## Arquitetura prevista

- **Runtime:** Cloudflare Workers (encaixa com o deploy em Cloudflare Pages —
  a mesma conta, grátis até 100k pedidos/dia) **ou** um serviço pequeno na VPS
  (Node/Hono ou Go) atrás do proxy da Cloudflare. Decidir quando se começar.
- **Forma:** API JSON (`/api/dns?name=…&type=MX`, `/api/whois?q=…`) + frontend
  a viver no mesmo design system do site estático (reutilizar
  `static/src/styles/global.css`).
- **URL:** `lab.<domínio>` ou `<domínio>/lab/` via routing da Cloudflare —
  decidir quando o domínio existir.

## Princípios (para quando se construir)

1. **Rate limiting desde o dia 1** — são ferramentas que fazem pedidos a
   terceiros; não podem virar proxy aberto.
2. **Sem estado/logs pessoais** — as consultas dos utilizadores não se guardam.
3. **Validação estrita de input** no servidor (hostnames, IPs) antes de
   qualquer consulta externa.
4. **Mesmo visual** do site estático: partilhar tokens de design e, se
   possível, componentes.

## Roadmap

- [ ] Decidir runtime (Workers vs. VPS) — depende de onde o site acabar alojado
- [ ] Esqueleto do projeto + deploy de um `/api/health`
- [ ] DNS lookup (API + página)
- [ ] Whois (API + página)
- [ ] Headers de segurança (API + página)
- [ ] DNSBL check
- [ ] Substituir a página "em construção" do `/lab/` por links reais
