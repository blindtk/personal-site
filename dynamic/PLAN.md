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
