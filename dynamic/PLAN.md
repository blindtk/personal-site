# dynamic/ — plano da app dinâmica ("Lab")

> **Estado: primeiro código a bordo.** `dynamic/worker/` já contém o Worker
> das features de segurança do site (honeypot, mapa de tráfego hostil,
> self-scan de cabeçalhos, ticker SOC e pipeline de violações CSP) — ver
> `dynamic/worker/README.md`.
> As ferramentas de rede abaixo (DNS/whois/…) continuam por fazer; a página
> `/lab/` ("em construção") apontará para elas quando existirem.

## Decisões registadas

- **2026-07 — Verificador de passwords comprometidas (k-anonimato)** (aprovado
  pelo dono do repo): ferramenta educativa que verifica se uma password aparece
  em fugas conhecidas via *range API* do Have I Been Pwned, **sem a password
  alguma vez sair do browser**. O cliente calcula o SHA-1 localmente
  (WebCrypto), envia só os 5 primeiros hex do hash ao Worker (`GET
  /api/pwned-range?prefix=XXXXX`), recebe ~800 sufixos que partilham esse
  prefixo e faz a correspondência localmente — o Worker (e o HIBP) nunca sabem
  que password foi testada. O Worker atua como *relay* anonimizador (o HIBP vê o
  IP de egress da Cloudflare, não o do visitante) e envia `Add-Padding: true`
  para uniformizar o tamanho das respostas. Vive na página **Segurança**
  (feature apoiada no Worker, como o self-scan — não no índice `/ferramentas/`,
  cujo contrato é 100% client-side). Lógica pura em `dynamic/worker/src/lib/
  pwned.js` (parse) e `static/src/scripts/pwned.js` (split/match), ambas
  testadas com vetores conhecidos. Princípios: validação estrita do prefixo
  (`^[0-9A-F]{5}$` — não é reutilizável como proxy aberto), rate limit desde o
  dia 1, cache 24h por prefixo (dataset público), zero logs de prefixos. A UI,
  em estilo de log de terminal, torna o protocolo de k-anonimato *visível* — é
  esse o produto, não o resultado da consulta.

- **2026-07 — Pipeline de violações CSP** (aprovado pelo dono do repo):
  `report-uri`/`report-to` na camada de header da CSP → `POST
  /api/csp-report` no Worker (validação estrita, rate limit, só agregados
  anónimos — nunca o URL completo) → painel "Violações CSP" na página
  Segurança. Papel duplo: canário de regressão da CSP por hashes +
  observatório do ruído que uma CSP estrita apanha. Rodagem: calibrar os
  buckets de ruído com dados reais antes de dar destaque ao painel.

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
