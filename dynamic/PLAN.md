# dynamic/ — plano da app dinâmica ("Lab")

> **Estado: primeiro código a bordo.** `dynamic/worker/` já contém o Worker
> das features de segurança do site (honeypot, mapa de tráfego hostil,
> self-scan de cabeçalhos, ticker SOC e pipeline de violações CSP) — ver
> `dynamic/worker/README.md`.
> As ferramentas de rede abaixo (DNS/whois/…) continuam por fazer; a página
> `/lab/` ("em construção") apontará para elas quando existirem.

## Decisões registadas

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
