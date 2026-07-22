# personal-site-worker

Backend das features de segurança do site (Bloco 3): honeypot, mapa de
tráfego hostil, self-scan de cabeçalhos, ticker SOC e recetor de violações
CSP. Um só Cloudflare Worker + um namespace KV.

> **Porque vive aqui e não em `static/`:** a regra do monorepo é que o
> `static/` é 100% cliente, sem backend. Tudo o que precisa de servidor
> pertence ao `dynamic/` — isto é o primeiro código real dessa área.

## Endpoints

| Rota | O que faz | Cache | Rate limit |
| --- | --- | --- | --- |
| *(iscos)* `/wp-login.php`, `/.env`, `/admin`, `/phpmyadmin/`, `/.git/config` | Regista só metadados (país, ASN, path, timestamp) e devolve 404 | — | — |
| `GET /api/honeypot` | Stats agregadas + últimas 30 tentativas | 60 s | — |
| `GET /api/map` | Origens por país (24 h / 7 d) | 60 s | — |
| `GET /api/scan` | Nota + checklist dos cabeçalhos do próprio site | 6 h | `?refresh=1`: 3/10 min |
| `GET /api/ticker` | CISA KEV + NVD críticos, sanitizados | 1 h | — |
| `POST /api/csp-report` | Recetor de violações CSP (`report-uri`/Reporting API) | — | 10/min por cliente + cap global 300/h |
| `GET /api/csp-violations` | Agregados 7d das violações (painel Segurança) | 60 s | — |
| `GET /api/ct` | Vigia CT: certificados emitidos p/ o domínio (logs de Certificate Transparency, 90 d) | 6 h | — |
| `GET /api/cf-stats` | Estado da zona Cloudflare: pedidos/cache/ameaças da zona (+ top países por ameaças) + invocações/erros deste Worker (GraphQL Analytics API) | 6 h | — |
| `GET /api/mirror` | Espelho: a "vista do servidor" deste pedido (TLS/ASN/país/UA, **nunca o IP**) | — (per-request, `no-store`) | 30/min por cliente |
| `GET /api/health` | Liveness | — | — |

## Privacidade (honeypot)

**Nenhum IP é armazenado.** Os eventos guardam apenas país (`cf-ipcountry`,
validado a 2 letras — resto vira `XX`), ASN (`request.cf.asn`, validado no
espaço 32-bit), path (só os iscos conhecidos) e um **timestamp arredondado
a 5 min**. O arredondamento é anonimização: sem o instante preciso não dá
para correlacionar ASN+path+timestamp com logs de terceiros. A única coisa
derivada do IP é a chave de rate limit: um hash SHA-256 truncado com salt
que roda ao dia (`RATE_SALT` + data UTC), guardado só durante a janela do
limite e nunca associado aos eventos. `recordHoneypot` nem sequer lê o IP.
Coberto por teste (`test/logic.test.mjs`): o IP nunca aparece em nenhum
valor do KV nem em nenhuma linha de log do Worker.

## Privacidade (violações CSP)

Os relatórios que os browsers enviam para `POST /api/csp-report` podem
trazer URLs completos (com paths e query strings, onde vivem tokens). O
Worker **nunca persiste o URL**: do `blocked-uri` guarda-se só a **origem**
(scheme + host), e extensões de browser bucketizam por scheme
(`chrome-extension://`), nunca pelo ID da extensão — que identificaria o
utilizador pelo que tem instalado. Sem IP, sem User-Agent, e ao contrário
do honeypot nem sequer há lista de eventos recentes: só contadores diários
por diretiva/categoria/origem (`src/lib/csp-report.js`, coberto por teste —
path e query nunca aparecem em nenhum valor do KV).

Defesas do endpoint (é o único POST do Worker, público por natureza):
`Content-Type` estrito, corpo ≤ 16 KB, rate limit por cliente, validação de
que o `document-uri` é do próprio site (relatórios forjados "de outros
sites" descartam-se com o mesmo 204 — indistinguível), cap de cardinalidade
das chaves de agregação (`~other` a partir de 40 fontes distintas/bucket) e
cap global de escritas por janela (`CSP_WRITE_CAP`).

## Vigia CT (`/api/ct`)

Qualquer certificado TLS emitido para o domínio fica registado em logs
públicos de Certificate Transparency — incluindo um que um atacante
conseguisse emitir após um takeover de DNS/registrar. O Worker consulta o
crt.sh (duas queries: apex e `%.domínio`, porque um certificado emitido só
para um subdomínio nunca apareceria na query do apex), deduplica
pré-certificado/folha pelo serial, e compara cada emissão com a allowlist
`CT_EXPECTED_ISSUERS` — o que não bater aparece como **inesperado** no
painel da página Segurança.

Sem input de visitantes (a query é fixa, derivada de `SCAN_TARGET`) — não
é reutilizável como proxy nem precisa de rate limit próprio. O crt.sh é
instável por natureza: a cache de 6 h com stale-while-revalidate serve o
último snapshot bom enquanto o refresh corre em background, o cron aquece a
cache, e se uma das duas queries falhar usa-se o resultado parcial da
outra (as duas falharem ⇒ 502 e o painel mostra o fallback). Os dados são
100 % públicos (estão nos logs CT); ainda assim tudo o que segue para o
cliente passa por `sanitizeText`, e só nomes pertencentes ao domínio são
persistidos (`src/lib/ct.js`, coberto por teste).

## Estado da Cloudflare (`/api/cf-stats`)

Painel da página Provas com métricas reais desta zona/Worker — pedidos,
taxa de cache, ameaças bloqueadas pelo edge da Cloudflare (com uma tabela
dos países de origem com mais ameaças bloqueadas nos últimos 7 dias),
invocações e erros do próprio Worker — via **GraphQL Analytics API**
(`api.cloudflare.com/client/v4/graphql`).

A tabela de países soma o campo `countryMap` de cada dia da janela (é por
dia, não por período — a agregação é feita aqui, em `topCountriesByThreats`
em `src/lib/cf-analytics.js`), filtra países sem nenhuma ameaça e códigos
inválidos, e mostra os 10 com mais ameaças bloqueadas. É um sinal mais
largo do que o "mapa de tráfego hostil" do Honeypot (`/api/map`): esse só
regista quem bateu nos paths-isco; isto cobre o que o WAF/edge da
Cloudflare bloqueou na zona **inteira**.

**Isto não é o Cloudflare Radar.** O Radar é agregado global e anónimo de
todos os clientes Cloudflare — não sabe nada sobre este domínio em
particular, só serve de contexto emprestado ("como está a internet lá
fora"). A GraphQL Analytics API, pelo contrário, só devolve dados **desta**
zona/conta, autenticados com `CF_API_TOKEN` — é a mesma fonte que alimenta
o dashboard da Cloudflare quando lá entras. Só agregados diários; nunca IPs
nem dados de visitantes individuais.

Precisa de três vars (`CF_ZONE_TAG`, `CF_ACCOUNT_ID`, `CF_WORKER_SCRIPT`,
ver `wrangler.toml`) e do secret `CF_API_TOKEN` (scope `Zone Analytics:Read`
+ `Account Analytics:Read`, criado em dash.cloudflare.com → Meu perfil →
Tokens de API). Sem qualquer um destes, a rota devolve 502 e o painel
mostra o fallback — mesmo padrão do vigia CT sem `SCAN_TARGET`.

Sem input de visitantes (a query é fixa), por isso sem rate limit próprio;
a cache de 6h já limita a frequência com que se bate na API da Cloudflare.
Lógica pura em `src/lib/cf-analytics.js` (parse da resposta GraphQL, testado
com vetores conhecidos — qualquer campo em falta ou schema que mude do lado
da Cloudflare degrada para 0, nunca rebenta o painel).

### Erros e logs

As respostas de erro ao cliente são sempre genéricas (`upstream_error`,
`rate_limited`, …) — nunca stack traces, paths internos ou detalhes do KV.
O detalhe (stack) fica só nos logs do Worker (server-side) via
`console.error`, e esses logs nunca incluem o IP.

### Cap de escritas ao KV

Cada tentativa nos iscos faz várias escritas. Para limitar custo/abuso se
alguém martelar os paths-isco, há um **cap global de escritas por janela**
(`HONEYPOT_WRITE_CAP` em `src/index.js`, por omissão 500 eventos/hora):
passado o teto, os eventos extra são descartados e o pedido devolve na
mesma o 404 indistinguível. Ver `src/lib/kvcap.js` (best-effort — o KV é
eventualmente consistente, o objetivo é limitar a ordem de grandeza).

## Desenvolvimento

```bash
cd dynamic/worker
npm install
npm test          # lógica pura (node --test) — sem rede nem Cloudflare
npx wrangler dev  # Worker local com KV em memória
```

Os módulos em `src/lib/` são puros e cobertos por `test/logic.test.mjs`
(agregação, sanitização, rate limit, parse dos feeds, nota de cabeçalhos)
com vetores conhecidos.

## Deploy

> Esta secção descreve o fluxo manual via `wrangler` CLI. Em produção o
> deploy corre automaticamente via **Workers Builds** (Git integration da
> Cloudflare) a cada push para `main` — mesma ideia, comandos por trás são os
> mesmos (`wrangler deploy`), mas configurado no dashboard em vez de correr à
> mão. Ver [`docs/cloudflare-deploy.md`](../../docs/cloudflare-deploy.md)
> para esse processo e os problemas reais resolvidos (rotas não colavam por
> `routes` estar mal posicionado no `wrangler.toml`, `workers.dev` público
> por omissão, etc.) — vale a pena ler antes de mexer neste ficheiro outra
> vez.

### 1. Namespace KV + secrets

```bash
npx wrangler kv namespace create HONEYPOT
npx wrangler kv namespace create HONEYPOT --preview
# cola os ids em wrangler.toml (id / preview_id)

npx wrangler secret put RATE_SALT     # qualquer string longa aleatória
npx wrangler secret put NVD_API_KEY   # opcional (sobe o rate limit do NVD)
```

### 2a. Deploy no domínio próprio (o que está em produção)

O bloco `routes` em `wrangler.toml` (paths-isco + `/api/*` no
`danielmala.co`) já está ativo — `npx wrangler deploy` (ou o push para
`main`, via Workers Builds) intercepta esses paths; o resto do site
continua servido pelo Cloudflare Pages. Como a API fica **same-origin**, o
frontend chama `/api/...` e a CSP `connect-src 'self'` basta — nada a
mudar.

### 2b. Deploy em `*.workers.dev` (para testar já, sem domínio)

`npx wrangler deploy` sem rotas publica em
`personal-site-worker.<conta>.workers.dev`. Nesse caso:

1. Define no build do site `PUBLIC_API_BASE` para esse URL (ver
   `static/src/config.ts`).
2. Autoriza a origem do site no Worker: `ALLOWED_ORIGINS` (var) com o URL
   `*.pages.dev`.
3. Acrescenta essa origem ao `connect-src` da CSP em
   `static/public/_headers` — é a **única** exceção à CSP `'self'`, e só
   é precisa neste modo de teste. No modo 2a não é necessária.

> Nota: os paths-isco só apanham scanners reais quando o Worker está nas
> rotas do domínio (2a). Em `*.workers.dev` (2b) o honeypot funciona para
> testes, mas o tráfego hostil real bate no Pages, não no Worker.

## Variáveis e secrets — resumo

| Nome | Tipo | Onde | Para quê |
| --- | --- | --- | --- |
| `KV` | binding | wrangler.toml | namespace único (eventos, buckets, caches, rate limit) |
| `RATE_SALT` | secret | `wrangler secret put` | hash de rate limit; rodar SEMANALMENTE (invalida limites acumulados de propósito) |
| `NVD_API_KEY` | secret | `wrangler secret put` | opcional, rate limit do NVD |
| `CF_API_TOKEN` | secret | `wrangler secret put` | token Analytics:Read (zona + conta) p/ `/api/cf-stats` |
| `ALLOWED_ORIGINS` | var | wrangler.toml | CORS (só no modo 2b) |
| `SCAN_TARGET` | var | wrangler.toml | URL que o self-scan inspeciona |
| `DEPLOY_TS` | var | `--var` no deploy | "tempo até 1.º scan" (opcional) |
| `CF_ZONE_TAG` | var | wrangler.toml | ID da zona, p/ `/api/cf-stats` |
| `CF_ACCOUNT_ID` | var | wrangler.toml | ID da conta, p/ `/api/cf-stats` |
| `CF_WORKER_SCRIPT` | var | wrangler.toml | nome deste Worker na conta, p/ `/api/cf-stats` |
