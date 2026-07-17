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

### 1. Namespace KV + secrets

```bash
npx wrangler kv namespace create HONEYPOT
npx wrangler kv namespace create HONEYPOT --preview
# cola os ids em wrangler.toml (id / preview_id)

npx wrangler secret put RATE_SALT     # qualquer string longa aleatória
npx wrangler secret put NVD_API_KEY   # opcional (sobe o rate limit do NVD)
```

### 2a. Deploy no domínio próprio (recomendado, quando existir)

Descomenta o bloco `routes` em `wrangler.toml` (paths-isco + `/api/*` no
`danielmala.co`) e faz `npx wrangler deploy`. O Worker intercepta esses
paths; o resto do site continua servido pelo Cloudflare Pages. Como a API
fica **same-origin**, o frontend chama `/api/...` e a CSP `connect-src
'self'` basta — nada a mudar.

### 2b. Deploy em `*.workers.dev` (para testar já, sem domínio)

`npx wrangler deploy` sem rotas publica em
`personal-site-worker.<conta>.workers.dev`. Nesse caso:

1. Define no build do site `PUBLIC_API_BASE` para esse URL (ver
   `static/src/config.ts`).
2. Autoriza a origem do site no Worker: `ALLOWED_ORIGINS` (var) com o URL
   `*.pages.dev`.
3. Acrescenta essa origem ao `connect-src` da CSP em
   `static/astro.config.mjs` — é a **única** exceção à CSP `'self'`, e só
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
| `ALLOWED_ORIGINS` | var | wrangler.toml | CORS (só no modo 2b) |
| `SCAN_TARGET` | var | wrangler.toml | URL que o self-scan inspeciona |
| `DEPLOY_TS` | var | `--var` no deploy | "tempo até 1.º scan" (opcional) |
