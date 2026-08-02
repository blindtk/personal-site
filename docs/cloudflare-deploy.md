# Deploy na Cloudflare — domínio, Pages, Worker, Access e WAF

Registo do processo real de pôr `danielmala.co` em produção: o domínio foi
comprado no Namecheap, o DNS passou a ser gerido pela Cloudflare, e o site
(Pages) + backend (Worker) foram ligados às rotas desse domínio. Este
documento existe para não perder o que só ficou registado em conversa —
inclui os problemas reais que apareceram e como foram corrigidos.

## 1. Domínio: Namecheap → Cloudflare

O domínio continua **registado no Namecheap** — só o DNS passou a ser
gerido pela Cloudflare (troca de nameservers, não transferência).

1. Namecheap: desligar parking/redirect do domínio e desativar PremiumDNS
   (incompatível com nameservers de terceiros).
2. Cloudflare: `Add a site` → `danielmala.co` → plano Free. Como era domínio
   novo, não havia registos DNS para importar.
3. Cloudflare dá 2 nameservers → colar no Namecheap em
   `Domain List → Manage → Nameservers → Custom DNS`.
4. Esperar o email "Active" da Cloudflare (minutos a poucas horas).

No ecrã de onboarding da Cloudflare também apareceu o **AI Crawl Control**
("Configure AI training & search policies"): `Search` e `Agent` ficaram em
Allow (para SEO e para assistentes de IA conseguirem responder sobre o
site), `Training` foi mudado para **Block** (o default "block on pages with
ads" não fazia sentido — o site não tem anúncios, por isso o default
equivalia a permitir tudo).

## 2. Cloudflare Pages (site estático)

`Workers & Pages → Create application → Pages → Connect to Git`, com a
GitHub App da Cloudflare instalada em modo **"Only select repositories"**
(só este repo — funciona com repo privado, não exige repo público).

Configuração do projeto:
- Root directory (advanced): `static`
- Build command: `npm run build`
- Build output directory: `dist` (relativo ao root directory, **não**
  `static/dist`)
- Custom domains: `danielmala.co` e `www.danielmala.co`

### Problema: `*.pages.dev` ficou público sem querer

Assim que o build passou, `personal-site-4fm.pages.dev` ficou **acessível a
qualquer pessoa**, sem proteção nenhuma — as regras de WAF da zona
`danielmala.co` (secção 4) não cobrem `*.pages.dev`, que é domínio da
própria Cloudflare, fora da zona. Corrigido com uma **Zero Trust Access
application** (secção 3), não com WAF.

## 3. Cloudflare Access — lockdown durante o desenvolvimento

> **Atualização (2026-07-31, confirmado pelo dono do repo):** a Access
> deixou de bloquear `danielmala.co`/`www.danielmala.co` — a política WAF
> geo (secção 5) é agora a proteção real para a produção, tal como previsto
> abaixo. **`*.pages.dev` continua atrás de Access** (confirmado) — só a
> aplicação/destination da produção foi ajustada; o resto desta secção
> descreve o lockdown tal como foi configurado durante o desenvolvimento e
> continua a aplicar-se às previews.

Enquanto o site não estava pronto para lançamento público, ficava atrás de
login por email (One-Time PIN) via Cloudflare Access — cobria `*.pages.dev`
**e** `danielmala.co`/`www.danielmala.co` ao mesmo tempo, ao contrário do
WAF de zona.

`Zero Trust → Access → Applications` — a Cloudflare já tinha criado uma
application "legacy" para o projeto Pages, mas mal configurada:

- **Destinations**: só tinha `*.personal-site-4fm.pages.dev` (wildcard de
  subdomínio) — cobria só os *previews*, não a produção
  (`personal-site-4fm.pages.dev` exato, sem subdomínio). Corrigido:
  acrescentar entradas sem subdomínio para `personal-site-4fm.pages.dev`,
  `danielmala.co` e `www.danielmala.co`.
- **Policy**: Source estava em "Everyone"/"All authenticated users" com
  todos os identity providers — como o único IdP é o One-Time PIN, isto
  deixava **qualquer pessoa** com qualquer email entrar. Corrigido: Source
  mudado para `Emails` = só o email do dono.

Antes de lançar a sério (ver secção 5), esta Access é desligada/ajustada ao
mesmo tempo que a regra WAF geo passa a ser a proteção real.

## 4. Worker (`dynamic/worker/`) — deploy e problemas resolvidos

Método usado: **Workers Builds** (deploy automático via Git), não
`wrangler deploy` manual.

`Workers & Pages → Create application → Connect to Git` → repo
`blindtk/personal-site` → configuração:
- **Path**: `dynamic/worker` (crítico — é monorepo, o `wrangler.toml` não
  está na raiz)
- **Build command**: vazio (sem passo de build — confirmado no
  `package.json`, só `wrangler deploy` trata do bundling)
- **Deploy command**: `npx wrangler deploy`
- **Builds for non-production branches**: **desligado** — ver problema
  abaixo

KV namespace criado via dashboard (`Storage & Databases → KV → Create a
namespace`, um para produção e um `_PREVIEW`), e os IDs colados no
`wrangler.toml`. Secrets (`RATE_SALT`, `NVD_API_KEY`) via `Settings →
Variables and Secrets` do Worker, com **Encrypt** ativado — nunca no
`wrangler.toml` (é ficheiro versionado; o gitleaks do CI apanha qualquer
deslize).

### Problema 1: `workers.dev` e preview URLs públicos por omissão

O primeiro deploy publicou `personal-site-worker.<conta>.workers.dev` **sem
proteção nenhuma** — fora do alcance da Access e do WAF de zona (mesma
razão que o `*.pages.dev`: domínio da Cloudflare, não da zona). Corrigido
no `wrangler.toml`:

```toml
workers_dev = false
preview_urls = false
```

### Problema 2: previews de branch/PR continuavam expostos

Mesmo com o acima, cada PR gerava dois URLs extra
(`<hash>-personal-site-worker.<conta>.workers.dev` e
`<branch>-personal-site-worker.<conta>.workers.dev`), publicados sem
proteção num comentário do bot `cloudflare-workers-and-pages` no PR — visível
a quem tiver acesso ao repo (hoje só o dono, mas passaria a todos se o repo
for público). Corrigido desligando **"Builds for non-production branches"**
nas Settings do Worker — deixa de gerar previews a cada PR.

### Problema 3: `routes` lido como variável de ambiente

O bug mais difícil de apanhar: o bloco `routes = [...]` estava colocado
**depois** do cabeçalho `[vars]` no `wrangler.toml`. Em TOML, uma chave
solta depois de abrir uma tabela pertence a essa tabela — por isso o
`routes` estava a ser lido como `env.routes` (visível no log de deploy:
`env.routes (...) Environment Variable`), nunca como configuração de rotas
real. Sintoma: todos os deploys via CI diziam `No targets deployed`, apesar
do upload do código correr sem erro. **Não era problema de permissões do
token de API** (chegou a suspeitar-se disso primeiro, e a corrigir-se à
mesma — sem efeito, porque não era a causa). A correção real foi mover
`routes` para antes de qualquer tabela (`[[kv_namespaces]]`, `[vars]`) no
ficheiro.

Enquanto isto não estava corrigido, as rotas foram adicionadas à mão no
dashboard (`Worker → Domains → Custom Domains and Routes → Add Route`) como
contorno temporário — deixou de ser necessário depois do fix.

## 5. WAF — regras da zona `danielmala.co`

`Security → WAF → Custom rules` (zona, não o Worker/Pages). Estas regras
divergem do desenho original preparado antes do lançamento — ver
["Histórico: desenho original vs. produção"](#histórico-desenho-original-vs-produção)
no fim desta secção para o que mudou e porquê.

Ordem exata das regras em produção (as `Skip` vêm antes; a regra do honeypot
vem antes da política de país, e cada regra que atua **para a evolução**):

| # | Regra | Condição (resumo) | Ação |
|---|---|---|---|
| 1 | Bots verificados | `cf.client.bot` (bots verificados pela Cloudflare) | Skip |
| 2 | CI headers check | `http.request.headers["x-ci-waf-token"][0] eq "<valor do secret CI_WAF_TOKEN>"` (migrado 2026-07-31 — ver nota abaixo) | Skip |
| 3 | Honeypot Paths | Path é `/.env`, `/.git/config`, `/wp-login.php`, `/admin` ou começa por `/phpmyadmin` | **Managed Challenge**, pára a avaliação |
| 4 | Allowed Countries - Site | fora dos paths acima **e** país é PT | **Managed Challenge**, pára a avaliação |
| 5 | Blocked Countries - Site | fora dos paths acima **e** país não é PT | **Block**, pára a avaliação |

Porquê cada regra:
- **2**: `.github/workflows/headers.yml` e `.github/workflows/invariants.yml`
  fazem `fetch` à produção a partir de runners do GitHub (normalmente fora de
  PT) — sem esta regra, ambos os workflows caem na política de país (regras
  4/5) depois do lançamento e passam a reportar produção partida por causa
  do próprio WAF, não de uma regressão real.
  > **Nota (2026-07-30):** o match original ("User-Agent contém
  > `headers-check`") era uma string pública, documentada neste próprio
  > ficheiro — qualquer pedido de fora do mundo podia copiá-la e saltar a
  > política de país (achado de uma sessão de validação de lançamento).
  > **Resolvido (2026-07-31, confirmado pelo dono do repo):** a regra no
  > dashboard já faz match pelo header assinado `X-Ci-Waf-Token`
  > (`http.request.headers["x-ci-waf-token"][0] eq "<valor do secret>"`),
  > não pelo User-Agent — os scripts (`check-headers.mjs`,
  > `check-invariants.mjs`) já enviavam o segredo `CI_WAF_TOKEN` (GitHub
  > Actions secret) neste header. Rotação: mudar o valor no GitHub Actions
  > (Settings → Secrets → Actions → `CI_WAF_TOKEN`) e na regra WAF ao mesmo
  > tempo, mesma disciplina do `RATE_SALT`/`CF_API_TOKEN`.
- **3**: os cinco paths-isco do honeypot (`dynamic/worker/`, `DECOYS` em
  `src/index.js`) recebem `Managed Challenge` em vez de passarem direto ao
  Worker, para qualquer visitante — decisão explícita do dono do repo: os
  iscos não ficam abertos ao mundo sem alguma barreira, mesmo sendo apenas
  um sensor que devolve 404. **Consequência a assumir, não um efeito
  colateral:** um Managed Challenge existe para filtrar bots automatizados —
  é exatamente o tráfego que o honeypot existe para observar. Enquanto esta
  regra estiver ativa, o honeypot só regista quem *resolve* o desafio (um
  browser real com JS, nalguns casos scanners avançados com automação
  tipo-browser), não o scanning de massa indiscriminado que domina a
  Internet. Ver `docs/backlog.md` para um resumo da análise desta troca
  (proteção vs. observabilidade) — o detalhe completo ficou no histórico do
  git depois de `docs/proposals/` ser consolidado em 2026-07-31.
- **4/5**: a política geográfica endureceu de "27 países da UE, Managed
  Challenge" (desenho original abaixo) para "só PT passa, com desafio; todo o
  resto é bloqueado" — mais restritivo do que o planeado, e sem a
  aproximação por `ip.geoip.is_in_european_union` (esse campo continua a
  exigir plano Business+, não está disponível no Free; deixou de ser
  relevante porque a lista já não tenta aproximar a UE).
- A ação **Log** (para observar sem afetar tráfego) continua **indisponível
  no Free** para Custom Rules — só `Managed Challenge`/`Block`/etc.

### Histórico: desenho original vs. produção

> Esta subsecção é registo histórico — não descreve o estado atual (a tabela
> acima é a fonte de verdade). Preservada porque explica *porquê* a produção
> diverge do que foi planeado.

O desenho abaixo (bots + previews sociais + CI + IP do dono a *Skip*,
catch-all de 27 países UE a `Managed Challenge`) foi o que ficou preparado
com antecedência, com a Access (secção 3) como proteção real enquanto isso —
a ideia registada era que a regra final ficaria já na ação definitiva sem
risco, porque ninguém de fora conseguia lá chegar de qualquer forma.

| # | Regra | Expressão | Ação |
|---|---|---|---|
| 1 | Bots verificados (SEO) | `(cf.client.bot)` | Skip |
| 2 | Previews sociais | `(http.user_agent contains "LinkedInBot") or (http.user_agent contains "Twitterbot") or (http.user_agent contains "facebookexternalhit")` | Skip |
| 3 | CI do GitHub Actions | `(http.user_agent contains "headers-check")` | Skip |
| 4 | O dono sempre | `(ip.src eq <IP>)` | Skip |
| 5 | Catch-all geo | `not (ip.geoip.country in {"PT" "AT" "BE" "BG" "HR" "CY" "CZ" "DK" "EE" "FI" "FR" "DE" "GR" "HU" "IE" "IT" "LV" "LT" "LU" "MT" "NL" "PL" "RO" "SK" "SI" "ES" "SE"})` | Managed Challenge |

**O que mudou, e porquê (2026-07-29):** as regras hoje em produção são mais
restritivas nalguns pontos (país único em vez de 27, `Block` em vez de
`Managed Challenge` para o resto do mundo) e têm uma peça nova e deliberada
(regra 3, dedicada ao honeypot) que o plano original não previa. As regras
"Previews sociais" e "O dono sempre" do desenho original **não foram
criadas, por escolha, não por esquecimento** — confirmado 2026-07-29 (ver
secção 7): os bots de preview social já são apanhados pela regra 1 (`cf.client.bot`
inclui os crawlers de preview conhecidos), e quanto ao dono, viajar para
fora de PT sujeita-o à regra 5 (Block) como qualquer visitante — decisão
mantida de propósito.

## 6. Repositório GitHub

Ficou **privado** durante o desenvolvimento — a Cloudflare Pages/Workers
Builds funcionam com repo privado (a GitHub App tem acesso concedido
explicitamente, "Only select repositories"; ao contrário do GitHub Pages,
não exige repo público). **Atualização: o repositório já é público**
(2026-07-31). Checklist que devia
ter sido confirmada antes disso — scan de segredos ao histórico completo,
permissões de Actions para PRs de forks, branch protection, secret
scanning — **não foi reverificada por este agente** (fora do alcance de
uma sessão sem acesso às definições do repositório no GitHub); vale a pena
confirmar manualmente que ficou feita.

## 7. Estado atual e o que falta

**Feito:** lançamento em produção (Fase 3, 2026-07-31 — Access desligada de
`danielmala.co`/`www.danielmala.co`, regra WAF 2 já autenticada por header
assinado em vez de User-Agent público, secção 5); decisões de desenho do WAF
confirmadas como deliberadas, não esquecidas (secção 5); `.github/expected-headers.json`
já aponta para produção real em vez de `SET-ME`; alias de email
(`me@danielmala.co`) em `static/src/config.ts` e `docs/dns-tls.md`
(2026-07-30); repositório público (secção 6) — checklist de pré-requisitos
da secção 6 não foi reverificada por este agente, vale a pena confirmar
manualmente.

**Por fazer:**

- [ ] CAA, HSTS preload, DNSSEC — checklist em [`docs/dns-tls.md`](dns-tls.md),
  por executar/confirmar.
