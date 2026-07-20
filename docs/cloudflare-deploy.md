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

Enquanto o site não está pronto para lançamento público, fica atrás de
login por email (One-Time PIN) via Cloudflare Access — cobre `*.pages.dev`
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

`Security → WAF → Custom rules` (zona, não o Worker/Pages). Preparadas com
antecedência, com a Access (secção 3) como proteção real enquanto isso —
por isso a regra final ficou já na ação definitiva (`Managed Challenge`),
sem risco, já que ninguém de fora consegue lá chegar de qualquer forma.

Ordem exata (as `Skip` têm de vir antes da regra catch-all):

| # | Regra | Expressão | Ação |
|---|---|---|---|
| 1 | Bots verificados (SEO) | `(cf.client.bot)` | Skip |
| 2 | Previews sociais | `(http.user_agent contains "LinkedInBot") or (http.user_agent contains "Twitterbot") or (http.user_agent contains "facebookexternalhit")` | Skip |
| 3 | CI do GitHub Actions | `(http.user_agent contains "headers-check")` | Skip |
| 4 | O dono sempre | `(ip.src eq <IP>)` | Skip |
| 5 | Catch-all geo | `not (ip.geoip.country in {"PT" "AT" "BE" "BG" "HR" "CY" "CZ" "DK" "EE" "FI" "FR" "DE" "GR" "HU" "IE" "IT" "LV" "LT" "LU" "MT" "NL" "PL" "RO" "SK" "SI" "ES" "SE"})` | Managed Challenge |

Porquê cada regra:
- **2**: `SITE_URL`/Open Graph é para ser partilhado no LinkedIn — o bot que
  gera a prévia do link corre fora da UE.
- **3**: `.github/workflows/headers.yml` faz `fetch` à produção a partir de
  runners do GitHub (normalmente fora da UE) com o User-Agent
  `headers-check` (`check-headers.mjs`) — sem esta regra o workflow falha
  depois do lançamento.
- **5**: lista fixa de códigos de país, não `ip.geoip.is_in_european_union`
  — esse campo **exige plano Business+**, não está disponível no Free. A
  desvantagem é que a lista não se atualiza sozinha se a UE mudar de
  composição (ex.: Brexit); rever manualmente se isso acontecer.
- A ação **Log** (para observar sem afetar tráfego) também **não está
  disponível no Free** para Custom Rules — só `Managed Challenge`/`Block`/
  etc. Como a Access já bloqueia tudo enquanto isto não é o lançamento a
  sério, não há risco em já ter a ação definitiva.

## 6. Repositório GitHub

Fica **privado** durante todo este processo — a Cloudflare Pages/Workers
Builds funcionam com repo privado (a GitHub App tem acesso concedido
explicitamente, "Only select repositories"; ao contrário do GitHub Pages,
não exige repo público). Tornar o repo público é uma decisão à parte, sem
prazo ligado ao lançamento do site — checklist antes de o fazer (scan de
segredos ao histórico completo, permissões de Actions para PRs de forks,
branch protection, secret scanning) fica para quando for decidido.

## 7. Checklist do que falta / decisões pendentes

- [ ] Lançamento (Fase 3): desligar/ajustar a Access + confirmar que a
  regra WAF catch-all está mesmo a fazer o trabalho sozinha.
- [ ] `.github/expected-headers.json` → `url` continua `SET-ME` de propósito
  (apontar para produção agora falharia o workflow `Headers`, porque a
  Access intercetava o pedido não autenticado do CI) — atualizar no
  lançamento.
- [ ] CAA, HSTS preload, DNSSEC — checklist em `docs/dns-tls.md`, por
  executar/confirmar.
- [ ] Alias de email (`hello@danielmala.co`) em vez do Hotmail pessoal —
  nota em `static/src/config.ts`.
- [ ] Repo público — checklist na secção 6, sem prazo definido.
