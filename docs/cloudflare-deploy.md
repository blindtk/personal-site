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

`Security → WAF → Custom rules` (zona, não o Worker/Pages).

> **Atualizado 2026-07-29** com as regras confirmadas em produção — divergem
> do desenho original abaixo descrito (catch-all geo com lista de 27 países da
> UE, sem regra dedicada aos paths-isco). O que mudou e porquê está na nota no
> fim desta secção.

Ordem exata das regras em produção (as `Skip` vêm antes; a regra do honeypot
vem antes da política de país, e cada regra que atua **para a evolução**):

| # | Regra | Condição (resumo) | Ação |
|---|---|---|---|
| 1 | Bots verificados | `cf.client.bot` (bots verificados pela Cloudflare) | Skip |
| 2 | CI headers check | User-Agent contém `headers-check` | Skip |
| 3 | Honeypot Paths | Path é `/.env`, `/.git/config`, `/wp-login.php`, `/admin` ou começa por `/phpmyadmin` | **Managed Challenge**, pára a avaliação |
| 4 | Allowed Countries - Site | fora dos paths acima **e** país é PT | **Managed Challenge**, pára a avaliação |
| 5 | Blocked Countries - Site | fora dos paths acima **e** país não é PT | **Block**, pára a avaliação |

Porquê cada regra:
- **2**: `.github/workflows/headers.yml` faz `fetch` à produção a partir de
  runners do GitHub (normalmente fora de PT) com o User-Agent
  `headers-check` (`check-headers.mjs`) — sem esta regra o workflow falha
  depois do lançamento.
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
  Internet. Ver `docs/honeypot-analise-evolucao.md` §0/§9.6 para a análise
  completa desta troca (proteção vs. observabilidade) e para a copy que a
  declara publicamente.
- **4/5**: a política geográfica endureceu de "27 países da UE, Managed
  Challenge" (desenho original abaixo) para "só PT passa, com desafio; todo o
  resto é bloqueado" — mais restritivo do que o planeado, e sem a
  aproximação por `ip.geoip.is_in_european_union` (esse campo continua a
  exigir plano Business+, não está disponível no Free; deixou de ser
  relevante porque a lista já não tenta aproximar a UE).
- A ação **Log** (para observar sem afetar tráfego) continua **indisponível
  no Free** para Custom Rules — só `Managed Challenge`/`Block`/etc.

**Nota (2026-07-29) — divergência entre o plano original e a produção.** O
desenho abaixo (bots + previews sociais + CI + IP do dono a *Skip*, catch-all
de 27 países UE a `Managed Challenge`) foi o que ficou preparado com
antecedência, com a Access (secção 3) como proteção real enquanto isso — a
ideia registada era que a regra final ficaria já na ação definitiva sem
risco, porque ninguém de fora conseguia lá chegar de qualquer forma. As
regras hoje em produção são mais restritivas nalguns pontos (país único em
vez de 27, `Block` em vez de `Managed Challenge` para o resto do mundo) e têm
uma peça nova e deliberada (regra 3, dedicada ao honeypot) que o plano
original não previa. Não ficou registado neste documento se as regras
"Previews sociais" (bots do LinkedIn/Twitter/Facebook) e "O dono sempre" (skip
por IP) do plano original chegaram a ser criadas e foram depois removidas, ou
se nunca chegaram a sair do plano — confirmar antes do checklist da secção 7,
para não assumir uma proteção (o IP do dono sempre passar) que pode não
existir.

### Desenho original (histórico, substituído pela tabela acima)

Preparado com antecedência, com a Access (secção 3) como proteção real
enquanto isso — por isso a regra final ficou já na ação definitiva (`Managed
Challenge`), sem risco, já que ninguém de fora conseguia lá chegar de
qualquer forma.

| # | Regra | Expressão | Ação |
|---|---|---|---|
| 1 | Bots verificados (SEO) | `(cf.client.bot)` | Skip |
| 2 | Previews sociais | `(http.user_agent contains "LinkedInBot") or (http.user_agent contains "Twitterbot") or (http.user_agent contains "facebookexternalhit")` | Skip |
| 3 | CI do GitHub Actions | `(http.user_agent contains "headers-check")` | Skip |
| 4 | O dono sempre | `(ip.src eq <IP>)` | Skip |
| 5 | Catch-all geo | `not (ip.geoip.country in {"PT" "AT" "BE" "BG" "HR" "CY" "CZ" "DK" "EE" "FI" "FR" "DE" "GR" "HU" "IE" "IT" "LV" "LT" "LU" "MT" "NL" "PL" "RO" "SK" "SI" "ES" "SE"})` | Managed Challenge |

## 6. Repositório GitHub

Fica **privado** durante todo este processo — a Cloudflare Pages/Workers
Builds funcionam com repo privado (a GitHub App tem acesso concedido
explicitamente, "Only select repositories"; ao contrário do GitHub Pages,
não exige repo público). Tornar o repo público é uma decisão à parte, sem
prazo ligado ao lançamento do site — checklist antes de o fazer (scan de
segredos ao histórico completo, permissões de Actions para PRs de forks,
branch protection, secret scanning) fica para quando for decidido.

## 7. Checklist do que falta / decisões pendentes

- [ ] Lançamento (Fase 3): desligar/ajustar a Access + confirmar que as
  regras WAF (secção 5) fazem mesmo o trabalho sozinhas.
- [x] **Confirmado (2026-07-29, decisão do dono do repo):** as regras
  "Previews sociais" e "O dono sempre" do desenho original **não** foram
  criadas, **por escolha, não por esquecimento**. Os bots de preview social
  (LinkedIn/Twitter/Facebook) já são apanhados pela regra 1 ("Bots
  verificados", `cf.client.bot`) — a lista de bots verificados da Cloudflare
  inclui os crawlers de preview conhecidos, tornando uma regra dedicada
  redundante. Quanto ao dono: aceite que viajar para fora de PT o sujeita
  à regra 5 (Block) como qualquer visitante — só PT passa (com Managed
  Challenge), decisão mantida de propósito.
- [ ] `.github/expected-headers.json` → `url` **voltou** a `SET-ME`
  (2026-07-29): tinha sido apontado para `https://danielmala.co/` numa
  revisão de segurança, mas a Access (secção 3) continua ativa — o cron
  diário do `Headers` passaria a falhar sempre por causa da página de login
  da Access, não de uma regressão real de headers, mascarando o sinal que
  interessa. Duas formas de ativar antes do lançamento, se quiseres o
  cron a verificar já: (a) criar um **Access Service Token** (Zero Trust →
  Access → Service Auth) e adicionar `CF-Access-Client-Id`/
  `CF-Access-Client-Secret` como secrets do GitHub + headers no
  `check-headers.mjs`; (b) esperar pela Fase 3 (Access desligada) e só
  então apontar o `url`. **Decidido (2026-07-30, preparação do repo para
  público):** via (b) — mantém-se `SET-ME` até a Access ser desligada na
  Fase 3.
- [ ] CAA, HSTS preload, DNSSEC — checklist em `docs/dns-tls.md`, por
  executar/confirmar.
- [x] Alias de email (`me@danielmala.co`) em vez do Hotmail pessoal — feito
  em `static/src/config.ts` e `docs/dns-tls.md` (2026-07-30). Nota: o
  endereço antigo continua no histórico do git; a mitigação real é o alias
  ser rotável.
- [ ] Repo público — checklist na secção 6, sem prazo definido.
