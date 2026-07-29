# personal-site

[![CI](https://github.com/blindtk/personal-site/actions/workflows/ci.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/ci.yml)
[![Security](https://github.com/blindtk/personal-site/actions/workflows/security.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/security.yml)
[![Headers](https://github.com/blindtk/personal-site/actions/workflows/headers.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/headers.yml)
[![Supply chain](https://github.com/blindtk/personal-site/actions/workflows/supply-chain.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/supply-chain.yml)
[![Invariants](https://github.com/blindtk/personal-site/actions/workflows/invariants.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/invariants.yml)

Site pessoal de Daniel Malaco — monorepo com três partes:

| Pasta | O que é | Estado |
| --- | --- | --- |
| `content/` | Todo o conteúdo em markdown (posts, sobre, projetos, links) — **a fonte única de verdade** | ✅ ativo |
| `static/` | O site estático (Astro): blog, ferramentas client-side, páginas | ✅ ativo |
| `dynamic/` | Backend em Cloudflare Worker: honeypot, mapa de tráfego hostil, self-scan e ticker SOC (`dynamic/worker/`); DNS/whois ainda planeados | ✅ em produção — ver [`dynamic/worker/README.md`](dynamic/worker/README.md) e [`dynamic/PLAN.md`](dynamic/PLAN.md) |

O site é bilingue: PT em `/` e EN em `/en/`.

---

## Desenvolver localmente

Precisas do [Node.js](https://nodejs.org) 22.12 ou superior (o site é construído com Node 24, a LTS atual).

```bash
cd static
npm install        # só na primeira vez
npm run dev        # abre http://localhost:4321
```

O `npm run dev` fica a correr e recarrega o browser automaticamente sempre que
gravas um ficheiro — tanto código em `static/src/` como markdown em `content/`.

Para gerar a versão final (a que vai para produção):

```bash
cd static
npm run build      # gera static/dist/
npm run preview    # serve o dist/ localmente para conferir
```

## Editar conteúdo (sem tocar em código)

- **Novo post:** cria `content/blog/pt/o-meu-post.md` (e opcionalmente o gémeo
  em `content/blog/en/` com o mesmo nome de ficheiro, para a versão inglesa).
  O post de exemplo `hello-world.md` mostra o formato do cabeçalho e podes
  apagá-lo quando tiveres o teu.
- **Página "Sobre":** edita `content/pages/sobre.md` e `content/pages/about.md`.
- **Projetos:** um ficheiro por projeto em `content/projects/pt/` + `en/`.
- **Links:** edita `content/links.json`.
- **Nome/handle, email, redes, domínio:** tudo em `static/src/config.ts`.

## Publicar (deploy) — Cloudflare Pages

Passos exatos, do zero, para quem nunca fez deploy:

1. **Cria conta na Cloudflare** (grátis): <https://dash.cloudflare.com/sign-up>.
2. No painel da Cloudflare, vai a **Workers & Pages → Create → Pages →
   Connect to Git**.
3. Autoriza a Cloudflare a aceder ao teu GitHub e escolhe o repositório
   `personal-site`.
4. No ecrã de configuração do build, preenche **exatamente** assim:
   - **Production branch:** `main`
   - **Framework preset:** `Astro`
   - **Build command:** `npm run build`
   - **Build output directory:** `dist`
   - **Root directory (advanced):** `static` ← importante! O projeto Astro
     vive na subpasta `static/`, não na raiz.
5. Clica **Save and Deploy**. A Cloudflare instala as dependências, corre o
   build e publica. Em ~2 minutos tens o site num endereço tipo
   `https://personal-site-abc.pages.dev`.
6. A partir daqui, **cada push para `main` publica automaticamente**. Pushes
   para outros branches criam pré-visualizações com URL próprio (útil para
   rever PRs).

### Domínio próprio

O site já corre em `danielmala.co` (comprado no Namecheap, DNS gerido pela
Cloudflare — nameservers trocados no registrar). `SITE_URL` em
`static/src/config.ts` já aponta para lá. Para o processo completo (troca de
nameservers, ligar o Worker, Access durante o desenvolvimento, regras de
WAF), ver [`docs/cloudflare-deploy.md`](docs/cloudflare-deploy.md).

### Alternativa: servir a partir da tua VPS (Cloudflare como proxy)

Se preferires alojar na tua VPS com a Cloudflare à frente (DNS + proxy):

1. Corre `npm run build` e copia `static/dist/` para a VPS, por exemplo:
   `rsync -avz --delete static/dist/ user@vps:/var/www/site/`
2. Serve a pasta com nginx/Caddy (é um site 100% estático — qualquer servidor
   de ficheiros serve).
3. Na Cloudflare: **DNS → Add record** → tipo `A`, nome `@`, IP da VPS, com o
   ícone da nuvem **laranja** (proxied) para teres CDN + TLS + ocultar o IP.

A opção Pages é mais simples (zero manutenção) e é a que está em produção —
o backend em `dynamic/` já corre num Worker à parte (não na mesma máquina do
site estático), por isso a VPS continua a ser só uma alternativa possível,
não uma necessidade.

## Segurança do pipeline

O repositório trata a própria cadeia de build como superfície de ataque.
Cada push/PR passa por:

| Verificação | Onde | O que garante |
| --- | --- | --- |
| **Build + `npm audit`** | `ci.yml` | O site compila sem erros e sem advisories high/critical nas dependências. |
| **OSV-Scanner** | `security.yml` | O `package-lock.json` não tem vulnerabilidades conhecidas (base [OSV.dev](https://osv.dev), inclui GHSA); falha o CI em qualquer *advisory* conhecido. |
| **gitleaks** | `security.yml` + hook local | Nenhum segredo (tokens Cloudflare, chaves) entra na história do git. Localmente: `pipx install pre-commit && pre-commit install`. |
| **Semgrep** | `security.yml` | SAST nas regras `p/typescript`/`p/javascript` + regras próprias para sinks de DOM XSS nos componentes `.astro` (`.semgrep/`). |
| **zizmor** | `security.yml` | Os próprios workflows são auditados: pins em falta, permissions excessivas, injeção de template, credenciais persistidas. |
| **Headers em produção** | `headers.yml` | Após cada deploy (e num cron diário), a produção é verificada contra `.github/expected-headers.json` — se um header de segurança faltar ou regredir, o workflow falha. |
| **`npm audit signatures` + SBOM** | `supply-chain.yml` (semanal + manual) | Verifica as assinaturas de registo do npm (deteta um pacote servido sem a assinatura esperada) e gera um SBOM (CycloneDX) dos dois lockfiles, como artefacto. Semanal, não por PR — ver nota de quota abaixo. |
| **Invariantes de produção** | `invariants.yml` (diário + manual) | Verifica `/api/health` e as rotas de leitura do Worker; se algo estiver genuinamente partido, abre uma Issue (fecha-se sozinha quando volta a passar). É o alerta que falta aos dashboards do honeypot/threat-intel — só pull, sem isto ninguém era avisado sem ir olhar. |

Práticas transversais: todas as actions **pinadas por commit SHA** (o
[Renovate](renovate.json5) mantém os digests e agrupa atualizações num PR
semanal), `permissions: {}` por omissão com o mínimo por job,
`persist-credentials: false` em todos os checkouts, e `npm ci
--ignore-scripts` em `ci.yml` (nenhuma dependência corre postinstall
arbitrário em CI). A CSP é uma linha estática em `static/public/_headers`
(sem hashes: zero `<script>`/`<style>` inline no site — ver
[docs/security-headers.md](docs/security-headers.md) e
[ADR 0001](docs/adr/0001-csp-sem-inline.md)). O plano DNS/TLS (CAA, HSTS
preload, DNSSEC) vive em [docs/dns-tls.md](docs/dns-tls.md). O processo de
deploy na Cloudflare (domínio, Pages, Worker, Access, WAF) e os problemas
reais resolvidos estão em [docs/cloudflare-deploy.md](docs/cloudflare-deploy.md).

**Nota de quota:** o repositório é privado, o que conta os minutos de
Actions contra a quota do plano Free (2.000 min/mês) e bloqueia o tier
gratuito do CodeQL/Dependency Review/secret scanning/Scorecard. É por isto
que verificações de baixa frequência (SBOM, assinaturas) vivem num workflow
semanal em vez de correrem em cada PR. Detalhe completo em
[docs/security-review-2026-07-29.md](docs/security-review-2026-07-29.md) §0.

## Arquitetura e decisões

- [`docs/architecture.md`](docs/architecture.md) — diagrama (Mermaid) de
  como o site, o Worker, o KV e as APIs externas se ligam, e onde ficam as
  fronteiras de confiança.
- [`docs/threat-model.md`](docs/threat-model.md) — modelo de ameaça vivo:
  ativos, superfícies de ataque, ataques mais prováveis/de maior impacto,
  riscos residuais aceites.
- [`docs/adr/`](docs/adr/) — ADRs (Architecture Decision Records): decisões
  com trade-offs reais e porque se recusaram as alternativas óbvias.
- [`docs/security-review-2026-07-29.md`](docs/security-review-2026-07-29.md) —
  revisão de segurança e engenharia completa (maturidade, gap analysis,
  avaliação de ferramentas, threat model, roadmap).

## Features de segurança (tema do site)

Além das ferramentas client-side, o site tem cinco vitrines de cibersegurança:

| Feature | Onde | Depende do Worker? |
| --- | --- | --- |
| **Heatmap MITRE ATT&CK** | `/attack` | Não — 100% estático (`content/attack.json`) |
| **Self-scan de cabeçalhos** | página Segurança | Sim — `/api/scan` |
| **Ticker SOC** (CISA KEV + NVD) | topo da Segurança | Sim — `/api/ticker` |
| **Painel do honeypot** | `/honeypot` | Sim — `/api/honeypot` |
| **Mapa de tráfego hostil** | `/honeypot` | Sim — `/api/map` |

As quatro que dependem do Worker degradam com graça quando ele não está
publicado (mostram uma nota em vez de partir). O backend, os endpoints, a
privacidade (nenhum IP armazenado) e o deploy estão em
[`dynamic/worker/README.md`](dynamic/worker/README.md). O heatmap ATT&CK
funciona sempre, por ser estático.

## Estrutura do código

```
content/               ← markdown: blog/, pages/, projects/, links.json
static/
  src/
    config.ts          ← nome, handle, email, redes, SITE_URL
    content.config.ts  ← schemas das coleções (lê de ../content)
    i18n/              ← strings de UI (ui.ts) e mapa de rotas (routes.ts)
    layouts/           ← BaseLayout (nav, footer, <head>)
    components/
      pages/           ← uma componente por página, partilhada por PT/EN
      tools/           ← as 4 ferramentas client-side
    scripts/           ← lógica pura das ferramentas (testável em Node)
    pages/             ← rotas finas: / (PT) e /en/ (EN)
  public/              ← favicon e ficheiros estáticos servidos tal-e-qual
dynamic/               ← PLAN.md (roadmap da futura app com backend)
```

Convenções de desenvolvimento: ver [CLAUDE.md](CLAUDE.md).

## Segurança

Para reportar uma vulnerabilidade, ver [SECURITY.md](.github/SECURITY.md) ou o
[`security.txt`](static/public/.well-known/security.txt) do site
([RFC 9116](https://www.rfc-editor.org/rfc/rfc9116)). Reporta sempre em
privado, nunca numa Issue pública.

## Licença

O **código** deste repositório está sob a licença [MIT](LICENSE) — reutiliza à
vontade, mantendo o aviso de copyright. O **conteúdo editorial** (textos do
blog e das páginas em `content/`, bio e materiais pessoais) e os elementos de
marca não estão cobertos pela MIT: continuam "todos os direitos reservados".
