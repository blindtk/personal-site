# personal-site

[![CI](https://github.com/blindtk/personal-site/actions/workflows/ci.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/ci.yml)
[![Security](https://github.com/blindtk/personal-site/actions/workflows/security.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/security.yml)
[![Headers](https://github.com/blindtk/personal-site/actions/workflows/headers.yml/badge.svg)](https://github.com/blindtk/personal-site/actions/workflows/headers.yml)

Site pessoal de Daniel Malaco — monorepo com três partes:

| Pasta | O que é | Estado |
| --- | --- | --- |
| `content/` | Todo o conteúdo em markdown (posts, sobre, projetos, links) — **a fonte única de verdade** | ✅ ativo |
| `static/` | O site estático (Astro): blog, ferramentas client-side, páginas | ✅ ativo |
| `dynamic/` | Backend em Cloudflare Worker: honeypot, mapa de tráfego hostil, self-scan e ticker SOC (`dynamic/worker/`); DNS/whois ainda planeados | ⚙️ primeiro código a bordo — ver [`dynamic/worker/README.md`](dynamic/worker/README.md) e [`dynamic/PLAN.md`](dynamic/PLAN.md) |
| `design/` | Mockups das 7 direções de design exploradas (a nº 4 foi a escolhida) | 🎨 referência |

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

### Ligar o domínio próprio (quando o comprares)

1. Compra o domínio (ex.: `danielmala.co`). Podes comprá-lo na própria
   Cloudflare (**Domain Registration → Register Domain**) — é o caminho mais
   simples, sem configuração de DNS manual.
2. No projeto Pages: **Custom domains → Set up a custom domain** → escreve o
   domínio → segue o assistente (se o domínio estiver na Cloudflare, é um
   clique; se estiver noutro registrar, ele diz-te que registos DNS criar).
3. Atualiza `SITE_URL` em `static/src/config.ts` para o domínio novo e faz
   push — isto corrige os URLs canónicos e o Open Graph.

### Alternativa: servir a partir da tua VPS (Cloudflare como proxy)

Se preferires alojar na tua VPS com a Cloudflare à frente (DNS + proxy):

1. Corre `npm run build` e copia `static/dist/` para a VPS, por exemplo:
   `rsync -avz --delete static/dist/ user@vps:/var/www/site/`
2. Serve a pasta com nginx/Caddy (é um site 100% estático — qualquer servidor
   de ficheiros serve).
3. Na Cloudflare: **DNS → Add record** → tipo `A`, nome `@`, IP da VPS, com o
   ícone da nuvem **laranja** (proxied) para teres CDN + TLS + ocultar o IP.

A opção Pages é mais simples (zero manutenção); a VPS dá jeito quando o
`dynamic/` existir e quiseres tudo na mesma máquina — decide-se nessa altura.

## Segurança do pipeline

O repositório trata a própria cadeia de build como superfície de ataque.
Cada push/PR passa por:

| Verificação | Onde | O que garante |
| --- | --- | --- |
| **Build + `npm audit`** | `ci.yml` | O site compila sem erros e sem advisories high/critical nas dependências. |
| **OSV-Scanner** | `security.yml` | O `package-lock.json` não tem vulnerabilidades conhecidas (base [OSV.dev](https://osv.dev), inclui GHSA); resultados também em *Security → Code scanning*. |
| **gitleaks** | `security.yml` + hook local | Nenhum segredo (tokens Cloudflare, chaves) entra na história do git. Localmente: `pipx install pre-commit && pre-commit install`. |
| **Semgrep** | `security.yml` | SAST nas regras `p/typescript`/`p/javascript` + regras próprias para sinks de DOM XSS nos componentes `.astro` (`.semgrep/`). |
| **zizmor** | `security.yml` | Os próprios workflows são auditados: pins em falta, permissions excessivas, injeção de template, credenciais persistidas. |
| **Headers em produção** | `headers.yml` | Após cada deploy (e num cron diário), a produção é verificada contra `.github/expected-headers.json` — se um header de segurança faltar ou regredir, o workflow falha. |

Práticas transversais: todas as actions **pinadas por commit SHA** (o
[Renovate](renovate.json5) mantém os digests e agrupa atualizações num PR
semanal), `permissions: {}` por omissão com o mínimo por job, e
`persist-credentials: false` em todos os checkouts. A CSP é gerada no build
em duas camadas (`<meta>` estrita por página + header site-wide com
`frame-ancestors` — ver [docs/security-headers.md](docs/security-headers.md)),
a partir de um único array de diretivas; um teste no `ci.yml`
(`check-csp-consistency.mjs`) falha se o header e a `<meta>` divergirem.
O plano DNS/TLS (CAA, HSTS preload, DNSSEC) vive em
[docs/dns-tls.md](docs/dns-tls.md).

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
