# personal-site

Site pessoal de Daniel Malaco — monorepo com três partes:

| Pasta | O que é | Estado |
| --- | --- | --- |
| `content/` | Todo o conteúdo em markdown (posts, sobre, projetos, links) — **a fonte única de verdade** | ✅ ativo |
| `static/` | O site estático (Astro): blog, ferramentas client-side, páginas | ✅ ativo |
| `dynamic/` | Futura app com backend (DNS lookup, whois, …) | 📝 só planeamento — ver [`dynamic/PLAN.md`](dynamic/PLAN.md) |
| `design/` | Mockups das 7 direções de design exploradas (a nº 4 foi a escolhida) | 🎨 referência |

O site é bilingue: PT em `/` e EN em `/en/`.

---

## Desenvolver localmente

Precisas do [Node.js](https://nodejs.org) 20 ou superior (o site foi construído com Node 22).

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
