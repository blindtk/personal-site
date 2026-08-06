// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import { SITE_URL } from './src/config.ts';

export default defineConfig({
  // Domínio de produção: muda em src/config.ts (SITE_URL), não aqui.
  site: SITE_URL,
  markdown: {
    // O Shiki (highlighter por defeito) emite estilos inline nos blocos de
    // código, incompatíveis com a CSP estrita. O Prism gera classes CSS —
    // sem impacto visual agora (nenhuma página renderizada tem blocos de
    // código; o blog está escondido) e, quando o blog voltar, os blocos
    // estilizam-se por classes no global.css.
    syntaxHighlight: 'prism',
  },
  // Content-Security-Policy: ficheiro estático em public/_headers, sem
  // 'unsafe-inline' em script-src/style-src. Zero <script>/<style> inline no
  // site inteiro — por isso 'self' basta, sem hashes para gerar nem manter,
  // e o header fica constante (~395 caracteres), sem teto que possa crescer
  // com mais páginas ou ferramentas.
  //
  // O "zero inline" é garantido por DOIS levers, não é automático:
  //   - build.inlineStylesheets: 'never' (abaixo) — todo o CSS vira
  //     <link rel="stylesheet"> externo.
  //   - vite.build.assetsInlineLimit: 0 (abaixo) — todo o <script> hoisted
  //     vira <script src="/_astro/…"> externo. SEM isto, o Astro inlina
  //     scripts pequenos num <script> sem src (o mirror, o ticker, os
  //     painéis da Segurança…), que ficariam BLOQUEADOS por script-src
  //     'self' — foi esse o bug que partiu os painéis quando se tentou o
  //     zero-inline sem este lever.
  //
  // Já usámos o security.csp do Astro (hashes SHA-256 por <script>/<style>
  // inline, um <meta> por página, header derivado no build). Abandonado:
  // esse mecanismo combina o script/estilo partilhado de cada página com o
  // específico dela num único bloco inline por página — o nº de hashes
  // cresce com o nº de *combinações* página×script, não com o nº de scripts
  // reais. Ao fim de ~50 páginas a união ultrapassava os 2000 caracteres por
  // linha do _headers do Cloudflare Pages, e o Pages descartava o header
  // inteiro (CSP ausente em produção). Externalizar tudo resolve na raiz.
  //
  // A fonte de verdade da CSP é agora só static/public/_headers.
  //
  // Endurecimentos mantidos (ver esse ficheiro para a lista completa):
  //   - object-src/base-uri 'none': sem plugins nem <base> injetável.
  //   - frame-src/worker-src 'none': o site não embebe iframes nem cria
  //     workers — fechado explicitamente em vez de herdar default-src 'self'.
  //   - form-action 'none': o único <form> (SubnetCalc) faz preventDefault e
  //     nunca submete — nada navega, por isso 'none' em vez de 'self'.
  //   - require-trusted-types-for 'script' + trusted-types 'none': todo o JS
  //     constrói DOM via createElement + textContent (zero innerHTML/eval).
  //   - img-src inclui blob: (a par de 'self'): o painel EXIF
  //     (ferramentas/exif) pré-visualiza a imagem carregada via
  //     URL.createObjectURL — sempre gerado pela própria página a partir de
  //     um File/Blob local, nunca um URL remoto, por isso não abre a
  //     política a imagens de terceiros.
  build: {
    // 'auto' (omissão do Astro) inlina CSS pequeno num <style> por página —
    // cada combinação de componentes gera um bloco de conteúdo diferente.
    // 'never' força sempre um <link rel="stylesheet"> externo, coberto por
    // 'self' (ver a nota do lever acima).
    inlineStylesheets: 'never',
  },
  vite: {
    // O par de inlineStylesheets: 'never' para JS. Sem isto o Astro inlina
    // scripts hoisted pequenos (mirror, ticker, painéis) num <script>
    // sem src, que script-src 'self' bloquearia. Com 0, tudo vira ficheiro
    // externo em /_astro/, coberto por 'self'. (Também externaliza pequenos
    // assets que seriam data: URIs — irrelevante aqui, o site não os tem.)
    build: { assetsInlineLimit: 0 },
  },
  i18n: {
    defaultLocale: 'pt',
    locales: ['pt', 'en'],
    routing: {
      prefixDefaultLocale: false,
    },
  },
  integrations: [
    sitemap({
      // As rotas PT/EN têm slugs traduzidos (ex.: /sobre/ vs /en/about/),
      // não o mesmo caminho com prefixo — por isso não se usa a opção i18n
      // do sitemap (que assume paths espelhados) para não gerar hreflang
      // errado. O <link rel="alternate" hreflang> já é feito à mão no
      // BaseLayout, por página.
      filter: (page) => !page.endsWith('/404/') && !page.endsWith('/404'),
      // lastmod global = data do build. Não há tracking de mtime por
      // página; isto sinaliza pelo menos que o sitemap foi gerado de
      // fresco em cada deploy, em vez de não ter lastmod nenhum.
      lastmod: new Date(),
    }),
  ],
});
