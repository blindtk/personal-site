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
  // site inteiro (ver build.inlineStylesheets abaixo e static/public/js/) —
  // por isso 'self' já é tão restrito quanto uma lista de hashes, sem hashes
  // para gerar nem para manter.
  //
  // Já usámos o security.csp do Astro (hashes SHA-256 por <script>/<style>
  // inline, um <meta> por página, header derivado no build). Abandonado:
  // esse mecanismo combina o script/estilo partilhado de cada página com o
  // específico dela num único bloco inline por página — o nº de hashes
  // cresce com o nº de *combinações* página×script, não com o nº de scripts
  // reais. Ao fim de ~50 páginas a união ultrapassava os 2000 caracteres por
  // linha do _headers do Cloudflare Pages, e o Pages descartava o header
  // inteiro (CSP ausente em produção). Eliminar o inline em vez de o
  // catalogar resolve na raiz e não volta a crescer.
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
    // 'self': sem isto, style-src precisava de um hash por combinação de
    // página×componente, o mesmo problema de crescimento descrito acima.
    inlineStylesheets: 'never',
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
