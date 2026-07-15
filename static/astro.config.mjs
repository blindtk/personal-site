// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import { SITE_URL } from './src/config.ts';

export default defineConfig({
  // Muda o domínio em src/config.ts (SITE_URL) quando comprares o teu.
  site: SITE_URL,
  markdown: {
    // O Shiki (highlighter por defeito) emite estilos inline nos blocos de
    // código, incompatíveis com a CSP estrita. O Prism gera classes CSS —
    // sem impacto visual agora (nenhuma página renderizada tem blocos de
    // código; o blog está escondido) e, quando o blog voltar, os blocos
    // estilizam-se por classes no global.css.
    syntaxHighlight: 'prism',
  },
  // Content-Security-Policy estrita, gerada em build. O Astro calcula os
  // hashes SHA-256 de cada <script> inline (ferramentas, Lab, toggle da
  // nav) e injeta-os num <meta http-equiv="content-security-policy"> por
  // pagina. Nem script-src nem style-src tem 'unsafe-inline': JS injetado
  // nao executa (defesa real contra XSS) e nao ha estilos inline — todos os
  // style="..." foram movidos para classes/CSS nos componentes.
  //   - frame-ancestors nao e valido em <meta>; o anti-clickjacking fica a
  //     cargo do X-Frame-Options em public/_headers.
  security: {
    csp: {
      directives: [
        "default-src 'self'",
        "img-src 'self'",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
      ],
    },
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
