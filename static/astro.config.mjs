// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import { SITE_URL } from './src/config.ts';

export default defineConfig({
  // Muda o domínio em src/config.ts (SITE_URL) quando comprares o teu.
  site: SITE_URL,
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
    }),
  ],
});
