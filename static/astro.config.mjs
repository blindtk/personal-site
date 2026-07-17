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
  //
  // FONTE ÚNICA DE VERDADE: este array é o único sítio onde as diretivas se
  // definem. O header real (dist/_headers) é DERIVADO destas <meta> pelo
  // scripts/csp-headers.mjs (união dos hashes de todas as páginas), nunca
  // escrito à mão — por isso não podem divergir. A única exceção é
  // frame-ancestors, inválida em <meta>: o csp-headers.mjs acrescenta-a só
  // no header (a par do X-Frame-Options em public/_headers, para browsers
  // antigos). Um teste no ci.yml (check-csp-consistency.mjs) volta a validar
  // que header e <meta> coincidem em cada build.
  //
  // Endurecimentos:
  //   - object-src/base-uri 'none': sem plugins nem <base> injetável.
  //   - frame-src/worker-src 'none': o site não embebe iframes nem cria
  //     workers — fechado explicitamente em vez de herdar default-src 'self'.
  //   - form-action 'none': o único <form> (SubnetCalc) faz preventDefault e
  //     nunca submete — nada navega, por isso 'none' em vez de 'self'.
  //   - require-trusted-types-for 'script' + trusted-types 'none': todo o JS
  //     constrói DOM via createElement + textContent (zero innerHTML/eval),
  //     logo nenhuma política de Trusted Types é precisa e proibimos criar
  //     uma — bloqueia sinks de injeção de script em runtime.
  security: {
    csp: {
      directives: [
        "default-src 'self'",
        "img-src 'self'",
        "font-src 'self'",
        "connect-src 'self'",
        "object-src 'none'",
        "frame-src 'none'",
        "worker-src 'none'",
        "base-uri 'none'",
        "form-action 'none'",
        "require-trusted-types-for 'script'",
        "trusted-types 'none'",
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
