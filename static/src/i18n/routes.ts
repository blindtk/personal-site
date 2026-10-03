import type { Lang } from '../config';

/** Mapa de rotas equivalentes entre idiomas (usado na nav e no seletor PT/EN). */
export const routes = {
  home: { pt: '/', en: '/en/' },
  about: { pt: '/sobre/', en: '/en/about/' },
  blog: { pt: '/blog/', en: '/en/blog/' },
  projects: { pt: '/projetos/', en: '/en/projects/' },
  tools: { pt: '/ferramentas/', en: '/en/tools/' },
  links: { pt: '/links/', en: '/en/links/' },
  contact: { pt: '/contactos/', en: '/en/contact/' },
  lab: { pt: '/lab/', en: '/en/lab/' },
  siteOverview: { pt: '/este-site/', en: '/en/this-site/' },
  performance: { pt: '/este-site/performance/', en: '/en/this-site/performance/' },
  security: { pt: '/este-site/seguranca/', en: '/en/this-site/security/' },
  cloudflare: { pt: '/este-site/cloudflare/', en: '/en/this-site/cloudflare/' },
  attack: { pt: '/attack/', en: '/en/attack/' },
  evidence: { pt: '/este-site/provas/', en: '/en/this-site/evidence/' },
  certifications: { pt: '/certificacoes/', en: '/en/certifications/' },
} as const;

export type RouteKey = keyof typeof routes;

/** Sub-rotas das ferramentas (mesmo slug em ambos os idiomas). */
export function toolUrl(lang: Lang, slug: string): string {
  return `${routes.tools[lang]}${slug}/`;
}

export function blogPostUrl(lang: Lang, slug: string): string {
  return `${routes.blog[lang]}${slug}/`;
}

// O projeto «Este site» não tem página própria em /projetos/: a secção
// Este site (Visão geral) já conta o que é e porque foi feito assim, e duas
// páginas sobre a mesma coisa eram a principal fonte de confusão. O cartão
// em Projetos liga diretamente à secção; a URL antiga redireciona (301).
export const SITE_PROJECT_SLUG = 'este-site';

export function projectUrl(lang: Lang, slug: string): string {
  if (slug === SITE_PROJECT_SLUG) return routes.siteOverview[lang];
  return `${routes.projects[lang]}${slug}/`;
}
