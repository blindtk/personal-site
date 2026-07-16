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
  security: { pt: '/seguranca/', en: '/en/security/' },
  honeypot: { pt: '/honeypot/', en: '/en/honeypot/' },
  attack: { pt: '/attack/', en: '/en/attack/' },
} as const;

export type RouteKey = keyof typeof routes;

/** Sub-rotas das ferramentas (mesmo slug em ambos os idiomas). */
export function toolUrl(lang: Lang, slug: string): string {
  return `${routes.tools[lang]}${slug}/`;
}

export function blogPostUrl(lang: Lang, slug: string): string {
  return `${routes.blog[lang]}${slug}/`;
}
