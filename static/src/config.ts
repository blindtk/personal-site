/**
 * Configuração central do site.
 * Tudo o que é "sobre ti" muda AQUI e reflete-se em todo o site.
 */

// Quando comprares o domínio (danielmala.co ou danielassismala.co),
// troca este valor. É usado para URLs canónicos e Open Graph.
export const SITE_URL = 'https://danielmala.co';

export const SITE = {
  /** Handle mostrado na nav e no rodapé (ex.: "whoami"). */
  handle: 'whoami',
  /** Nome real, usado no "Sobre" e nos metadados. */
  name: 'Daniel Assis Malaco',
  role: {
    pt: 'Information Security Engineer',
    en: 'Information Security Engineer',
  },
  description: {
    pt: 'Site pessoal de Daniel Assis Malaco — Information Security Engineer. Blog, projetos e ferramentas de rede e segurança.',
    en: 'Personal site of Daniel Assis Malaco — Information Security Engineer. Blog, projects, and networking/security tools.',
  },
  /** Contactos e redes. Deixa vazio ('') para esconder. */
  // Recomendação: quando o domínio estiver ativo, cria um alias (ex.:
  // hello@danielmala.co) e troca aqui — o hotmail deixa de estar exposto
  // e podes rodar o alias se começar a receber spam.
  email: 'daniel_malaco@hotmail.com',
  github: 'https://github.com/blindtk',
  linkedin: 'https://www.linkedin.com/in/danielmalaco',
  /** Página de contactos: estado atual e chave PGP. */
  contact: {
    availability: {
      pt: 'Aberto a conversas sobre segurança — oportunidades, projetos ou troca de ideias.',
      en: 'Open to conversations about security — opportunities, projects, or trading notes.',
    },
    responseTime: {
      pt: 'normalmente 24–48 h, em dias úteis',
      en: 'usually 24–48 h, on weekdays',
    },
    /** Fingerprint da chave PGP (deixa '' até publicares a chave). */
    pgpFingerprint: '',
  },
} as const;

export type Lang = 'pt' | 'en';

// Base da API das features dinâmicas (Worker do Bloco 3, em dynamic/worker/).
// Vazio = same-origin (/api/...): correto quando o Worker está nas rotas do
// próprio domínio, e mantém a CSP connect-src 'self'. Para testar contra um
// Worker em *.workers.dev, define PUBLIC_API_BASE no build (ver
// dynamic/worker/README.md, modo 2b) — exige também abrir o connect-src.
export const API_BASE = import.meta.env.PUBLIC_API_BASE ?? '';
