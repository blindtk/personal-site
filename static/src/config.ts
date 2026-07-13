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
  name: 'Daniel Malaco',
  role: {
    pt: 'IT & Segurança',
    en: 'IT & Security',
  },
  description: {
    pt: 'Site pessoal de Daniel Malaco — IT & Segurança. Blog, projetos e ferramentas de rede e segurança.',
    en: 'Personal site of Daniel Malaco — IT & Security. Blog, projects, and networking/security tools.',
  },
  /** Contactos e redes. Deixa vazio ('') para esconder. */
  email: 'daniel_malaco@hotmail.com',
  github: 'https://github.com/blindtk',
  linkedin: '',
} as const;

export type Lang = 'pt' | 'en';
