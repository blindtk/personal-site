/**
 * Lista de ferramentas: slug + kind (client/server), sem texto traduzido.
 * Fonte única para o índice de ferramentas e para os stats da Home — evita
 * que os dois divirjam quando se acrescenta ou remove uma ferramenta.
 */
export const TOOLS = [
  { slug: 'subnets', kind: 'client' },
  { slug: 'hashes', kind: 'client' },
  { slug: 'encoder', kind: 'client' },
  { slug: 'passwords', kind: 'client' },
  { slug: 'email-headers', kind: 'client' },
  { slug: 'exif', kind: 'client' },
  { slug: 'csp', kind: 'client' },
  { slug: 'passkeys', kind: 'client' },
  { slug: 'pwned', kind: 'server' },
  { slug: 'self-scan', kind: 'server' },
  { slug: 'mirror', kind: 'server' },
] as const;
