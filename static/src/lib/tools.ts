/**
 * Lista de ferramentas: slug + kind (client/server), sem texto traduzido.
 * Fonte única para o índice de ferramentas e para os stats da Home — evita
 * que os dois divirjam quando se acrescenta ou remove uma ferramenta.
 * Glifos: os mesmos do Lab (LabDesktop.astro) onde a ferramenta lá existe —
 * símbolos, não texto, por isso não vão para ui.ts.
 */
export const TOOLS = [
  { slug: 'subnets', glyph: '⌗', kind: 'client' },
  { slug: 'hashes', glyph: '#', kind: 'client' },
  { slug: 'passwords', glyph: '⚿', kind: 'client' },
  { slug: 'email-headers', glyph: '@', kind: 'client' },
  { slug: 'exif', glyph: '◎', kind: 'client' },
  { slug: 'csp', glyph: '{}', kind: 'client' },
  { slug: 'pwned', glyph: '⊘', kind: 'server' },
  { slug: 'mirror', glyph: '⇄', kind: 'server' },
] as const;
