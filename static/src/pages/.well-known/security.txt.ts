import type { APIRoute } from 'astro';
import { SITE, SITE_URL } from '../../config';

// security.txt (RFC 9116) — política de divulgação de vulnerabilidades.
// Gerado a partir de src/config.ts (email + domínio) para nunca desatualizar.
// O campo Expires é obrigatório na norma; calculamo-lo em build (1 ano à
// frente), por isso cada build renova a validade automaticamente.
export const GET: APIRoute = () => {
  const expires = new Date();
  expires.setUTCFullYear(expires.getUTCFullYear() + 1);

  const lines = [
    `Contact: mailto:${SITE.email}`,
    `Expires: ${expires.toISOString()}`,
    'Preferred-Languages: pt, en',
    `Canonical: ${SITE_URL}/.well-known/security.txt`,
  ];

  return new Response(lines.join('\n') + '\n', {
    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
  });
};
