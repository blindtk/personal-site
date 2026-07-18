// Espelho (/api/mirror) — constrói a "vista do servidor" de um pedido: o que
// qualquer servidor aprende sobre um visitante no handshake, antes de cookies
// ou JavaScript. É o simétrico do honeypot (que mostra o que o site vê dos
// atacantes); aqui mostra-se ao próprio visitante o que ele revela.
//
// Regras de privacidade, fortes por construção:
//   · O IP NUNCA é devolvido — o servidor vê-o, mas não o ecoamos nem o
//     guardamos. Devolve-se só a marca de que ele é visível.
//   · Nada é persistido: o endpoint não escreve estado nenhum (só o rate
//     limit toca no KV). A resposta morre no ecrã do visitante.
//   · Não há input de visitante (sem query params) — não é reutilizável como
//     proxy nem amplificador.
//
// Lógica pura (sem `Request`/rede) para ser testável em Node: recebe um getter
// de cabeçalhos e o objeto `cf` da Cloudflare, e devolve o objeto sanitizado.

import { normalizeCountry, normalizeAsn, sanitizeText } from './sanitize.js';

/**
 * @param {(name: string) => (string|null)} get  getter case-insensitive de cabeçalhos
 * @param {object} cf  request.cf da Cloudflare (pode vir vazio em dev)
 * @returns objeto sanitizado, sem IP, pronto a serializar em JSON
 */
export function serverView(get, cf = {}) {
  const g = typeof get === 'function' ? get : () => null;
  const str = (v, max) => {
    const cleaned = sanitizeText(typeof v === 'string' ? v : '', max);
    return cleaned.length ? cleaned : null;
  };
  const c = cf && typeof cf === 'object' ? cf : {};

  return {
    // Ligação (só a Cloudflare, que terminou o TLS, sabe isto).
    tlsVersion: str(c.tlsVersion, 24),
    tlsCipher: str(c.tlsCipher, 48),
    httpProtocol: str(c.httpProtocol, 16),
    // Geografia derivada do IP — sem o IP.
    country: normalizeCountry(c.country || g('cf-ipcountry')),
    asn: normalizeAsn(c.asn),
    asOrganization: str(c.asOrganization, 60),
    colo: str(c.colo, 8),
    // Cabeçalhos que o browser anuncia em todo o pedido.
    userAgent: str(g('user-agent'), 200),
    acceptLanguage: str(g('accept-language'), 120),
    acceptEncoding: str(g('accept-encoding'), 80),
    // Sinais de privacidade e client-hints (só presentes se o site os pedir).
    dnt: g('dnt') === '1' ? 'dnt' : g('sec-gpc') === '1' ? 'gpc' : 'unset',
    secChUaPlatform: str(g('sec-ch-ua-platform'), 24),
    // Presença do referer (não o valor: é a navegação anterior do visitante).
    refererPresent: typeof g('referer') === 'string' && g('referer').length > 0,
    // Marca explícita de que o IP é visível ao servidor mas não é devolvido.
    ipWithheld: true,
  };
}
