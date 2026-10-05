// Espelho (/api/mirror) — constrói a "vista do servidor" de um pedido: o que
// qualquer servidor aprende sobre um visitante no handshake, antes de cookies
// ou JavaScript. É o simétrico do honeypot (que mostra o que o site vê dos
// atacantes); aqui mostra-se ao próprio visitante o que ele revela.
//
// Regras de privacidade, fortes por construção:
//   · O IP é devolvido SÓ a quem fez o pedido — é o dele, e ele já o sabe
//     (ADR 0023). Nunca é guardado nem registado, e a resposta é `no-store`
//     (nenhuma cache partilhada o pode servir a outra pessoa).
//   · Nada é persistido: o endpoint não escreve estado nenhum (só o rate
//     limit toca no KV, com uma chave derivada por hash). A resposta morre
//     no ecrã do visitante.
//   · Não há input de visitante (sem query params) — não é reutilizável como
//     proxy nem amplificador.
//
// Lógica pura (sem `Request`/rede) para ser testável em Node: recebe um getter
// de cabeçalhos e o objeto `cf` da Cloudflare, e devolve o objeto sanitizado.

import { normalizeCountry, normalizeAsn, sanitizeText } from './sanitize.js';

const IPV4_RE = /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/;
const HEX_GROUP_RE = /^[0-9a-f]{1,4}$/;

function isIpv4(s) {
  return IPV4_RE.test(s) && s.split('.').every((o) => Number(o) <= 255);
}

/**
 * Valida o IP do cliente (`cf-connecting-ip`) antes de o ecoar. Fail-closed:
 * só passa um IPv4 em notação decimal canónica (sem zeros à esquerda, que
 * alguns parsers leem como octal) ou um IPv6 (RFC 4291, com `::` e IPv4
 * embebido); listas, portas, zone IDs (`%eth0`) e qualquer lixo viram null.
 * A Cloudflare já entrega um IP limpo — isto é defesa em profundidade para o
 * caso de o cabeçalho chegar forjado (só possível fora da Cloudflare).
 * @returns {{ ip: string, version: 4|6 } | null}
 */
export function normalizeIp(input) {
  if (typeof input !== 'string' || input.length === 0 || input.length > 45) return null;
  if (isIpv4(input)) return { ip: input, version: 4 };

  const s = input.toLowerCase();
  if (!/^[0-9a-f:.]+$/.test(s)) return null;
  const halves = s.split('::');
  if (halves.length > 2) return null;
  const parts = halves.map((h) => (h === '' ? [] : h.split(':')));
  const all = parts.flat();
  // IPv4 embebido só no último grupo do endereço (vale 2 grupos de 16 bits).
  let count = all.length;
  const last = all[all.length - 1];
  if (last !== undefined && last.includes('.')) {
    const lastHalf = parts[parts.length - 1];
    if (lastHalf[lastHalf.length - 1] !== last || !isIpv4(last)) return null;
    all.pop();
    count += 1;
  }
  if (!all.every((g) => HEX_GROUP_RE.test(g))) return null;
  if (halves.length === 2 ? count > 7 : count !== 8) return null;
  return { ip: s, version: 6 };
}

/**
 * @param {(name: string) => (string|null)} get  getter case-insensitive de cabeçalhos
 * @param {object} cf  request.cf da Cloudflare (pode vir vazio em dev)
 * @returns objeto sanitizado, pronto a serializar em JSON
 */
export function serverView(get, cf = {}) {
  const g = typeof get === 'function' ? get : () => null;
  const str = (v, max) => {
    const cleaned = sanitizeText(typeof v === 'string' ? v : '', max);
    return cleaned.length ? cleaned : null;
  };
  const c = cf && typeof cf === 'object' ? cf : {};
  const addr = normalizeIp(g('cf-connecting-ip'));

  return {
    // O IP de quem pediu — só para ele (ver o topo do ficheiro).
    ip: addr ? addr.ip : null,
    ipVersion: addr ? addr.version : null,
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
  };
}
