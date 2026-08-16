// Validação de IP público (não privado/reservado/bogon), pura e testável.
// Usada só para decidir se um IP entra na lista pública de ameaças do
// honeypot (ADR 0020, docs/adr/0020-honeypot-public-ip.md) — nunca para
// decidir se um pedido é servido; o Worker devolve 404 a qualquer pedido
// de qualquer IP, sempre. Defesa em profundidade: o cf-connecting-ip da
// Cloudflare praticamente nunca é privado/reservado, mas valida-se na
// mesma, mesmo padrão do resto de lib/sanitize.js.

// [rede, tamanho do prefixo] — gamas IPv4 privadas/reservadas/bogon.
const IPV4_RESERVED = [
  ['0.0.0.0', 8], // "esta rede"
  ['10.0.0.0', 8], // RFC 1918
  ['100.64.0.0', 10], // CGNAT (RFC 6598)
  ['127.0.0.0', 8], // loopback
  ['169.254.0.0', 16], // link-local
  ['172.16.0.0', 12], // RFC 1918
  ['192.0.0.0', 24], // atribuições de protocolo IETF
  ['192.0.2.0', 24], // TEST-NET-1 (documentação)
  ['192.88.99.0', 24], // relay 6to4 (descontinuado, continua reservado)
  ['192.168.0.0', 16], // RFC 1918
  ['198.18.0.0', 15], // benchmarking (RFC 2544)
  ['198.51.100.0', 24], // TEST-NET-2 (documentação)
  ['203.0.113.0', 24], // TEST-NET-3 (documentação)
  ['224.0.0.0', 4], // multicast
  ['240.0.0.0', 4], // reservado + broadcast (255.255.255.255)
];

function parseIpv4(ip) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const parts = m.slice(1, 5).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return parts.reduce((acc, p) => (acc << 8) + p, 0) >>> 0;
}

function isPublicIpv4(ip) {
  const n = parseIpv4(ip);
  if (n === null) return false;
  return !IPV4_RESERVED.some(([net, prefix]) => {
    const netInt = parseIpv4(net);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (n & mask) === (netInt & mask);
  });
}

/** Expande um endereço IPv6 (com ou sem "::") para um BigInt de 128 bits, ou null se inválido. */
function parseIpv6(ip) {
  if (typeof ip !== 'string' || !/^[0-9a-fA-F:]+$/.test(ip)) return null;
  const halves = ip.split('::');
  if (halves.length > 2) return null; // "::" só pode aparecer uma vez
  let groups;
  if (halves.length === 1) {
    groups = ip.split(':');
    if (groups.length !== 8) return null;
  } else {
    const head = halves[0] ? halves[0].split(':') : [];
    const tail = halves[1] ? halves[1].split(':') : [];
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null; // "::" tem de comprimir pelo menos 1 grupo
    groups = [...head, ...Array(missing).fill('0'), ...tail];
  }
  let value = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    value = (value << 16n) | BigInt(Number.parseInt(g, 16));
  }
  return value;
}

function matchesIpv6Range(value, net, prefix) {
  const netValue = parseIpv6(net);
  if (netValue === null) return false;
  const shift = 128n - BigInt(prefix);
  const mask = prefix === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << shift) - 1n);
  return (value & mask) === (netValue & mask);
}

// IPv6 não se valida por exclusão como o IPv4: a maior parte do espaço de
// endereços nem sequer está alocada — é reservada pela IANA para o
// futuro (nem "privada" no sentido do RFC 1918, nem routável hoje). Uma
// lista de exclusões deixava passar qualquer coisa fora dela, incluindo
// gamas nunca alocadas (ex.: 4000::1) — achado real de revisão. A regra
// certa é a oposta: só 2000::/3 (unicast global, a única gama alocada
// para tráfego público) conta como público; dentro dela excluem-se as
// duas gamas de documentação. ULA (fc00::/7), link-local (fe80::/10),
// multicast (ff00::/8), loopback/unspecified e o antigo site-local
// (fec0::/10, descontinuado) ficam de fora automaticamente, por não
// caírem em 2000::/3 — não precisam de exclusão explícita.
const IPV6_DOC_RANGES = [
  ['2001:db8::', 32], // RFC 3849
  ['3fff::', 20], // RFC 9637 (2024) — expande a gama de documentação
];

function isPublicIpv6(ip) {
  // IPv4 mapeado em IPv6 (::ffff:a.b.c.d) — a decisão segue o IPv4 embutido.
  // NAT64 (64:ff9b::/96) fica de fora desta exceção, de propósito: embora
  // carregue tráfego real de tradução, o prefixo em si não está em
  // 2000::/3 — mais simples e mais correto tratá-lo como qualquer outro
  // endereço fora do unicast global do que abrir uma segunda exceção.
  const mapped = /^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i.exec(ip);
  if (mapped) return isPublicIpv4(mapped[1]);
  const value = parseIpv6(ip);
  if (value === null) return false;
  if (!matchesIpv6Range(value, '2000::', 3)) return false;
  return !IPV6_DOC_RANGES.some(([net, prefix]) => matchesIpv6Range(value, net, prefix));
}

/** true se `ip` é uma string de IP válida (v4 ou v6) e pública — nunca privada, reservada, loopback, link-local, multicast, ou de documentação. */
export function isPublicIp(ip) {
  if (typeof ip !== 'string' || ip.length === 0) return false;
  return ip.includes(':') ? isPublicIpv6(ip) : isPublicIpv4(ip);
}
