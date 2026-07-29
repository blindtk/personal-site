/**
 * Cálculo de subnets IPv4 — lógica pura, sem DOM, para ser testável.
 */

export function parseCidr(input) {
  const m = String(input).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/);
  if (!m) return null;
  const octets = m.slice(1, 5).map(Number);
  const prefix = Number(m[5]);
  if (octets.some((o) => o > 255) || prefix > 32) return null;
  const ip = ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  return { ip, prefix };
}

export function intToIp(n) {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

export function intToBinary(n, prefix) {
  const bits = (n >>> 0).toString(2).padStart(32, '0');
  const grouped = bits.match(/.{8}/g).join('.');
  // posição do separador rede|hosts contando com os pontos
  const sep = prefix + Math.floor((prefix - 1) / 8);
  return { network: grouped.slice(0, Math.max(sep, 0)), hosts: grouped.slice(Math.max(sep, 0)) };
}

/**
 * Classifica o endereço (privado, público, loopback, …) usando chaves i18n.
 * @returns {'loopback' | 'private' | 'linkLocal' | 'cgnat' | 'multicast' | 'public'}
 */
export function classify(ip) {
  const a = ip >>> 24;
  const b = (ip >>> 16) & 255;
  if (a === 127) return 'loopback';
  if (a === 10) return 'private';
  if (a === 172 && b >= 16 && b <= 31) return 'private';
  if (a === 192 && b === 168) return 'private';
  if (a === 169 && b === 254) return 'linkLocal';
  if (a === 100 && b >= 64 && b <= 127) return 'cgnat';
  if (a >= 224 && a <= 239) return 'multicast';
  return 'public';
}

export function calcSubnet(input) {
  const parsed = parseCidr(input);
  if (!parsed) return null;
  const { ip, prefix } = parsed;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const wildcard = ~mask >>> 0;
  const network = (ip & mask) >>> 0;
  const broadcast = (network | wildcard) >>> 0;

  let hosts, firstHost, lastHost;
  /** @type {'single' | 'p2p' | null} */
  let special = null;
  if (prefix === 32) {
    hosts = 1;
    firstHost = lastHost = ip;
    special = 'single';
  } else if (prefix === 31) {
    hosts = 2;
    firstHost = network;
    lastHost = broadcast;
    special = 'p2p';
  } else {
    hosts = 2 ** (32 - prefix) - 2;
    firstHost = network + 1;
    lastHost = broadcast - 1;
  }

  return {
    ip, prefix, mask, wildcard, network, broadcast,
    hosts, firstHost, lastHost,
    kind: classify(ip),
    special,
    binary: intToBinary(ip, prefix),
  };
}
