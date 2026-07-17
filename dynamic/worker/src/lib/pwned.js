// Verificador de passwords comprometidas por k-anonimato (Have I Been Pwned
// range API). O cliente calcula o SHA-1 localmente e só envia os 5 primeiros
// hex do hash; o Worker relaia a consulta ao HIBP e devolve os sufixos que
// partilham esse prefixo — a correspondência final é feita no browser. A
// password NUNCA chega ao Worker, e o HIBP vê só o IP de egress da Cloudflare.
//
// Como o resto do Worker: a função de PARSE (pura, testável) está separada da
// de FETCH (rede). Nada sai daqui sem passar pela validação de parseRanges.

/**
 * Valida/normaliza um prefixo do hash SHA-1: exatamente 5 hex, maiúsculas.
 * É a única forma de input aceite pela rota — não é reutilizável como proxy
 * aberto (não dá para pedir mais nada a ninguém através dele). '' se inválido.
 */
export function normalizePrefix(input) {
  return typeof input === 'string' && /^[0-9a-fA-F]{5}$/.test(input) ? input.toUpperCase() : '';
}

/**
 * Parse da resposta em texto da range API (`SUFIXO:CONTAGEM` por linha, com
 * `\r\n`) → lista de [sufixo(35 hex, maiúsculas), contagem(int >= 0)]. Linhas
 * malformadas caem. Mantém as entradas de contagem 0 (padding do `Add-Padding`
 * do HIBP): preservá-las uniformiza o tamanho da resposta ponta-a-ponta; a
 * correspondência no cliente é que só considera "comprometida" se count > 0.
 */
export function parseRanges(text, limit = 2000) {
  if (typeof text !== 'string') return [];
  const out = [];
  for (const rawLine of text.split('\n')) {
    if (out.length >= limit) break;
    const line = rawLine.trim();
    if (!line) continue;
    const idx = line.indexOf(':');
    if (idx !== 35) continue; // sufixo tem sempre 35 hex (40 - 5 do prefixo)
    const suffix = line.slice(0, idx);
    if (!/^[0-9A-F]{35}$/.test(suffix.toUpperCase())) continue;
    const count = Number.parseInt(line.slice(idx + 1), 10);
    if (!Number.isInteger(count) || count < 0) continue;
    out.push([suffix.toUpperCase(), count]);
  }
  return out;
}

const RANGE_URL = 'https://api.pwnedpasswords.com/range/';

/**
 * Busca e faz parse dos sufixos de um prefixo. `Add-Padding: true` pede ao
 * HIBP que injete entradas falsas (contagem 0) para que o tamanho da resposta
 * não revele quantos hits reais existem. O chamador é responsável por validar
 * o prefixo (normalizePrefix) antes de chegar aqui.
 */
export async function fetchRange(prefix, { timeoutMs = 5000 } = {}) {
  const res = await fetch(`${RANGE_URL}${prefix}`, {
    headers: {
      'user-agent': 'personal-site-worker (pwned k-anonymity check)',
      'add-padding': 'true',
    },
    signal: AbortSignal.timeout(timeoutMs),
    cf: { cacheTtl: 86400 },
  });
  if (!res.ok) throw new Error(`hibp_status_${res.status}`);
  return parseRanges(await res.text());
}
