// "O teu pedido, etapa a etapa" (/este-site/) — lógica pura, sem DOM.
// Transforma o que o browser sabe sobre o pedido que trouxe esta página
// (Navigation Timing, os cabeçalhos de um HEAD à mesma página, a resposta do
// /api/mirror) em factos prontos a mostrar, um por etapa. O desenho e a
// animação vivem em src/components/site/RequestPath.astro e
// request-path-anim.ts.
//
// Regra geral: um valor que não se consegue validar devolve null e a página
// mostra "—". Nunca se afirma um número que não veio do pedido.

const ms = (v) => (Number.isFinite(v) && v >= 0 ? Math.round(v) : null);

const PROTOCOLS = { h3: 'HTTP/3', h2: 'HTTP/2', 'http/1.1': 'HTTP/1.1', 'http/1.0': 'HTTP/1.0' };

/** `nextHopProtocol` (ALPN: "h2", "h3", "http/1.1") → "HTTP/2" etc.; desconhecido → null. */
export function protocolLabel(alpn) {
  return typeof alpn === 'string' ? PROTOCOLS[alpn.toLowerCase()] ?? null : null;
}

/**
 * PerformanceNavigationTiming → fases do pedido, em ms inteiros.
 *
 * - `dnsMs` 0 → `dnsCached`: o sistema já conhecia o nome, nada saiu para a rede.
 * - `connectMs` 0 → `reused`: ligação reaproveitada (ou resposta da cache).
 * - `tlsMs` só existe quando houve aperto de mão TLS neste pedido
 *   (`secureConnectionStart` > 0).
 * - `prerendered`: a página foi pré-carregada (speculation rules) e só
 *   ativada depois — as fases medem o pré-carregamento, não o clique.
 * - `fromCache`: veio da cache HTTP do browser (transferSize 0 com corpo).
 *
 * Entrada inválida ou com tempos incoerentes (fim antes do início) → null.
 */
export function navPhases(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const n = (k) => (typeof entry[k] === 'number' ? entry[k] : NaN);
  const dnsMs = ms(n('domainLookupEnd') - n('domainLookupStart'));
  const connectMs = ms(n('connectEnd') - n('connectStart'));
  const ttfbMs = ms(n('responseStart') - n('requestStart'));
  if (dnsMs === null || connectMs === null || ttfbMs === null) return null;
  const secure = n('secureConnectionStart');
  const tlsMs = secure > 0 ? ms(n('connectEnd') - secure) : null;
  return {
    protocol: protocolLabel(entry.nextHopProtocol),
    dnsMs,
    dnsCached: dnsMs === 0,
    connectMs,
    reused: connectMs === 0,
    tlsMs,
    ttfbMs,
    prerendered: n('activationStart') > 0,
    fromCache: n('transferSize') === 0 && n('decodedBodySize') > 0,
  };
}

/**
 * `cf-ray` → código IATA do data center da Cloudflare que respondeu
 * ("8f1c2a3b4d5e6f70-LIS" → "LIS"). Formato inesperado → null.
 */
export function coloFromRay(ray) {
  if (typeof ray !== 'string') return null;
  const m = /^[0-9a-f]{16}-([A-Z]{3})$/.exec(ray.trim());
  return m ? m[1] : null;
}

const CACHE_STATES = new Set([
  'HIT', 'MISS', 'EXPIRED', 'STALE', 'BYPASS', 'REVALIDATED', 'UPDATING', 'DYNAMIC', 'NONE',
]);

/** `cf-cache-status` → um dos valores documentados pela Cloudflare, ou null. */
export function cacheState(value) {
  if (typeof value !== 'string') return null;
  const v = value.trim().toUpperCase();
  return CACHE_STATES.has(v) ? v : null;
}

/**
 * Compara cabeçalhos recebidos com o contrato de .github/expected-headers.json
 * ({ nome: [substrings obrigatórios] }), com a mesma regra do workflow
 * verify-headers (.github/scripts/check-headers.mjs): o cabeçalho tem de
 * existir e conter cada substring, sem distinguir maiúsculas.
 *
 * `get(nome)` devolve o valor ou null (como Headers#get).
 */
export function checkHeaders(get, contract) {
  const rows = [];
  if (typeof get !== 'function' || !contract || typeof contract !== 'object') {
    return { present: 0, total: 0, rows };
  }
  for (const [name, required] of Object.entries(contract)) {
    if (!Array.isArray(required)) continue;
    const raw = get(name);
    const value = typeof raw === 'string' ? raw.toLowerCase() : null;
    const missing = value === null
      ? [...required]
      : required.filter((part) => !value.includes(String(part).toLowerCase()));
    rows.push({ name, ok: value !== null && missing.length === 0, absent: value === null, missing });
  }
  return { present: rows.filter((r) => r.ok).length, total: rows.length, rows };
}

/**
 * Registos CAA esperados (`0 issue "letsencrypt.org"`, ...) → as autoridades
 * que podem emitir certificados para o domínio, sem repetir, pela ordem em
 * que aparecem. Só `issue`: `issuewild` repete as mesmas e `iodef` é o
 * contacto, não uma autoridade.
 */
export function caaIssuers(records) {
  const out = [];
  for (const rec of Array.isArray(records) ? records : []) {
    const m = /^\d+\s+issue\s+"([^";\s]+)/.exec(typeof rec === 'string' ? rec : '');
    if (m && !out.includes(m[1])) out.push(m[1]);
  }
  return out;
}

const TOKEN = /^[A-Za-z0-9._/-]{1,24}$/;

/**
 * Resposta do /api/mirror → só o que a etapa do Worker mostra: versão de
 * TLS, protocolo HTTP e data center. O IP, o ASN e o user-agent ficam de
 * fora de propósito (esta é uma página de leitura, não o Espelho).
 * Documento de erro ou sem nenhum campo válido → null.
 */
export function mirrorFacts(doc) {
  if (!doc || typeof doc !== 'object' || 'error' in doc) return null;
  const pick = (v) => (typeof v === 'string' && TOKEN.test(v) ? v : null);
  const facts = {
    tlsVersion: pick(doc.tlsVersion),
    httpProtocol: pick(doc.httpProtocol),
    colo: typeof doc.colo === 'string' && /^[A-Z]{3}$/.test(doc.colo) ? doc.colo : null,
  };
  return Object.values(facts).some((v) => v !== null) ? facts : null;
}
