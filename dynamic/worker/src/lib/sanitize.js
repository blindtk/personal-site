// Sanitização e normalização de output derivado de fontes externas
// (feeds CISA/NVD). Puro, sem dependências — testável em Node.
// A regra do projeto: nada vindo de fora chega ao cliente sem passar por
// aqui. O frontend ainda renderiza via textContent (nunca innerHTML), mas
// isto é a defesa em profundidade do lado do servidor.

/**
 * Normaliza um código de país ISO-3166-1 alpha-2 (ex.: cf-ipcountry).
 * Só aceita exatamente duas letras A-Z; qualquer outra coisa (incluindo
 * 'T1' do Tor, cabeçalhos forjados, ou valores vazios) vira 'XX'. É
 * defesa em profundidade: mesmo que o cabeçalho chegasse manipulado (só
 * possível fora da Cloudflare), nunca entra lixo nos buckets.
 */
export function normalizeCountry(input) {
  return typeof input === 'string' && /^[A-Za-z]{2}$/.test(input) ? input.toUpperCase() : 'XX';
}

/**
 * Normaliza um ASN para inteiro positivo dentro do espaço válido
 * (1..4_294_967_294, 32-bit) ou null. Duas fontes com tipos diferentes:
 *   · `request.cf.asn` (o pedido em si, ex.: /api/mirror) — número;
 *   · `clientAsn` do `firewallEventsAdaptive` (GraphQL da Cloudflare) —
 *     **string** de dígitos.
 * Só se aceitava número, por isso o `firewallDetailBreakdown` descartava
 * TODOS os ASNs do firewall: em produção, cada snapshot diário `fw:<dia>`
 * ficou gravado com `byAsn: {}`, e as tabelas de redes do painel (24h na
 * tab Cloudflare, 7d nas Tendências) nunca mostraram uma linha vinda da
 * Cloudflare. Aceita-se agora a string de dígitos, com a mesma validação.
 */
export function normalizeAsn(input) {
  let value = input;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    // Só dígitos: um "AS32613" ou "" não é um ASN válido para persistir.
    if (!/^\d+$/.test(trimmed)) return null;
    value = Number.parseInt(trimmed, 10);
  }
  if (typeof value !== 'number' || !Number.isInteger(value)) return null;
  return value >= 1 && value <= 4_294_967_294 ? value : null;
}

/** Escapa os cinco caracteres perigosos em contexto HTML. */
export function escapeHtml(str) {
  // `detect-replaceall-sanitization` pede DOMPurify/sanitize-html: não se
  // aplica — isto não é limpeza de HTML por lista de tags permitidas, é o
  // escape completo dos cinco caracteres (`&` primeiro, logo sem duplo-escape).
  // O Worker não tem DOM nem HTML de terceiros para higienizar, e meter uma
  // biblioteca de sanitização no bundle seria mais superfície, não menos.
  // `no-replaceall` avisa que `replaceAll` falta em browsers antigos: este
  // ficheiro só corre no workerd (V8 recente) e no Node dos testes.
  // nosemgrep: javascript.audit.detect-replaceall-sanitization, javascript.lang.correctness.no-replaceall
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/**
 * Texto plano seguro: remove caracteres de controlo e os sinais de tag,
 * colapsa espaços e trunca. Nunca devolve markup nem UTF-16 malformado.
 */
export function sanitizeText(input, maxLen = 160) {
  if (typeof input !== 'string') return '';
  const cleaned = input
    // surrogates soltos (JSON de fora pode trazê-los) viram U+FFFD
    .toWellFormed()
    // remove caracteres de controlo (C0 + DEL + C1), incluindo \n e \t —
    // o C1 inclui o CSI (U+009B), que um terminal interpreta como ESC [
    .replace(/[\x00-\x1F\x7F-\x9F]/g, ' ')
    // controlos bidi (LRM/RLM/ALM, embeddings/overrides, isolates): um
    // U+202E num path ou num user-agent da firewall inverte visualmente o
    // resto do texto no painel. São invisíveis, por isso saem sem espaço.
    .replace(/[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/g, '')
    // tira sinais de tag por precaução (o texto legítimo não os tem)
    .replace(/[<>]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (cleaned.length <= maxLen) return cleaned;
  let cut = cleaned.slice(0, maxLen - 1);
  // não partir um par de surrogates (emoji e afins) ao meio
  if (/[\uD800-\uDBFF]$/.test(cut)) cut = cut.slice(0, -1);
  return `${cut}…`;
}
