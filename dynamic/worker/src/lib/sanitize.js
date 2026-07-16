// Sanitização e normalização de output derivado de fontes externas
// (feeds CISA/NVD). Puro, sem dependências — testável em Node.
// A regra do projeto: nada vindo de fora chega ao cliente sem passar por
// aqui. O frontend ainda renderiza via textContent (nunca innerHTML), mas
// isto é a defesa em profundidade do lado do servidor.

/** Garante um inteiro dentro de [min, max]; devolve dflt se não for número. */
export function clampInt(value, min, max, dflt) {
  const n = Number.parseInt(value, 10);
  if (Number.isNaN(n)) return dflt;
  return Math.min(max, Math.max(min, n));
}

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
 * (1..4_294_967_294, 32-bit) ou null. request.cf.asn já é numérico, mas
 * validamos na mesma antes de persistir.
 */
export function normalizeAsn(input) {
  if (typeof input !== 'number' || !Number.isInteger(input)) return null;
  return input >= 1 && input <= 4_294_967_294 ? input : null;
}

/**
 * Arredonda um timestamp (epoch ms) para o início da sua janela de
 * `windowMs`. Usado para anonimizar os eventos do honeypot: guardar o
 * instante exato permitiria correlacionar ASN+path+timestamp preciso com
 * logs de terceiros; uma granularidade de 5 min corta essa correlação
 * mantendo os buckets horários/diários corretos. Puro e determinístico.
 */
export function floorToWindow(ms, windowMs) {
  if (typeof ms !== 'number' || !Number.isFinite(ms) || windowMs <= 0) return ms;
  return Math.floor(ms / windowMs) * windowMs;
}

/** Escapa os cinco caracteres perigosos em contexto HTML. */
export function escapeHtml(str) {
  return String(str)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

/**
 * Texto plano seguro: remove caracteres de controlo e os sinais de tag,
 * colapsa espaços e trunca. Nunca devolve markup.
 */
export function sanitizeText(input, maxLen = 160) {
  if (typeof input !== 'string') return '';
  const cleaned = input
    // remove caracteres de controlo (C0 + DEL), incluindo \n e \t
    .replace(/[\x00-\x1F\x7F]/g, ' ')
    // tira sinais de tag por precaução (o texto legítimo não os tem)
    .replace(/[<>]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  return cleaned.length > maxLen ? `${cleaned.slice(0, maxLen - 1)}…` : cleaned;
}

/** Valida/normaliza um CVE-ID (CVE-AAAA-NNNN+). Devolve '' se inválido. */
export function normalizeCveId(input) {
  if (typeof input !== 'string') return '';
  const m = input.trim().toUpperCase().match(/^CVE-(\d{4})-(\d{4,7})$/);
  return m ? `CVE-${m[1]}-${m[2]}` : '';
}

/**
 * Normaliza uma entrada do ticker vinda de CISA KEV ou NVD para uma forma
 * estrita e escapada. Devolve null se não for válida (sem CVE-ID).
 * source ∈ {'kev','nvd'}; severity é uma string curta livre (sanitizada).
 */
export function normalizeTickerItem(raw) {
  const id = normalizeCveId(raw && raw.id);
  if (!id) return null;
  const source = raw.source === 'kev' ? 'kev' : 'nvd';
  return {
    id,
    source,
    severity: sanitizeText(raw.severity ?? '', 24),
    title: sanitizeText(raw.title ?? '', 140),
  };
}
