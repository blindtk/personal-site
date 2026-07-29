// Pipeline de violações CSP — lógica pura, sem Cloudflare, testável em Node.
// Recebe os relatórios que os browsers enviam quando a Content-Security-Policy
// bloqueia algo, e reduz cada um a três campos agregáveis: diretiva efetiva,
// origem bloqueada (bucketizada) e categoria. O mesmo princípio do honeypot:
// nunca IP, nunca User-Agent, nunca o URL completo — do blocked-uri só a
// ORIGEM (scheme + host); path, query e fragmentos (onde vivem tokens) nunca
// são persistidos.
//
// Desde 2026-07 quem envia é sempre um clique explícito no browser (botão
// na página Provas, static/public/js/csp-report.js) — a CSP não tem
// report-uri/report-to, por isso já não há um POST automático por violação
// de cada visitante (ver docs/security-headers.md). O wire format não
// mudou: continuamos a aceitar os dois formatos que os browsers usariam
// nativamente, porque o envio manual reconstrói o mesmo corpo.
//
// Dois formatos no wire, normalizados para um só:
//   · legado `report-uri` — Content-Type application/csp-report, um objeto
//     { "csp-report": { "document-uri", "effective-directive", "blocked-uri" } }
//   · Reporting API `report-to` — Content-Type application/reports+json, uma
//     LISTA [{ type: "csp-violation", url, body: { documentURL,
//     effectiveDirective, blockedURL } }]
// O Chrome usa os dois; o Firefox só o legado; o Safari envia o legado com
// campos parcialmente camelCase — daí o lookup tolerante em `pick`.

/** Content-Types aceites no POST (qualquer parâmetro extra é ignorado). */
export const REPORT_CONTENT_TYPES = ['application/csp-report', 'application/reports+json'];

/** Máximo de violações processadas por pedido (um batch reports+json pode trazer várias). */
export const MAX_REPORTS_PER_REQUEST = 20;

// Diretiva CSP plausível: minúsculas, hífens, tamanho curto. Rejeita lixo
// forjado antes de virar chave de agregação no KV.
const DIRECTIVE_RE = /^[a-z][a-z0-9-]{1,39}$/;

// Schemes de extensões de browser — a esmagadora maioria dos relatórios CSP
// de um site sem terceiros vem daqui. Bucketizam-se por scheme (nunca pelo
// ID da extensão, que identificaria o utilizador pelo que tem instalado).
const EXTENSION_SCHEMES = new Set([
  'chrome-extension', 'moz-extension', 'safari-extension',
  'safari-web-extension', 'ms-browser-extension', 'extension',
]);

// Valores-palavra do blocked-uri (sem URL): código bloqueado dentro da
// própria página — sem JS/CSS inline em lado nenhum, um "inline" é ou
// regressão da build ou injeção real. Ambos interessam; ambos são categoria
// "self".
const KEYWORD_BLOCKED = new Set(['inline', 'eval', 'wasm-eval', 'self', 'unsafe-eval']);

/** Primeiro valor string não-vazio entre várias chaves (os 3 browsers divergem nos nomes). */
function pick(obj, keys) {
  for (const k of keys) {
    const v = obj?.[k];
    if (typeof v === 'string' && v.length > 0) return v;
  }
  return '';
}

/**
 * Parse do corpo de um POST de relatórios para uma lista de violações cruas
 * { documentUri, directive, blockedUri }. Nunca lança: corpo inválido → [].
 * `contentType` decide o formato; o tamanho do corpo é validado pelo caller.
 */
export function parseReports(text, contentType = '') {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    return [];
  }
  const ct = String(contentType).split(';')[0].trim().toLowerCase();

  if (ct === 'application/reports+json') {
    if (!Array.isArray(data)) return [];
    return data
      .filter((r) => r && r.type === 'csp-violation' && typeof r.body === 'object' && r.body !== null)
      .slice(0, MAX_REPORTS_PER_REQUEST)
      .map((r) => ({
        documentUri: pick(r.body, ['documentURL', 'document-uri']) || pick(r, ['url']),
        directive: pick(r.body, ['effectiveDirective', 'effective-directive', 'violatedDirective', 'violated-directive']),
        blockedUri: pick(r.body, ['blockedURL', 'blocked-uri']),
        sourceFile: pick(r.body, ['sourceFile', 'source-file']),
      }));
  }

  // legado: um único objeto embrulhado em "csp-report"
  const body = data?.['csp-report'];
  if (typeof body !== 'object' || body === null) return [];
  return [{
    documentUri: pick(body, ['document-uri', 'documentURL', 'documentURI']),
    directive: pick(body, ['effective-directive', 'effectiveDirective', 'violated-directive', 'violatedDirective']),
    blockedUri: pick(body, ['blocked-uri', 'blockedURL', 'blockedURI']),
    sourceFile: pick(body, ['source-file', 'sourceFile']),
  }];
}

/** Origem (scheme://host[:porta]) de um URL, ou '' se não fizer parse. */
function originOf(url) {
  try {
    return new URL(url).origin;
  } catch {
    return '';
  }
}

/** Scheme isolado de um URL/URI ("chrome-extension", "https", …), ou '' se não houver. */
function schemeOf(value) {
  const m = String(value ?? '').trim().toLowerCase().match(/^([a-z][a-z0-9+.-]*):?/);
  return m ? m[1] : '';
}

/**
 * Normaliza uma violação crua para a forma agregável, ou null se inválida.
 * `siteOrigin` é a origem do próprio site — relatórios cujo documento não é
 * nosso são descartados (é a defesa principal contra POSTs forjados: quem
 * inventa relatórios "de outros sites" não entra nos buckets).
 *
 * Devolve { directive, category, source }:
 *   directive — diretiva efetiva ('script-src-elem', 'style-src', …)
 *   category  — 'extension' (ruído), 'self' (origem própria/inline — candidata
 *               a regressão da build), 'external' (origem terceira), 'other'
 *   source    — bucket da origem bloqueada, NUNCA um URL completo:
 *               'chrome-extension://' | 'self' | 'inline' | 'https://host' | 'data:' …
 */
export function normalizeViolation(raw, siteOrigin) {
  if (!raw || typeof raw !== 'object') return null;

  // o documento tem de ser do próprio site
  if (originOf(raw.documentUri) !== siteOrigin) return null;

  // "script-src 'self' https:" → "script-src" (o Safari envia a diretiva com valores)
  const directive = String(raw.directive ?? '').trim().toLowerCase().split(/\s+/)[0] ?? '';
  if (!DIRECTIVE_RE.test(directive)) return null;

  const blocked = String(raw.blockedUri ?? '').trim();

  // palavra-chave (inline/eval/self) ou vazio: bloqueio dentro da própria página.
  // Isto NÃO prova que o código é nosso: uma extensão que injeta um <script>
  // diretamente (em vez de o carregar de chrome-extension://) produz o mesmo
  // blocked-uri "inline" — o browser não distingue pelo blocked-uri. O único
  // sinal que sobra é sourceFile (o ficheiro de onde partiu a chamada, tirado
  // da call stack do JS engine): se apontar para uma extensão, reclassifica
  // como ruído em vez de acender o alerta de "regressão da build". Só o
  // scheme é guardado (nunca o ficheiro/linha) — mesmo princípio de
  // privacidade do resto desta função.
  if (blocked === '' || KEYWORD_BLOCKED.has(blocked.toLowerCase())) {
    const sourceScheme = schemeOf(raw.sourceFile);
    if (EXTENSION_SCHEMES.has(sourceScheme)) {
      return { directive, category: 'extension', source: `${sourceScheme}://` };
    }
    return { directive, category: 'self', source: blocked === '' ? 'inline' : blocked.toLowerCase() };
  }

  // scheme isolado ("data", "blob") ou URL com scheme conhecido
  const scheme = schemeOf(blocked);
  if (EXTENSION_SCHEMES.has(scheme)) {
    return { directive, category: 'extension', source: `${scheme}://` };
  }
  if (scheme === 'data' || scheme === 'blob' || scheme === 'filesystem') {
    return { directive, category: 'other', source: `${scheme}:` };
  }

  const origin = originOf(blocked);
  if (!origin || origin === 'null') {
    // não faz parse como URL nem é palavra-chave — bucket único, sem eco do input
    return { directive, category: 'other', source: 'unparsed' };
  }
  if (origin === siteOrigin) {
    return { directive, category: 'self', source: 'self' };
  }
  // origem terceira: guarda-se SÓ a origem (truncada por segurança extra)
  return { directive, category: 'external', source: origin.slice(0, 120) };
}

// ---------- agregação (espelha lib/aggregate.js do honeypot) ----------

/** Máximo de fontes distintas por bucket — teto de cardinalidade no KV.
 *  Quem tentar inflacionar com origens inventadas cai no balde '~other'. */
export const MAX_SOURCES_PER_BUCKET = 40;

export function emptyCspBucket() {
  return { total: 0, byDirective: {}, byCategory: {}, bySource: {} };
}

/** Incrementa um bucket com uma violação normalizada. */
export function addCspEvent(bucket, { directive, category, source }, maxSources = MAX_SOURCES_PER_BUCKET) {
  bucket.total += 1;
  bucket.byDirective[directive] = (bucket.byDirective[directive] ?? 0) + 1;
  bucket.byCategory[category] = (bucket.byCategory[category] ?? 0) + 1;
  const key = `${directive}|${category}|${source}`;
  const known = Object.prototype.hasOwnProperty.call(bucket.bySource, key);
  const capped = !known && Object.keys(bucket.bySource).length >= maxSources;
  const finalKey = capped ? '~other' : key;
  bucket.bySource[finalKey] = (bucket.bySource[finalKey] ?? 0) + 1;
  return bucket;
}

/** Soma vários buckets num só. Ignora entradas nulas. */
export function mergeCspBuckets(buckets) {
  const out = emptyCspBucket();
  for (const b of buckets) {
    if (!b) continue;
    out.total += b.total ?? 0;
    for (const [k, v] of Object.entries(b.byDirective ?? {})) out.byDirective[k] = (out.byDirective[k] ?? 0) + v;
    for (const [k, v] of Object.entries(b.byCategory ?? {})) out.byCategory[k] = (out.byCategory[k] ?? 0) + v;
    for (const [k, v] of Object.entries(b.bySource ?? {})) out.bySource[k] = (out.bySource[k] ?? 0) + v;
  }
  return out;
}

/** Chave do par com maior contagem, ou null. */
function topKey(counts) {
  let best = null;
  let bestN = -1;
  for (const [k, v] of Object.entries(counts)) {
    if (v > bestN) { best = k; bestN = v; }
  }
  return best;
}

/**
 * Stats para GET /api/csp-violations a partir dos buckets diários (7d).
 * `days` vem ordenado do mais recente para o mais antigo (dias[0] = hoje);
 * a série `daily` sai invertida (mais antigo primeiro) para desenhar.
 */
export function cspStats(days = []) {
  const week = mergeCspBuckets(days);
  const cat = (name) => week.byCategory[name] ?? 0;
  const sources = Object.entries(week.bySource)
    .map(([key, count]) => {
      const [directive, category, source] = key === '~other'
        ? ['—', 'other', '~other']
        : key.split('|');
      return { directive, category, source, count };
    })
    .sort((a, b) => b.count - a.count)
    .slice(0, 20);
  return {
    reports7d: week.total,
    topDirective: topKey(week.byDirective),
    sourceCount: Object.keys(week.bySource).filter((k) => k !== '~other').length,
    byCategory: {
      extension: cat('extension'),
      self: cat('self'),
      external: cat('external'),
      other: cat('other'),
    },
    sources,
    daily: days.map((d) => d?.total ?? 0).reverse(),
  };
}
