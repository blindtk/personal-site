/**
 * Analisador de Content-Security-Policy — lógica pura, sem DOM nem rede, para
 * poder ser testada em Node. A componente CspLint.astro só faz a ligação ao
 * DOM; toda a leitura crítica da política vive aqui.
 *
 * O que faz: recebe o texto de uma CSP (valor de header, uma ou mais linhas,
 * ou o conteúdo de uma <meta http-equiv>) e devolve, por diretiva, o que
 * protege, o que só finge proteger (unsafe-inline, wildcards contornáveis) e
 * o que falta (base-uri, object-src, frame-ancestors…). As heurísticas seguem
 * o CSP Level 3 e os bypasses públicos bem conhecidos — não pretende ser um
 * validador normativo completo, e o subset coberto está declarado nos testes.
 *
 * As mensagens são devolvidas como IDs estáveis (+ parâmetros dir/token); a
 * tradução PT/EN vive no i18n e é aplicada na componente. Assim a lógica fica
 * livre de strings de UI e testável de forma determinística.
 */

// Diretivas que buscam sub-recursos e que, quando ausentes, herdam de
// default-src (é isto que torna default-src 'none' tão forte).
const FETCH_DIRECTIVES = new Set([
  'child-src', 'connect-src', 'default-src', 'font-src', 'frame-src',
  'img-src', 'manifest-src', 'media-src', 'object-src', 'prefetch-src',
  'script-src', 'script-src-elem', 'script-src-attr', 'style-src',
  'style-src-elem', 'style-src-attr', 'worker-src',
]);

// Diretivas de documento/navegação (não herdam de default-src).
const OTHER_DIRECTIVES = new Set([
  'base-uri', 'sandbox', 'form-action', 'frame-ancestors',
  'report-uri', 'report-to', 'upgrade-insecure-requests',
  'block-all-mixed-content', 'require-trusted-types-for', 'trusted-types',
]);

const KNOWN_DIRECTIVES = new Set([...FETCH_DIRECTIVES, ...OTHER_DIRECTIVES]);

const LEVEL_RANK = { bad: 0, warn: 1, ok: 2, info: 3 };

const isNonce = (t) => /^'nonce-[A-Za-z0-9+/\-_=]+'$/.test(t);
const isHash = (t) => /^'sha(256|384|512)-[A-Za-z0-9+/\-_=]+'$/.test(t);
// Uma origem-esquema nua (https:, http:, data:, blob:, ws:, …) sem host.
const isSchemeSource = (t) => /^[a-z][a-z0-9+.-]*:$/i.test(t);

/**
 * Parte o texto de uma CSP em diretivas. Junta múltiplas linhas, separa por
 * ';', minúscula o nome da diretiva. Pela spec, a PRIMEIRA ocorrência de uma
 * diretiva vence e as repetidas são ignoradas — devolvemos essa informação
 * (duplicate) para a podermos sinalizar.
 * @returns {{ order: string[], map: Map<string, {name, tokens, raw, duplicate}>, count }}
 */
export function parseCsp(text) {
  const order = [];
  const map = new Map();
  if (typeof text !== 'string') return { order, map, count: 0 };

  const segments = text
    .replace(/[\r\n]+/g, ' ')
    .split(';')
    .map((s) => s.trim())
    .filter(Boolean);

  for (const seg of segments) {
    const parts = seg.split(/\s+/);
    const name = parts[0].toLowerCase();
    if (!name) continue;
    const tokens = parts.slice(1);
    if (map.has(name)) {
      // Diretiva repetida: a spec manda ignorar; marca-se a primeira.
      map.get(name).duplicate = true;
      continue;
    }
    map.set(name, { name, tokens, raw: seg, duplicate: false });
    order.push(name);
  }
  return { order, map, count: order.length };
}

/** Valor efetivo de uma diretiva de fetch, com o fallback para default-src. */
function effective(map, name) {
  if (map.has(name)) return map.get(name);
  if (FETCH_DIRECTIVES.has(name) && name !== 'default-src' && map.has('default-src')) {
    return { ...map.get('default-src'), inherited: true };
  }
  return null;
}

const hasToken = (dir, tok) => !!dir && dir.tokens.some((t) => t.toLowerCase() === tok);
const isNone = (dir) => !!dir && dir.tokens.length === 1 && dir.tokens[0].toLowerCase() === "'none'";

/**
 * Classifica cada token de uma diretiva de script como perigoso ('bad'),
 * duvidoso ('warn') ou neutro (null). Usado para o realce na tabela.
 */
function flagScriptToken(tok) {
  const low = tok.toLowerCase();
  if (low === "'unsafe-inline'") return 'bad';
  if (low === '*') return 'bad';
  if (low === "'unsafe-eval'") return 'warn';
  if (low.startsWith('*.')) return 'warn';
  if (isSchemeSource(tok)) return 'warn';
  return null;
}

function flagGenericToken(tok) {
  if (tok === '*') return 'warn';
  if (tok.toLowerCase() === "'unsafe-inline'") return 'warn';
  return null;
}

/**
 * Analisa uma CSP e devolve o veredicto completo:
 *  { grade, counts, findings, rows, empty }
 * - findings: achados ordenados (bad → warn → ok → info), cada um
 *   { level, id, dir?, token? } — id é a chave de mensagem no i18n.
 * - rows: linhas da tabela "diretiva a diretiva", já com os tokens marcados e
 *   as diretivas recomendadas em falta (verdict 'miss').
 * @returns {{
 *   grade: string,
 *   counts: { bad: number, warn: number, ok: number, info: number, directives: number },
 *   findings: { level: string, id: string, dir?: string, token?: string }[],
 *   rows: {
 *     name: string,
 *     verdict: 'bad' | 'ok' | 'warn' | 'miss',
 *     tokens: { t: string, flag: 'bad' | 'warn' | null }[],
 *     missing: boolean,
 *     recommend?: string,
 *   }[],
 *   empty: boolean,
 * }}
 */
export function analyzeCsp(text) {
  const { map, count } = parseCsp(text);
  const findings = [];
  const add = (level, id, extra = {}) => findings.push({ level, id, ...extra });

  if (count === 0) {
    return { grade: '—', counts: { bad: 0, warn: 0, ok: 0, info: 0, directives: 0 }, findings: [], rows: [], empty: true };
  }

  const defaultSrc = map.get('default-src') ?? null;
  const defaultIsNone = isNone(defaultSrc);

  // ---- script-src (com fallback para default-src) ----
  const script = effective(map, 'script-src');
  if (script) {
    const nonce = script.tokens.some(isNonce);
    const hash = script.tokens.some(isHash);
    const strictDynamic = hasToken(script, "'strict-dynamic'");
    if (hasToken(script, "'unsafe-inline'")) {
      if (nonce || hash || strictDynamic) add('info', 'script-unsafe-inline-nonce');
      else add('bad', 'script-unsafe-inline');
    }
    if (hasToken(script, "'unsafe-eval'")) add('warn', 'script-unsafe-eval');
    if (hasToken(script, '*')) add('bad', 'script-wildcard');
    for (const t of script.tokens) {
      if (t.toLowerCase().startsWith('*.')) add('warn', 'script-wildcard-host', { token: t });
      else if (isSchemeSource(t)) add('warn', 'script-scheme', { token: t });
    }
    if (strictDynamic) add('ok', 'script-strict-dynamic');
    else if (nonce) add('ok', 'script-nonce');
    else if (hash) add('ok', 'script-hash');
  } else {
    add('warn', 'script-missing');
  }

  // ---- default-src ----
  if (!defaultSrc) add('warn', 'default-src-missing');
  else if (defaultIsNone) add('ok', 'default-src-none');

  // ---- object-src ----
  const object = map.get('object-src') ?? null;
  if (object) {
    if (!isNone(object)) add('warn', 'object-src-open');
  } else if (!defaultIsNone) {
    add('warn', 'object-src-missing');
  }

  // ---- base-uri ----
  if (!map.has('base-uri')) add('warn', 'base-uri-missing');
  else add('ok', 'base-uri-ok');

  // ---- form-action ----
  if (!map.has('form-action')) add('info', 'form-action-missing');

  // ---- frame-ancestors ----
  const frameAnc = map.get('frame-ancestors') ?? null;
  if (!frameAnc) add('warn', 'frame-ancestors-missing');
  else if (isNone(frameAnc) || (frameAnc.tokens.length === 1 && frameAnc.tokens[0].toLowerCase() === "'self'")) add('ok', 'frame-ancestors-ok');
  else if (hasToken(frameAnc, '*')) add('warn', 'frame-ancestors-open');

  // ---- style-src ----
  const style = effective(map, 'style-src');
  if (style && hasToken(style, "'unsafe-inline'")) add('warn', 'style-unsafe-inline');

  // ---- wildcards genéricos noutras diretivas de fetch ----
  for (const name of ['img-src', 'connect-src', 'font-src', 'media-src', 'frame-src']) {
    const d = map.get(name);
    if (d && hasToken(d, '*')) add('warn', 'wildcard', { dir: name });
  }

  // ---- endurecimentos presentes ----
  if (map.has('upgrade-insecure-requests')) add('ok', 'upgrade-insecure');
  const rtt = map.get('require-trusted-types-for');
  if (rtt && hasToken(rtt, "'script'")) add('ok', 'trusted-types');
  if (map.has('report-uri') || map.has('report-to')) add('info', 'reporting');
  if (map.has('report-uri') && !map.has('report-to')) add('info', 'report-uri-legacy');

  // ---- diretivas desconhecidas / repetidas ----
  for (const [name, d] of map) {
    if (!KNOWN_DIRECTIVES.has(name)) add('info', 'unknown-directive', { dir: name });
    if (d.duplicate) add('info', 'duplicate-directive', { dir: name });
  }

  // ---- ordenação estável dos achados ----
  findings.sort((a, b) => LEVEL_RANK[a.level] - LEVEL_RANK[b.level]);

  // ---- linhas da tabela ----
  const rows = buildRows(map);

  // ---- contagens e nota ----
  const counts = { bad: 0, warn: 0, ok: 0, info: 0, directives: count };
  for (const f of findings) counts[f.level] += 1;
  const grade = gradeFor(counts);

  return { grade, counts, findings, rows, empty: false };
}

// Diretivas recomendadas que, se ausentes, aparecem na tabela como 'miss'
// com o token recomendado (literal de CSP, não texto traduzível).
const RECOMMENDED = [
  { name: 'default-src', recommend: "'self'" },
  { name: 'script-src', recommend: "'self'" },
  { name: 'object-src', recommend: "'none'" },
  { name: 'base-uri', recommend: "'none'" },
  { name: 'form-action', recommend: "'self'" },
  { name: 'frame-ancestors', recommend: "'none'" },
];

/** Veredicto por diretiva presente, para a coluna da direita da tabela. */
function verdictFor(name, dir) {
  const flagTok = name.startsWith('script-src') ? flagScriptToken : flagGenericToken;
  const flags = dir.tokens.map((t) => flagTok(t));
  if (flags.includes('bad')) return 'bad';
  if (isNone(dir)) return 'ok';
  if (name === 'frame-ancestors' && (isNone(dir) || dir.tokens.some((t) => t.toLowerCase() === "'self'"))) return 'ok';
  if (flags.includes('warn')) return 'warn';
  if (name === 'object-src' && !isNone(dir)) return 'warn';
  return 'ok';
}

function buildRows(map) {
  const rows = [];
  const seen = new Set();
  for (const [name, dir] of map) {
    const flagTok = name.startsWith('script-src') ? flagScriptToken
      : name === 'default-src' || FETCH_DIRECTIVES.has(name) || name === 'frame-ancestors' || name === 'form-action' || name === 'base-uri'
        ? flagGenericToken
        : () => null;
    const tokens = dir.tokens.length
      ? dir.tokens.map((t) => ({ t, flag: flagTok(t) }))
      : [{ t: '(sem valor)', flag: null }];
    rows.push({ name, verdict: verdictFor(name, dir), tokens, missing: false });
    seen.add(name);
  }
  for (const { name, recommend } of RECOMMENDED) {
    if (!seen.has(name)) rows.push({ name, verdict: 'miss', tokens: [], missing: true, recommend });
  }
  return rows;
}

/**
 * Nota por letra a partir das contagens. Penalização = 2×graves + 1×avisos;
 * as letras são derivadas dessa penalização (determinístico e testável). O
 * tom (good/mid/bad) para o CSS deriva daqui em gradeTone().
 */
export function gradeFor(counts) {
  const penalty = counts.bad * 2 + counts.warn;
  if (counts.bad === 0 && counts.warn === 0) return 'A';
  if (penalty <= 1) return 'A';
  if (penalty <= 2) return 'B';
  if (penalty <= 4) return 'C';
  if (penalty <= 6) return 'D';
  return 'F';
}

/**
 * Preenche a mensagem de um achado com os seus parâmetros ({dir}, {token}).
 * Partilhada entre o render no build (Astro) e o render no cliente, para que
 * a lógica de tradução viva num só sítio. `messages` é o dicionário i18n
 * id→template; se faltar a chave, cai para o próprio id (visível em dev).
 */
export function fillMessage(finding, messages) {
  const tmpl = (messages && messages[finding.id]) || finding.id;
  return tmpl.replace(/\{(\w+)\}/g, (_, k) => (finding[k] != null ? String(finding[k]) : ''));
}

/** Tom para o CSS do selo de nota (mesmos data-grade do .grade-badge partilhado). */
export function gradeTone(grade) {
  if (/^A/.test(grade)) return 'good';
  if (/^[BC]/.test(grade)) return 'mid';
  return 'bad';
}
