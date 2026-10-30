// Radar — notícias e alertas de cibersegurança agregados por RSS/Atom (e o
// JSON do catálogo KEV da CISA). Só o cron busca os feeds; a rota pública
// (/api/radar) serve o resultado já normalizado do KV e nunca vai à rede.
//
// Sem dependências: um leitor de XML mínimo (sem DOM, sem entidades
// declaradas no DTD — logo sem "billion laughs") que só extrai o que o Radar
// mostra: título, link e data de cada item. Tudo o que vem de fora passa por
// aqui antes de chegar ao KV: texto sem HTML nem controlos (sanitizeText),
// links só https:, datas válidas e não futuras. O frontend renderiza na mesma
// com textContent — isto é a defesa do lado do servidor.
//
// Como o resto do Worker: as funções de PARSE (puras, testáveis) estão
// separadas das de FETCH (rede).

import { sanitizeText } from './sanitize.js';

export const MAX_TITLE_LEN = 160;
export const MAX_URL_LEN = 2048;
// Itens guardados por fonte e no total. 8 fontes × 10 = 80: uma fonte muito
// prolífica (Dark Reading publica 50 de cada vez) não empurra os alertas,
// que saem com menos frequência, para fora da lista.
export const MAX_ITEMS_PER_SOURCE = 10;
export const MAX_ITEMS = 80;
// Teto de itens lidos de um documento antes de ordenar: o feed do CNCS vem do
// mais antigo para o mais recente (~350 itens), por isso não se pode parar
// nos primeiros N — mas um feed hostil com milhões de itens também não.
export const MAX_PARSE_ITEMS = 2000;
// Folga para relógios de publicadores adiantados; acima disto a data é
// tratada como inválida (um item "do futuro" ficava preso no topo).
export const FUTURE_SKEW_MS = 3600_000;

const DEFAULT_MAX_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 8000;

/**
 * Fontes confirmadas (2026-10-29). Fora: ENISA — o site novo descontinuou os
 * feeds RSS (página de imprensa da própria ENISA) e os URLs antigos dão 404.
 * `maxBytes` por fonte: o feed do CNCS traz todos os alertas desde 2016 com o
 * corpo inteiro (~1,7 MB, do mais antigo para o mais recente — cortar cedo
 * perdia justamente os novos); o KEV (~1,8 MB) vem do mais recente para o mais
 * antigo, por isso chegam os primeiros 64 KiB (~35 entradas).
 */
export const RADAR_SOURCES = [
  { id: 'cncs', name: 'CNCS', type: 'alert', lang: 'pt', format: 'xml', url: 'https://www.cncs.gov.pt/docs/alertas-seguranca/feed-rss/index.xml', maxBytes: 4 * 1024 * 1024 },
  { id: 'cert-eu', name: 'CERT-EU', type: 'alert', lang: 'en', format: 'xml', url: 'https://cert.europa.eu/publications/security-advisories-rss' },
  { id: 'ncsc-uk', name: 'NCSC UK', type: 'alert', lang: 'en', format: 'xml', url: 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml' },
  { id: 'cisa-kev', name: 'CISA KEV', type: 'alert', lang: 'en', format: 'kev', url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json', maxBytes: 64 * 1024 },
  { id: 'the-record', name: 'The Record', type: 'news', lang: 'en', format: 'xml', url: 'https://therecord.media/feed' },
  { id: 'bleepingcomputer', name: 'BleepingComputer', type: 'news', lang: 'en', format: 'xml', url: 'https://www.bleepingcomputer.com/feed/' },
  { id: 'securityweek', name: 'SecurityWeek', type: 'news', lang: 'en', format: 'xml', url: 'https://www.securityweek.com/feed/' },
  { id: 'darkreading', name: 'Dark Reading', type: 'news', lang: 'en', format: 'xml', url: 'https://www.darkreading.com/rss.xml' },
];

// ---------- entidades e texto ----------

// Entidades com nome que aparecem nos feeds reais (o CNCS escreve o
// português todo assim: &atilde;, &ccedil;…). Uma desconhecida fica como está.
const NAMED_ENTITIES = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
  aacute: 'á', agrave: 'à', acirc: 'â', atilde: 'ã', auml: 'ä',
  eacute: 'é', egrave: 'è', ecirc: 'ê', iacute: 'í', igrave: 'ì', icirc: 'î',
  oacute: 'ó', ograve: 'ò', ocirc: 'ô', otilde: 'õ', ouml: 'ö',
  uacute: 'ú', ugrave: 'ù', ucirc: 'û', uuml: 'ü', ccedil: 'ç', ntilde: 'ñ',
  Aacute: 'Á', Agrave: 'À', Acirc: 'Â', Atilde: 'Ã', Eacute: 'É', Ecirc: 'Ê',
  Iacute: 'Í', Oacute: 'Ó', Ocirc: 'Ô', Otilde: 'Õ', Uacute: 'Ú', Ccedil: 'Ç',
  ldquo: '“', rdquo: '”', lsquo: '‘', rsquo: '’',
  laquo: '«', raquo: '»', ndash: '–', mdash: '—', hellip: '…',
  euro: '€', copy: '©', reg: '®', trade: '™', deg: '°', ordm: 'º', ordf: 'ª',
};

/**
 * Descodifica entidades numéricas (&#233; &#xE9;) e as com nome acima. Um
 * code point inválido (0, surrogate, > U+10FFFF) vira U+FFFD em vez de lançar.
 */
export function decodeEntities(str) {
  return String(str).replace(/&(#[xX][0-9a-fA-F]{1,8}|#\d{1,8}|[a-zA-Z][a-zA-Z0-9]{1,15});/g, (m, body) => {
    if (body[0] === '#') {
      const cp = body[1] === 'x' || body[1] === 'X'
        ? Number.parseInt(body.slice(2), 16)
        : Number.parseInt(body.slice(1), 10);
      const valid = cp > 0 && cp <= 0x10FFFF && !(cp >= 0xD800 && cp <= 0xDFFF);
      return valid ? String.fromCodePoint(cp) : '�';
    }
    return Object.hasOwn(NAMED_ENTITIES, body) ? NAMED_ENTITIES[body] : m;
  });
}

/** Remove tags HTML (e comentários) de um texto, deixando um espaço no lugar. */
export function stripHtml(str) {
  return String(str).replace(/<!--[\s\S]*?-->/g, ' ').replace(/<\/?[a-zA-Z][^>]*>/g, ' ');
}

/**
 * Conteúdo cru de um elemento XML → string: as secções CDATA ficam
 * literais, o resto tem as entidades XML descodificadas. É o "valor" do nó.
 */
function xmlValue(raw) {
  let out = '';
  let i = 0;
  while (i < raw.length) {
    const start = raw.indexOf('<![CDATA[', i);
    if (start < 0) { out += decodeEntities(raw.slice(i)); break; }
    out += decodeEntities(raw.slice(i, start));
    const end = raw.indexOf(']]>', start + 9);
    if (end < 0) { out += raw.slice(start + 9); break; }
    out += raw.slice(start + 9, end);
    i = end + 3;
  }
  return out;
}

/**
 * Título de um item → texto plano. O valor do nó é muitas vezes HTML (Atom
 * `type="html"`, ou CDATA com `&amp;` duplamente codificado, como o do Dark
 * Reading): tiram-se as tags, descodifica-se mais uma vez e sanitiza-se
 * (controlos, bidi, `<>` que sobrem, truncatura em MAX_TITLE_LEN).
 */
export function cleanTitle(raw) {
  return sanitizeText(decodeEntities(stripHtml(xmlValue(raw))), MAX_TITLE_LEN);
}

/**
 * Valida um link: só `https:` absoluto, sem credenciais, até MAX_URL_LEN.
 * Tudo o resto — `javascript:`, `data:`, `http:`, relativo, lixo — dá null.
 * Devolve a forma normalizada pelo parser de URL (o que o browser abriria).
 */
export function safeHttpsUrl(input) {
  if (typeof input !== 'string') return null;
  const s = input.trim();
  if (s === '' || s.length > MAX_URL_LEN) return null;
  let url;
  try {
    url = new URL(s);
  } catch {
    return null;
  }
  if (url.protocol !== 'https:' || url.username || url.password || !url.hostname) return null;
  return url.href.length > MAX_URL_LEN ? null : url.href;
}

/**
 * Domínio de uma fonte para validar os links dos seus itens: o host do URL do
 * feed sem um `www.` à frente (o CNCS liga para dyn.cncs.gov.pt).
 */
export function sourceHost(feedUrl) {
  return new URL(feedUrl).hostname.replace(/^www\./, '');
}

/**
 * O link (já validado por safeHttpsUrl) é do domínio da fonte ou de um
 * subdomínio dele? Um feed comprometido ou sequestrado não consegue assim
 * meter num site de segurança links para outro domínio (phishing).
 */
export function linkOnHost(url, host) {
  const h = new URL(url).hostname;
  return h === host || h.endsWith(`.${host}`);
}

// ---------- datas ----------

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
// Zonas por nome que os feeds usam de facto. O RFC 822 só define as dos EUA
// (e o Date.parse do V8 só conhece essas): o CERT-EU publica em "CEST", que
// o Date.parse transformava em NaN.
const ZONES = {
  GMT: 0, UT: 0, UTC: 0, Z: 0, WET: 0, WEST: 60, BST: 60, CET: 60, CEST: 120, EET: 120, EEST: 180,
  EST: -300, EDT: -240, CST: -360, CDT: -300, MST: -420, MDT: -360, PST: -480, PDT: -420,
};

/** Data RFC 822/1123 do RSS ("Fri, 23 Oct 2026 16:36:26 CEST") → epoch ms ou null. */
export function parseRfc822(input) {
  if (typeof input !== 'string') return null;
  const m = input.trim().match(
    /^(?:[A-Za-z]{3},?\s+)?(\d{1,2})\s+([A-Za-z]{3})[a-z]*\s+(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([+-]\d{4}|[A-Za-z]{1,5})?$/,
  );
  if (!m) return null;
  const [, dd, mon, yyyy, hh, mi, ss = '0', zone = 'GMT'] = m;
  const month = MONTHS[mon.toLowerCase()];
  if (month === undefined) return null;
  let offsetMin;
  if (/^[+-]\d{4}$/.test(zone)) {
    const sign = zone[0] === '-' ? -1 : 1;
    offsetMin = sign * (Number(zone.slice(1, 3)) * 60 + Number(zone.slice(3)));
  } else {
    offsetMin = ZONES[zone.toUpperCase()];
    if (offsetMin === undefined) return null;
  }
  const [d, h, min, sec] = [Number(dd), Number(hh), Number(mi), Number(ss)];
  if (d < 1 || d > 31 || h > 23 || min > 59 || sec > 60) return null;
  const ms = Date.UTC(Number(yyyy), month, d, h, min, sec) - offsetMin * 60_000;
  // 31 Feb passa no regex mas o Date.UTC rola para março: recusa-se.
  if (new Date(ms + offsetMin * 60_000).getUTCDate() !== d) return null;
  return ms;
}

/** Data ISO 8601 / RFC 3339 do Atom (e do KEV, só a data) → epoch ms ou null. */
export function parseIsoDate(input) {
  if (typeof input !== 'string') return null;
  const s = input.trim();
  const m = s.match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?)?$/i);
  if (!m) return null;
  const [, y, mo, d, h = '00', mi = '00', sec = '00', tz = 'Z'] = m;
  // Sem fuso → UTC (determinístico, não depende do fuso de quem corre).
  const zone = tz.toUpperCase() === 'Z' ? 'Z' : `${tz.slice(0, 3)}:${tz.slice(-2)}`;
  const ms = Date.parse(`${y}-${mo}-${d}T${h}:${mi}:${sec}${zone}`);
  if (!Number.isFinite(ms)) return null;
  if (new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d))).getUTCDate() !== Number(d)) return null;
  return ms;
}

/** Qualquer das duas formas; null se inválida ou mais no futuro do que FUTURE_SKEW_MS. */
export function parseFeedDate(input, now) {
  const ms = parseRfc822(input) ?? parseIsoDate(input);
  if (ms === null || ms > now + FUTURE_SKEW_MS) return null;
  return ms;
}

// ---------- leitor de XML mínimo ----------

/** Índice do `>` que fecha a tag aberta em `lt`, saltando valores entre aspas. -1 se truncada. */
function tagEnd(xml, lt) {
  let quote = '';
  for (let i = lt + 1; i < xml.length; i++) {
    const c = xml[i];
    if (quote) { if (c === quote) quote = ''; continue; }
    if (c === '"' || c === "'") quote = c;
    else if (c === '>') return i;
  }
  return -1;
}

/** Atributos de uma tag (`href="…"`) → objeto, valores com entidades descodificadas. */
function parseAttrs(src) {
  const attrs = {};
  for (const m of src.matchAll(/([A-Za-z_:][\w:.-]*)\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) {
    attrs[m[1].toLowerCase()] = decodeEntities(m[2] ?? m[3]);
  }
  return attrs;
}

/**
 * Posição de `</name>` a partir de `from`, saltando CDATA e comentários. -1
 * se não existe (XML truncado). `memo` guarda as próximas posições de
 * CDATA/comentário entre chamadas sobre o mesmo documento (`from` só avança).
 */
function findClose(xml, name, from, memo) {
  const close = `</${name}`;
  let i = from;
  // As próximas posições de CDATA/comentário só se recalculam quando `i` as
  // ultrapassa (e -1, "não há mais", é definitivo): procurá-las de novo em
  // cada fecho varria o resto do documento por cada item — O(n²), ~90 ms de
  // CPU no feed do CNCS, quando o plano Free dá 10 ms por invocação.
  for (;;) {
    const c = xml.indexOf(close, i);
    if (c < 0) return -1;
    if (memo.cdata !== -1 && memo.cdata < i) memo.cdata = xml.indexOf('<![CDATA[', i);
    if (memo.comment !== -1 && memo.comment < i) memo.comment = xml.indexOf('<!--', i);
    const { cdata, comment } = memo;
    const skip = [cdata, comment].filter((x) => x >= 0 && x < c).sort((a, b) => a - b)[0];
    if (skip === undefined) {
      const after = xml[c + close.length];
      if (after === '>' || /\s/.test(after ?? '')) return c;
      i = c + close.length;
      continue;
    }
    const end = skip === cdata ? xml.indexOf(']]>', skip + 9) : xml.indexOf('-->', skip + 4);
    if (end < 0) return -1;
    i = end + 3;
  }
}

/**
 * Percorre os elementos `<name …>` de `xml` (sem descer num elemento do mesmo
 * nome dentro de outro), saltando CDATA e comentários — um `<item>` escrito
 * dentro da descrição em CDATA não é um item. Um elemento sem fecho (XML
 * truncado) termina a iteração: os completos antes dele ficam.
 */
export function* elements(xml, name, limit = Infinity) {
  const open = `<${name}`;
  const memo = { cdata: -2, comment: -2 };
  let i = 0;
  let n = 0;
  while (n < limit) {
    const lt = xml.indexOf('<', i);
    if (lt < 0) return;
    if (xml.startsWith('<![CDATA[', lt)) {
      const e = xml.indexOf(']]>', lt + 9);
      if (e < 0) return;
      i = e + 3;
      continue;
    }
    if (xml.startsWith('<!--', lt)) {
      const e = xml.indexOf('-->', lt + 4);
      if (e < 0) return;
      i = e + 3;
      continue;
    }
    const next = xml[lt + open.length];
    if (xml.startsWith(open, lt) && (next === '>' || next === '/' || /\s/.test(next ?? ''))) {
      const gt = tagEnd(xml, lt);
      if (gt < 0) return;
      const head = xml.slice(lt + open.length, gt);
      if (head.trimEnd().endsWith('/')) {
        yield { attrs: parseAttrs(head), inner: '' };
        n++;
        i = gt + 1;
        continue;
      }
      const close = findClose(xml, name, gt + 1, memo);
      if (close < 0) return;
      yield { attrs: parseAttrs(head), inner: xml.slice(gt + 1, close) };
      n++;
      i = close + name.length + 2;
      continue;
    }
    i = lt + 1;
  }
}

const first = (xml, name) => elements(xml, name, 1).next().value ?? null;

/** Link de uma entrada Atom: o `rel="alternate"` (ou sem rel), não o `self`/`enclosure`. */
function atomLink(inner) {
  for (const el of elements(inner, 'link', 20)) {
    const rel = (el.attrs.rel ?? 'alternate').toLowerCase();
    if (rel === 'alternate' && el.attrs.href) return el.attrs.href;
  }
  return null;
}

/**
 * Documento RSS 2.0 ou Atom → os `limit` itens válidos mais recentes,
 * [{ t, u, d }] do mais recente para o mais antigo. Itens sem título, sem
 * link https: (ou, com `host`, com link fora desse domínio — ver
 * linkOnHost) ou sem data válida (inválida, ausente, futura) caem — o Radar
 * ordena por data e um item sem ela não tem onde ficar.
 *
 * Em duas passagens: primeiro só a data de cada item (barato), depois título
 * e link apenas dos mais recentes até haver `limit` válidos. O feed do CNCS
 * traz ~350 alertas desde 2016 e só os 10 mais novos chegam ao Radar —
 * limpar os outros todos era CPU gasta para nada.
 */
export function parseFeed(xml, now = Date.now(), limit = MAX_ITEMS_PER_SOURCE, host = null) {
  if (typeof xml !== 'string') return [];
  // Atom tem <feed> na raiz; RSS 2.0 tem <rss>/<channel>. Só o cabeçalho conta.
  const head = xml.slice(0, 4096);
  const isAtom = /<feed[\s>]/.test(head) && !/<(rss|channel)[\s>]/.test(head);
  const dated = [];
  for (const el of elements(xml, isAtom ? 'entry' : 'item', MAX_PARSE_ITEMS)) {
    const date = isAtom
      ? first(el.inner, 'published') ?? first(el.inner, 'updated')
      : first(el.inner, 'pubDate') ?? first(el.inner, 'dc:date');
    const d = date ? parseFeedDate(xmlValue(date.inner), now) : null;
    if (d !== null) dated.push({ d, inner: el.inner });
  }
  dated.sort((a, b) => b.d - a.d);
  const out = [];
  for (const { d, inner } of dated) {
    if (out.length >= limit) break;
    const titleEl = first(inner, 'title');
    const t = titleEl ? cleanTitle(titleEl.inner) : '';
    let link = null;
    if (isAtom) {
      link = atomLink(inner);
    } else {
      const linkEl = first(inner, 'link');
      if (linkEl) link = xmlValue(linkEl.inner);
    }
    const u = safeHttpsUrl(link);
    if (t && u && (!host || linkOnHost(u, host))) out.push({ t, u, d });
  }
  return out;
}

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;

/**
 * Catálogo KEV da CISA (JSON) → [{ t, u, d }]. Aceita o documento truncado
 * pelo teto de bytes: em vez de JSON.parse do catálogo inteiro (~1,8 MB, CPU
 * que o plano Free não tem), lê-se cada objeto de `vulnerabilities` à vez —
 * são planos (sem chavetas aninhadas) — e o último, cortado a meio, cai.
 * O link é a página do CVE no NVD, construída a partir de um cveID validado.
 */
export function parseKev(text, now = Date.now()) {
  if (typeof text !== 'string') return [];
  const start = text.indexOf('"vulnerabilities"');
  if (start < 0) return [];
  const re = /\{[^{}]*\}/g;
  re.lastIndex = start;
  const out = [];
  for (let m = re.exec(text), n = 0; m && n < MAX_PARSE_ITEMS; m = re.exec(text), n++) {
    let v;
    try {
      v = JSON.parse(m[0]);
    } catch {
      continue;
    }
    const cve = typeof v?.cveID === 'string' ? v.cveID.trim() : '';
    if (!CVE_RE.test(cve)) continue;
    const name = typeof v.vulnerabilityName === 'string' ? v.vulnerabilityName : '';
    const t = sanitizeText(name ? `${cve}: ${name}` : cve, MAX_TITLE_LEN);
    const d = typeof v.dateAdded === 'string' ? parseIsoDate(v.dateAdded) : null;
    if (d === null || d > now + FUTURE_SKEW_MS) continue;
    out.push({ t, u: `https://nvd.nist.gov/vuln/detail/${cve}`, d });
  }
  return out;
}

// ---------- agregação ----------

const byDateDesc = (a, b) => b.d - a.d || (a.u < b.u ? -1 : a.u > b.u ? 1 : 0);

/**
 * Junta os resultados de cada fonte no documento guardado no KV:
 *   { generated, sources: [{ id, name, type, lang, ok }], items: [{ t, u, s, d }] }
 * `results[i]` é a lista de itens da fonte i, ou null se falhou. Uma fonte
 * conta como ok só se deu pelo menos um item válido; se não, ficam os seus
 * itens de `prev` (o documento anterior no KV, revalidados). Por fonte, os
 * MAX_ITEMS_PER_SOURCE mais recentes; no total, deduplicado por URL (fica a
 * ocorrência mais recente) e cortado em MAX_ITEMS, do mais recente para o
 * mais antigo. `d` sai como ISO 8601.
 */
export function buildRadar(sources, results, now = Date.now(), prev = null) {
  const seen = new Set();
  const items = [];
  const prevItems = Array.isArray(prev?.items) ? prev.items : [];
  sources.forEach((src, i) => {
    let list;
    if (Array.isArray(results[i]) && results[i].length > 0) {
      list = [...results[i]].sort(byDateDesc);
    } else {
      // Fonte em baixo: mantém os itens que tinha na recolha anterior (a
      // fonte aparece na mesma como `ok: false`), em vez de a apagar do
      // Radar por uma falha de 30 min.
      list = prevItems
        .filter((it) => it?.s === src.id)
        .map((it) => ({ t: sanitizeText(it.t, MAX_TITLE_LEN), u: safeHttpsUrl(it.u), d: Date.parse(it.d) }))
        .filter((it) => it.t && it.u && Number.isFinite(it.d))
        .sort(byDateDesc);
    }
    for (const it of list.slice(0, MAX_ITEMS_PER_SOURCE)) items.push({ ...it, s: src.id });
  });
  items.sort(byDateDesc);
  const unique = [];
  for (const it of items) {
    if (seen.has(it.u)) continue;
    seen.add(it.u);
    unique.push({ t: it.t, u: it.u, s: it.s, d: new Date(it.d).toISOString() });
    if (unique.length >= MAX_ITEMS) break;
  }
  return {
    generated: new Date(now).toISOString(),
    sources: sources.map((src, i) => ({
      id: src.id, name: src.name, type: src.type, lang: src.lang,
      ok: Array.isArray(results[i]) && results[i].length > 0,
    })),
    items: unique,
  };
}

// ---------- rede ----------

/**
 * Corpo da resposta como texto, lido até `maxBytes` no máximo: depois disso
 * a leitura é cancelada (o resto nem chega a ser descarregado) e devolve-se o
 * que entrou — os parsers aguentam um documento cortado a meio.
 */
export async function readCapped(res, maxBytes) {
  const reader = res.body?.getReader?.();
  if (!reader) {
    const text = await res.text();
    return text.length > maxBytes ? text.slice(0, maxBytes) : text;
  }
  const decoder = new TextDecoder();
  let total = 0;
  let out = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    const room = maxBytes - total;
    const chunk = value.byteLength > room ? value.subarray(0, room) : value;
    total += chunk.byteLength;
    out += decoder.decode(chunk, { stream: true });
    if (total >= maxBytes) {
      await reader.cancel().catch(() => {});
      break;
    }
  }
  return out + decoder.decode();
}

/** Busca e faz parse de uma fonte. Lança em erro de rede, timeout ou status ≠ 2xx. */
export async function fetchSource(src, { now = Date.now(), timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const res = await fetch(src.url, {
    headers: {
      // UA honesto: com um "Mozilla/5.0" a imitar um browser, o BleepingComputer
      // e a SecurityWeek respondem com o desafio da Cloudflare em vez do feed.
      'user-agent': 'personal-site-worker (radar; +https://danielmala.co/radar/)',
      accept: src.format === 'kev'
        ? 'application/json'
        : 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/xml;q=0.9, */*;q=0.5',
    },
    signal: AbortSignal.timeout(timeoutMs),
    // URLs fixos e de confiança: um redirect não é esperado, e segui-lo levava
    // o pedido para fora da lista acima. Se um feed mudar de sítio, a fonte
    // aparece em baixo no painel — o sinal para atualizar o URL aqui. Não é
    // 'error': o workerd rejeita esse valor ("won't be implemented since it
    // does not make sense at the edge"), o que derrubava as 8 fontes. Com
    // 'manual' a resposta 3xx chega cá, e `res.ok` é falso para ela.
    redirect: 'manual',
  });
  if (!res.ok) throw new Error(`radar_status_${res.status}`);
  const text = await readCapped(res, src.maxBytes ?? DEFAULT_MAX_BYTES);
  // O KEV não precisa: o link é construído aqui (NVD), não vem do feed.
  return src.format === 'kev'
    ? parseKev(text, now)
    : parseFeed(text, now, MAX_ITEMS_PER_SOURCE, sourceHost(src.url));
}

/**
 * Busca todas as fontes em paralelo, cada uma com o seu timeout: uma fonte em
 * baixo (ou lenta, ou com lixo) fica com `ok: false` e não derruba as outras.
 */
export async function collectRadar(sources = RADAR_SOURCES, { now = Date.now(), timeoutMs, prev = null } = {}) {
  const settled = await Promise.allSettled(sources.map((src) => fetchSource(src, { now, timeoutMs })));
  const results = settled.map((r, i) => {
    if (r.status === 'fulfilled') return r.value;
    console.error('radar_source_failed', sources[i].id, r.reason?.message ?? String(r.reason));
    return null;
  });
  return buildRadar(sources, results, now, prev);
}
