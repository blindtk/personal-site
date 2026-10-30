// «O link verdadeiro» — lógica pura (sem DOM, sem rede), testável em Node.
//
// Núcleo: dado um URL e o domínio que o serviço realmente usa, dizer se o
// link é legítimo ou, se não for, QUE truque usa. O parsing é o do próprio
// browser (WHATWG URL): é ele que decide para onde o link vai, por isso
// qualquer regex sobre o texto cru (a abordagem ingénua) discordaria dele
// em casos como «https://cgd.pt\@evil.com» ou «https://ｃｇｄ.pt».

export const ROUNDS = 10;

/** Truques que um link falso pode usar (a ordem é a da UI). */
export const TRICKS = [
  'homograph',
  'subdomain',
  'userinfo',
  'typosquat',
  'tld',
  'http',
  'path',
  'shortener',
  'ip',
];

// Sufixos públicos de MAIS de um rótulo. Não é a Public Suffix List inteira
// (≈10 mil entradas): é o subconjunto que importa para este jogo — sufixos
// portugueses, uns quantos comuns e plataformas onde qualquer pessoa obtém
// um subdomínio (nome.github.io é de «nome», não do github.io). Fora desta
// lista, o sufixo é só o último rótulo.
const MULTI_LABEL_SUFFIXES = new Set([
  'com.pt', 'org.pt', 'edu.pt', 'gov.pt', 'net.pt', 'int.pt', 'nome.pt', 'publ.pt',
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.br', 'com.au', 'co.jp',
  'github.io', 'gitlab.io', 'pages.dev', 'web.app', 'netlify.app', 'vercel.app',
  'herokuapp.com', 'blogspot.com', 'workers.dev',
]);

// Encurtadores: escondem o destino, por isso nunca provam nada.
const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'is.gd', 'cutt.ly', 'rb.gy', 'ow.ly',
  'buff.ly', 'lnkd.in', 'tiny.cc', 'shorturl.at', 'goo.gl', 'rebrand.ly',
]);

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

function suffixLength(labels) {
  if (labels.length >= 2 && MULTI_LABEL_SUFFIXES.has(labels.slice(-2).join('.'))) return 2;
  return 1;
}

/**
 * Faz o parse como um browser e devolve o que interessa para decidir o
 * destino real. Devolve null (falha fechada) para tudo o que não seja um URL
 * http(s) completo com um nome de máquina bem formado.
 */
export function parseUrl(raw) {
  if (typeof raw !== 'string') return null;
  let u;
  try {
    u = new URL(raw.trim());
  } catch {
    return null;
  }
  // «cgd.pt:443/x» é lido como esquema «cgd.pt:»; javascript:, data:, ftp:…
  // também não são ligações web. Só se aceita http(s).
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;

  // Um único ponto final é o domínio absoluto («cgd.pt.» == «cgd.pt»).
  const hostname = u.hostname.endsWith('.') ? u.hostname.slice(0, -1) : u.hostname;
  if (!hostname) return null;

  const isIp = IPV4.test(hostname) || hostname.startsWith('[');
  const labels = hostname.split('.');
  if (!isIp && labels.some((l) => l === '')) return null; // «a..b»

  let registrable = hostname;
  let suffix = hostname;
  let brand = '';
  let subLabels = [];
  if (!isIp) {
    const sl = suffixLength(labels);
    suffix = labels.slice(-sl).join('.');
    if (labels.length > sl) {
      registrable = labels.slice(-(sl + 1)).join('.');
      brand = labels[labels.length - sl - 1];
      subLabels = labels.slice(0, -(sl + 1));
    }
  }

  return {
    scheme: u.protocol.slice(0, -1),
    hasUserinfo: u.username !== '' || u.password !== '',
    hostname,
    isIp,
    labels,
    subLabels,
    registrable,
    suffix,
    brand,
    rest: decodeSafe(u.pathname + u.search + u.hash).toLowerCase(),
  };
}

function decodeSafe(s) {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

// ---------- Punycode (RFC 3492) ----------
// O WHATWG URL só converte Unicode → ASCII (xn--…). Para mostrar ao jogador
// o que o rótulo «diz» é preciso o caminho inverso, e `domainToUnicode` só
// existe em Node.

const BASE = 36;
const T_MIN = 1;
const T_MAX = 26;
const SKEW = 38;
const DAMP = 700;

function adapt(delta, numPoints, first) {
  let d = first ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - T_MIN) * T_MAX) >> 1) {
    d = Math.floor(d / (BASE - T_MIN));
    k += BASE;
  }
  return k + Math.floor(((BASE - T_MIN + 1) * d) / (d + SKEW));
}

function digitValue(code) {
  if (code >= 48 && code <= 57) return code - 22; // 0-9 → 26-35
  if (code >= 65 && code <= 90) return code - 65; // A-Z
  if (code >= 97 && code <= 122) return code - 97; // a-z
  return -1;
}

/** Descodifica um rótulo punycode (sem o prefixo «xn--»). null se malformado. */
export function punycodeDecode(input) {
  const out = [];
  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) {
    const c = input.charCodeAt(j);
    if (c >= 0x80) return null;
    out.push(c);
  }
  let n = 128;
  let i = 0;
  let bias = 72;
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length; ) {
    const oldi = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (idx >= input.length) return null;
      const digit = digitValue(input.charCodeAt(idx++));
      if (digit < 0) return null;
      i += digit * w;
      if (i > 0x7fffffff) return null;
      const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const len = out.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    if (n > 0x10ffff) return null;
    i %= len;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

/** «xn--pple-43d.com» → «аpple.com». Rótulos inválidos ficam como estão. */
export function toUnicodeHost(hostname) {
  return hostname
    .split('.')
    .map((l) => (l.startsWith('xn--') ? (punycodeDecode(l.slice(4)) ?? l) : l))
    .join('.');
}

const SCRIPTS = [
  { name: 'cyrillic', re: /\p{Script=Cyrillic}/u },
  { name: 'greek', re: /\p{Script=Greek}/u },
  { name: 'latin', re: /\p{Script=Latin}/u },
];

/** Carateres não-ASCII de um texto, com o ponto de código e o alfabeto. */
export function nonAsciiChars(text) {
  const seen = new Set();
  const out = [];
  for (const ch of text) {
    if (ch.charCodeAt(0) < 0x80 || seen.has(ch)) continue;
    seen.add(ch);
    const cp = ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0');
    const script = SCRIPTS.find((sc) => sc.re.test(ch))?.name ?? 'other';
    out.push({ char: ch, code: `U+${cp}`, script });
  }
  return out;
}

// ---------- Classificação ----------

// Trocas que a vista confunde: 0↔o, 1↔l, 5↔s, «rn»↔m, «vv»↔w.
function fold(s) {
  return s.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/1/g, 'l').replace(/5/g, 's');
}

function editDistance(a, b) {
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length];
}

// «cgd-pt», «seguro-cgd», «cgdonline», «cgb», «paypa1», «rnicrosoft»…
function looksLikeBrand(label, brand) {
  if (brand.length < 3 || label === brand) return false;
  if (label.split('-').includes(brand)) return true;
  if (label.includes(brand)) return true;
  if (fold(label) === fold(brand)) return true;
  return editDistance(label, brand) <= (brand.length >= 8 ? 2 : 1);
}

function brandInSubdomain(subLabels, brand) {
  if (brand.length < 3) return false;
  return subLabels.some((l) => l === brand || l.split('-').includes(brand));
}

/**
 * Que truque usa `raw`, tendo em conta que o domínio verdadeiro do serviço é
 * `expectedDomain` (ex.: «cgd.pt»)? Devolve 'legit' ou um de TRICKS; 'other'
 * (domínio sem relação) ou 'invalid' (não é um URL web).
 */
export function classify(raw, expectedDomain) {
  const p = parseUrl(raw);
  if (!p) return 'invalid';
  const want = parseUrl(`https://${expectedDomain}/`);
  if (!want || want.isIp) throw new RangeError(`domínio esperado inválido: ${expectedDomain}`);

  if (p.isIp) return 'ip';
  // Nenhum serviço legítimo precisa de credenciais no link; e a parte antes
  // do @ é exatamente onde o atacante escreve o nome que queres ver.
  if (p.hasUserinfo) return 'userinfo';
  if (p.registrable === want.registrable) return p.scheme === 'https' ? 'legit' : 'http';
  if (SHORTENERS.has(p.registrable)) return 'shortener';
  if (p.labels.some((l) => l.startsWith('xn--'))) return 'homograph';
  if (brandInSubdomain(p.subLabels, want.brand)) return 'subdomain';
  if (p.brand === want.brand && p.suffix !== want.suffix) return 'tld';
  if (looksLikeBrand(p.brand, want.brand)) return 'typosquat';
  if (want.brand.length >= 3 && p.rest.includes(want.brand)) return 'path';
  return 'other';
}

// ---------- Rondas ----------

function shuffle(items, rng) {
  const a = [...items];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(rng() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

/**
 * Uma ronda a partir de um cenário {id, prompt, domain, note, legit, decoys}.
 * Falha (em vez de servir uma ronda sem resposta ou com duas) se os dados
 * não tiverem exatamente UM link legítimo.
 */
export function buildRound(scenario, rng = Math.random) {
  const urls = [scenario.legit, ...scenario.decoys.map((d) => (typeof d === 'string' ? d : d.url))];
  const options = shuffle(urls, rng).map((url) => ({ url, trick: classify(url, scenario.domain) }));
  const answers = options.flatMap((o, i) => (o.trick === 'legit' ? [i] : []));
  if (answers.length !== 1) {
    throw new Error(`cenário ${scenario.id}: ${answers.length} links legítimos (esperado 1)`);
  }
  return {
    id: scenario.id,
    prompt: scenario.prompt,
    note: scenario.note,
    domain: scenario.domain,
    options,
    answer: answers[0],
  };
}

/** `count` cenários distintos, sorteados, cada um já transformado em ronda. */
export function pickRounds(scenarios, count = ROUNDS, rng = Math.random) {
  if (count > scenarios.length) {
    throw new RangeError(`${count} rondas pedidas, só há ${scenarios.length} cenários`);
  }
  return shuffle(scenarios, rng)
    .slice(0, count)
    .map((s) => buildRound(s, rng));
}

// ---------- Pontuação ----------

/** 'perfect' | 'good' | 'ok' | 'low' — a UI traduz. */
export function rate(score, total = ROUNDS) {
  if (score >= total) return 'perfect';
  if (score >= total * 0.8) return 'good';
  if (score >= total * 0.5) return 'ok';
  return 'low';
}

/** Lê o melhor resultado guardado; qualquer lixo no localStorage vira null. */
export function parseBest(raw, total = ROUNDS) {
  if (typeof raw !== 'string' || !/^\d{1,3}$/.test(raw)) return null;
  const n = Number(raw);
  return n <= total ? n : null;
}
