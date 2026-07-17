/**
 * Análise forense de cabeçalhos de email — lógica pura, sem DOM.
 *
 * Parsing tolerante por natureza: cabeçalhos Received não têm gramática
 * rigorosa (cada MTA escreve à sua maneira), por isso nada aqui lança
 * exceções para input arbitrário — o que não se conseguir estruturar
 * fica disponível em bruto e a análise continua.
 *
 * Importante: isto *interpreta* os veredictos já presentes no cabeçalho
 * (Authentication-Results, Received-SPF). Não verifica SPF/DKIM por si —
 * isso exigiria DNS e validação criptográfica no servidor de receção.
 */

/** Desdobra linhas contínuas (RFC 5322 folding) e devolve [{name, value}] pela ordem original. */
export function unfoldHeaders(raw) {
  if (typeof raw !== 'string') return [];
  const text = raw.replace(/\r\n?/g, '\n');
  // O bloco de cabeçalhos termina na primeira linha em branco — o resto é corpo.
  const block = text.split(/\n[ \t]*\n/)[0] ?? '';
  const headers = [];
  for (const line of block.split('\n')) {
    if (/^[ \t]/.test(line) && headers.length) {
      headers[headers.length - 1].value += ' ' + line.trim();
    } else {
      const m = line.match(/^([!-9;-~]+):[ \t]?(.*)$/);
      if (m) headers.push({ name: m[1], value: m[2].trim() });
      // Linhas sem dois-pontos fora de folding (ex.: "From " de mbox) ignoram-se.
    }
  }
  return headers;
}

/** Remove comentários (…) do RFC 5322, com suporte a aninhamento. */
export function stripComments(value) {
  let out = '';
  let depth = 0;
  for (let i = 0; i < value.length; i++) {
    const c = value[i];
    if (c === '\\' && depth > 0) { i++; continue; }
    if (c === '(') { depth++; continue; }
    if (c === ')' && depth > 0) { depth--; continue; }
    if (depth === 0) out += c;
  }
  return out.replace(/\s+/g, ' ').trim();
}

/** Extrai o addr-spec de "Nome <a@b>" / "a@b (Nome)" / "a@b". */
export function extractAddress(value) {
  if (!value) return null;
  const angled = value.match(/<([^<>\s]+@[^<>\s]+)>/);
  if (angled) return angled[1].toLowerCase();
  const bare = stripComments(value).match(/([^\s"<>,;]+@[^\s"<>,;]+)/);
  return bare ? bare[1].toLowerCase() : null;
}

export function domainOf(addr) {
  if (!addr) return null;
  const at = addr.lastIndexOf('@');
  if (at < 0) return null;
  return addr.slice(at + 1).toLowerCase().replace(/\.$/, '') || null;
}

/**
 * Alinhamento relaxado entre dois domínios: iguais, ou um é subdomínio do
 * outro. Aproximação do alinhamento organizacional do DMARC — sem a Public
 * Suffix List não distinguimos "example.co.uk" de "co.uk", e assume-se o
 * caso comum.
 */
export function domainsAligned(a, b) {
  if (!a || !b) return false;
  const x = a.toLowerCase().replace(/\.$/, '');
  const y = b.toLowerCase().replace(/\.$/, '');
  return x === y || x.endsWith('.' + y) || y.endsWith('.' + x);
}

const IPV4_RE = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/g;

function isPrivateIp(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((n) => n > 255)) return false;
  return (
    p[0] === 10 ||
    p[0] === 127 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 169 && p[1] === 254)
  );
}

function parseDate(str) {
  if (!str) return null;
  const d = new Date(stripComments(str));
  return Number.isNaN(d.getTime()) ? null : d;
}

/**
 * Faz o parsing tolerante de um cabeçalho Received.
 * Forma típica: "from <helo> (<dns> [<ip>]) by <servidor> with <proto> id <id> for <dest>; <data>"
 * — mas qualquer cláusula pode faltar (o primeiro hop raramente tem "from").
 */
export function parseReceived(value) {
  const semi = value.lastIndexOf(';');
  const clauses = semi >= 0 ? value.slice(0, semi) : value;
  const date = semi >= 0 ? parseDate(value.slice(semi + 1)) : null;

  // O "from" vai até ao "by" (fora de comentários); os IPs vivem muitas
  // vezes dentro do comentário, por isso captura-se antes de os remover.
  const clean = stripComments(clauses);
  const fromRaw = (() => {
    const m = clauses.match(/(?:^|\s)from\s+([\s\S]*?)(?=\s+by\s+|$)/i);
    return m ? m[1].trim() : null;
  })();
  const fromMatch = clean.match(/(?:^|\s)from\s+(\S+)/i);
  const byMatch = clean.match(/(?:^|\s)by\s+(\S+)/i);
  const withMatch = clean.match(/(?:^|\s)with\s+([A-Za-z0-9_-]+)/i);
  const forMatch = clean.match(/(?:^|\s)for\s+<?([^\s<>;]+@[^\s<>;]+)>?/i);

  const ips = [];
  if (fromRaw) {
    for (const m of fromRaw.matchAll(IPV4_RE)) {
      if (!ips.includes(m[1])) ips.push(m[1]);
    }
    for (const m of fromRaw.matchAll(/\[IPv6:([0-9a-fA-F:.]+)\]/g)) {
      if (!ips.includes(m[1])) ips.push(m[1]);
    }
  }

  const proto = withMatch ? withMatch[1].toUpperCase() : null;
  // ESMTPS/ESMTPSA/UTF8SMTPS… = sessão SMTP sobre TLS; HTTPS = submissão web.
  const tls = proto ? /SMTPSA?$/.test(proto) || proto === 'HTTPS' : null;

  return {
    raw: value,
    from: fromMatch ? fromMatch[1].replace(/^\[|\]$/g, '') : null,
    fromIps: ips,
    hasPrivateIp: ips.some(isPrivateIp),
    by: byMatch ? byMatch[1] : null,
    proto,
    tls,
    for: forMatch ? forMatch[1].toLowerCase() : null,
    date,
  };
}

/**
 * Parsing de Authentication-Results (RFC 8601):
 * "<authserv-id>; spf=pass smtp.mailfrom=…; dkim=pass header.d=…; dmarc=…"
 */
export function parseAuthResults(value) {
  const clean = stripComments(value);
  const parts = clean.split(';').map((p) => p.trim()).filter(Boolean);
  if (!parts.length) return { authserv: null, results: [] };
  const authserv = parts[0].split(/\s/)[0] || null;
  const results = [];
  for (const part of parts.slice(1)) {
    const m = part.match(/^([a-z0-9-]+)\s*=\s*([a-z0-9]+)/i);
    if (!m) continue;
    const props = {};
    for (const pm of part.matchAll(/([a-z]+)\.([a-z]+)\s*=\s*("[^"]*"|[^\s;]+)/gi)) {
      props[`${pm[1].toLowerCase()}.${pm[2].toLowerCase()}`] = pm[3].replace(/^"|"$/g, '');
    }
    results.push({ method: m[1].toLowerCase(), result: m[2].toLowerCase(), props });
  }
  return { authserv, results };
}

function findAll(headers, name) {
  const n = name.toLowerCase();
  return headers.filter((h) => h.name.toLowerCase() === n);
}

function findFirst(headers, name) {
  return findAll(headers, name)[0] ?? null;
}

const FAIL_RESULTS = ['fail', 'permerror'];
const SOFT_RESULTS = ['softfail', 'temperror', 'neutral', 'policy'];

/** 'pass' | 'soft' | 'fail' | 'none' — para o UI colorir sem conhecer cada token. */
export function verdictClass(result) {
  if (!result || result === 'none') return 'none';
  if (result === 'pass' || result === 'bestguesspass') return 'pass';
  if (FAIL_RESULTS.includes(result)) return 'fail';
  if (SOFT_RESULTS.includes(result)) return 'soft';
  return 'soft';
}

const HOUR = 3600;
// Tolerância a relógios dessincronizados entre MTAs antes de acusar
// timestamps a andar para trás.
const CLOCK_SKEW_S = 60;

/**
 * Análise completa: devolve null se o texto não contiver cabeçalhos.
 * flags: [{id, level: 'bad'|'warn'|'info', params}] — o UI traduz cada id.
 */
export function analyze(raw) {
  const headers = unfoldHeaders(raw);
  if (!headers.length) return null;

  const val = (name) => findFirst(headers, name)?.value ?? null;

  const fromAddr = extractAddress(val('From'));
  const returnPath = extractAddress(val('Return-Path'));
  const replyTo = extractAddress(val('Reply-To'));
  const fromDomain = domainOf(fromAddr);

  const summary = {
    from: fromAddr,
    fromRaw: val('From'),
    to: extractAddress(val('To')),
    subject: val('Subject'),
    date: parseDate(val('Date')),
    messageId: val('Message-ID') ?? val('Message-Id'),
    returnPath,
    replyTo,
  };

  // --- Cadeia de Received: no cabeçalho o topo é o último hop; a ordem
  // cronológica é a inversa. delaySeconds = tempo desde o hop anterior.
  const received = findAll(headers, 'Received').map((h) => parseReceived(h.value));
  const hops = received.slice().reverse();
  for (let i = 0; i < hops.length; i++) {
    const prev = i > 0 ? hops[i - 1].date : null;
    hops[i].delaySeconds =
      prev && hops[i].date ? Math.round((hops[i].date - prev) / 1000) : null;
  }

  // --- Autenticação: só o Authentication-Results do topo (escrito pelo
  // fornecedor de receção) merece confiança — os de baixo podem vir forjados.
  const arHeaders = findAll(headers, 'Authentication-Results');
  const ar = arHeaders.length ? parseAuthResults(arHeaders[0].value) : null;
  const method = (m) => ar?.results.find((r) => r.method === m) ?? null;

  const spf = method('spf');
  const dkim = method('dkim');
  const dmarc = method('dmarc');

  let spfResult = spf?.result ?? null;
  let spfSource = spf ? 'authentication-results' : null;
  const receivedSpf = val('Received-SPF');
  if (!spfResult && receivedSpf) {
    const m = stripComments(receivedSpf).match(/^(\w+)/);
    if (m) {
      spfResult = m[1].toLowerCase();
      spfSource = 'received-spf';
    }
  }

  // Domínio DKIM: do Authentication-Results, ou do d= da própria assinatura.
  let dkimDomain = dkim?.props['header.d'] ?? null;
  if (!dkimDomain && dkim?.props['header.i']) {
    dkimDomain = domainOf(dkim.props['header.i']) ?? dkim.props['header.i'].replace(/^@/, '');
  }
  const dkimSig = val('DKIM-Signature');
  if (!dkimDomain && dkimSig) {
    const m = dkimSig.match(/(?:^|;)\s*d\s*=\s*([^;\s]+)/);
    if (m) dkimDomain = m[1].toLowerCase();
  }

  const auth = {
    source: ar ? arHeaders[0].value : null,
    authserv: ar?.authserv ?? null,
    count: arHeaders.length,
    spf: { result: spfResult, class: verdictClass(spfResult), source: spfSource },
    dkim: { result: dkim?.result ?? null, class: verdictClass(dkim?.result ?? null), domain: dkimDomain },
    dmarc: { result: dmarc?.result ?? null, class: verdictClass(dmarc?.result ?? null) },
  };

  // --- Red flags, das mais graves para as informativas.
  const flags = [];
  const flag = (id, level, params = {}) => flags.push({ id, level, params });

  for (const [name, m] of [['SPF', auth.spf], ['DKIM', auth.dkim], ['DMARC', auth.dmarc]]) {
    if (m.result && FAIL_RESULTS.includes(m.result)) {
      flag('authFail', 'bad', { method: name, result: m.result });
    } else if (m.result && SOFT_RESULTS.includes(m.result)) {
      flag('authSoft', 'warn', { method: name, result: m.result });
    }
  }

  if (arHeaders.length > 1) flag('multipleAuth', 'warn', { count: arHeaders.length });

  const retDomain = domainOf(returnPath);
  if (fromDomain && retDomain && !domainsAligned(fromDomain, retDomain)) {
    flag('fromReturnMismatch', 'warn', { from: fromDomain, ret: retDomain });
  }
  const replyDomain = domainOf(replyTo);
  if (fromDomain && replyDomain && !domainsAligned(fromDomain, replyDomain)) {
    flag('replyToDivergent', 'warn', { reply: replyDomain, from: fromDomain });
  }
  if (auth.dkim.class === 'pass' && dkimDomain && fromDomain && !domainsAligned(dkimDomain, fromDomain)) {
    flag('dkimMisaligned', 'warn', { dkim: dkimDomain, from: fromDomain });
  }

  hops.forEach((hop, i) => {
    if (hop.delaySeconds !== null && hop.delaySeconds < -CLOCK_SKEW_S) {
      flag('hopBackwards', 'warn', { hop: i + 1 });
    } else if (hop.delaySeconds !== null && hop.delaySeconds > HOUR) {
      flag('bigGap', 'info', { hop: i + 1, delay: formatDelay(hop.delaySeconds) });
    }
  });

  if (!ar && !receivedSpf) flag('authMissing', 'info');
  if (!summary.messageId) flag('noMessageId', 'warn');
  if (!hops.length) flag('noHops', 'info');

  return { headers, summary, hops, auth, flags };
}

/** 42 → "42s", 3700 → "1h 1m" — para o UI e para os params das flags. */
export function formatDelay(seconds) {
  if (seconds === null || seconds === undefined) return '—';
  const sign = seconds < 0 ? '-' : '+';
  let s = Math.abs(Math.round(seconds));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  s = s % 60;
  if (h) return `${sign}${h}h ${m}m`;
  if (m) return `${sign}${m}m ${s}s`;
  return `${sign}${s}s`;
}
