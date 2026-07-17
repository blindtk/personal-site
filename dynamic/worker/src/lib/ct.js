// Vigia CT — monitorização dos logs públicos de Certificate Transparency
// para o domínio do próprio site (via crt.sh). Qualquer certificado emitido
// para o domínio — incluindo um que um atacante conseguisse emitir após um
// takeover de DNS/registrar — fica registado nos logs CT; aqui compara-se
// cada emissão com a allowlist de emissores esperados. Sem input de
// visitantes: o domínio vem de SCAN_TARGET, a query é sempre a mesma.
// Como em feeds.js, as funções de PARSE (puras, testáveis) estão separadas
// das de FETCH (rede).

import { sanitizeText } from './sanitize.js';

// Emissores esperados por omissão: Let's Encrypt + Google Trust Services é
// o par que a Cloudflare usa (primário + backup) nos certificados do site.
// Override por env var CT_EXPECTED_ISSUERS (lista separada por vírgulas).
export const DEFAULT_EXPECTED_ISSUERS = ["Let's Encrypt", 'Google Trust Services'];

export const CT_WINDOW_DAYS = 90;
export const MAX_CERTS = 40;
export const MAX_NAMES_PER_CERT = 8;

const DAY_MS = 86400_000;

/** Allowlist vinda do env (CSV) ou a por omissão. */
export function parseExpectedIssuers(csv) {
  const list = typeof csv === 'string'
    ? csv.split(',').map((s) => sanitizeText(s, 60)).filter(Boolean)
    : [];
  return list.length > 0 ? list : DEFAULT_EXPECTED_ISSUERS;
}

/**
 * Rótulo curto de um DN de emissor do crt.sh
 * ("C=US, O=Let's Encrypt, CN=R11" → "Let's Encrypt R11").
 * Sem O=/CN= reconhecíveis, devolve o DN inteiro sanitizado.
 */
export function issuerLabel(dn) {
  if (typeof dn !== 'string') return '';
  const part = (key) => {
    // valor até à próxima vírgula; DNs do crt.sh não trazem vírgulas escapadas
    const m = dn.match(new RegExp(`(?:^|, ?)${key}=([^,]+)`));
    return m ? m[1].trim().replace(/^"|"$/g, '') : '';
  };
  const org = part('O');
  const cn = part('CN');
  const label = org && cn && cn !== org ? `${org} ${cn}` : org || cn || dn;
  return sanitizeText(label, 60);
}

/** True se o rótulo do emissor bate com algum esperado (substring, sem caso). */
export function isExpectedIssuer(label, expected) {
  const l = String(label).toLowerCase();
  return expected.some((e) => l.includes(String(e).toLowerCase()));
}

// As datas do crt.sh vêm sem timezone ("2026-07-02T09:00:00"); em ES isso
// parseia como hora LOCAL, o que tornaria o resultado dependente do fuso de
// quem corre (Worker é UTC, testes não necessariamente). Fixa-se UTC.
function parseCtDate(s) {
  if (typeof s !== 'string' || s === '') return null;
  const iso = /[zZ]$|[+-]\d\d:\d\d$/.test(s) ? s : `${s}Z`;
  const ms = Date.parse(iso);
  return Number.isFinite(ms) ? ms : null;
}

/** True se o nome (SAN) pertence ao domínio: apex, subdomínio ou wildcard. */
function nameBelongsTo(name, domain) {
  const n = name.toLowerCase();
  return n === domain || n.endsWith(`.${domain}`) || n === `*.${domain}`;
}

/**
 * Normaliza uma entrada do JSON do crt.sh. Devolve null se não disser
 * respeito ao domínio ou se faltar o essencial. Cada campo que segue para o
 * cliente passa por sanitizeText — a regra do projeto para dados externos.
 */
export function normalizeCtEntry(raw, { domain, expectedIssuers }) {
  if (!raw || typeof raw !== 'object') return null;
  const loggedAt = parseCtDate(raw.entry_timestamp) ?? parseCtDate(raw.not_before);
  const notBefore = parseCtDate(raw.not_before);
  const notAfter = parseCtDate(raw.not_after);
  if (loggedAt === null || notBefore === null) return null;

  const names = [];
  for (const line of String(raw.name_value ?? '').split('\n')) {
    const name = sanitizeText(line, 80).toLowerCase();
    if (name && nameBelongsTo(name, domain) && !names.includes(name)) names.push(name);
    if (names.length >= MAX_NAMES_PER_CERT) break;
  }
  if (names.length === 0) return null;
  names.sort();

  const issuer = issuerLabel(raw.issuer_name);
  return {
    serial: sanitizeText(String(raw.serial_number ?? ''), 40),
    loggedAt,
    notBefore,
    notAfter,
    issuer,
    names,
    expected: isExpectedIssuer(issuer, expectedIssuers),
  };
}

/**
 * Pipeline completo de parse: normaliza, filtra à janela, deduplica
 * (o crt.sh lista pré-certificado e certificado-folha como entradas
 * separadas com o mesmo serial) e ordena do mais recente para o mais
 * antigo. Aceita a concatenação das respostas das duas queries (apex e
 * %.domínio), que se sobrepõem — a deduplicação também trata disso.
 */
export function parseCtEntries(entries, {
  domain,
  expectedIssuers = DEFAULT_EXPECTED_ISSUERS,
  now = Date.now(),
  windowDays = CT_WINDOW_DAYS,
  limit = MAX_CERTS,
} = {}) {
  const list = Array.isArray(entries) ? entries : [];
  const cutoff = now - windowDays * DAY_MS;
  const seen = new Set();
  const out = [];
  for (const raw of list) {
    const cert = normalizeCtEntry(raw, { domain, expectedIssuers });
    if (!cert || cert.loggedAt < cutoff || cert.loggedAt > now + DAY_MS) continue;
    // dedupe: serial quando existe; senão emissor+notBefore+nomes
    const key = cert.serial || `${cert.issuer}|${cert.notBefore}|${cert.names.join(',')}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(cert);
  }
  out.sort((a, b) => b.loggedAt - a.loggedAt);
  // o serial serve só à deduplicação — não precisa de ir para o cliente
  return out.slice(0, limit).map(({ serial, ...cert }) => cert);
}

/** Sumário para os stats do painel. */
export function ctStats(certs) {
  const issuers = new Set();
  const names = new Set();
  let unexpected = 0;
  for (const c of certs) {
    issuers.add(c.issuer);
    for (const n of c.names) names.add(n);
    if (!c.expected) unexpected += 1;
  }
  return { total: certs.length, issuerCount: issuers.size, nameCount: names.size, unexpected };
}

const CRTSH_URL = 'https://crt.sh/';

/**
 * Busca e agrega as emissões CT do domínio. Duas queries (apex e
 * %.domínio) porque um certificado emitido só para um subdomínio nunca
 * apareceria na query do apex — é exatamente o caso que interessa apanhar.
 * Degrada para os resultados parciais se uma query falhar; lança se
 * falharem as duas (a rota devolve 502 e o painel mostra o fallback —
 * ou serve-se o último snapshot bom via cache stale-while-revalidate).
 */
export async function fetchCtWatch(env, { timeoutMs = 8000, now = Date.now() } = {}) {
  const domain = new URL(env.SCAN_TARGET || 'https://danielmala.co/').hostname.toLowerCase();
  const expectedIssuers = parseExpectedIssuers(env.CT_EXPECTED_ISSUERS);
  const headers = { 'user-agent': 'personal-site-worker (ct-watch)', accept: 'application/json' };

  const queries = [domain, `%.${domain}`];
  const results = await Promise.all(
    queries.map((q) =>
      fetch(`${CRTSH_URL}?q=${encodeURIComponent(q)}&output=json`, {
        headers,
        signal: AbortSignal.timeout(timeoutMs),
        cf: { cacheTtl: 3600 },
      })
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null),
    ),
  );
  if (results.every((r) => r === null)) throw new Error('crtsh_unavailable');

  const merged = results.flatMap((r) => (Array.isArray(r) ? r : []));
  const certs = parseCtEntries(merged, { domain, expectedIssuers, now });
  return {
    domain,
    windowDays: CT_WINDOW_DAYS,
    expectedIssuers,
    certs,
    summary: ctStats(certs),
    fetchedAt: now,
  };
}
