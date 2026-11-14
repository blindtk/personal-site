/**
 * Resumo agregado do honeypot externo (repo honeypot-vps-infra, ADR 0019/0022)
 * — validação pura, sem DOM nem I/O, testável em Node.
 *
 * O ficheiro content/intel-summary.json é gerado fora deste repositório e
 * chega por pull request (docs/intel-sync.md). Aqui só entram AGREGADOS:
 * contagens, técnicas ATT&CK e nomes de utilizador tentados. Nenhum endereço
 * IP pode atravessar esta fronteira, por isso qualquer texto com forma de
 * IPv4/IPv6 falha o build em vez de ser publicado.
 *
 * Contrato (tudo obrigatório):
 *   {
 *     "generatedAt": "2026-11-10T06:00:00Z",   // fim da janela, ISO 8601 UTC
 *     "windowDays": 7,                          // 1..31
 *     "totals": { "events": 0, "sources": 0, "sessions": 0 },
 *     "techniques": [{ "id": "T1110.001", "name": "…", "count": 0 }],  // ≤ 10
 *     "usernames":  [{ "name": "root", "count": 0 }]                   // ≤ 10
 *   }
 */

export const INTEL_MAX_ROWS = 10;
export const INTEL_MAX_AGE_DAYS = 30;
const NAME_MAX = 80;
const USER_MAX = 32;

const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
// ASCII imprimível, sem espaços nas pontas: nomes de utilizador e de técnicas
// não precisam de mais, e isto deixa de fora caracteres de controlo e bidi.
const PRINTABLE = /^[\x21-\x7e](?:[\x20-\x7e]*[\x21-\x7e])?$/;
const IPV4 = /(?:\d{1,3}\.){3}\d{1,3}/;
const IPV6 = /(?:[0-9a-f]{1,4}:){3,}[0-9a-f]{0,4}/i;

const isCount = (n) => typeof n === 'number' && Number.isInteger(n) && n >= 0;

function text(value, max, what) {
  if (typeof value !== 'string' || value.length > max || !PRINTABLE.test(value)) {
    throw new Error(`intel-summary: ${what} inválido`);
  }
  if (IPV4.test(value) || IPV6.test(value)) {
    throw new Error(`intel-summary: ${what} parece um endereço IP — só agregados entram neste site`);
  }
  return value;
}

function rows(list, what, mapRow) {
  if (!Array.isArray(list) || list.length > INTEL_MAX_ROWS) {
    throw new Error(`intel-summary: ${what} tem de ser uma lista com até ${INTEL_MAX_ROWS} linhas`);
  }
  const out = list.map(mapRow);
  if (new Set(out.map((r) => r.key)).size !== out.length) {
    throw new Error(`intel-summary: ${what} tem linhas repetidas`);
  }
  return out.sort((a, b) => b.count - a.count).map(({ key, ...row }) => row);
}

/**
 * Valida e normaliza o documento. Lança `Error` (falha o build) se o schema
 * não bater. Devolve `{ …, stale }`: `stale` é verdadeiro quando o resumo tem
 * mais de INTEL_MAX_AGE_DAYS dias em `now` — a página deixa de o mostrar em
 * vez de apresentar uma "última semana" que já não o é.
 */
export function parseIntelSummary(doc, now = Date.now()) {
  if (typeof doc?.generatedAt !== 'string' || !ISO_UTC.test(doc.generatedAt)) {
    throw new Error('intel-summary: generatedAt tem de ser ISO 8601 em UTC (…Z)');
  }
  const generated = Date.parse(doc.generatedAt);
  if (!Number.isFinite(generated) || generated > now + 3_600_000) {
    throw new Error('intel-summary: generatedAt inválido ou no futuro');
  }
  if (!Number.isInteger(doc.windowDays) || doc.windowDays < 1 || doc.windowDays > 31) {
    throw new Error('intel-summary: windowDays tem de estar entre 1 e 31');
  }
  const t = doc.totals;
  if (!isCount(t?.events) || !isCount(t?.sources) || !isCount(t?.sessions)) {
    throw new Error('intel-summary: totals tem de ter events, sources e sessions inteiros ≥ 0');
  }
  const techniques = rows(doc.techniques, 'techniques', (r) => {
    if (typeof r?.id !== 'string' || !TECHNIQUE_ID.test(r.id) || !isCount(r.count)) {
      throw new Error('intel-summary: técnica inválida (id Txxxx[.xxx], count inteiro ≥ 0)');
    }
    return { key: r.id, id: r.id, name: text(r.name, NAME_MAX, 'nome de técnica'), count: r.count };
  });
  const usernames = rows(doc.usernames, 'usernames', (r) => {
    if (!isCount(r?.count)) throw new Error('intel-summary: count de utilizador inválido');
    const name = text(r.name, USER_MAX, 'nome de utilizador');
    return { key: name, name, count: r.count };
  });
  return {
    generatedAt: new Date(generated).toISOString(),
    windowDays: doc.windowDays,
    totals: { events: t.events, sources: t.sources, sessions: t.sessions },
    techniques,
    usernames,
    stale: now - generated > INTEL_MAX_AGE_DAYS * 86_400_000,
  };
}

/** URL da técnica no site do MITRE (id já validado: Txxxx ou Txxxx.xxx). */
export function techniqueUrl(id) {
  const [base, sub] = id.split('.');
  return `https://attack.mitre.org/techniques/${base}/${sub ? `${sub}/` : ''}`;
}
