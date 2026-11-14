/**
 * Painel "O que o sensor viu" (página do projeto Threat Intel) — leitura pura
 * da resposta de /api/intel, sem DOM, testável em Node.
 *
 * O Worker já reduz o history.json do honeypot a agregados
 * (dynamic/worker/src/lib/intel.js). Aqui volta-se a validar o que vai para
 * a página: os ids de técnica entram num href e os nomes de campanha em
 * texto, por isso só passam com o formato exato. Qualquer documento que não
 * seja um resumo válido dá `null` e o painel fica com o texto de build.
 */

const DAY = /^\d{4}-\d{2}-\d{2}$/;
const TECHNIQUE_ID = /^T\d{4}(\.\d{3})?$/;
const CAMPAIGN = /^[a-z0-9][a-z0-9-]{0,31}$/;
// O Worker deixa de servir um dia com mais de 3 dias; a cache à frente dele
// (30 min) e o TTL do KV não mudam isso. Um dia mais antigo aqui é um erro.
export const INTEL_MAX_AGE_MS = 4 * 86_400_000;

const isCount = (n) => typeof n === 'number' && Number.isInteger(n) && n >= 0;
const countOrNull = (n) => (isCount(n) ? n : null);

export function normalizeIntel(doc, now = Date.now()) {
  if (doc?.ok !== true || typeof doc.day !== 'string' || !DAY.test(doc.day) || !isCount(doc.addresses)) return null;
  const dayMs = Date.parse(`${doc.day}T00:00:00Z`);
  if (!Number.isFinite(dayMs) || dayMs > now || now - dayMs > INTEL_MAX_AGE_MS) return null;
  const techniques = (Array.isArray(doc.techniques) ? doc.techniques : [])
    .filter((t) => typeof t?.id === 'string' && TECHNIQUE_ID.test(t.id) && isCount(t.count) && t.count > 0)
    .map((t) => ({ id: t.id, count: t.count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);
  const campaigns = (Array.isArray(doc.campaigns) ? doc.campaigns : [])
    .filter((name) => typeof name === 'string' && CAMPAIGN.test(name))
    .slice(0, 12);
  const delta = Number.isInteger(doc.addressesDelta) && isCount(doc.deltaDays) && doc.deltaDays > 0
    ? { value: doc.addressesDelta, days: doc.deltaDays }
    : null;
  return {
    day: doc.day,
    addresses: doc.addresses,
    delta,
    sessions7d: countOrNull(doc.sessions7d),
    credentialPairs: countOrNull(doc.credentialPairs),
    artifacts: countOrNull(doc.artifacts),
    techniques,
    campaigns,
  };
}

/** URL da técnica no site do MITRE (id já validado: Txxxx ou Txxxx.xxx). */
export function techniqueUrl(id) {
  const [base, sub] = id.split('.');
  return `https://attack.mitre.org/techniques/${base}/${sub ? `${sub}/` : ''}`;
}
