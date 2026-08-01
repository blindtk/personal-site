// Self-scan: em vez de raspar HTML de terceiros, o Worker busca o próprio
// site e inspeciona os cabeçalhos de segurança que ele devolve — é a mesma
// informação que o securityheaders.com avalia, mas de fonte fiável. A nota
// por letra é derivada da cobertura. gradeFromHeaders é puro e testável;
// os links para os scanners externos continuam a ser oferecidos à parte.

/**
 * Cabeçalhos avaliados e o seu peso. Alinhado com o que o site serve
 * (ver static/public/_headers).
 */
export const SECURITY_HEADERS = [
  { name: 'content-security-policy', weight: 3 },
  { name: 'strict-transport-security', weight: 2 },
  { name: 'x-frame-options', weight: 1 },
  { name: 'x-content-type-options', weight: 1 },
  { name: 'referrer-policy', weight: 1 },
  { name: 'permissions-policy', weight: 1 },
  { name: 'cross-origin-opener-policy', weight: 1 },
  { name: 'cross-origin-resource-policy', weight: 1 },
  { name: 'cross-origin-embedder-policy', weight: 1 },
];

function letter(ratio) {
  if (ratio >= 1) return 'A+';
  if (ratio >= 0.9) return 'A';
  if (ratio >= 0.75) return 'B';
  if (ratio >= 0.6) return 'C';
  if (ratio >= 0.4) return 'D';
  if (ratio > 0) return 'E';
  return 'F';
}

/**
 * Recebe um getter get(name)->value|null (case-insensitive à responsabilidade
 * do chamador) e devolve { grade, score, max, checklist }.
 */
export function gradeFromHeaders(get) {
  let score = 0;
  let max = 0;
  const checklist = SECURITY_HEADERS.map(({ name, weight }) => {
    max += weight;
    const value = get(name);
    const present = typeof value === 'string' && value.length > 0;
    if (present) score += weight;
    return { name, present, value: present ? value : null };
  });
  return { grade: letter(score / max), score, max, checklist };
}
