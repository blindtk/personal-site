// "Experimenta a regra" (projeto Homelab) — lógica pura, sem DOM.
// Decide o que a firewall faz a um pedido entre dois segmentos, a partir da
// política publicada em content/homelab-policy.json: só passa o que tem uma
// regra explícita; o resto é negado por omissão. A cena 3D e a interface
// vivem em src/components/homelab/.

const own = (o, k) => o !== null && typeof o === 'object' && Object.hasOwn(o, k);

/**
 * Problemas de forma na política (lista vazia = válida): ids repetidos ou
 * inválidos, regras que apontam para segmentos que não existem, `default`
 * que não seja "deny". Usado no build e nos testes, para que um erro no JSON
 * falhe alto em vez de mostrar um "passa" errado.
 */
export function policyIssues(policy) {
  const issues = [];
  if (!policy || typeof policy !== 'object') return ['policy is not an object'];
  if (policy.default !== 'deny') issues.push('default must be "deny"');
  const ids = Array.isArray(policy.segments) ? policy.segments.map((s) => s?.id) : [];
  if (ids.length < 2) issues.push('need at least two segments');
  for (const id of ids) {
    if (typeof id !== 'string' || !/^[a-z][a-z0-9-]{0,23}$/.test(id)) issues.push(`bad segment id: ${String(id)}`);
  }
  if (new Set(ids).size !== ids.length) issues.push('duplicate segment id');
  for (const [i, r] of (Array.isArray(policy.rules) ? policy.rules : []).entries()) {
    if (!ids.includes(r?.from)) issues.push(`rule ${i}: unknown from ${String(r?.from)}`);
    if (r?.to !== '*' && !ids.includes(r?.to)) issues.push(`rule ${i}: unknown to ${String(r?.to)}`);
    if (!own(r?.reason, 'pt') || !own(r?.reason, 'en')) issues.push(`rule ${i}: reason needs pt and en`);
  }
  return issues;
}

/**
 * Pedido de `from` para `to` →
 *   { verdict: 'allow', rule }  — há uma regra explícita (a primeira que casa);
 *   { verdict: 'deny', rule: null } — não há: deny all por omissão;
 *   { verdict: 'same' }   — o mesmo segmento (não é um caminho entre segmentos);
 *   { verdict: 'invalid' } — segmento desconhecido ou política inválida.
 * Uma regra com `to: "*"` cobre qualquer destino; `from` nunca é coringa.
 *
 * @returns {{ verdict: 'allow' | 'deny' | 'same' | 'invalid', rule: object | null }}
 */
export function decideFlow(policy, from, to) {
  if (policyIssues(policy).length > 0) return { verdict: 'invalid', rule: null };
  const ids = policy.segments.map((s) => s.id);
  if (!ids.includes(from) || !ids.includes(to)) return { verdict: 'invalid', rule: null };
  if (from === to) return { verdict: 'same', rule: null };
  const rule = (policy.rules ?? []).find((r) => r.from === from && (r.to === '*' || r.to === to)) ?? null;
  return rule ? { verdict: 'allow', rule } : { verdict: 'deny', rule: null };
}
