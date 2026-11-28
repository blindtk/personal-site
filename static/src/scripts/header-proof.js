// "curl -sI" ao vivo nas Provas (/este-site/provas/#h-headers) — lógica pura.
// Recebe os cabeçalhos que o browser obteve num HEAD à própria página e
// devolve as linhas a mostrar, cada uma marcada contra o contrato de
// .github/expected-headers.json com a mesma regra do workflow verify-headers
// (checkHeaders, em request-path.js). O DOM vive em HeaderProof.astro.
import { checkHeaders } from './request-path.js';

/**
 * `entries`: pares [nome, valor] (Headers#entries — nomes já em minúsculas,
 * por ordem alfabética). Devolve:
 *   lines   — uma por cabeçalho recebido, por ordem de nome, com `status`
 *             'ok' | 'bad' (do contrato) ou null (fora do contrato); no fim,
 *             uma linha 'absent' (valor null) por cada cabeçalho do contrato
 *             que não veio.
 *   present / total — quantos cabeçalhos do contrato cumprem.
 * Entradas que não sejam pares de strings são ignoradas; um nome repetido
 * fica com o primeiro valor (Headers já junta repetidos com ", ").
 */
export function headerLines(entries, contract) {
  const received = new Map();
  for (const pair of entries ?? []) {
    if (!Array.isArray(pair) || typeof pair[0] !== 'string' || typeof pair[1] !== 'string') continue;
    const name = pair[0].trim().toLowerCase();
    if (name && !received.has(name)) received.set(name, pair[1]);
  }
  const { present, total, rows } = checkHeaders((n) => received.get(n.toLowerCase()) ?? null, contract);
  const byName = new Map(rows.map((r) => [r.name.toLowerCase(), r]));
  const lines = [...received.keys()].sort().map((name) => {
    const row = byName.get(name);
    return { name, value: received.get(name), status: row ? (row.ok ? 'ok' : 'bad') : null, missing: row?.missing ?? [] };
  });
  for (const row of rows) {
    if (row.absent) lines.push({ name: row.name.toLowerCase(), value: null, status: 'absent', missing: row.missing });
  }
  return { lines, present, total };
}
