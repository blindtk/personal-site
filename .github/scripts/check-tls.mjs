// Avalia o JSON produzido pelo testssl.sh (--jsonfile, formato "flat" — ver
// tls-check.yml) e classifica cada achado pela severidade que o próprio
// testssl.sh já atribui (CRITICAL/HIGH/MEDIUM/LOW/WARN/INFO/OK), em vez de
// reinventar heurísticas de "o que é grave": CRITICAL/HIGH (grade F,
// protocolos obsoletos ainda aceites, vulnerabilidades conhecidas tipo
// Heartbleed/POODLE/ROBOT, certificado inválido/expirado) viram ::error::
// e falham o job; MEDIUM/LOW (preferência de cifras, detalhes sem risco
// direto) viram ::warning::; INFO/OK/DEBUG só aparecem no log. Mesmo padrão
// hard/soft de check-invariants.mjs, aqui por severidade em vez de contagem.
import { readFileSync } from 'node:fs';

const jsonPath = process.argv[2];
if (!jsonPath) {
  console.error('::error::check-tls: uso: node check-tls.mjs <caminho-para-testssl.json>');
  process.exit(1);
}

let findings;
try {
  const raw = readFileSync(jsonPath, 'utf8');
  findings = JSON.parse(raw);
  if (!Array.isArray(findings)) throw new Error('esperava um array (formato --jsonfile "flat")');
} catch (err) {
  console.error(`::error::check-tls: não consegui ler/parsear ${jsonPath} — ${err?.message ?? err}`);
  process.exit(1);
}

const HARD = new Set(['CRITICAL', 'HIGH']);
const SOFT = new Set(['MEDIUM', 'LOW', 'WARN']);

let hardFailures = 0;
let softFailures = 0;

for (const f of findings) {
  const severity = String(f.severity ?? '').toUpperCase();
  const label = `${f.id ?? '?'}: ${f.finding ?? ''}${f.cve ? ` (${f.cve})` : ''}`;
  if (HARD.has(severity)) {
    console.error(`::error::[${severity}] ${label}`);
    hardFailures += 1;
  } else if (SOFT.has(severity)) {
    console.log(`::warning::[${severity}] ${label}`);
    softFailures += 1;
  } else if (severity && severity !== 'OK' && severity !== 'INFO' && severity !== 'DEBUG') {
    // severidade nova/desconhecida do testssl.sh — não descartar em silêncio
    console.log(`::warning::[severidade desconhecida "${severity}"] ${label}`);
    softFailures += 1;
  }
}

console.log('');
console.log(`${findings.length} achado(s) no total — ${hardFailures} crítico(s)/alto(s), ${softFailures} médio(s)/baixo(s).`);
if (hardFailures > 0) {
  console.error(`::error::${hardFailures} achado(s) CRITICAL/HIGH do testssl.sh.`);
  process.exit(1);
}
console.log('Nenhum achado CRITICAL/HIGH.');
