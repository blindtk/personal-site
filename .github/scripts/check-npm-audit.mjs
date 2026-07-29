// Gate de `npm audit` com exceções justificadas e datadas. O npm audit não
// tem mecanismo de exceção próprio (ao contrário do osv-scanner.toml, que já
// cobre isto para o OSV-Scanner) — sem isto, um único falso positivo (já
// aconteceu: GHSA-hpcx-pg6g-x697/MAL-2026-10726, astro 7.1.0) bloqueia
// qualquer PR indefinidamente, sem forma declarativa de o ignorar.
//
// Uso: node check-npm-audit.mjs <diretório-com-package.json>
// Corre `npm audit --json` nesse diretório e falha em qualquer advisory
// high/critical que não esteja em .github/npm-audit-allowlist.json (ou cuja
// entrada tenha expirado — força revisão periódica, mesmo padrão do
// osv-scanner.toml).
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const pkgDir = process.argv[2];
if (!pkgDir) {
  console.error('uso: check-npm-audit.mjs <diretório-do-package.json>');
  process.exit(1);
}

const allowlistPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'npm-audit-allowlist.json');
const { ignored } = JSON.parse(readFileSync(allowlistPath, 'utf8'));
const today = new Date().toISOString().slice(0, 10);

let report;
try {
  const out = execFileSync('npm', ['audit', '--json'], { cwd: pkgDir, encoding: 'utf8' });
  report = JSON.parse(out);
} catch (err) {
  // npm audit sai !=0 quando há vulnerabilidades — o que interessa é o
  // stdout (JSON), não o código de saída.
  if (!err.stdout) throw err;
  report = JSON.parse(err.stdout);
}

const failures = [];
for (const vuln of Object.values(report.vulnerabilities ?? {})) {
  if (vuln.severity !== 'high' && vuln.severity !== 'critical') continue;
  for (const via of vuln.via) {
    // `via` mistura strings (nome de outro pacote, vulnerabilidade herdada —
    // já reportada no seu próprio bloco top-level) com objetos (o advisory
    // concreto, com url). Só os objetos têm um GHSA ID para verificar aqui.
    if (typeof via !== 'object' || !via.url) continue;
    const ghsaId = via.url.split('/').pop();
    const allow = ignored.find((i) => i.ghsaId === ghsaId);
    if (allow && allow.ignoreUntil >= today) {
      console.log(`::notice::${pkgDir}: ignorado (allowlist até ${allow.ignoreUntil}) ${ghsaId} em ${vuln.name} — ${allow.reason}`);
      continue;
    }
    if (allow) {
      console.error(`::error::${pkgDir}: exceção EXPIRADA (${allow.ignoreUntil}) para ${ghsaId} em ${vuln.name} — rever .github/npm-audit-allowlist.json`);
    } else {
      console.error(`::error::${pkgDir}: ${vuln.severity} em ${vuln.name}: ${via.title} (${via.url})`);
    }
    failures.push(ghsaId);
  }
}

if (failures.length > 0) {
  console.error(`${pkgDir}: ${failures.length} advisory(s) high/critical não coberta(s) pela allowlist.`);
  process.exit(1);
}
console.log(`${pkgDir}: npm audit ok (sem advisories high/critical fora da allowlist).`);
