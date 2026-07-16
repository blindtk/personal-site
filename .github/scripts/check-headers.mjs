// Verifica que a produção serve os headers de segurança esperados
// (.github/expected-headers.json) e falha se algum faltar ou regredir.
// Alvo, por ordem de prioridade:
//   1. TARGET_URL  — input manual do workflow_dispatch
//   2. DEPLOY_URL  — environment_url do evento deployment_status (Pages)
//   3. url         — valor versionado no expected-headers.json
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const cfgPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'expected-headers.json');
const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
const target = process.env.TARGET_URL || process.env.DEPLOY_URL || cfg.url;

if (!target || target.startsWith('SET-ME')) {
  console.log('::notice::check-headers: URL de produção por definir em .github/expected-headers.json — verificação ignorada.');
  process.exit(0);
}

console.log(`A verificar ${target}`);
const res = await fetch(target, {
  redirect: 'follow',
  headers: { 'user-agent': 'headers-check (GitHub Actions; personal-site)' },
});
console.log(`HTTP ${res.status}`);
if (!res.ok) {
  console.error(`::error::check-headers: resposta ${res.status} de ${target}`);
  process.exit(1);
}

let failures = 0;
for (const [name, required] of Object.entries(cfg.headers)) {
  const value = res.headers.get(name);
  if (value === null) {
    console.error(`::error::Header em falta: ${name}`);
    failures += 1;
    continue;
  }
  const missing = required.filter((part) => !value.toLowerCase().includes(part.toLowerCase()));
  if (missing.length > 0) {
    console.error(`::error::Header ${name} regrediu — falta ${missing.map((m) => JSON.stringify(m)).join(', ')} (valor atual: ${value})`);
    failures += 1;
  } else {
    console.log(`ok  ${name}: ${value}`);
  }
}

if (failures > 0) {
  console.error(`::error::${failures} header(s) em falta ou regredidos.`);
  process.exit(1);
}
console.log('Todos os headers esperados presentes.');
