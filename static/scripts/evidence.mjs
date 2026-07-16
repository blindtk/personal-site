// Gera dist/evidence.json — as "provas" verificáveis servidas na página
// /provas (EN /en/evidence). É a fonte de verdade dos hashes SHA-256 dos
// scripts inline: lê a união dos hashes de todas as <meta> CSP do build, em
// vez de os escrever à mão (é impossível estarem desatualizados).
//
// Corre depois do `astro build` e antes do `csp-headers.mjs` (ver
// package.json). Não toca em nenhuma <meta> nem no _headers — só escreve um
// ficheiro novo — por isso a derivação da CSP (csp-headers.mjs) e o teste de
// consistência header vs <meta> continuam válidos.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist');

function* htmlFiles(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* htmlFiles(path);
    else if (entry.name.endsWith('.html')) yield path;
  }
}

const META_RE = /<meta http-equiv="content-security-policy" content="([^"]*)"/i;
// Um hash CSP é 'sha256-<base64>' (o base64 inclui + / =). Recolhe todos os
// que aparecem no script-src de qualquer página.
const HASH_RE = /'sha256-[A-Za-z0-9+/=]+'/g;

const hashes = new Set();
let pages = 0;

for (const file of htmlFiles(dist)) {
  const match = readFileSync(file, 'utf8').match(META_RE);
  if (!match) continue;
  pages += 1;
  const scriptSrc = match[1]
    .split(';')
    .map((d) => d.trim())
    .find((d) => d.startsWith('script-src'));
  if (!scriptSrc) continue;
  for (const h of scriptSrc.match(HASH_RE) ?? []) hashes.add(h.slice(1, -1));
}

if (pages === 0) {
  throw new Error('evidence: nenhuma <meta> CSP encontrada em dist/ — mudou o output do Astro?');
}
if (hashes.size === 0) {
  throw new Error('evidence: nenhum hash sha256 em script-src — a CSP mudou de formato?');
}

// Commit atual (best-effort): em CI/Cloudflare há clone git; localmente
// também. Se falhar, o campo fica null e a página degrada com graça.
function gitInfo() {
  try {
    const NUL = String.fromCharCode(0);
    const fmt = execSync('git log -1 --format=%H%x00%h%x00%cI%x00%s', {
      cwd: dist,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    const [full, short, date, subject] = fmt.split(NUL);
    return { full, short, date, subject };
  } catch {
    return null;
  }
}

const evidence = {
  generatedAt: new Date().toISOString(),
  commit: gitInfo(),
  scriptHashes: [...hashes].sort(),
};

writeFileSync(join(dist, 'evidence.json'), JSON.stringify(evidence, null, 2) + '\n');
console.log(`evidence: evidence.json gerado (${hashes.size} hashes de ${pages} páginas).`);
