// Garante que a CSP servida como *header* (dist/_headers) e a que viaja em
// cada <meta http-equiv> não divergem. Corre sobre o build local no ci.yml,
// logo a seguir a `npm run build`, e falha se as duas camadas deixarem de
// coincidir — a rede de segurança contra alguém editar uma e esquecer a outra.
//
// Invariante testada (o header é DERIVADO das <meta> por scripts/csp-headers.mjs):
//   1. Os nomes de diretiva do header == (união dos nomes das <meta>) + frame-ancestors.
//   2. Para cada <meta>, os valores de cada diretiva são um subconjunto dos
//      valores da mesma diretiva no header (o header é a união de todas as páginas).
//   3. frame-ancestors existe só no header (inválida em <meta>); nenhuma outra
//      diretiva pode existir num sítio e faltar no outro.
import { readdirSync, readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const dist = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'static', 'dist');

// Diretivas válidas em header mas nunca em <meta> — o browser ignora-as na
// <meta>, por isso o csp-headers.mjs só as põe no header. Não são divergência.
const HEADER_ONLY = new Set(['frame-ancestors']);

const META_RE = /<meta http-equiv="content-security-policy" content="([^"]*)"/i;
const HEADER_RE = /^\s*Content-Security-Policy:\s*(.+)$/im;

/** "a 'self' x; b y" -> Map { a => Set{'self',x}, b => Set{y} } */
function parse(csp) {
  const map = new Map();
  for (const directive of csp.split(';')) {
    const [name, ...values] = directive.trim().split(/\s+/).filter(Boolean);
    if (name) map.set(name.toLowerCase(), new Set(values));
  }
  return map;
}

function* htmlFiles(dir) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* htmlFiles(path);
    else if (entry.name.endsWith('.html')) yield path;
  }
}

const headersFile = readFileSync(join(dist, '_headers'), 'utf8');
const headerMatch = headersFile.match(HEADER_RE);
if (!headerMatch) {
  console.error('::error::check-csp-consistency: sem Content-Security-Policy em dist/_headers.');
  process.exit(1);
}
const header = parse(headerMatch[1]);

const errors = [];
let pages = 0;

for (const file of htmlFiles(dist)) {
  const match = readFileSync(file, 'utf8').match(META_RE);
  if (!match) continue;
  pages += 1;
  const rel = file.slice(dist.length + 1);
  const meta = parse(match[1]);

  for (const [name, values] of meta) {
    if (HEADER_ONLY.has(name)) {
      errors.push(`${rel}: diretiva ${name} não devia estar na <meta> (só no header).`);
      continue;
    }
    if (!header.has(name)) {
      errors.push(`${rel}: <meta> tem "${name}" mas o header não.`);
      continue;
    }
    const hv = header.get(name);
    for (const v of values) {
      if (!hv.has(v)) errors.push(`${rel}: header falta ${JSON.stringify(v)} em "${name}" (presente na <meta>).`);
    }
  }
}

if (pages === 0) {
  console.error('::error::check-csp-consistency: nenhuma <meta> CSP em dist/ — build vazio?');
  process.exit(1);
}

// O header não pode ter diretivas a mais além das <meta> (só as HEADER_ONLY).
const allMetaNames = new Set();
for (const file of htmlFiles(dist)) {
  const match = readFileSync(file, 'utf8').match(META_RE);
  if (match) for (const name of parse(match[1]).keys()) allMetaNames.add(name);
}
for (const name of header.keys()) {
  if (!allMetaNames.has(name) && !HEADER_ONLY.has(name)) {
    errors.push(`header tem "${name}" que não aparece em nenhuma <meta> nem é header-only.`);
  }
}
for (const name of HEADER_ONLY) {
  if (!header.has(name)) errors.push(`header não tem a diretiva header-only "${name}".`);
}

if (errors.length > 0) {
  for (const e of errors) console.error(`::error::${e}`);
  console.error(`::error::check-csp-consistency: ${errors.length} divergência(s) header vs <meta>.`);
  process.exit(1);
}
console.log(`check-csp-consistency: header e <meta> coincidem em ${pages} páginas.`);
