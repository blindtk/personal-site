// Gera a Content-Security-Policy como *header* real em dist/_headers, a
// partir das <meta http-equiv> que o Astro emite por página no build.
//
// Porquê duas camadas:
//   1) a <meta> por página é estrita (só os hashes daquela página) e viaja
//      dentro do HTML — portável para qualquer servidor;
//   2) o header é a união dos hashes de todas as páginas + frame-ancestors
//      (diretiva inválida em <meta>) — e é a única camada que scanners
//      externos (securityheaders.com, Observatory) conseguem ver.
// O browser aplica a interseção das duas: por página continua a valer a
// política estrita da <meta>.
//
// Corre como parte de `npm run build` (ver package.json). Falha alto se o
// formato do build mudar — antes falhar que publicar sem CSP no header.
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
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
const directives = new Map();
let pages = 0;

for (const file of htmlFiles(dist)) {
  const match = readFileSync(file, 'utf8').match(META_RE);
  if (!match) continue;
  pages += 1;
  for (const directive of match[1].split(';')) {
    const [name, ...values] = directive.trim().split(/\s+/).filter(Boolean);
    if (!name) continue;
    const set = directives.get(name) ?? new Set();
    for (const value of values) set.add(value);
    directives.set(name, set);
  }
}

if (pages === 0) {
  throw new Error('csp-headers: nenhuma <meta> CSP encontrada em dist/ — mudou o output do Astro?');
}

// Só é válida em header (nunca em <meta>): anti-clickjacking a sério, a par
// do X-Frame-Options que já vai no _headers para browsers antigos.
directives.set('frame-ancestors', new Set(["'none'"]));

// Reporting de violações — também header-only (o browser ignora estas
// diretivas numa <meta>). report-uri é o mecanismo legado (Firefox/Safari);
// report-to aponta para o nome declarado em Reporting-Endpoints no
// public/_headers (Chrome). O recetor é o Worker (dynamic/worker/).
directives.set('report-uri', new Set(['/api/csp-report']));
directives.set('report-to', new Set(['csp-endpoint']));

const ORDER = [
  'default-src', 'script-src', 'style-src', 'img-src', 'font-src',
  'connect-src', 'object-src', 'frame-src', 'worker-src', 'base-uri',
  'form-action', 'frame-ancestors', 'require-trusted-types-for', 'trusted-types',
  'report-uri', 'report-to',
];
const names = [
  ...ORDER.filter((n) => directives.has(n)),
  ...[...directives.keys()].filter((n) => !ORDER.includes(n)),
];
const csp = names
  .map((n) => [n, ...[...directives.get(n)].sort()].join(' '))
  .join('; ');

const headersPath = join(dist, '_headers');
const original = readFileSync(headersPath, 'utf8');
if (original.includes('Content-Security-Policy:')) {
  throw new Error('csp-headers: dist/_headers já contém CSP — não a ponhas em public/_headers, é gerada aqui.');
}
const updated = original.replace(/^\/\*$/m, () => `/*\n  Content-Security-Policy: ${csp}`);
if (updated === original) {
  throw new Error('csp-headers: bloco "/*" não encontrado em dist/_headers.');
}
writeFileSync(headersPath, updated);
console.log(
  `csp-headers: header gerada a partir de ${pages} páginas ` +
  `(${directives.get('script-src')?.size ?? 0} fontes em script-src).`
);
