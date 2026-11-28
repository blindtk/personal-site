// Prepara os filmes antes de um check ou render. Tudo o que o vídeo afirma
// vem do repositório, não de texto escrito à mão:
//   1. tokens.css — o bloco :root de static/src/styles/global.css (as cores
//      do site), copiado para assets/ de cada filme.
//   2. gsap.min.js — do node_modules (versão fixada), nunca de uma CDN.
//   3. ci-pipeline: as faixas de workflows geradas a partir de
//      .github/workflows/*.yml (as que correm em pull_request e as que correm
//      depois do deploy, por check_run), escritas entre marcadores no
//      index.html — o diff mostra quando a lista muda.
import { readFileSync, writeFileSync, readdirSync, copyFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { FILMS } from './env.mjs';

const at = (p) => fileURLToPath(new URL(`../${p}`, import.meta.url));

// 1 + 2
const css = readFileSync(at('../static/src/styles/global.css'), 'utf8');
const root = /:root\s*\{[\s\S]*?\n\}/.exec(css);
if (!root) throw new Error('global.css: bloco :root não encontrado');
const tokens = `/* Gerado por scripts/prepare.mjs a partir de static/src/styles/global.css. Não editar. */\n${root[0]}\n`;
for (const film of FILMS) {
  writeFileSync(at(`films/${film}/assets/tokens.css`), tokens);
  copyFileSync(at('node_modules/gsap/dist/gsap.min.js'), at(`films/${film}/assets/gsap.min.js`));
}

// 3. Gatilhos de nível superior de cada workflow (o bloco `on:`).
function triggers(yml) {
  const lines = yml.split('\n');
  const start = lines.findIndex((l) => /^on:\s*$/.test(l));
  if (start < 0) return [];
  const out = [];
  for (const l of lines.slice(start + 1)) {
    if (/^\S/.test(l)) break;
    const m = /^ {2}([a-z_]+):/.exec(l);
    if (m) out.push(m[1]);
  }
  return out;
}
const dir = at('../.github/workflows');
const wfs = readdirSync(dir).filter((f) => f.endsWith('.yml')).sort()
  .map((f) => ({ name: f.replace(/\.yml$/, ''), on: triggers(readFileSync(`${dir}/${f}`, 'utf8')) }));
const onPr = wfs.filter((w) => w.on.includes('pull_request')).map((w) => w.name);
const afterDeploy = wfs.filter((w) => w.on.includes('check_run')).map((w) => w.name);
if (onPr.length === 0 || afterDeploy.length === 0) throw new Error('workflows: lista vazia — o parser falhou?');

const esc = (s) => s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
const lanes = onPr.map((name, i) => `        <div class="lane" id="lane-${i}"><span class="lane-name">${esc(name)}</span><span class="bar"><span class="fill" id="fill-${i}"></span></span><span class="ok" id="ok-${i}">✓</span></div>`).join('\n');
const verifies = afterDeploy.map((name, i) => `        <div class="pill verify" id="verify-${i}"><span class="ok">✓</span> ${esc(name)}</div>`).join('\n');

const file = at('films/ci-pipeline/index.html');
let html = readFileSync(file, 'utf8');
const put = (tag, body) => {
  const re = new RegExp(`(<!-- ${tag}:start -->)[\\s\\S]*?(\\s*<!-- ${tag}:end -->)`);
  if (!re.test(html)) throw new Error(`ci-pipeline/index.html: marcadores ${tag} em falta`);
  html = html.replace(re, `$1\n${body}$2`);
};
put('lanes', lanes);
put('verifies', verifies);
html = html.replace(/data-lanes="\d+"/, `data-lanes="${onPr.length}"`).replace(/data-verifies="\d+"/, `data-verifies="${afterDeploy.length}"`);
writeFileSync(file, html);
console.log(`prepare: tokens + gsap em ${FILMS.length} filmes; ${onPr.length} workflows em PR (${onPr.join(', ')}); ${afterDeploy.length} depois do deploy (${afterDeploy.join(', ')})`);
