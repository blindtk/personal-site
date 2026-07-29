// Regressão do controlo de segurança mais frágil do site: a CSP de
// public/_headers contra o HTML REALMENTE construído em dist/.
//
// Porquê este teste existe (2026-07, revisão de segurança — ronda 4): o
// `_headers` traz um hash SHA-256 do único <script> inline do site (o bloco
// JSON-LD do BaseLayout). Esse hash é escrito À MÃO e o conteúdo do bloco vem
// de src/config.ts — logo, qualquer alteração a SITE.name/role/url/redes
// invalida-o em silêncio. Foi exatamente o que aconteceu: o commit 3461d70
// ("Drop 'Assis' from displayed name") mudou SITE.name e ninguém recalculou o
// hash — a CSP passou a bloquear o JSON-LD em TODAS as páginas, em produção,
// durante dias, sem que nada falhasse.
//
// Nenhum controlo existente apanhava isto:
//   · o check-headers.mjs compara substrings ("script-src" está lá, o hash
//     errado passa) e, além disso, nunca chegou a correr contra produção;
//   · o csp-lint.test.mjs testa a FERRAMENTA de análise de CSP (/ferramentas/),
//     não a política do próprio site;
//   · o `astro check`/build não sabem nada de CSP.
//
// Cobre também o segundo lever da arquitetura (astro.config.mjs): "zero
// <script> inline executável". Se uma atualização do Astro voltar a inlinar
// scripts hoisted, aparece aqui um bloco inline sem `type="application/ld+json"`
// e o teste falha — em vez de os painéis partirem em silêncio em produção.
//
// Requer `npm run build` antes (o ci.yml corre build antes de test).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const distDir = join(root, 'dist');

/** Todos os .html de dist/, recursivamente. */
function htmlFiles(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...htmlFiles(full));
    else if (entry.name.endsWith('.html')) out.push(full);
  }
  return out;
}

/**
 * Blocos <script> inline (sem src) de um HTML. Os comentários HTML são
 * removidos primeiro: o BaseLayout tem um comentário que CONTÉM um
 * `<script src=…>` de exemplo, e sem isto ele seria lido como bloco inline.
 */
function inlineScripts(html) {
  const semComentarios = html.replace(/<!--[\s\S]*?-->/g, '');
  return [...semComentarios.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)]
    .filter((m) => !/\ssrc=/i.test(m[1]))
    .map((m) => ({ attrs: m[1].trim(), body: m[2] }));
}

const cspHash = (body) => `sha256-${createHash('sha256').update(body, 'utf8').digest('base64')}`;

const headers = readFileSync(join(root, 'public', '_headers'), 'utf8');
const csp = headers.match(/^\s*Content-Security-Policy:\s*(.+)$/m)?.[1] ?? '';

test('dist/ existe (este teste corre depois do build)', () => {
  assert.ok(
    existsSync(distDir),
    'dist/ não existe — corre `npm run build` antes de `npm test` (é a ordem do ci.yml).',
  );
});

test('a CSP do _headers autoriza TODOS os scripts inline construídos', () => {
  const ficheiros = htmlFiles(distDir);
  assert.ok(ficheiros.length > 0, 'nenhum .html em dist/');

  const emFalta = new Map(); // hash -> { attrs, exemplo, nFicheiros }
  for (const f of ficheiros) {
    for (const { attrs, body } of inlineScripts(readFileSync(f, 'utf8'))) {
      const hash = cspHash(body);
      if (csp.includes(hash)) continue;
      const registo = emFalta.get(hash) ?? { attrs, exemplo: body.slice(0, 120), nFicheiros: 0 };
      registo.nFicheiros += 1;
      emFalta.set(hash, registo);
    }
  }

  assert.deepEqual(
    [...emFalta.keys()],
    [],
    `Script(s) inline sem hash autorizado na CSP — seriam BLOQUEADOS em produção:\n${[...emFalta]
      .map(([h, r]) => `  ${h}  (${r.nFicheiros} páginas, attrs=[${r.attrs}])\n    início: ${r.exemplo}`)
      .join('\n')}\nCorrige o hash em static/public/_headers (e em docs/security-headers.md).`,
  );
});

test('o lever "zero inline executável" continua de pé: só JSON-LD é inline', () => {
  const executaveis = [];
  for (const f of htmlFiles(distDir)) {
    for (const { attrs } of inlineScripts(readFileSync(f, 'utf8'))) {
      if (!/type\s*=\s*["']application\/ld\+json["']/i.test(attrs)) {
        executaveis.push(`${f.replace(root, '.')}  attrs=[${attrs}]`);
      }
    }
  }
  assert.deepEqual(
    executaveis,
    [],
    `<script> inline executável no build — os levers de astro.config.mjs\n(build.inlineStylesheets:'never' + vite.build.assetsInlineLimit:0) deixaram\nde garantir "zero inline":\n${executaveis.join('\n')}`,
  );
});

test('a CSP não regrediu para unsafe-inline/unsafe-eval em script-src', () => {
  const scriptSrc = csp.match(/script-src([^;]*)/)?.[1] ?? '';
  assert.ok(!scriptSrc.includes("'unsafe-inline'"), "script-src ganhou 'unsafe-inline'");
  assert.ok(!scriptSrc.includes("'unsafe-eval'"), "script-src ganhou 'unsafe-eval'");
});
