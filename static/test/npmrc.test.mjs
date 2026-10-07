import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// O build do Cloudflare Pages corre o seu próprio `npm clean-install` antes do
// comando de build; é este ficheiro que impede os scripts de instalação das
// dependências (esbuild) de correrem aí. Apagá-lo reativa-os sem dar sinal.
test('static/.npmrc desativa os scripts de ciclo de vida das dependências', () => {
  const rc = readFileSync(new URL('../.npmrc', import.meta.url), 'utf8');
  const active = rc.split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  assert.ok(active.includes('ignore-scripts=true'), active.join(' | '));
});
