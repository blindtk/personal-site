// node scripts/hf.mjs <comando> [args…] — corre a CLI do HyperFrames (a
// versão fixada no package.json) em cada filme, com o ambiente de env.mjs.
// Ex.: node scripts/hf.mjs check   ·   node scripts/hf.mjs snapshot --at 10
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { FILMS, hfEnv } from './env.mjs';

const bin = fileURLToPath(new URL('../node_modules/.bin/hyperframes', import.meta.url));
let failed = false;
for (const film of FILMS) {
  const cwd = fileURLToPath(new URL(`../films/${film}/`, import.meta.url));
  console.log(`\n== ${film}`);
  const r = spawnSync(bin, process.argv.slice(2), { cwd, env: hfEnv(), stdio: 'inherit' });
  if (r.status !== 0) failed = true;
}
process.exit(failed ? 1 : 0);
