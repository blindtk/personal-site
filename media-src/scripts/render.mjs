// Renderiza os filmes e escreve os ficheiros finais em static/public/video/:
//   <film>.mp4  — H.264, yuv420p, sem áudio, faststart (todos os browsers)
//   <film>.webp — poster: o frame que já resume o diagrama (POSTER_AT)
// Sem WebM/AV1: neste conteúdo (formas planas sobre fundo escuro) o AV1 saía
// do mesmo tamanho que o H.264 (~200 KB por minuto), por isso um MP4 chega.
// Precisa de Node 22+, FFmpeg com libx264 e libwebp, e um Chrome.
// Nunca corre no CI do site (ver README.md).
import { spawnSync } from 'node:child_process';
import { mkdirSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { FILMS, hfEnv } from './env.mjs';

const at = (p) => fileURLToPath(new URL(`../${p}`, import.meta.url));
const bin = at('node_modules/.bin/hyperframes');
const outDir = at('../static/public/video');
mkdirSync(at('out'), { recursive: true });
mkdirSync(outDir, { recursive: true });

// Segundo do frame usado como poster: o diagrama completo, legível parado.
const POSTER_AT = { 'honeypot-pipeline': 46, 'ci-pipeline': 14.5 };

const run = (cmd, args, opts = {}) => {
  const r = spawnSync(cmd, args, { stdio: 'inherit', ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} → ${r.status}`);
};
const only = process.argv.slice(2);
for (const film of FILMS.filter((f) => only.length === 0 || only.includes(f))) {
  const master = at(`out/${film}.mp4`);
  run(bin, ['render', '-q', 'delivery', '--crf', '12', '-o', master], { cwd: at(`films/${film}`), env: hfEnv() });
  run('ffmpeg', ['-y', '-v', 'error', '-i', master, '-an', '-c:v', 'libx264', '-preset', 'slow', '-crf', '27',
    '-pix_fmt', 'yuv420p', '-movflags', '+faststart', `${outDir}/${film}.mp4`]);
  run('ffmpeg', ['-y', '-v', 'error', '-ss', String(POSTER_AT[film]), '-i', master, '-frames:v', '1',
    '-c:v', 'libwebp', '-quality', '80', `${outDir}/${film}.webp`]);
  for (const ext of ['mp4', 'webp']) {
    console.log(`${film}.${ext}: ${(statSync(`${outDir}/${film}.${ext}`).size / 1024).toFixed(0)} KB`);
  }
}
