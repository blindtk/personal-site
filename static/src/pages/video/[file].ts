// /video/<filme>.<pt|en>.vtt — as legendas dos vídeos, servidas como ficheiro
// estático a partir de content/video/{pt,en}/<filme>.vtt (o texto editorial
// vive em content/, não em public/). Gerado no build; validado com parseVtt,
// por isso uma legenda malformada parte o build.
import type { APIRoute } from 'astro';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseVtt } from '../../scripts/vtt.js';

const dir = (lang: string) => fileURLToPath(new URL(`../../../../content/video/${lang}/`, import.meta.url));

export function getStaticPaths() {
  return ['pt', 'en'].flatMap((lang) =>
    readdirSync(dir(lang))
      .filter((f) => f.endsWith('.vtt'))
      .map((f) => {
        const text = readFileSync(`${dir(lang)}${f}`, 'utf8');
        parseVtt(text);
        return { params: { file: `${f.slice(0, -4)}.${lang}.vtt` }, props: { text } };
      }),
  );
}

export const GET: APIRoute = ({ props }) =>
  new Response(props.text as string, { headers: { 'content-type': 'text/vtt; charset=utf-8' } });
