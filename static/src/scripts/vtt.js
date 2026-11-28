// Legendas WebVTT dos vídeos (content/video/{pt,en}/*.vtt) — lógica pura.
// O mesmo ficheiro serve três coisas: a faixa <track> do vídeo, a
// transcrição em texto na página e os testes que garantem que PT e EN
// estão sincronizados.

const TIME = /^(?:(\d{2,}):)?(\d{2}):(\d{2})\.(\d{3})$/;

/** "00:01:02.500" ou "01:02.500" → segundos; formato inválido → null. */
export function vttTime(s) {
  const m = TIME.exec(typeof s === 'string' ? s.trim() : '');
  if (!m) return null;
  const [, h = '0', mi, se, ms] = m;
  if (Number(mi) > 59 || Number(se) > 59) return null;
  return Number(h) * 3600 + Number(mi) * 60 + Number(se) + Number(ms) / 1000;
}

/**
 * Texto WebVTT → [{ start, end, text }]. Só o necessário para estes
 * ficheiros: cabeçalho WEBVTT, blocos separados por linha vazia, um
 * identificador opcional, a linha de tempos (definições de posição depois
 * dos tempos são ignoradas) e o texto (linhas juntas por espaço). Lança um
 * erro em vez de devolver cues truncadas: um ficheiro malformado deve
 * partir o build, não aparecer meio vazio no site.
 */
export function parseVtt(text) {
  if (typeof text !== 'string') throw new Error('vtt: not a string');
  const blocks = text.replace(/\r\n?/g, '\n').trim().split(/\n{2,}/);
  if (!/^WEBVTT(?:[ \t].*)?$/.test(blocks[0].split('\n')[0])) throw new Error('vtt: missing WEBVTT header');
  const cues = [];
  for (const block of blocks.slice(1)) {
    const lines = block.split('\n');
    if (/^NOTE(?:\s|$)/.test(lines[0])) continue;
    const i = lines.findIndex((l) => l.includes('-->'));
    if (i < 0 || i > 1) throw new Error(`vtt: cue without timing: ${lines[0]}`);
    const [a, rest] = lines[i].split('-->');
    const start = vttTime(a);
    const end = vttTime(rest.trim().split(/\s+/)[0]);
    if (start === null || end === null || end <= start) throw new Error(`vtt: bad timing: ${lines[i]}`);
    if (cues.length && start < cues[cues.length - 1].end) throw new Error(`vtt: overlapping cue at ${lines[i]}`);
    const body = lines.slice(i + 1).join(' ').trim();
    if (!body) throw new Error(`vtt: empty cue at ${lines[i]}`);
    cues.push({ start, end, text: body });
  }
  if (cues.length === 0) throw new Error('vtt: no cues');
  return cues;
}

/** Segundos → "0:07" / "1:02" para a transcrição. */
export function clock(seconds) {
  const s = Math.floor(seconds);
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}
