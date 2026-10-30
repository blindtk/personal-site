// Desenho do globo de ataques em canvas 2D — só a ligação ao DOM; a
// matemática (projeção, arcos, espessura) está em scripts/attack-globe.js.
// Importado de forma lazy pela AttackMapPage (import() quando o canvas se
// aproxima do ecrã), por isso este módulo e o JSON geográfico ficam num
// chunk que só esta página descarrega.
import geo from '../../data/attack-map-geo.json';
import {
  landDots, toVec, rotate, isHidden, arcPoints, sqrtScale, globeShapes, bubbleShapes,
} from '../../scripts/attack-globe.js';

type Vec = [number, number, number];
type Pair = [string, string, number];

/**
 * O que desenhar: `pairs` (Radar: arcos origem → alvo, mundo) ou
 * `countries` (firewall deste site: bolhas nos países de origem).
 */
export interface GlobeData {
  pairs?: Pair[];
  countries?: { country: string; action: string; count: number; total?: number }[];
}

const DEG = Math.PI / 180;
const SPIN = 0.00012; // rad/ms — uma volta em ~50 s
const ARC_SEGMENTS = 40;

export interface GlobeController {
  setPlaying(playing: boolean): void;
  destroy(): void;
}

export function mountGlobe(canvas: HTMLCanvasElement, data: GlobeData, { playing: initial }: { playing: boolean }): GlobeController | null {
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;

  // Cores das variáveis CSS (global.css), nunca literais.
  const css = getComputedStyle(document.documentElement);
  const v = (name: string) => css.getPropertyValue(name).trim();
  const color = {
    sphere: v('--bg-raise'),
    rim: v('--border-strong'),
    land: v('--faint'),
    origin: v('--accent-2'),
    target: v('--accent'),
    // bolhas: a mesma leitura de cores da página Cloudflare
    blocked: v('--danger'),
    challenged: v('--accent-2'),
    allowed: v('--accent'),
  };

  const land = landDots(geo).map(([lat, lon]: number[]) => toVec(lat, lon) as Vec);
  const pairs = data.pairs ?? [];
  const { arcs, rings } = globeShapes(pairs, geo.centroids);
  const maxPct = pairs.reduce((m, p) => Math.max(m, p[2]), 0);
  const lineWidth = (pct: number) => sqrtScale(pct, maxPct, { min: 0.75, max: 5 });
  const arcGeo = arcs
    .map((a) => ({
      pts: arcPoints(a.from, a.to, ARC_SEGMENTS) as Vec[],
      width: lineWidth(a.pct),
      // fase própria por arco, para os "cometas" não andarem em uníssono
      phase: (a.pct * 7.31) % 1,
    }))
    .filter((a) => a.pts.length > 0);
  const ringGeo = rings.map((r) => ({ at: toVec(r.at[0], r.at[1]) as Vec, width: lineWidth(r.pct) }));
  const bubbles = bubbleShapes(data.countries ?? [], geo.centroids);
  const maxCount = bubbles.reduce((m, b) => Math.max(m, b.count), 0);
  // Raio em fração do raio do globo, para escalar com o canvas.
  const bubbleGeo = bubbles.map((b) => ({
    at: toVec(b.at[0], b.at[1]) as Vec,
    r: sqrtScale(b.count, maxCount, { min: 0.015, max: 0.09 }),
    fill: color[b.cls as 'blocked' | 'challenged' | 'allowed'] ?? color.allowed,
  }));

  // Vista inicial: Atlântico Norte ao centro (Américas, Europa e África à vista).
  let phi = 30 * DEG;
  let theta = 25 * DEG;
  let playing = initial;
  let size = 0;
  let last = 0;
  let clock = 0;
  let raf = 0;
  let onScreen = true;

  function resize() {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    size = canvas.clientWidth;
    canvas.width = Math.round(size * dpr);
    canvas.height = Math.round(size * dpr);
    ctx!.setTransform(dpr, 0, 0, dpr, 0, 0);
    draw();
  }

  function draw() {
    if (!size) return;
    const c = ctx!;
    const cx = size / 2;
    const cy = size / 2;
    // Margem para os arcos que sobem acima da superfície (até ~1,4 raios).
    const R = size / 2.7;
    const px = (p: Vec): [number, number] => [cx + p[0] * R, cy - p[1] * R];
    c.clearRect(0, 0, size, size);

    c.beginPath();
    c.arc(cx, cy, R, 0, Math.PI * 2);
    c.fillStyle = color.sphere;
    c.fill();
    c.lineWidth = 1;
    c.strokeStyle = color.rim;
    c.stroke();

    c.fillStyle = color.land;
    const dot = Math.max(1, R / 130);
    for (const d of land) {
      const p = rotate(d, phi, theta) as Vec;
      if (p[2] <= 0) continue;
      const [x, y] = px(p);
      c.globalAlpha = 0.35 + 0.65 * p[2];
      c.fillRect(x - dot / 2, y - dot / 2, dot, dot);
    }
    c.globalAlpha = 1;

    const marker = (p: Vec, fill: string, r: number) => {
      if (p[2] <= 0) return;
      const [x, y] = px(p);
      c.beginPath();
      c.arc(x, y, r, 0, Math.PI * 2);
      c.fillStyle = fill;
      c.fill();
    };

    c.lineCap = 'round';
    for (const a of arcGeo) {
      const pts = a.pts.map((p) => rotate(p, phi, theta) as Vec);
      const [x0, y0] = px(pts[0]);
      const [x1, y1] = px(pts[pts.length - 1]);
      const grad = c.createLinearGradient(x0, y0, x1, y1);
      grad.addColorStop(0, color.origin);
      grad.addColorStop(1, color.target);
      c.strokeStyle = grad;
      c.lineWidth = a.width;
      // Arco inteiro (ténue a rodar, firme parado) e, a rodar, um "cometa"
      // a percorrê-lo da origem para o alvo.
      c.globalAlpha = playing ? 0.45 : 0.85;
      strokePolyline(c, pts, 0, pts.length - 1, px);
      if (playing) {
        const head = ((clock / 2200 + a.phase) % 1.4) * (pts.length - 1);
        c.globalAlpha = 1;
        strokePolyline(c, pts, Math.max(0, Math.floor(head - 8)), Math.min(pts.length - 1, Math.floor(head)), px);
      }
      c.globalAlpha = 1;
      marker(pts[0], color.origin, 2.2);
      marker(pts[pts.length - 1], color.target, 2.6);
    }

    for (const b of bubbleGeo) {
      const p = rotate(b.at, phi, theta) as Vec;
      if (p[2] <= 0) continue;
      const [x, y] = px(p);
      c.beginPath();
      c.arc(x, y, b.r * R, 0, Math.PI * 2);
      c.fillStyle = b.fill;
      c.globalAlpha = 0.3;
      c.fill();
      c.globalAlpha = 0.95;
      c.lineWidth = 1.25;
      c.strokeStyle = b.fill;
      c.stroke();
      c.globalAlpha = 1;
    }

    for (const r of ringGeo) {
      const p = rotate(r.at, phi, theta) as Vec;
      if (p[2] <= 0) continue;
      const [x, y] = px(p);
      c.beginPath();
      c.arc(x, y, 3 + r.width * 1.6, 0, Math.PI * 2);
      c.lineWidth = Math.max(1, r.width / 2);
      c.strokeStyle = color.origin;
      c.stroke();
      marker(p, color.target, 2.6);
    }
  }

  function frame(t: number) {
    raf = 0;
    const dt = last ? Math.min(t - last, 100) : 0;
    last = t;
    if (playing) {
      phi += dt * SPIN;
      clock += dt;
    }
    draw();
    schedule();
  }

  function schedule() {
    if (playing && onScreen && !raf) raf = requestAnimationFrame(frame);
  }

  // Arrastar para rodar (rato, toque, caneta). theta limitado para o globo
  // nunca ficar de pernas para o ar.
  let drag: { x: number; y: number } | null = null;
  const onDown = (e: PointerEvent) => {
    drag = { x: e.clientX, y: e.clientY };
    canvas.setPointerCapture(e.pointerId);
  };
  const onMove = (e: PointerEvent) => {
    if (!drag) return;
    const R = size / 2.7 || 1;
    phi += (e.clientX - drag.x) / R;
    theta = Math.max(-60 * DEG, Math.min(60 * DEG, theta + (e.clientY - drag.y) / R));
    drag = { x: e.clientX, y: e.clientY };
    if (!playing) draw();
  };
  const onUp = () => { drag = null; };
  canvas.addEventListener('pointerdown', onDown);
  canvas.addEventListener('pointermove', onMove);
  canvas.addEventListener('pointerup', onUp);
  canvas.addEventListener('pointercancel', onUp);

  const ro = new ResizeObserver(resize);
  ro.observe(canvas);
  // Fora do ecrã não se anima — não gasta CPU/bateria a rodar o invisível.
  const io = new IntersectionObserver(([entry]) => {
    onScreen = entry.isIntersecting;
    last = 0;
    schedule();
  });
  io.observe(canvas);

  resize();
  schedule();

  return {
    setPlaying(next: boolean) {
      playing = next;
      last = 0;
      if (!playing && raf) {
        cancelAnimationFrame(raf);
        raf = 0;
      }
      draw();
      schedule();
    },
    destroy() {
      if (raf) cancelAnimationFrame(raf);
      ro.disconnect();
      io.disconnect();
      canvas.removeEventListener('pointerdown', onDown);
      canvas.removeEventListener('pointermove', onMove);
      canvas.removeEventListener('pointerup', onUp);
      canvas.removeEventListener('pointercancel', onUp);
    },
  };
}

/** Traça pts[from..to], partindo a linha onde o arco passa por trás do globo. */
function strokePolyline(
  c: CanvasRenderingContext2D,
  pts: Vec[],
  from: number,
  to: number,
  px: (p: Vec) => [number, number],
) {
  if (to <= from) return;
  c.beginPath();
  let pen = false;
  for (let i = from; i <= to; i++) {
    if (isHidden(pts[i])) {
      pen = false;
      continue;
    }
    const [x, y] = px(pts[i]);
    if (pen) c.lineTo(x, y);
    else c.moveTo(x, y);
    pen = true;
  }
  c.stroke();
}
