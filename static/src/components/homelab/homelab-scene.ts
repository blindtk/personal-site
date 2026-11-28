// Cena 3D do "Experimenta a regra" (HomelabFlow.astro): os quatro segmentos
// à volta da firewall, em vista isométrica, e o caminho do pedido escolhido.
// Importado de forma lazy (import()) só quando o visitante carrega em "Ver
// em 3D": quem não carrega não descarrega o three.js.
//
// Escolhas que mantêm a CSP atual (docs/adr/0025): geometria procedural,
// sem loaders de glTF, sem Draco/KTX2 (workers) nem WASM; cores planas
// (MeshBasicMaterial, sem luzes) lidas das variáveis CSS. Não há ciclo de
// render: desenha-se quando algo muda e durante as animações curtas.
import {
  BoxGeometry, BufferGeometry, Color, EdgesGeometry, Group, Line, LineBasicMaterial,
  LineSegments, Mesh, MeshBasicMaterial, OrthographicCamera, Scene, SphereGeometry,
  Vector3, WebGLRenderer,
} from 'three';

export interface HomelabScene {
  show(from: string, to: string, verdict: 'allow' | 'deny' | 'same' | 'invalid'): void;
  rotate(step: 1 | -1): void;
}

interface Options {
  segments: string[];
  firewallLabel: string;
  still: () => boolean;
}

// Posições no plano (x, z): a firewall ao centro, os segmentos à volta.
const RING = 3.4;
const SLOTS: [number, number][] = [[-RING, 0], [0, -RING], [RING, 0], [0, RING]];

export function mountHomelabScene(stage: HTMLElement, canvas: HTMLCanvasElement, opts: Options): HomelabScene | null {
  let renderer: WebGLRenderer;
  try {
    renderer = new WebGLRenderer({ canvas, antialias: true, alpha: true });
  } catch {
    return null;
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

  const css = getComputedStyle(document.documentElement);
  const c = (name: string) => new Color(css.getPropertyValue(name).trim() || '#888');
  const color = {
    box: c('--bg-raise-2'),
    edge: c('--border-strong'),
    firewall: c('--bg-raise'),
    firewallEdge: c('--accent-2'),
    allow: c('--accent'),
    deny: c('--danger'),
    link: c('--border'),
  };

  const scene = new Scene();
  const camera = new OrthographicCamera(-1, 1, 1, -1, 0.1, 100);
  let azimuth = Math.PI / 4;
  const placeCamera = () => {
    const r = 14;
    camera.position.set(Math.sin(azimuth) * r, r * 0.82, Math.cos(azimuth) * r);
    camera.lookAt(0, 0, 0);
  };

  const outlined = (geo: BoxGeometry, fill: Color, edge: Color) => {
    const g = new Group();
    g.add(new Mesh(geo, new MeshBasicMaterial({ color: fill })));
    const lines = new LineSegments(new EdgesGeometry(geo), new LineBasicMaterial({ color: edge }));
    g.add(lines);
    return { group: g, lines };
  };

  // Firewall: uma laje larga e baixa, a cor âmbar das zonas de controlo.
  const fw = outlined(new BoxGeometry(2.4, 0.4, 2.4), color.firewall, color.firewallEdge);
  scene.add(fw.group);

  // Segmentos, cada um ligado à firewall (e só a ela).
  const centers = new Map<string, Vector3>();
  const segEdges = new Map<string, LineBasicMaterial>();
  opts.segments.slice(0, SLOTS.length).forEach((id, i) => {
    const [x, z] = SLOTS[i];
    const seg = outlined(new BoxGeometry(1.8, 0.9, 1.8), color.box, color.edge);
    seg.group.position.set(x, 0.25, z);
    scene.add(seg.group);
    segEdges.set(id, seg.lines.material as LineBasicMaterial);
    centers.set(id, new Vector3(x, 0.75, z));
    const link = new Line(
      new BufferGeometry().setFromPoints([new Vector3(x * 0.72, 0.05, z * 0.72), new Vector3(x * 0.36, 0.05, z * 0.36)]),
      new LineBasicMaterial({ color: color.link }),
    );
    scene.add(link);
  });

  // Caminho do pedido e o "pacote".
  const pathMat = new LineBasicMaterial({ color: color.allow });
  const path = new Line(new BufferGeometry(), pathMat);
  scene.add(path);
  const packetMat = new MeshBasicMaterial({ color: color.allow });
  const packet = new Mesh(new SphereGeometry(0.2, 16, 12), packetMat);
  packet.visible = false;
  scene.add(packet);

  // Rótulos em HTML por cima do canvas (texto de verdade, nítido), mas
  // aria-hidden: a escolha e o resultado já estão nos controlos e no texto.
  const labels = new Map<string, HTMLElement>();
  const addLabel = (key: string, text: string) => {
    const el = document.createElement('span');
    el.className = 'hf-label';
    el.textContent = text;
    stage.append(el);
    labels.set(key, el);
  };
  for (const id of centers.keys()) addLabel(id, id);
  addLabel('__fw', opts.firewallLabel);

  let width = 0;
  let height = 0;
  function render() {
    renderer.render(scene, camera);
    const v = new Vector3();
    for (const [key, el] of labels) {
      v.copy(key === '__fw' ? new Vector3(0, 0.3, 0) : centers.get(key)!).setY(key === '__fw' ? 0.3 : 1.1);
      v.project(camera);
      el.style.transform = `translate(${((v.x + 1) / 2) * width}px, ${((1 - v.y) / 2) * height}px) translate(-50%, -100%)`;
    }
  }

  function resize() {
    width = stage.clientWidth;
    height = Math.round(Math.min(width * 0.7, 380));
    renderer.setSize(width, height, false);
    canvas.style.height = `${height}px`;
    const aspect = width / height;
    const view = 3.9;
    camera.left = -view * aspect;
    camera.right = view * aspect;
    camera.top = view;
    camera.bottom = -view;
    camera.updateProjectionMatrix();
    render();
  }

  // Animações curtas por rAF; nada corre quando não há nada a mudar.
  let raf = 0;
  function animate(duration: number, step: (t: number) => void, done?: () => void) {
    cancelAnimationFrame(raf);
    const start = performance.now();
    const tick = (now: number) => {
      // O carimbo do rAF é o início do frame e pode ser anterior a `start`.
      const t = Math.max(0, Math.min(1, (now - start) / duration));
      step(t);
      render();
      if (t < 1) raf = requestAnimationFrame(tick);
      else done?.();
    };
    raf = requestAnimationFrame(tick);
  }
  const easeOut = (t: number) => 1 - (1 - t) ** 3;

  placeCamera();
  const ro = new ResizeObserver(resize);
  ro.observe(stage);
  resize();

  return {
    show(from, to, verdict) {
      cancelAnimationFrame(raf);
      for (const [id, m] of segEdges) {
        m.color.copy(id === from ? color.allow : id === to ? color.firewallEdge : color.edge);
      }
      (fw.lines.material as LineBasicMaterial).color.copy(color.firewallEdge);
      const a = centers.get(from);
      const b = centers.get(to);
      if (!a || !b || verdict === 'same' || verdict === 'invalid') {
        path.visible = false;
        packet.visible = false;
        render();
        return;
      }
      const hub = new Vector3(0, 0.45, 0);
      const ok = verdict === 'allow';
      const points = ok ? [a, hub, b] : [a, hub];
      pathMat.color.copy(ok ? color.allow : color.deny);
      packetMat.color.copy(ok ? color.allow : color.deny);
      path.geometry.dispose();
      path.geometry = new BufferGeometry().setFromPoints(points);
      path.visible = true;
      packet.visible = true;
      const end = points[points.length - 1];
      const blocked = () => (fw.lines.material as LineBasicMaterial).color.copy(ok ? color.firewallEdge : color.deny);
      if (opts.still()) {
        packet.position.copy(end);
        blocked();
        render();
        return;
      }
      // O pacote percorre o caminho; se for negado, pára na firewall e ela
      // acende a vermelho. Explicação, por isso pode passar dos 300 ms.
      const legs = points.length - 1;
      animate(700 * legs, (t) => {
        const e = easeOut(t) * legs;
        const i = Math.min(legs - 1, Math.floor(e));
        packet.position.lerpVectors(points[i], points[i + 1], e - i);
      }, blocked);
    },
    rotate(stepDir) {
      const from = azimuth;
      const to = azimuth + (stepDir * Math.PI) / 2;
      if (opts.still()) {
        azimuth = to;
        placeCamera();
        render();
        return;
      }
      animate(300, (t) => {
        azimuth = from + (to - from) * easeOut(t);
        placeCamera();
      });
    },
  };
}
