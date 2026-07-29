// Geometria do mapa de tráfego hostil (feature 3.2). Puro e testável em
// Node: projeção equirectangular simples + geração de arcos. Sem dependências
// de mapa pesadas — o "mapa" é um campo de pontos com nós projetados
// geograficamente e arcos até ao destino (este site).

// Centróides aproximados (lon, lat) dos países mais prováveis de aparecer
// no honeypot. Países fora desta lista contam nos totais mas não desenham
// arco (sem coordenada) — é aceitável e nunca inventa dados.
export const COUNTRY_COORDS = {
  RU: [100, 60], CN: [105, 35], US: [-98, 39], BR: [-51, -10], NL: [5, 52],
  DE: [10, 51], GB: [-2, 54], FR: [2, 47], IN: [79, 22], VN: [106, 16],
  KR: [128, 36], JP: [138, 36], UA: [32, 49], IR: [53, 32], TR: [35, 39],
  PL: [19, 52], RO: [25, 46], ID: [113, -1], SG: [104, 1], HK: [114, 22],
  TW: [121, 24], ZA: [24, -29], NG: [8, 9], EG: [30, 26], SA: [45, 24],
  AE: [54, 24], PK: [70, 30], BD: [90, 24], TH: [101, 15], MY: [102, 4],
  PH: [122, 13], MX: [-102, 23], CA: [-106, 56], AR: [-64, -34], CL: [-71, -30],
  AU: [133, -25], ES: [-4, 40], IT: [12, 42], SE: [18, 60], NO: [8, 61],
  FI: [26, 64], CZ: [15, 50], BG: [25, 43], CH: [8, 47], MD: [28, 47],
};

// Destino do mapa: não há "um sítio" físico real (Cloudflare Pages/Workers
// correm numa rede global anycast — cada visitante é servido pelo edge mais
// próximo dele, não por um datacenter fixo). O ponto fica perto da Europa
// só por legibilidade do mapa; o rótulo (ver i18n) identifica o domínio, não
// uma cidade — para não sugerir que o servidor "está" nalgum sítio.
/** @type {[number, number]} */
export const DESTINATION = [-8.6, 41.1];

/** Projeção equirectangular de [lon,lat] para [x,y] numa tela w×h. */
export function project([lon, lat], w = 800, h = 340) {
  const x = ((lon + 180) / 360) * w;
  const y = ((90 - lat) / 180) * h;
  return [Math.round(x * 10) / 10, Math.round(y * 10) / 10];
}

/**
 * Caminho SVG de um arco de `a` até `b` (ambos [x,y]). O ponto de controlo
 * é levantado acima do segmento para dar a curva; `lift` controla a altura
 * relativa à distância.
 */
export function arcPath(a, b, lift = 0.28) {
  const [ax, ay] = a;
  const [bx, by] = b;
  const mx = (ax + bx) / 2;
  const dist = Math.hypot(bx - ax, by - ay);
  const cy = Math.min(ay, by) - dist * lift;
  return `M${ax},${ay} Q${mx},${Math.round(cy * 10) / 10} ${bx},${by}`;
}

/** Coordenada projetada de um país, ou null se não conhecemos o centróide. */
export function countryPoint(code, w, h) {
  const c = COUNTRY_COORDS[code];
  return c ? project(c, w, h) : null;
}
