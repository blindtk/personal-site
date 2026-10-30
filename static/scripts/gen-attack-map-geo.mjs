// Gera static/src/data/attack-map-geo.json — os dados geográficos do globo de
// ataques (/este-site/mapa-de-ataques/): centróides por país (ISO 3166-1 alfa-2) e a
// máscara de terra em pontos. Corre-se À MÃO, só quando se quiser regenerar;
// as dependências NÃO entram no package.json do site (são só para isto):
//
//   cd "$(mktemp -d)" && npm init -y >/dev/null &&
//   npm i world-atlas@2 d3-geo@3 topojson-client@3 i18n-iso-countries@7 &&
//   node /caminho/para/static/scripts/gen-attack-map-geo.mjs > attack-map-geo.json
//
// Fonte: Natural Earth (domínio público) via world-atlas (ISC). Centróide =
// o do MAIOR polígono do país (o de França ficava no Atlântico por causa da
// Guiana, o dos EUA puxado pelo Alasca). Máscara: grelha de 2°, um bit por
// célula (1 = terra), linhas de norte para sul, em base64.
import { createRequire } from 'node:module';

const require = createRequire(`${process.cwd()}/`);
const { geoArea, geoCentroid, geoContains } = require('d3-geo');
const { feature } = require('topojson-client');
const countries = require('i18n-iso-countries');

const STEP = 2;
const round1 = (n) => Math.round(n * 10) / 10;

const world = require('world-atlas/countries-10m.json');
const centroids = {};
for (const f of feature(world, world.objects.countries).features) {
  const code = f.properties?.name === 'Kosovo' ? 'XK' : countries.numericToAlpha2(f.id);
  if (!code || centroids[code]) continue;
  const polys = f.geometry.type === 'MultiPolygon'
    ? f.geometry.coordinates.map((coordinates) => ({ type: 'Polygon', coordinates }))
    : [f.geometry];
  const biggest = polys.reduce((a, b) => (geoArea(b) > geoArea(a) ? b : a));
  const [lon, lat] = geoCentroid(biggest);
  centroids[code] = [round1(lat), round1(lon)];
}

// Códigos atribuídos que o Natural Earth não separa como país (departamentos
// ultramarinos franceses, ilhas pequenas): coordenadas aproximadas, à mão.
const EXTRA = {
  BQ: [12.2, -68.3], BV: [-54.4, 3.4], CC: [-12.2, 96.8], CX: [-10.5, 105.6], GF: [4, -53],
  GP: [16.2, -61.6], MQ: [14.6, -61], RE: [-21.1, 55.5], SJ: [78, 16], TK: [-9.2, -171.8], YT: [-12.8, 45.2],
};
for (const [code, latlon] of Object.entries(EXTRA)) centroids[code] ??= latlon;

const landTopo = require('world-atlas/land-110m.json');
const land = feature(landTopo, landTopo.objects.land);
const cols = 360 / STEP;
const rows = 180 / STEP;
const bits = new Uint8Array(Math.ceil((cols * rows) / 8));
for (let r = 0; r < rows; r++) {
  const lat = 90 - STEP / 2 - r * STEP;
  for (let c = 0; c < cols; c++) {
    const lon = -180 + STEP / 2 + c * STEP;
    if (geoContains(land, [lon, lat])) {
      const i = r * cols + c;
      bits[i >> 3] |= 1 << (i & 7);
    }
  }
}

const sorted = Object.fromEntries(Object.entries(centroids).sort(([a], [b]) => (a < b ? -1 : 1)));
process.stdout.write(`${JSON.stringify({
  source: 'Natural Earth (public domain) via world-atlas; static/scripts/gen-attack-map-geo.mjs',
  step: STEP,
  cols,
  rows,
  land: Buffer.from(bits).toString('base64'),
  centroids: sorted,
})}\n`);
