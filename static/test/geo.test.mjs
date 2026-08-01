import { test } from 'node:test';
import assert from 'node:assert/strict';
import { project, arcPath, countryPoint, COUNTRY_COORDS, DESTINATION } from '../src/scripts/geo.js';

test('project: os 4 cantos da projeção equirectangular, tela 800×340 por omissão', () => {
  assert.deepEqual(project([0, 0]), [400, 170]); // centro
  assert.deepEqual(project([-180, 90]), [0, 0]); // canto superior esquerdo
  assert.deepEqual(project([180, -90]), [800, 340]); // canto inferior direito
  assert.deepEqual(project([180, 90]), [800, 0]); // canto superior direito
  assert.deepEqual(project([-180, -90]), [0, 340]); // canto inferior esquerdo
});

test('project: respeita w/h explícitos', () => {
  assert.deepEqual(project([0, 0], 400, 200), [200, 100]);
});

test('arcPath: curva simétrica entre dois pontos ao mesmo y', () => {
  assert.equal(arcPath([0, 0], [100, 0]), 'M0,0 Q50,-28 100,0');
  // lift maior levanta mais o ponto de controlo (mais negativo)
  assert.equal(arcPath([0, 0], [100, 0], 0.5), 'M0,0 Q50,-50 100,0');
});

test('countryPoint: projeta o centróide conhecido, null para código desconhecido', () => {
  assert.deepEqual(countryPoint('RU', 800, 340), project(COUNTRY_COORDS.RU, 800, 340));
  assert.equal(countryPoint('XX', 800, 340), null); // sem centróide conhecido
});

test('COUNTRY_COORDS/DESTINATION: formato [lon, lat] preservado', () => {
  assert.equal(Object.keys(COUNTRY_COORDS).length > 0, true);
  for (const coords of Object.values(COUNTRY_COORDS)) {
    assert.equal(coords.length, 2);
    assert.ok(coords[0] >= -180 && coords[0] <= 180); // longitude
    assert.ok(coords[1] >= -90 && coords[1] <= 90); // latitude
  }
  assert.equal(DESTINATION.length, 2);
});
