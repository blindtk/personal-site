import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseExif, gpsToDecimal, formatExposure } from '../src/scripts/exif.js';

// Fixture gerada com piexif (ver o script que a criou): Make/Model/GPS
// conhecidos, para verificar a extração byte a byte contra valores exatos.
const fixturePath = fileURLToPath(new URL('./fixtures/exif-sample.jpg', import.meta.url));
const sampleBytes = new Uint8Array(readFileSync(fixturePath));

test('parseExif: lê tags 0th e Exif SubIFD de um JPEG real', () => {
  const tags = parseExif(sampleBytes);
  assert.ok(tags);
  assert.equal(tags.make, 'TESTCAM');
  assert.equal(tags.model, 'Model X1');
  assert.equal(tags.software, 'unit-test');
  assert.equal(tags.orientation, 6);
  assert.equal(tags.dateTimeOriginal, '2024:01:02 03:04:05');
  assert.equal(tags.lensModel, 'Lens 50mm');
  assert.equal(tags.fNumber, 2.8);
  assert.equal(tags.exposureTime, 1 / 125);
  assert.equal(tags.iso, 400);
  assert.equal(tags.focalLength, 50);
  assert.equal(tags.focalLengthIn35mm, 50);
  assert.equal(tags.pixelXDimension, 16);
  assert.equal(tags.pixelYDimension, 12);
});

test('parseExif: GPS IFD presente com lat/lon/alt em bruto', () => {
  const tags = parseExif(sampleBytes);
  assert.ok(tags.gps);
  assert.equal(tags.gps.latRef, 'N');
  assert.equal(tags.gps.lonRef, 'W');
  assert.equal(tags.gps.alt, 15);
});

test('gpsToDecimal: converte DMS para decimal e aplica o sinal do ref', () => {
  const tags = parseExif(sampleBytes);
  const dec = gpsToDecimal(tags.gps);
  assert.ok(Math.abs(dec.lat - 37.7749) < 1e-3);
  assert.ok(Math.abs(dec.lon - -122.4194) < 1e-3);
  assert.equal(dec.altitude, 15);
});

test('gpsToDecimal: sem GPS IFD devolve null', () => {
  assert.equal(gpsToDecimal(null), null);
  assert.equal(gpsToDecimal({}), null);
});

test('parseExif: não-JPEG devolve null', () => {
  assert.equal(parseExif(new Uint8Array([0, 1, 2, 3])), null);
  assert.equal(parseExif(new Uint8Array()), null);
});

test('parseExif: JPEG sem segmento Exif devolve null', () => {
  // SOI + APP0 (JFIF, sem Exif) + EOI — JPEG válido, mas sem metadados.
  const bytes = new Uint8Array([
    0xff, 0xd8,
    0xff, 0xe0, 0x00, 0x10, ...Array(14).fill(0),
    0xff, 0xd9,
  ]);
  assert.equal(parseExif(bytes), null);
});

test('formatExposure: frações curtas vs. segundos inteiros', () => {
  assert.equal(formatExposure(1 / 250), '1/250s');
  assert.equal(formatExposure(2), '2s');
  assert.equal(formatExposure(0), null);
  assert.equal(formatExposure(null), null);
});
