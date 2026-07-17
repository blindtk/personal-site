// Leitura de metadados EXIF (JPEG/TIFF, RFC "Exif 2.3") — sem DOM, testável
// com node --test. A remoção de metadados (canvas) vive no componente, que
// é quem tem acesso ao DOM.

const TAGS_0TH = {
  0x010f: 'make',
  0x0110: 'model',
  0x0112: 'orientation',
  0x0131: 'software',
  0x0132: 'dateTime',
  0x8769: 'exifIfdPointer',
  0x8825: 'gpsIfdPointer',
};

const TAGS_EXIF = {
  0x9003: 'dateTimeOriginal',
  0x9004: 'dateTimeDigitized',
  0xa434: 'lensModel',
  0x829d: 'fNumber',
  0x829a: 'exposureTime',
  0x8827: 'iso',
  0x920a: 'focalLength',
  0xa405: 'focalLengthIn35mm',
  0xa002: 'pixelXDimension',
  0xa003: 'pixelYDimension',
};

const TAGS_GPS = {
  1: 'latRef',
  2: 'lat',
  3: 'lonRef',
  4: 'lon',
  5: 'altRef',
  6: 'alt',
  0x1d: 'dateStamp',
};

// Tamanho em bytes de cada valor, por tipo TIFF (secção 4.6.2 da spec Exif).
const TYPE_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 6: 1, 7: 1, 8: 2, 9: 4, 10: 8 };

export const ORIENTATION_LABELS = {
  1: 'normal',
  2: 'flipH',
  3: 'rotate180',
  4: 'flipV',
  5: 'transpose',
  6: 'rotate90cw',
  7: 'transverse',
  8: 'rotate90ccw',
};

function readIfd(view, tiffStart, ifdOffsetAbs, little, tagMap) {
  const get16 = (o) => view.getUint16(o, little);
  const get32 = (o) => view.getUint32(o, little);
  const count = get16(ifdOffsetAbs);
  const entries = {};
  for (let i = 0; i < count; i++) {
    const entryOffset = ifdOffsetAbs + 2 + i * 12;
    const tag = get16(entryOffset);
    const type = get16(entryOffset + 2);
    const numValues = get32(entryOffset + 4);
    const typeSize = TYPE_SIZE[type] || 1;
    const totalSize = typeSize * numValues;
    const valueField = entryOffset + 8;
    // Valores que cabem em 4 bytes ficam inline; os restantes são um offset
    // (relativo ao início do bloco TIFF) para os dados reais.
    const dataAbs = totalSize <= 4 ? valueField : tiffStart + get32(valueField);
    const name = tagMap[tag];
    if (!name) continue;
    let value = null;
    try {
      if (type === 2) {
        const chars = [];
        for (let j = 0; j < numValues - 1; j++) chars.push(view.getUint8(dataAbs + j));
        value = String.fromCharCode(...chars);
      } else if (type === 3) {
        value = numValues === 1 ? get16(dataAbs) : Array.from({ length: numValues }, (_, j) => get16(dataAbs + j * 2));
      } else if (type === 4) {
        value = numValues === 1 ? get32(dataAbs) : Array.from({ length: numValues }, (_, j) => get32(dataAbs + j * 4));
      } else if (type === 5) {
        const readRat = (o) => get32(o) / (get32(o + 4) || 1);
        value = numValues === 1 ? readRat(dataAbs) : Array.from({ length: numValues }, (_, j) => readRat(dataAbs + j * 8));
      } else if (type === 1) {
        value = numValues === 1 ? view.getUint8(dataAbs) : Array.from({ length: numValues }, (_, j) => view.getUint8(dataAbs + j));
      }
    } catch {
      value = null;
    }
    entries[name] = value;
  }
  return entries;
}

/**
 * Extrai os metadados EXIF de um JPEG. `bytes` é o ficheiro completo.
 * Devolve `null` se não for JPEG ou não tiver segmento APP1 Exif.
 */
export function parseExif(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (view.byteLength < 4 || view.getUint16(0) !== 0xffd8) return null;

  let offset = 2;
  while (offset < view.byteLength - 4) {
    if (view.getUint8(offset) !== 0xff) break;
    const marker = view.getUint8(offset + 1);
    if (marker === 0xd9 || marker === 0xda) break; // EOI ou SOS: acabaram os APPn
    const size = view.getUint16(offset + 2);
    if (marker === 0xe1) {
      const id = String.fromCharCode(...bytes.slice(offset + 4, offset + 8));
      if (id === 'Exif') {
        const tiffStart = offset + 4 + 6;
        const byteOrder = view.getUint16(tiffStart);
        const little = byteOrder === 0x4949;
        const get32 = (o) => view.getUint32(o, little);
        const ifd0Offset = get32(tiffStart + 4);
        const ifd0 = readIfd(view, tiffStart, tiffStart + ifd0Offset, little, TAGS_0TH);
        const exifIfd = ifd0.exifIfdPointer
          ? readIfd(view, tiffStart, tiffStart + ifd0.exifIfdPointer, little, TAGS_EXIF)
          : {};
        const gps = ifd0.gpsIfdPointer
          ? readIfd(view, tiffStart, tiffStart + ifd0.gpsIfdPointer, little, TAGS_GPS)
          : null;
        delete ifd0.exifIfdPointer;
        delete ifd0.gpsIfdPointer;
        return { ...ifd0, ...exifIfd, gps };
      }
    }
    offset += 2 + size;
  }
  return null;
}

/** Graus/minutos/segundos (formato GPS EXIF) para grau decimal. */
function dms(arr) {
  return arr[0] + arr[1] / 60 + arr[2] / 3600;
}

/** Converte a GPS IFD crua em `{ lat, lon, altitude }` decimal, ou `null`. */
export function gpsToDecimal(gps) {
  if (!gps || !gps.lat || !gps.lon) return null;
  let lat = dms(gps.lat);
  if (gps.latRef === 'S') lat = -lat;
  let lon = dms(gps.lon);
  if (gps.lonRef === 'W') lon = -lon;
  const result = { lat, lon, altitude: null };
  if (typeof gps.alt === 'number') {
    result.altitude = gps.altRef === 1 ? -gps.alt : gps.alt;
  }
  return result;
}

/** `0.004` -> `1/250s`; `2` -> `2s`. */
export function formatExposure(value) {
  if (!value) return null;
  return value < 1 ? `1/${Math.round(1 / value)}s` : `${value}s`;
}
