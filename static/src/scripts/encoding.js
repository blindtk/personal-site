/**
 * Codificação/descodificação Base64, URL e hex — UTF-8 aware, sem DOM.
 */

function bytesToBinaryString(bytes) {
  let s = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    s += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return s;
}

export function base64Encode(text) {
  const bytes = new TextEncoder().encode(text);
  return btoa(bytesToBinaryString(bytes));
}

export function base64Decode(b64) {
  const bin = atob(b64.trim());
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

export function urlEncode(text) {
  return encodeURIComponent(text);
}

export function urlDecode(text) {
  return decodeURIComponent(text.replace(/\+/g, '%20'));
}

export function hexEncode(text) {
  const bytes = new TextEncoder().encode(text);
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function hexDecode(hex) {
  const clean = hex.replace(/[\s:]/g, '').toLowerCase();
  if (!/^[0-9a-f]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error('invalid hex');
  }
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

export const codecs = {
  base64: { encode: base64Encode, decode: base64Decode },
  url: { encode: urlEncode, decode: urlDecode },
  hex: { encode: hexEncode, decode: hexDecode },
};
