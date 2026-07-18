/**
 * Laboratório de passkeys — lógica pura (sem DOM, sem WebAuthn) para dissecar
 * o que um autenticador devolve. A componente PasskeyLab.astro trata da API
 * WebAuthn e da verificação com WebCrypto; aqui vive só o que é determinístico
 * e testável em Node: o parsing binário do authenticatorData, a descodificação
 * das flags, o mapa de AAGUIDs e a conversão da assinatura ECDSA de DER para
 * o formato raw (r||s) que o WebCrypto exige.
 *
 * Estruturas: WebAuthn §6.1 (authenticator data). O authenticatorData NÃO é
 * CBOR — é um layout binário de offsets fixos; só a chave pública COSE no fim
 * é que é CBOR, e essa lemo-la à parte via response.getPublicKey() (SPKI), por
 * isso não é preciso um parser CBOR aqui.
 */

/** Uint8Array → hex minúsculo. */
export function bytesToHex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/**
 * Descodifica o byte de flags do authenticatorData (WebAuthn §6.1).
 * bit0 UP (user present), bit2 UV (user verified), bit3 BE (backup eligible),
 * bit4 BS (backup state / synced), bit6 AT (attested cred data), bit7 ED (ext).
 */
export function decodeFlags(byte) {
  return {
    up: !!(byte & 0x01),
    uv: !!(byte & 0x04),
    be: !!(byte & 0x08),
    bs: !!(byte & 0x10),
    at: !!(byte & 0x40),
    ed: !!(byte & 0x80),
    raw: byte,
  };
}

/** Formata 16 bytes de AAGUID na forma canónica 8-4-4-4-12. */
export function formatAaguid(hex) {
  if (typeof hex !== 'string' || hex.length !== 32) return hex || '';
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

// Subconjunto de AAGUIDs conhecidos (os gestores/plataformas mais comuns). A
// lista oficial é grande; aqui só o suficiente para dar nome ao caso típico.
// São identificadores PÚBLICOS (metadata service da FIDO Alliance), não
// segredos — mas por serem UUIDs aleatórios, a entropia de alguns cruza por
// acaso o limiar da regra generic-api-key do gitleaks (falso positivo).
// `gitleaks:allow` neutraliza cada linha independentemente da regra.
const AAGUIDS = {
  '00000000-0000-0000-0000-000000000000': 'Sem AAGUID (não atestado)', // gitleaks:allow
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud Keychain', // gitleaks:allow
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager', // gitleaks:allow
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome on Mac', // gitleaks:allow
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello', // gitleaks:allow
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello', // gitleaks:allow
  'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden', // gitleaks:allow
  '531126d6-e717-415c-9320-3d9aa6981239': 'Dashlane', // gitleaks:allow
  'bada5566-a7aa-401f-bd96-45619a55120d': '1Password', // gitleaks:allow
  'b84e4048-15dc-4dd0-8640-f4f60813c8af': 'NordPass', // gitleaks:allow
  'f8a011f3-8c0a-4d15-8006-17111f9edc7d': 'Security Key (Yubico)', // gitleaks:allow
  'ee882879-721c-4913-9775-3dfcce97072a': 'YubiKey 5', // gitleaks:allow
};

/** Nome legível de um AAGUID (canónico) ou null se desconhecido. */
export function aaguidLabel(canonical) {
  return AAGUIDS[canonical] ?? null;
}

/** Nome do algoritmo COSE (getPublicKeyAlgorithm devolve estes inteiros). */
export function coseAlgName(alg) {
  switch (alg) {
    case -7: return 'ES256 (ECDSA P-256)';
    case -8: return 'EdDSA (Ed25519)';
    case -35: return 'ES384 (ECDSA P-384)';
    case -257: return 'RS256 (RSA)';
    default: return alg != null ? `alg ${alg}` : 'desconhecido';
  }
}

/**
 * Faz o parsing do authenticatorData (Uint8Array) para os seus campos. Lê os
 * dados de credencial atestada quando a flag AT está presente. Devolve null se
 * o buffer for demasiado curto para ser válido.
 */
export function parseAuthData(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 37) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const rpIdHash = bytes.slice(0, 32);
  const flags = decodeFlags(bytes[32]);
  const signCount = view.getUint32(33, false); // big-endian

  const result = {
    rpIdHash: bytesToHex(rpIdHash),
    flags,
    signCount,
    aaguid: null,
    aaguidCanonical: null,
    aaguidName: null,
    credentialId: null,
    credentialIdLength: 0,
  };

  if (flags.at && bytes.length >= 55) {
    const aaguidHex = bytesToHex(bytes.slice(37, 53));
    const credIdLen = view.getUint16(53, false);
    const canonical = formatAaguid(aaguidHex);
    result.aaguid = aaguidHex;
    result.aaguidCanonical = canonical;
    result.aaguidName = aaguidLabel(canonical);
    result.credentialIdLength = credIdLen;
    if (bytes.length >= 55 + credIdLen) {
      result.credentialId = bytesToHex(bytes.slice(55, 55 + credIdLen));
    }
  }
  return result;
}

/**
 * Converte uma assinatura ECDSA em DER (SEQUENCE de dois INTEGER r,s — o
 * formato que o WebAuthn produz) para o formato raw r||s de tamanho fixo
 * (`size` bytes cada, 32 para P-256) que o crypto.subtle.verify espera.
 * Puro; lança em DER malformado.
 */
export function derEcdsaToRaw(der, size = 32) {
  if (!(der instanceof Uint8Array)) throw new TypeError('der deve ser Uint8Array');
  let i = 0;
  if (der[i++] !== 0x30) throw new Error('DER: SEQUENCE esperado');
  // comprimento da sequência (assumimos forma curta ou 0x81 — assinaturas ECDSA cabem)
  let seqLen = der[i++];
  if (seqLen & 0x80) {
    const n = seqLen & 0x7f;
    seqLen = 0;
    for (let k = 0; k < n; k++) seqLen = (seqLen << 8) | der[i++];
  }
  const readInt = () => {
    if (der[i++] !== 0x02) throw new Error('DER: INTEGER esperado');
    let len = der[i++];
    let start = i;
    // remove o byte 0x00 de sinal à cabeça
    while (len > 0 && der[start] === 0x00) { start++; len--; }
    const bytes = der.slice(start, start + len);
    i = start + len;
    if (bytes.length > size) throw new Error('DER: INTEGER maior do que o tamanho da curva');
    const out = new Uint8Array(size);
    out.set(bytes, size - bytes.length); // alinhado à direita (big-endian)
    return out;
  };
  const r = readInt();
  const s = readInt();
  const raw = new Uint8Array(size * 2);
  raw.set(r, 0);
  raw.set(s, size);
  return raw;
}

/**
 * Concatena os dados assinados numa asserção WebAuthn: authenticatorData ||
 * SHA-256(clientDataJSON). É sobre isto que a assinatura é verificada.
 */
export function concatSignedData(authData, clientDataHash) {
  const out = new Uint8Array(authData.length + clientDataHash.length);
  out.set(authData, 0);
  out.set(clientDataHash, authData.length);
  return out;
}
