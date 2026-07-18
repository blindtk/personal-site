import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  bytesToHex, decodeFlags, formatAaguid, aaguidLabel, coseAlgName,
  parseAuthData, derEcdsaToRaw, concatSignedData,
} from '../src/scripts/passkeys.js';

test('bytesToHex: bytes → hex minúsculo com padding', () => {
  assert.equal(bytesToHex(new Uint8Array([0x00, 0x0f, 0xff, 0xa5])), '000fffa5');
});

test('decodeFlags: 0x5D = UP+UV+BE+BS+AT (passkey sincronizada, atestada)', () => {
  const f = decodeFlags(0x5d);
  assert.equal(f.up, true);
  assert.equal(f.uv, true);
  assert.equal(f.be, true);
  assert.equal(f.bs, true);
  assert.equal(f.at, true);
  assert.equal(f.ed, false);
  assert.equal(f.raw, 0x5d);
});

test('decodeFlags: 0x01 = só UP (presença, sem verificação)', () => {
  const f = decodeFlags(0x01);
  assert.equal(f.up, true);
  assert.equal(f.uv, false);
  assert.equal(f.at, false);
});

test('formatAaguid: 32 hex → canónico 8-4-4-4-12', () => {
  assert.equal(
    formatAaguid('fbfc3007154e4ecc8c0b6e020557d7bd'),
    'fbfc3007-154e-4ecc-8c0b-6e020557d7bd',
  );
});

test('aaguidLabel: iCloud Keychain reconhecido; desconhecido → null', () => {
  assert.equal(aaguidLabel('fbfc3007-154e-4ecc-8c0b-6e020557d7bd'), 'iCloud Keychain');
  assert.equal(aaguidLabel('00000000-0000-0000-0000-000000000000'), 'Sem AAGUID (não atestado)');
  assert.equal(aaguidLabel('11111111-1111-1111-1111-111111111111'), null);
});

test('coseAlgName: ES256/RS256/EdDSA', () => {
  assert.equal(coseAlgName(-7), 'ES256 (ECDSA P-256)');
  assert.equal(coseAlgName(-257), 'RS256 (RSA)');
  assert.equal(coseAlgName(-8), 'EdDSA (Ed25519)');
});

// Constrói um authenticatorData realista com dados de credencial atestada.
function buildAuthData() {
  const rpIdHash = new Uint8Array(32).fill(0xaa);
  const flags = new Uint8Array([0x5d]); // UP+UV+BE+BS+AT
  const signCount = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
  const aaguid = Uint8Array.from(
    'fbfc3007154e4ecc8c0b6e020557d7bd'.match(/../g).map((h) => parseInt(h, 16)),
  );
  const credId = new Uint8Array(16).fill(0x11);
  const credIdLen = new Uint8Array([0x00, credId.length]);
  const parts = [rpIdHash, flags, signCount, aaguid, credIdLen, credId];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

test('parseAuthData: extrai rpIdHash, flags, signCount, AAGUID e credId', () => {
  const data = parseAuthData(buildAuthData());
  assert.ok(data);
  assert.equal(data.rpIdHash, 'aa'.repeat(32));
  assert.equal(data.flags.at, true);
  assert.equal(data.flags.uv, true);
  assert.equal(data.signCount, 0);
  assert.equal(data.aaguidCanonical, 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd');
  assert.equal(data.aaguidName, 'iCloud Keychain');
  assert.equal(data.credentialIdLength, 16);
  assert.equal(data.credentialId, '11'.repeat(16));
});

test('parseAuthData: buffer curto demais → null', () => {
  assert.equal(parseAuthData(new Uint8Array(10)), null);
  assert.equal(parseAuthData('não é bytes'), null);
});

test('parseAuthData: sem flag AT não lê dados de credencial', () => {
  const bytes = new Uint8Array(37);
  bytes.set(new Uint8Array(32).fill(1), 0);
  bytes[32] = 0x05; // UP+UV, sem AT
  const data = parseAuthData(bytes);
  assert.equal(data.flags.at, false);
  assert.equal(data.aaguid, null);
  assert.equal(data.credentialId, null);
});

test('derEcdsaToRaw: DER r=1,s=1 → 64 bytes alinhados à direita', () => {
  // SEQUENCE { INTEGER 1, INTEGER 1 }
  const der = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
  const raw = derEcdsaToRaw(der, 32);
  assert.equal(raw.length, 64);
  assert.equal(raw[31], 1);
  assert.equal(raw[63], 1);
  assert.equal(raw[0], 0);
  assert.equal(raw[32], 0);
});

test('derEcdsaToRaw: remove o byte de sinal 0x00 à cabeça de um INTEGER', () => {
  // INTEGER com 0x00 de sinal antes de 0xFF (para não ser negativo)
  const der = new Uint8Array([0x30, 0x08, 0x02, 0x02, 0x00, 0xff, 0x02, 0x02, 0x00, 0x80]);
  const raw = derEcdsaToRaw(der, 32);
  assert.equal(raw.length, 64);
  assert.equal(raw[31], 0xff);
  assert.equal(raw[63], 0x80);
});

test('derEcdsaToRaw: DER malformado lança', () => {
  assert.throws(() => derEcdsaToRaw(new Uint8Array([0x31, 0x00]), 32));
  assert.throws(() => derEcdsaToRaw('nope', 32));
});

test('concatSignedData: authData || hash(clientData)', () => {
  const a = new Uint8Array([1, 2, 3]);
  const h = new Uint8Array([9, 9]);
  assert.deepEqual([...concatSignedData(a, h)], [1, 2, 3, 9, 9]);
});
