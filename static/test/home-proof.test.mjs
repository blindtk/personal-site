import { test } from 'node:test';
import assert from 'node:assert/strict';
import { firewallStopped, unexpectedCerts } from '../src/scripts/home-proof.js';

test('firewallStopped: soma bloqueados e desafiados, deixa de fora o que passou', () => {
  const doc = {
    firewall7d: {
      byAction: [
        { key: 'block', count: 445 },
        { key: 'managed_challenge', count: 120 },
        // contém "challenge" mas foi resolvido: passou, não foi travado
        { key: 'managed_challenge_bypassed', count: 503 },
        { key: 'skip', count: 12 },
      ],
    },
  };
  assert.equal(firewallStopped(doc), 565);
});

test('firewallStopped: lista vazia é um 0 legítimo (semana sem eventos)', () => {
  assert.equal(firewallStopped({ firewall7d: { byAction: [] } }), 0);
});

test('firewallStopped: documento de erro ou contagem inválida não afirma nada', () => {
  for (const doc of [
    null,
    { error: 'rate_limited' },
    { firewall7d: {} },
    { firewall7d: { byAction: 'x' } },
    { firewall7d: { byAction: [{ key: 'block', count: '445' }] } },
    { firewall7d: { byAction: [{ key: 'block', count: -1 }] } },
    { firewall7d: { byAction: [{ key: 'block', count: 1.5 }] } },
    { firewall7d: { byAction: [{ key: 'block', count: NaN }] } },
    { firewall7d: { byAction: [{ count: 3 }] } },
  ]) {
    assert.equal(firewallStopped(doc), null, JSON.stringify(doc));
  }
});

test('unexpectedCerts: devolve a contagem quando há certificados observados', () => {
  assert.equal(unexpectedCerts({ summary: { total: 14, unexpected: 0 } }), 0);
  assert.equal(unexpectedCerts({ summary: { total: 14, unexpected: 2 } }), 2);
  assert.equal(unexpectedCerts({ summary: { total: 1, unexpected: 1 } }), 1);
});

test('unexpectedCerts: sem certificados observados não há "0 inesperados"', () => {
  assert.equal(unexpectedCerts({ summary: { total: 0, unexpected: 0 } }), null);
});

test('unexpectedCerts: resumo em falta, incoerente ou malformado falha fechado', () => {
  for (const doc of [
    null,
    { error: 'upstream' },
    { summary: {} },
    { summary: { total: 14 } },
    { summary: { total: 14, unexpected: '0' } },
    { summary: { total: 14, unexpected: -1 } },
    { summary: { total: 2, unexpected: 3 } },
  ]) {
    assert.equal(unexpectedCerts(doc), null, JSON.stringify(doc));
  }
});
