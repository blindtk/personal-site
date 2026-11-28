import { test } from 'node:test';
import assert from 'node:assert/strict';
import { firewallStopped, unexpectedCerts, pulseCadence } from '../src/scripts/home-proof.js';

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

test('pulseCadence: ritmo alto em tempo real, cada pulso vale N pedidos', () => {
  // 50 400 em 7 dias = 300/h = um a cada 12 s → já ≥ 3 s com N = 1
  assert.deepEqual(pulseCadence(50400), { perHour: 300, eventsPerPulse: 1, speedup: 1, periodSec: 12 });
  // 604 800 em 7 dias = 3600/h = um por segundo → N = 5 (5 s); N = 2 daria 2 s
  assert.deepEqual(pulseCadence(604800), { perHour: 3600, eventsPerPulse: 5, speedup: 1, periodSec: 5 });
});

test('pulseCadence: fronteiras exatas dos limites de legibilidade', () => {
  // um a cada 15 s exatos (240/h) ainda é tempo real, sem câmara rápida
  assert.deepEqual(pulseCadence(240 * 168), { perHour: 240, eventsPerPulse: 1, speedup: 1, periodSec: 15 });
  // um a cada 3 s exatos (1200/h) já chega com N = 1
  assert.equal(pulseCadence(1200 * 168).eventsPerPulse, 1);
  // um pouco mais depressa que 3 s pede N = 2
  assert.equal(pulseCadence(1201 * 168).eventsPerPulse, 2);
});

test('pulseCadence: ritmo baixo usa câmara rápida, um pedido por pulso', () => {
  // 565 em 7 dias ≈ 3,36/h = um a cada ~1070,4 s → ×100 dá 10,7 s (×50 daria 21,4 s)
  const c = pulseCadence(565);
  assert.equal(c.eventsPerPulse, 1);
  assert.equal(c.speedup, 100);
  assert.equal(c.periodSec, 10.7);
  // um a cada 15,01 s já não cabe em tempo real
  assert.equal(pulseCadence(Math.floor((3600 / 15.01) * 168)).speedup, 2);
});

test('pulseCadence: semana sem eventos pára o traço; contagem inválida não afirma nada', () => {
  assert.deepEqual(pulseCadence(0), { perHour: 0, eventsPerPulse: null, speedup: null, periodSec: null });
  for (const v of [null, -1, 1.5, NaN, '565', undefined]) assert.equal(pulseCadence(v), null, String(v));
});
