import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeIntel, techniqueUrl, INTEL_MAX_AGE_MS } from '../src/scripts/intel-summary.js';

const NOW = Date.parse('2026-11-14T13:00:00Z');
// Resposta real de /api/intel para o history.json do sensor de 2026-11-14
// (dynamic/worker/test/fixtures/intel/), encurtada nas técnicas.
const valid = () => ({
  ok: true,
  day: '2026-11-14',
  addresses: 13185,
  addressesNotScanners: 9668,
  artifacts: 83,
  credentialPairs: 3908,
  usernames: 4716,
  sessions7d: 454,
  sessionDays: 7,
  addressesDelta: 471,
  deltaDays: 6,
  techniques: [{ id: 'T1078', count: 1212 }, { id: 'T1595.002', count: 8003 }, { id: 'T1059.004', count: 631 }],
  campaigns: ['bashlite', 'mirai', 'redtail'],
  fetched: '2026-11-14T13:00:00.000Z',
});
const withField = (patch) => Object.assign(valid(), patch);

test('normalizeIntel: resumo válido, técnicas por contagem', () => {
  const s = normalizeIntel(valid(), NOW);
  assert.equal(s.addresses, 13185);
  assert.deepEqual(s.delta, { value: 471, days: 6 });
  assert.equal(s.sessions7d, 454);
  assert.deepEqual(s.techniques.map((t) => t.id), ['T1595.002', 'T1078', 'T1059.004']);
  assert.deepEqual(s.campaigns, ['bashlite', 'mirai', 'redtail']);
});

test('normalizeIntel: { ok: false }, erro do Worker ou lixo não mostram nada', () => {
  for (const doc of [null, 'x', {}, { ok: false }, { error: 'upstream_error' }, withField({ ok: 'true' }), withField({ addresses: '13185' }), withField({ addresses: -1 }), withField({ day: '14/11/2026' })]) {
    assert.equal(normalizeIntel(doc, NOW), null, JSON.stringify(doc));
  }
});

test('normalizeIntel: um dia com mais de 4 dias, ou no futuro, não é mostrado', () => {
  const start = Date.parse('2026-11-14T00:00:00Z');
  assert.notEqual(normalizeIntel(valid(), start + INTEL_MAX_AGE_MS), null);
  assert.equal(normalizeIntel(valid(), start + INTEL_MAX_AGE_MS + 1), null);
  assert.equal(normalizeIntel(valid(), start - 1), null);
});

test('normalizeIntel: só ids ATT&CK exatos chegam ao href e só slugs às campanhas', () => {
  const s = normalizeIntel(withField({
    techniques: [
      { id: 'T1110', count: 5 },
      { id: 'T1110/../../x', count: 9 },
      { id: 'javascript:alert(1)', count: 9 },
      { id: 'T1059.004', count: '3' },
      { id: 'T1105', count: 0 },
    ],
    campaigns: ['mirai', '<img src=x>', '203.0.113.7', 'Red Tail', 7],
  }), NOW);
  assert.deepEqual(s.techniques, [{ id: 'T1110', count: 5 }]);
  assert.deepEqual(s.campaigns, ['mirai']);
});

test('normalizeIntel: contagens opcionais em falta ficam null, não 0', () => {
  const s = normalizeIntel(withField({ sessions7d: null, artifacts: undefined, credentialPairs: 1.5, addressesDelta: null }), NOW);
  assert.equal(s.sessions7d, null);
  assert.equal(s.artifacts, null);
  assert.equal(s.credentialPairs, null);
  assert.equal(s.delta, null);
});

test('normalizeIntel: variação negativa é válida (endereços saem pela retenção)', () => {
  assert.deepEqual(normalizeIntel(withField({ addressesDelta: -120 }), NOW).delta, { value: -120, days: 6 });
});

test('techniqueUrl: técnica e sub-técnica apontam para o caminho do MITRE', () => {
  assert.equal(techniqueUrl('T1110'), 'https://attack.mitre.org/techniques/T1110/');
  assert.equal(techniqueUrl('T1110.001'), 'https://attack.mitre.org/techniques/T1110/001/');
});
