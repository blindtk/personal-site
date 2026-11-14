import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseIntelSummary, techniqueUrl, INTEL_MAX_AGE_DAYS } from '../src/scripts/intel-summary.js';

const NOW = Date.parse('2026-11-14T12:00:00Z');
const DAY = 86_400_000;
const valid = () => ({
  generatedAt: '2026-11-10T06:00:00Z',
  windowDays: 7,
  totals: { events: 18432, sources: 912, sessions: 3310 },
  techniques: [
    { id: 'T1059.004', name: 'Unix Shell', count: 220 },
    { id: 'T1110.001', name: 'Brute Force: Password Guessing', count: 15020 },
    { id: 'T1105', name: 'Ingress Tool Transfer', count: 310 },
  ],
  usernames: [
    { name: 'admin', count: 2100 },
    { name: 'root', count: 9800 },
  ],
});
const withField = (patch) => Object.assign(valid(), patch);

test('parseIntelSummary: documento válido sai ordenado por contagem e não está stale', () => {
  const s = parseIntelSummary(valid(), NOW);
  assert.deepEqual(s.techniques.map((r) => r.id), ['T1110.001', 'T1105', 'T1059.004']);
  assert.deepEqual(s.usernames, [{ name: 'root', count: 9800 }, { name: 'admin', count: 2100 }]);
  assert.deepEqual(s.totals, { events: 18432, sources: 912, sessions: 3310 });
  assert.equal(s.stale, false);
});

test('parseIntelSummary: fica stale ao milissegundo seguinte ao limite de idade', () => {
  const generated = Date.parse('2026-11-10T06:00:00Z');
  const limit = generated + INTEL_MAX_AGE_DAYS * DAY;
  assert.equal(parseIntelSummary(valid(), limit).stale, false);
  assert.equal(parseIntelSummary(valid(), limit + 1).stale, true);
});

test('parseIntelSummary: um IP em qualquer texto falha o build (só agregados)', () => {
  const cases = [
    { usernames: [{ name: '203.0.113.7', count: 3 }] },
    { usernames: [{ name: 'user@198.51.100.20', count: 3 }] },
    { usernames: [{ name: '2001:db8:0:1::7', count: 3 }] },
    { techniques: [{ id: 'T1110', name: 'Brute Force from 192.0.2.1', count: 3 }] },
  ];
  for (const patch of cases) {
    assert.throws(() => parseIntelSummary(withField(patch), NOW), /endereço IP/, JSON.stringify(patch));
  }
});

test('parseIntelSummary: ids de técnica fora do formato ATT&CK são recusados', () => {
  for (const id of ['T110', 'T11100', 'T1110.01', 't1110', 'T1110/001', 'TA0006', '']) {
    const patch = { techniques: [{ id, name: 'x', count: 1 }] };
    assert.throws(() => parseIntelSummary(withField(patch), NOW), /técnica inválida/, id);
  }
});

test('parseIntelSummary: aceita exatamente 10 linhas e recusa a 11.ª', () => {
  const users = (n) => Array.from({ length: n }, (_, i) => ({ name: `user${i}`, count: i }));
  assert.equal(parseIntelSummary(withField({ usernames: users(10) }), NOW).usernames.length, 10);
  assert.throws(() => parseIntelSummary(withField({ usernames: users(11) }), NOW), /até 10 linhas/);
});

test('parseIntelSummary: nome de utilizador com 32 caracteres passa, 33 não', () => {
  const ok = withField({ usernames: [{ name: 'a'.repeat(32), count: 1 }] });
  assert.equal(parseIntelSummary(ok, NOW).usernames[0].name.length, 32);
  const long = withField({ usernames: [{ name: 'a'.repeat(33), count: 1 }] });
  assert.throws(() => parseIntelSummary(long, NOW), /nome de utilizador inválido/);
});

test('parseIntelSummary: caracteres de controlo, bidi e espaços nas pontas são recusados', () => {
  for (const name of ['root\n', ' root', 'root ', 'ro‮ot', 'r\u0000t', '']) {
    const patch = { usernames: [{ name, count: 1 }] };
    assert.throws(() => parseIntelSummary(withField(patch), NOW), /nome de utilizador inválido/, JSON.stringify(name));
  }
});

test('parseIntelSummary: contagens negativas, fracionárias ou em texto falham', () => {
  for (const count of [-1, 1.5, '3', null, NaN]) {
    assert.throws(() => parseIntelSummary(withField({ usernames: [{ name: 'root', count }] }), NOW));
    assert.throws(() => parseIntelSummary(withField({ totals: { events: count, sources: 1, sessions: 1 } }), NOW));
  }
});

test('parseIntelSummary: linhas repetidas falham em vez de somarem em silêncio', () => {
  const patch = { techniques: [{ id: 'T1110', name: 'a', count: 1 }, { id: 'T1110', name: 'b', count: 2 }] };
  assert.throws(() => parseIntelSummary(withField(patch), NOW), /repetidas/);
});

test('parseIntelSummary: data sem Z, inválida ou no futuro é recusada', () => {
  for (const generatedAt of ['2026-11-10T06:00:00+01:00', '2026-11-10', '2026-13-40T00:00:00Z', '2026-11-14T13:00:01Z', 42]) {
    assert.throws(() => parseIntelSummary(withField({ generatedAt }), NOW), /generatedAt/, String(generatedAt));
  }
  // até 1 h de avanço de relógio é tolerado
  assert.equal(parseIntelSummary(withField({ generatedAt: '2026-11-14T13:00:00Z' }), NOW).stale, false);
});

test('parseIntelSummary: janela fora de 1..31 dias é recusada', () => {
  for (const windowDays of [0, 32, 7.5, '7']) {
    assert.throws(() => parseIntelSummary(withField({ windowDays }), NOW), /windowDays/);
  }
});

test('techniqueUrl: técnica e sub-técnica apontam para o caminho do MITRE', () => {
  assert.equal(techniqueUrl('T1110'), 'https://attack.mitre.org/techniques/T1110/');
  assert.equal(techniqueUrl('T1110.001'), 'https://attack.mitre.org/techniques/T1110/001/');
});
