import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  formatNumber,
  formatBytes,
  formatPercent,
  relativeTime,
  groupBy,
  withBars,
  threatRate,
  sparkPath,
  plural,
  firewallActionClass,
  firewallActionTone,
  sumByActionClass,
  classifyDaily,
  logScaleX,
  areaRadius,
  currentCertificate,
  daysUntil,
  certProgressPct,
} from '../src/scripts/observability.js';

test('formatNumber: milhares e não-números', () => {
  assert.equal(formatNumber(1234567, 'en-GB'), '1,234,567');
  assert.equal(formatNumber(0, 'en-GB'), '0');
  assert.equal(formatNumber('nope'), '—');
});

test('formatBytes: base 1024 com vetores conhecidos', () => {
  assert.equal(formatBytes(0), '0 B');
  assert.equal(formatBytes(512), '512 B');
  assert.equal(formatBytes(1024, 'en-GB'), '1 KB');
  assert.equal(formatBytes(1536, 'en-GB'), '1.5 KB');
  assert.equal(formatBytes(1048576, 'en-GB'), '1 MB');
  assert.equal(formatBytes(-5), '0 B');
});

test('formatPercent: fração → percentagem', () => {
  assert.equal(formatPercent(0.1234), '12.3%');
  assert.equal(formatPercent(1), '100.0%');
  assert.equal(formatPercent(0, 0), '0%');
  assert.equal(formatPercent(NaN), '—');
});

test('relativeTime: escolhe a maior unidade', () => {
  const now = 1_000_000_000_000;
  assert.deepEqual(relativeTime(now - 30_000, now), { value: 30, unit: 'second' });
  assert.deepEqual(relativeTime(now - 5 * 60_000, now), { value: 5, unit: 'minute' });
  assert.deepEqual(relativeTime(now - 3 * 3600_000, now), { value: 3, unit: 'hour' });
  assert.deepEqual(relativeTime(now - 2 * 86400_000, now), { value: 2, unit: 'day' });
  // futuro trata-se como agora (nunca negativo)
  assert.deepEqual(relativeTime(now + 10_000, now), { value: 0, unit: 'second' });
});

test('groupBy: agrega, soma, ordena e corta', () => {
  const rows = [
    { country: 'PT', hits: 3 },
    { country: 'US', hits: 5 },
    { country: 'PT', hits: 2 },
    { country: '', hits: 9 },
  ];
  const out = groupBy(rows, (r) => r.country, (r) => r.hits, 2);
  // Empate (PT=5, US=5): ordenação estável mantém a ordem de inserção (PT
  // foi visto primeiro), por isso PT fica à frente de US.
  assert.deepEqual(out, [
    { key: 'PT', value: 5 },
    { key: 'US', value: 5 },
  ]);
  // contagem por omissão (valueFn = 1)
  assert.deepEqual(groupBy(['a', 'b', 'a'], (x) => x), [
    { key: 'a', value: 2 },
    { key: 'b', value: 1 },
  ]);
  assert.deepEqual(groupBy(null, (x) => x), []);
});

test('withBars: escala relativa ao máximo', () => {
  assert.deepEqual(withBars([{ value: 10 }, { value: 5 }, { value: 0 }]), [
    { value: 10, pct: 100 },
    { value: 5, pct: 50 },
    { value: 0, pct: 0 },
  ]);
  assert.deepEqual(withBars([{ value: 0 }]), [{ value: 0, pct: 0 }]);
});

test('sparkPath: linha/área num viewBox, vazio degrada', () => {
  assert.deepEqual(sparkPath([]), { line: '', area: '', max: 0 });
  const sp = sparkPath([0, 10], { width: 100, height: 30, pad: 2 });
  assert.equal(sp.max, 10);
  // 2 pontos: x começa no pad (2) e acaba em width-pad (98)
  assert.ok(sp.line.startsWith('M2.00 28.00')); // valor 0 → fundo (30-2)
  assert.ok(sp.line.includes('L98.00 2.00')); // valor 10 (=max) → topo (pad)
  // a área fecha até à base
  assert.ok(sp.area.endsWith('Z'));
  // um único ponto centra-se
  assert.ok(sparkPath([5]).line.startsWith('M50.00'));
});

test('threatRate: clamp e defesa', () => {
  assert.equal(threatRate(50, 1000), 0.05);
  assert.equal(threatRate(5, 0), 0);
  assert.equal(threatRate(2000, 1000), 1);
  assert.equal(threatRate('x', 10), 0);
});

test('plural: pelas regras do idioma, não por n===1 à mão', () => {
  assert.equal(plural(1, { one: 'país', other: 'países' }, 'pt-PT'), 'país');
  assert.equal(plural(0, { one: 'país', other: 'países' }, 'pt-PT'), 'países');
  assert.equal(plural(2, { one: 'país', other: 'países' }, 'pt-PT'), 'países');
  assert.equal(plural(1, { one: 'country', other: 'countries' }, 'en-GB'), 'country');
  assert.equal(plural(5, { one: 'country', other: 'countries' }, 'en-GB'), 'countries');
  // sem 'one' definido, degrada para 'other'
  assert.equal(plural(1, { other: 'x' }, 'en-GB'), 'x');
});

test('firewallActionClass: bypassed/solved contam como passado, não como desafiado', () => {
  assert.equal(firewallActionClass('block'), 'blocked');
  assert.equal(firewallActionClass('drop'), 'blocked');
  assert.equal(firewallActionClass('skip'), 'allowed');
  assert.equal(firewallActionClass('allow'), 'allowed');
  assert.equal(firewallActionClass('log'), 'allowed');
  assert.equal(firewallActionClass('managed_challenge'), 'challenged');
  assert.equal(firewallActionClass('js_challenge'), 'challenged');
  assert.equal(firewallActionClass('link_maze_injected'), 'challenged');
  // a ordem importa: "bypassed"/"solved" contêm "challenge" mas são passagens
  assert.equal(firewallActionClass('managed_challenge_bypassed'), 'allowed');
  assert.equal(firewallActionClass('managed_challenge_non_interactive_solved'), 'allowed');
  // desconhecida degrada para 'allowed' (nunca inventa um alarme)
  assert.equal(firewallActionClass('something_new'), 'allowed');
});

test('firewallActionTone: só bloqueado/desafiado pintam; passado fica neutro', () => {
  assert.equal(firewallActionTone('block'), 'down');
  assert.equal(firewallActionTone('managed_challenge'), 'warn');
  assert.equal(firewallActionTone('skip'), undefined);
  assert.equal(firewallActionTone('managed_challenge_bypassed'), undefined);
});

test('sumByActionClass: soma só as linhas cuja classe está na lista', () => {
  const rows = [
    { key: 'skip', count: 411 },
    { key: 'block', count: 39 },
    { key: 'managed_challenge', count: 21 },
    { key: 'managed_challenge_bypassed', count: 24 },
  ];
  assert.equal(sumByActionClass(rows, ['blocked', 'challenged']), 60); // 39+21
  assert.equal(sumByActionClass(rows, ['allowed']), 435); // 411+24
  assert.equal(sumByActionClass([], ['blocked']), 0);
});

test('classifyDaily: reparte byAction cru de cada dia em bloqueado/desafiado/passado', () => {
  const out = classifyDaily([
    { date: '2026-08-01', byAction: { block: 445, managed_challenge: 111, skip: 311 } },
    { date: '2026-08-02', byAction: {} },
    { date: '2026-08-03', byAction: { managed_challenge_bypassed: 444, block: 42 } },
  ]);
  assert.deepEqual(out, [
    { date: '2026-08-01', blocked: 445, challenged: 111, allowed: 311, total: 867 },
    { date: '2026-08-02', blocked: 0, challenged: 0, allowed: 0, total: 0 },
    { date: '2026-08-03', blocked: 42, challenged: 0, allowed: 444, total: 486 },
  ]);
  assert.deepEqual(classifyDaily(undefined), []);
});

test('logScaleX: mapeia 1..1000 para um range de pixels, clamped', () => {
  const opts = { min: 1, max: 1000, rangeMin: 0, rangeMax: 300 };
  assert.equal(logScaleX(1, opts), 0);
  assert.equal(logScaleX(1000, opts), 300);
  assert.equal(logScaleX(31.622776601683793, opts), 150); // sqrt(1000), meio da escala log
  // fora do domínio: clampa aos extremos, nunca NaN
  assert.equal(logScaleX(0, opts), 0);
  assert.equal(logScaleX(999999, opts), 300);
  // min===max: degrada para o centro do range, sem dividir por zero
  assert.equal(logScaleX(5, { min: 10, max: 10, rangeMin: 0, rangeMax: 300 }), 150);
});

test('areaRadius: cresce em raiz quadrada, nunca abaixo do mínimo', () => {
  assert.equal(areaRadius(0), 4); // mínimo
  assert.equal(areaRadius(-5), 4); // negativo degrada para 0 → mínimo
  assert.equal(areaRadius(100, { minR: 4, k: 1 }), 10); // sqrt(100)=10
  assert.equal(areaRadius(4, { minR: 4, k: 2 }), 4); // sqrt(4)*2=4, empata no mínimo
});

test('currentCertificate: escolhe o válido, do domínio exato, de emissor esperado, mais recente', () => {
  const now = 1_700_000_000_000;
  const DAY = 86_400_000;
  const certs = [
    // wildcard: não cobre o domínio exato nos `names`
    { notBefore: now - 5 * DAY, notAfter: now + 80 * DAY, issuer: 'Let\'s Encrypt', names: ['*.danielmala.co'], expected: true },
    // expirado
    { notBefore: now - 100 * DAY, notAfter: now - 10 * DAY, issuer: 'Let\'s Encrypt', names: ['danielmala.co'], expected: true },
    // emissor inesperado
    { notBefore: now - 2 * DAY, notAfter: now + 88 * DAY, issuer: 'Evil CA', names: ['danielmala.co'], expected: false },
    // válido, domínio exato, esperado — o mais antigo dos dois válidos
    { notBefore: now - 10 * DAY, notAfter: now + 80 * DAY, issuer: 'Google Trust Services WR1', names: ['danielmala.co'], expected: true },
    // válido, domínio exato, esperado — notBefore mais recente: este ganha
    { notBefore: now - 1 * DAY, notAfter: now + 89 * DAY, issuer: 'Google Trust Services WE1', names: ['danielmala.co'], expected: true },
  ];
  const current = currentCertificate(certs, { domain: 'danielmala.co', now });
  assert.equal(current.issuer, 'Google Trust Services WE1');
  assert.equal(currentCertificate([], { domain: 'danielmala.co', now }), null);
  assert.equal(currentCertificate(certs, { domain: 'outro.dominio', now }), null);
});

test('daysUntil e certProgressPct: contagem regressiva e progresso do certificado', () => {
  const now = 1_700_000_000_000;
  const DAY = 86_400_000;
  assert.equal(daysUntil(now + 73 * DAY + 1, now), 74); // arredonda para cima
  assert.equal(daysUntil(now - DAY, now), 0); // já passou → nunca negativo
  assert.equal(daysUntil(now, now), 0);
  // 18% decorrido: emitido há 13 dias, validade de 73 dias
  const notBefore = now - 13 * DAY;
  const notAfter = now + 60 * DAY;
  assert.equal(certProgressPct(notBefore, notAfter, now), 18);
  assert.equal(certProgressPct(now, now, now), 0); // span 0 não rebenta
});
