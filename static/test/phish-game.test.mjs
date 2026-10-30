import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  LIVES, PER_LEVEL, BASE_TIME_MS, MIN_TIME_MS, BEST_KEY,
  levelFor, timeLimitMs, shuffle, createGame, fromText, locate, segments, loadBest, saveBest,
} from '../src/scripts/phish-game.js';

const mk = (n, verdict = 'phishing') =>
  Array.from({ length: n }, (_, i) => ({ id: `s${i}`, verdict }));

// Relógio manual: o único que o jogo vê.
function clock(t = 1000) {
  return { now: () => t, set: (v) => (t = v), advance: (d) => (t += d) };
}

test('levelFor: o nível muda exatamente à 5.ª resposta', () => {
  assert.equal(levelFor(0), 1);
  assert.equal(levelFor(PER_LEVEL - 1), 1);
  assert.equal(levelFor(PER_LEVEL), 2);
  assert.equal(levelFor(2 * PER_LEVEL - 1), 2);
  assert.equal(levelFor(2 * PER_LEVEL), 3);
});

test('createGame: a 5.ª resposta sobe o nível e encurta o tempo; a 4.ª não', () => {
  const c = clock();
  const g = createGame({ scenarios: mk(10), now: c.now, rng: () => 0 });
  const results = [];
  for (let i = 0; i < PER_LEVEL; i++) {
    const s = g.next();
    assert.equal(g.limitMs(), BASE_TIME_MS, `pergunta ${i + 1} ainda no nível 1`);
    results.push(g.answer(s.verdict));
  }
  assert.deepEqual(results.map((r) => r.leveledUp), [false, false, false, false, true]);
  g.next();
  assert.equal(g.level(), 2);
  assert.ok(g.limitMs() < BASE_TIME_MS);
});

test('timeLimitMs: encurta com o nível e nunca desce do mínimo', () => {
  assert.equal(timeLimitMs(1), BASE_TIME_MS);
  assert.ok(timeLimitMs(2) < timeLimitMs(1));
  assert.equal(timeLimitMs(1000), MIN_TIME_MS);
});

test('createGame: a vida a 0 termina exatamente nessa resposta', () => {
  const g = createGame({ scenarios: mk(10), rng: () => 0 });
  for (let i = 1; i < LIVES; i++) {
    g.next();
    const r = g.answer('legit'); // errado
    assert.equal(r.over, null, `com ${LIVES - i} vida(s) ainda se joga`);
    assert.equal(r.lives, LIVES - i);
  }
  g.next();
  const last = g.answer('legit');
  assert.equal(last.lives, 0);
  assert.equal(last.over, 'lives');
  assert.equal(g.next(), null, 'não há pergunta depois da última vida');
  assert.equal(g.state.phase, 'over');
});

test('createGame: tempo a esgotar no ms exato (limite-1 ainda vale, limite já não)', () => {
  const c = clock(5000);
  const g = createGame({ scenarios: mk(3), now: c.now, rng: () => 0 });
  g.next();
  c.set(5000 + BASE_TIME_MS - 1);
  assert.equal(g.tick(), null);
  assert.equal(g.remainingMs(), 1);
  c.set(5000 + BASE_TIME_MS);
  const r = g.tick();
  assert.equal(r.timedOut, true);
  assert.equal(r.lifeLost, true);
  assert.equal(r.points, 0);
  assert.equal(g.tick(), null, 'um timeout só conta uma vez');
});

test('createGame: responder no ms do limite conta como timeout, mesmo com o veredito certo', () => {
  const c = clock(0);
  const g = createGame({ scenarios: mk(3), now: c.now, rng: () => 0 });
  const s = g.next();
  c.set(BASE_TIME_MS - 1);
  const ok = g.answer(s.verdict);
  assert.equal(ok.correct, true);
  assert.equal(ok.points, 10 + 0, 'sobra 1 ms: sem bónus de segundos');

  const s2 = g.next();
  c.advance(BASE_TIME_MS);
  const late = g.answer(s2.verdict);
  assert.equal(late.correct, false);
  assert.equal(late.timedOut, true);
});

test('createGame: sem limite de tempo nunca expira', () => {
  const c = clock(0);
  const g = createGame({ scenarios: mk(2), now: c.now, timed: false });
  g.next();
  c.advance(10 * 60 * 1000);
  assert.equal(g.tick(), null);
});

test('createGame: baralho esgotado termina o jogo, sem repetir cartas', () => {
  const g = createGame({ scenarios: mk(3), rng: () => 0.5 });
  const seen = [];
  let r;
  for (let s = g.next(); s; s = g.next()) {
    seen.push(s.id);
    r = g.answer(s.verdict);
    if (r.over) break;
  }
  assert.equal(new Set(seen).size, 3);
  assert.equal(r.over, 'deck');
  assert.equal(g.next(), null);
  assert.equal(g.state.lives, LIVES);
});

test('createGame: perder a última vida na última carta é «lives», não «deck»', () => {
  const g = createGame({ scenarios: mk(LIVES), rng: () => 0 });
  let r;
  for (let i = 0; i < LIVES; i++) {
    g.next();
    r = g.answer('legit');
  }
  assert.equal(r.over, 'lives');
});

test('createGame: responder fora de uma pergunta é ignorado', () => {
  const g = createGame({ scenarios: mk(3), rng: () => 0 });
  assert.equal(g.answer('phishing'), null, 'antes de começar');
  const s = g.next();
  g.answer(s.verdict);
  assert.equal(g.answer(s.verdict), null, 'a mesma pergunta não pontua duas vezes');
});

test('shuffle: é permutação, não altera o original e usa o rng', () => {
  const src = [1, 2, 3, 4, 5];
  assert.deepEqual([...shuffle(src, () => 0.999999)].sort(), src);
  assert.deepEqual(src, [1, 2, 3, 4, 5]);
  assert.notDeepEqual(shuffle(src, () => 0), src);
});

test('segments/locate: citação colada ao fim do texto e sobreposição', () => {
  const s = { from: { name: 'A', address: 'a@x.pt' }, subject: '', body: ['vê x.pt/ab'] };
  const loc = locate(s, 'x.pt/ab');
  assert.deepEqual(loc, { field: 'body', para: 0, start: 3, end: 10 });
  assert.deepEqual(segments(s.body[0], [{ ...loc, signal: 0 }]), [
    { text: 'vê ' },
    { text: 'x.pt/ab', signal: 0 },
  ]);
  assert.equal(locate(s, 'inexistente'), null);
  assert.equal(locate(s, ''), null, 'citação vazia não marca nada');
  assert.deepEqual(
    segments('abcdef', [{ start: 0, end: 4, signal: 0 }, { start: 2, end: 6, signal: 1 }]),
    [{ text: 'abcd', signal: 0 }, { text: 'ef' }],
  );
  assert.equal(fromText(s), 'A <a@x.pt>');
});

test('loadBest/saveBest: guarda só recordes e tolera localStorage a lançar', () => {
  const mem = new Map();
  const ok = { getItem: (k) => mem.get(k) ?? null, setItem: (k, v) => mem.set(k, v) };
  assert.equal(loadBest(ok), 0);
  assert.equal(saveBest(ok, 80), true);
  assert.equal(saveBest(ok, 80), false, 'empate não é recorde');
  assert.equal(saveBest(ok, 40), false);
  assert.equal(loadBest(ok), 80);
  mem.set(BEST_KEY, 'lixo');
  assert.equal(loadBest(ok), 0, 'valor corrompido fica a 0');
  mem.set(BEST_KEY, '-5');
  assert.equal(loadBest(ok), 0);

  const boom = { getItem() { throw new Error('SecurityError'); }, setItem() { throw new Error('QuotaExceeded'); } };
  assert.equal(loadBest(boom), 0);
  assert.doesNotThrow(() => saveBest(boom, 50));
});

// ---- Conteúdo: o que um erro de edição partiria só em produção ----

const load = (lang) =>
  JSON.parse(readFileSync(new URL(`../../content/phish/${lang}/scenarios.json`, import.meta.url), 'utf8'));
const KINDS = new Set(['sender', 'link', 'urgency', 'data', 'attachment']);

for (const lang of ['pt', 'en']) {
  test(`cenários ${lang}: ≥30, ~metade legítimos, ids únicos`, () => {
    const all = load(lang);
    assert.ok(all.length >= 30);
    const legit = all.filter((s) => s.verdict === 'legit').length;
    assert.ok(legit >= all.length * 0.4 && legit <= all.length * 0.6, `legítimos: ${legit}/${all.length}`);
    assert.equal(new Set(all.map((s) => s.id)).size, all.length);
  });

  test(`cenários ${lang}: cada sinal marca uma citação real, sem sobreposições`, () => {
    for (const s of load(lang)) {
      assert.ok(['email', 'sms', 'whatsapp'].includes(s.channel), s.id);
      assert.ok(['phishing', 'legit'].includes(s.verdict), s.id);
      if (s.channel === 'email') assert.ok(s.subject, `${s.id}: e-mail sem assunto`);
      const bad = s.signals.filter((x) => x.tone === 'bad').length;
      if (s.verdict === 'phishing') assert.ok(bad >= 2, `${s.id}: phishing com poucos sinais maus`);
      else assert.equal(bad, 0, `${s.id}: legítimo com sinal «bad»`);
      assert.ok(s.signals.length >= 2, s.id);
      const spans = [];
      for (const sig of s.signals) {
        assert.ok(KINDS.has(sig.kind), `${s.id}: kind ${sig.kind}`);
        assert.ok(sig.why, `${s.id}: sinal sem explicação`);
        const loc = locate(s, sig.quote);
        assert.ok(loc, `${s.id}: citação não encontrada: ${sig.quote}`);
        for (const o of spans.filter((x) => x.field === loc.field && x.para === loc.para)) {
          assert.ok(loc.end <= o.start || loc.start >= o.end, `${s.id}: sinais sobrepostos`);
        }
        spans.push(loc);
      }
    }
  });
}

test('cenários: PT e EN têm os mesmos ids, vereditos, canais e sinais, pela mesma ordem', () => {
  const pt = load('pt');
  const en = load('en');
  assert.deepEqual(en.map((s) => s.id), pt.map((s) => s.id));
  pt.forEach((p, i) => {
    const e = en[i];
    assert.equal(e.channel, p.channel, p.id);
    assert.equal(e.verdict, p.verdict, p.id);
    assert.equal(e.body.length, p.body.length, `${p.id}: nº de parágrafos`);
    assert.equal(!!e.attachment, !!p.attachment, p.id);
    assert.deepEqual(
      e.signals.map((x) => [x.kind, x.tone]),
      p.signals.map((x) => [x.kind, x.tone]),
      p.id,
    );
  });
});
