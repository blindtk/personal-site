/**
 * «Phishing ou legítimo?» — lógica do jogo, sem DOM, relógio e RNG injetáveis.
 */

import { shuffle } from './game-kit.js';

export const LIVES = 3;
export const PER_LEVEL = 5;
export const BASE_TIME_MS = 20000;
export const TIME_STEP_MS = 2500;
export const MIN_TIME_MS = 7500;

/** Nível da pergunta que se segue a `answered` respostas: sobe à 5.ª, 10.ª, … */
export function levelFor(answered) {
  return Math.floor(answered / PER_LEVEL) + 1;
}

export function timeLimitMs(level) {
  return Math.max(MIN_TIME_MS, BASE_TIME_MS - (level - 1) * TIME_STEP_MS);
}

/**
 * Estado de uma partida. O baralho é baralhado uma vez e percorrido sem
 * repetições. `timed: false` desliga o limite (acessibilidade).
 */
export function createGame({ scenarios, rng = Math.random, now = Date.now, timed = true }) {
  const deck = shuffle(scenarios, rng);
  let index = -1;
  let lives = LIVES;
  let score = 0;
  let correct = 0;
  let answered = 0;
  let startedAt = 0;
  let phase = 'idle'; // idle | question | feedback | over
  let over = null; // null | 'lives' | 'deck'

  const level = () => levelFor(answered);
  const limit = () => timeLimitMs(level());
  const elapsed = () => now() - startedAt;
  const expired = () => timed && phase === 'question' && elapsed() >= limit();

  function next() {
    if (over || index + 1 >= deck.length) {
      phase = 'over';
      return null;
    }
    index++;
    phase = 'question';
    startedAt = now();
    return deck[index];
  }

  /** `verdict`: 'phishing' | 'legit' | null (null = tempo esgotado). */
  function answer(verdict) {
    if (phase !== 'question') return null;
    const scenario = deck[index];
    const timedOut = verdict === null || expired();
    const wasLevel = level();
    const remaining = timed ? Math.max(0, limit() - elapsed()) : 0;
    const ok = !timedOut && verdict === scenario.verdict;
    const points = ok ? 10 * wasLevel + Math.floor(remaining / 1000) : 0;
    answered++;
    score += points;
    if (ok) correct++;
    else lives--;
    if (lives === 0) over = 'lives';
    else if (index + 1 >= deck.length) over = 'deck';
    phase = 'feedback';
    return {
      scenario,
      correct: ok,
      timedOut,
      points,
      lifeLost: !ok,
      lives,
      score,
      leveledUp: levelFor(answered) > wasLevel,
      level: levelFor(answered),
      over,
    };
  }

  /** Chamar num temporizador: devolve o resultado se o tempo acabou agora. */
  function tick() {
    return expired() ? answer(null) : null;
  }

  return {
    next,
    answer,
    tick,
    level,
    remainingMs: () => (phase === 'question' && timed ? Math.max(0, limit() - elapsed()) : 0),
    limitMs: limit,
    get state() {
      return { lives, score, correct, answered, phase, over, total: deck.length, number: index + 1 };
    },
  };
}

/** Texto do remetente tal como é mostrado no cartão. */
export function fromText(s) {
  return s.from.address ? `${s.from.name} <${s.from.address}>` : s.from.name;
}

/**
 * Procura a citação de um sinal no remetente, assunto, parágrafos do corpo
 * ou anexo (por esta ordem). Devolve null se não existir em lado nenhum.
 */
export function locate(scenario, quote) {
  const fields = [
    ['from', fromText(scenario)],
    ['subject', scenario.subject || ''],
    ...scenario.body.map((p, para) => ['body', p, para]),
    ['attachment', scenario.attachment || ''],
  ];
  for (const [field, text, para] of fields) {
    const start = quote ? text.indexOf(quote) : -1;
    if (start !== -1) return { field, para, start, end: start + quote.length };
  }
  return null;
}

/** Parte `text` em segmentos; os que pertencem a um sinal levam o seu índice. */
export function segments(text, marks) {
  const sorted = [...marks].sort((a, b) => a.start - b.start);
  const out = [];
  let pos = 0;
  for (const m of sorted) {
    if (m.start < pos) continue; // sobreposto: o primeiro ganha
    if (m.start > pos) out.push({ text: text.slice(pos, m.start) });
    out.push({ text: text.slice(m.start, m.end), signal: m.signal });
    pos = m.end;
  }
  if (pos < text.length) out.push({ text: text.slice(pos) });
  return out;
}
