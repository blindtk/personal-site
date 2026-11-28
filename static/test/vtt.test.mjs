import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { parseVtt, vttTime, clock } from '../src/scripts/vtt.js';

const dir = (lang) => new URL(`../../content/video/${lang}/`, import.meta.url);
const files = readdirSync(dir('pt')).filter((f) => f.endsWith('.vtt')).sort();

test('vttTime: as duas formas do WebVTT, e minutos/segundos fora de 0–59 recusados', () => {
  assert.equal(vttTime('00:00:30.500'), 30.5);
  assert.equal(vttTime('01:02.250'), 62.25);
  assert.equal(vttTime('01:00:00.000'), 3600);
  for (const bad of ['1:02.250', '00:60.000', '00:00:61.000', '00:00:01,000', '', null]) {
    assert.equal(vttTime(bad), null, String(bad));
  }
});

test('parseVtt: cues com identificador, definições de posição, NOTE e texto em duas linhas', () => {
  const cues = parseVtt('WEBVTT - legendas\n\nNOTE comentário\n\nc1\n00:00.000 --> 00:02.000 line:90%\nUma linha\ne outra\n\n00:02.000 --> 00:03.500\nFim');
  assert.deepEqual(cues, [
    { start: 0, end: 2, text: 'Uma linha e outra' },
    { start: 2, end: 3.5, text: 'Fim' },
  ]);
});

test('parseVtt: malformado parte o build em vez de dar cues truncadas', () => {
  for (const bad of [
    'WEBVTX\n\n00:00.000 --> 00:01.000\nx',
    'WEBVTT\n\n00:00.000 --> 00:01.000\n',
    'WEBVTT\n\n00:02.000 --> 00:01.000\nx',
    'WEBVTT\n\n00:00.000 --> 00:02.000\na\n\n00:01.000 --> 00:03.000\nb',
    'WEBVTT\n\nsó texto',
    'WEBVTT',
  ]) {
    assert.throws(() => parseVtt(bad), undefined, bad);
  }
});

test('legendas do site: cada vídeo tem PT e EN, com os mesmos tempos cue a cue', () => {
  assert.deepEqual(readdirSync(dir('en')).filter((f) => f.endsWith('.vtt')).sort(), files);
  assert.ok(files.length > 0);
  for (const f of files) {
    const pt = parseVtt(readFileSync(new URL(f, dir('pt')), 'utf8'));
    const en = parseVtt(readFileSync(new URL(f, dir('en')), 'utf8'));
    assert.deepEqual(pt.map((c) => [c.start, c.end]), en.map((c) => [c.start, c.end]), f);
  }
});

test('clock: formato da transcrição', () => {
  assert.equal(clock(0), '0:00');
  assert.equal(clock(7.9), '0:07');
  assert.equal(clock(62), '1:02');
});
