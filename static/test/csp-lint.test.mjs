import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCsp, analyzeCsp, gradeFor, gradeTone } from '../src/scripts/csp-lint.js';

const ids = (r) => r.findings.map((f) => f.id);
const has = (r, id) => ids(r).includes(id);
const finding = (r, id) => r.findings.find((f) => f.id === id);
const row = (r, name) => r.rows.find((x) => x.name === name);

test('parseCsp: separa diretivas, minúscula o nome, junta múltiplas linhas', () => {
  const { map, order, count } = parseCsp("default-src 'self';\nSCRIPT-SRC 'self' 'unsafe-inline'");
  assert.equal(count, 2);
  assert.deepEqual(order, ['default-src', 'script-src']);
  assert.deepEqual(map.get('script-src').tokens, ["'self'", "'unsafe-inline'"]);
});

test('parseCsp: a primeira ocorrência vence e a repetida é marcada', () => {
  const { map } = parseCsp("script-src 'self'; script-src 'none'");
  assert.deepEqual(map.get('script-src').tokens, ["'self'"]);
  assert.equal(map.get('script-src').duplicate, true);
});

test('parseCsp: texto vazio ou inválido → zero diretivas', () => {
  assert.equal(parseCsp('').count, 0);
  assert.equal(parseCsp('   ;;  ').count, 0);
  assert.equal(parseCsp(null).count, 0);
});

test('unsafe-inline sem nonce/hash em script-src é falha grave', () => {
  const r = analyzeCsp("default-src 'self'; script-src 'self' 'unsafe-inline'");
  assert.ok(has(r, 'script-unsafe-inline'));
  assert.equal(finding(r, 'script-unsafe-inline').level, 'bad');
  assert.ok(!has(r, 'script-unsafe-inline-nonce'));
});

test("unsafe-inline com nonce presente é ignorado pelos browsers modernos (info, não bad)", () => {
  const r = analyzeCsp("script-src 'self' 'unsafe-inline' 'nonce-abc123=='");
  assert.ok(has(r, 'script-unsafe-inline-nonce'));
  assert.ok(!has(r, 'script-unsafe-inline'));
  assert.ok(has(r, 'script-nonce'));
});

test("strict-dynamic também neutraliza o unsafe-inline", () => {
  const r = analyzeCsp("script-src 'self' 'unsafe-inline' 'strict-dynamic' 'nonce-x'");
  assert.ok(has(r, 'script-unsafe-inline-nonce'));
  assert.ok(has(r, 'script-strict-dynamic'));
});

test('wildcard total em script-src é falha grave; wildcard de host é aviso com o token', () => {
  const r = analyzeCsp("script-src * https://cdn.exemplo.com *.googleapis.com");
  assert.ok(has(r, 'script-wildcard'));
  assert.equal(finding(r, 'script-wildcard').level, 'bad');
  const host = finding(r, 'script-wildcard-host');
  assert.ok(host);
  assert.equal(host.token, '*.googleapis.com');
});

test("esquema nu (https:) em script-src é aviso", () => {
  const r = analyzeCsp("script-src 'self' https:");
  const f = finding(r, 'script-scheme');
  assert.ok(f);
  assert.equal(f.token, 'https:');
});

test('script-src ausente cai para default-src (fallback), sem achado de ausência', () => {
  const withDefault = analyzeCsp("default-src 'self' 'unsafe-inline'");
  assert.ok(!has(withDefault, 'script-missing'));
  // herda o unsafe-inline do default-src
  assert.ok(has(withDefault, 'script-unsafe-inline'));
  const noDefault = analyzeCsp("img-src 'self'");
  assert.ok(has(noDefault, 'script-missing'));
});

test('object-src / base-uri / frame-ancestors em falta são sinalizados', () => {
  const r = analyzeCsp("default-src 'self'");
  assert.ok(has(r, 'object-src-missing'));
  assert.ok(has(r, 'base-uri-missing'));
  assert.ok(has(r, 'frame-ancestors-missing'));
});

test("default-src 'none' torna a ausência de object-src inofensiva", () => {
  const r = analyzeCsp("default-src 'none'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'");
  assert.ok(!has(r, 'object-src-missing'));
  assert.ok(has(r, 'default-src-none'));
});

test('wildcard genérico em img-src é aviso com a diretiva no achado', () => {
  const r = analyzeCsp("default-src 'self'; img-src *");
  const f = finding(r, 'wildcard');
  assert.ok(f);
  assert.equal(f.dir, 'img-src');
});

test('endurecimentos são reconhecidos como ok/info', () => {
  const r = analyzeCsp("default-src 'none'; script-src 'nonce-x'; base-uri 'none'; frame-ancestors 'none'; upgrade-insecure-requests; require-trusted-types-for 'script'; report-to csp");
  assert.ok(has(r, 'upgrade-insecure'));
  assert.ok(has(r, 'trusted-types'));
  assert.ok(has(r, 'reporting'));
});

test('report-uri sem report-to é sinalizado como legado', () => {
  const r = analyzeCsp("default-src 'self'; report-uri /csp");
  assert.ok(has(r, 'report-uri-legacy'));
});

test('diretiva desconhecida é info', () => {
  const r = analyzeCsp("default-src 'self'; foo-src 'self'");
  const f = finding(r, 'unknown-directive');
  assert.ok(f);
  assert.equal(f.dir, 'foo-src');
});

test('texto vazio devolve estado empty sem crashar', () => {
  const r = analyzeCsp('');
  assert.equal(r.empty, true);
  assert.equal(r.grade, '—');
  assert.deepEqual(r.rows, []);
});

test('tabela: diretivas presentes com veredicto e recomendadas em falta como miss', () => {
  const r = analyzeCsp("script-src 'self' 'unsafe-inline'; frame-ancestors 'none'");
  const script = row(r, 'script-src');
  assert.equal(script.verdict, 'bad');
  // o token unsafe-inline vem marcado 'bad' para o realce
  assert.ok(script.tokens.some((t) => t.t === "'unsafe-inline'" && t.flag === 'bad'));
  assert.equal(row(r, 'frame-ancestors').verdict, 'ok');
  const baseUri = row(r, 'base-uri');
  assert.ok(baseUri.missing);
  assert.equal(baseUri.verdict, 'miss');
  assert.equal(baseUri.recommend, "'none'");
});

test('gradeFor: penalização determinística e monótona', () => {
  assert.equal(gradeFor({ bad: 0, warn: 0 }), 'A');
  assert.equal(gradeFor({ bad: 0, warn: 1 }), 'A');
  assert.equal(gradeFor({ bad: 0, warn: 2 }), 'B');
  assert.equal(gradeFor({ bad: 1, warn: 0 }), 'B');
  assert.equal(gradeFor({ bad: 1, warn: 2 }), 'C');
  assert.equal(gradeFor({ bad: 2, warn: 2 }), 'D');
  assert.equal(gradeFor({ bad: 3, warn: 1 }), 'F');
});

test('gradeTone mapeia para os data-grade do CSS', () => {
  assert.equal(gradeTone('A'), 'good');
  assert.equal(gradeTone('C'), 'mid');
  assert.equal(gradeTone('F'), 'bad');
});

test('política forte e completa não tem achados graves', () => {
  const strong = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; upgrade-insecure-requests";
  const r = analyzeCsp(strong);
  assert.equal(r.counts.bad, 0);
  assert.ok(/^A/.test(r.grade));
});
