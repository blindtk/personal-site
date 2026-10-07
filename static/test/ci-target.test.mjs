import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isTrustedTarget, isProductionTarget, PAGES_PROJECT_HOST } from '../../.github/scripts/lib/target.mjs';

// Estes gates decidem para onde vão ACCESS_CLIENT_* e CI_WAF_TOKEN.

const trusted = (u) => isTrustedTarget(new URL(u));
const prod = (u) => isProductionTarget(new URL(u));

test('isProductionTarget: só https://danielmala.co na porta por omissão', () => {
  assert.equal(prod('https://danielmala.co/'), true);
  assert.equal(prod('https://danielmala.co:443/x'), true); // 443 normaliza para a omissão
  for (const bad of [
    'https://danielmala.co:8443/',
    'http://danielmala.co/',
    'https://www.danielmala.co/',
    'https://danielmala.co.evil.example/',
    'https://danielmala.co@evil.example/', // o host real é evil.example
    `https://abc.${PAGES_PROJECT_HOST}/`, // previews nunca recebem o token do WAF
  ]) {
    assert.equal(prod(bad), false, bad);
  }
});

test('isTrustedTarget: produção, o projeto Pages e UM nível de preview', () => {
  assert.equal(trusted('https://danielmala.co/'), true);
  assert.equal(trusted(`https://${PAGES_PROJECT_HOST}/`), true);
  assert.equal(trusted(`https://bec0dd7f.${PAGES_PROJECT_HOST}/`), true); // preview por commit
  assert.equal(trusted(`https://claude-security-audit-fixes.${PAGES_PROJECT_HOST}/`), true); // alias de branch
});

test('isTrustedTarget: dois níveis, sufixo colado, outros projetos e portas/esquemas não passam', () => {
  for (const bad of [
    `https://a.b.${PAGES_PROJECT_HOST}/`, // dois rótulos
    `https://.${PAGES_PROJECT_HOST}/`, // rótulo vazio (o WHATWG URL recusa-o ou normaliza-o)
    `https://x${PAGES_PROJECT_HOST}/`, // sem ponto: outro domínio
    `https://${PAGES_PROJECT_HOST}.evil.example/`,
    'https://other.pages.dev/',
    'https://pages.dev/',
    `https://abc.${PAGES_PROJECT_HOST}:8443/`,
    `http://abc.${PAGES_PROJECT_HOST}/`,
    `https://${PAGES_PROJECT_HOST}@evil.example/`,
  ]) {
    let ok;
    try { ok = trusted(bad); } catch { ok = false; } // URL inválido também é "não confiável"
    assert.equal(ok, false, bad);
  }
});
