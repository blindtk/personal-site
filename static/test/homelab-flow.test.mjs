import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { decideFlow, policyIssues } from '../src/scripts/homelab-flow.js';

const policy = JSON.parse(readFileSync(new URL('../../content/homelab-policy.json', import.meta.url), 'utf8'));

test('policyIssues: a política publicada é válida', () => {
  assert.deepEqual(policyIssues(policy), []);
});

test('decideFlow: o bench administra todos os outros segmentos', () => {
  for (const to of ['vault', 'archive', 'workshop']) {
    const r = decideFlow(policy, 'bench', to);
    assert.equal(r.verdict, 'allow', to);
    assert.equal(r.rule.from, 'bench');
  }
});

test('decideFlow: a regra tem sentido — o caminho inverso é negado por omissão', () => {
  assert.deepEqual(decideFlow(policy, 'vault', 'bench'), { verdict: 'deny', rule: null });
  assert.deepEqual(decideFlow(policy, 'workshop', 'vault'), { verdict: 'deny', rule: null });
});

test('decideFlow: mesmo segmento e ids desconhecidos não viram "passa"', () => {
  assert.equal(decideFlow(policy, 'vault', 'vault').verdict, 'same');
  for (const [from, to] of [['*', 'vault'], ['vault', '*'], ['__proto__', 'vault'], ['bench', 'toString'], [undefined, 'vault']]) {
    assert.equal(decideFlow(policy, from, to).verdict, 'invalid', `${from}→${to}`);
  }
});

test('decideFlow: política com erro falha fechado, mesmo que uma regra casasse', () => {
  const typo = { ...policy, rules: [{ ...policy.rules[0], from: 'bnech' }] };
  assert.deepEqual(policyIssues(typo), ['rule 0: unknown from bnech']);
  assert.equal(decideFlow(typo, 'bench', 'vault').verdict, 'invalid');
  const allowAll = { ...policy, default: 'allow' };
  assert.equal(decideFlow(allowAll, 'workshop', 'vault').verdict, 'invalid');
});

test('policyIssues: ids repetidos, inválidos e razões sem os dois idiomas', () => {
  const bad = {
    default: 'deny',
    segments: [{ id: 'vault' }, { id: 'vault' }, { id: 'Bad Id' }],
    rules: [{ from: 'vault', to: 'nowhere', reason: { pt: 'x' } }],
  };
  assert.deepEqual(policyIssues(bad), [
    'bad segment id: Bad Id',
    'duplicate segment id',
    'rule 0: unknown to nowhere',
    'rule 0: reason needs pt and en',
  ]);
  assert.deepEqual(policyIssues(null), ['policy is not an object']);
});
