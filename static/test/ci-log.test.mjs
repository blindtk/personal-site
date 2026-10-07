import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeForLog } from '../../.github/scripts/lib/log.mjs';

// Os check-*.mjs imprimem dados de fora (cabeçalhos, API do Observatory, DNS,
// testssl.sh) numa linha `::error::…`. Uma quebra de linha seguida de `::` num
// valor forjado começaria um comando de workflow novo (::add-mask::,
// ::stop-commands::, …).

test('sanitizeForLog: quebras de linha e controlos não deixam começar uma linha nova', () => {
  for (const nl of ['\n', '\r', '\r\n', '\x85', '\u2028', '\u2029', '\x1b[31m', '\x00']) {
    const out = sanitizeForLog(`ok${nl}::add-mask::segredo`);
    assert.ok(!/[\n\r\x00-\x1f\x7f-\x9f\u2028\u2029]/.test(out), JSON.stringify(nl));
    assert.ok(!out.includes('::'), JSON.stringify(nl));
  }
});

test('sanitizeForLog: "::" no meio de uma linha também é desarmado; texto normal passa igual', () => {
  assert.equal(sanitizeForLog('a::b'), 'a: :b');
  assert.equal(sanitizeForLog('HTTP/2 200 OK'), 'HTTP/2 200 OK');
  assert.equal(sanitizeForLog(null), 'null');
});

test('sanitizeForLog: trunca a maxLen exato', () => {
  assert.equal(sanitizeForLog('a'.repeat(200)).length, 200);
  assert.equal(sanitizeForLog('a'.repeat(201)).length, 200);
  assert.equal(sanitizeForLog('a'.repeat(300), 300).length, 300);
});
