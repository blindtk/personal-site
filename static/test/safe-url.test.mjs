import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { isHttpsUrl, isGithubRepoUrl, assertHttpsUrls } from '../src/scripts/safe-url.js';

const require = createRequire(import.meta.url);

test('isHttpsUrl: só https sem credenciais embebidas', () => {
  assert.equal(isHttpsUrl('https://haveibeenpwned.com'), true);
  assert.equal(isHttpsUrl('https://www.credly.com/badges/f38c5c9e'), true);
  for (const bad of [
    'javascript:alert(1)',
    'data:text/html,<script>1</script>',
    'http://example.org',
    'ftp://example.org',
    '//example.org',
    'https://github.com@evil.example/', // userinfo: o host real é evil.example
    'https://user:pw@example.org',
    'not a url',
    '',
    null,
    undefined,
    42,
  ]) {
    assert.equal(isHttpsUrl(bad), false, String(bad));
  }
});

test('isGithubRepoUrl: exatamente https://github.com/<dono>/<repo>', () => {
  assert.equal(isGithubRepoUrl('https://github.com/blindtk/personal-site'), true);
  assert.equal(isGithubRepoUrl('https://github.com/a/b.c-d_e'), true);
  for (const bad of [
    'https://github.com/blindtk',
    'https://github.com/blindtk/personal-site/issues',
    'https://github.com/blindtk/personal-site?x=1',
    'https://github.com/blindtk/personal-site#readme',
    'https://github.com/blindtk/personal-site/',
    'http://github.com/blindtk/personal-site',
    'https://github.com.evil.example/a/b',
    'https://evil.example/github.com/a/b',
    'https://github.com@evil.example/a/b',
    'javascript:alert(1)//github.com/a/b',
    'https://github.com/a b/c',
  ]) {
    assert.equal(isGithubRepoUrl(bad), false, bad);
  }
});

test('assertHttpsUrls: lança com a origem e o URL ofensivo', () => {
  assert.doesNotThrow(() => assertHttpsUrls(['https://a.example', 'https://b.example/x'], 'x.json'));
  assert.throws(() => assertHttpsUrls(['https://a.example', 'javascript:alert(1)'], 'x.json'), /x\.json.*javascript:alert\(1\)/);
});

test('o content/ real cumpre a política (catálogo, links e certificados)', () => {
  const catalog = require('../../content/catalog.json');
  for (const cat of catalog.categories) {
    for (const r of cat.repos) assert.equal(isGithubRepoUrl(r.url), true, r.url);
  }
  const links = require('../../content/links.json');
  assertHttpsUrls(links.flatMap((g) => g.items.map((i) => i.url)), 'content/links.json');
  const certs = require('../../content/certs.json');
  assertHttpsUrls(certs.items.flatMap((i) => (i.url ? [i.url] : [])), 'content/certs.json');
});
