import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { domainToUnicode } from 'node:url';
import {
  ROUNDS,
  TRICKS,
  parseUrl,
  classify,
  punycodeDecode,
  toUnicodeHost,
  nonAsciiChars,
  buildRound,
  pickRounds,
  rate,
} from '../src/scripts/link-game.js';
import { ui } from '../src/i18n/ui.ts';

const require = createRequire(import.meta.url);

// PRNG determinístico (mulberry32) para as rondas serem reproduzíveis.
function seeded(seed) {
  let a = seed;
  return () => {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

// ---------- Parser: destino real ----------

test('parseUrl: o destino é o que vem depois do @, não o nome que o precede', () => {
  const p = parseUrl('https://cgd.pt@evil.example/');
  assert.equal(p.hostname, 'evil.example');
  assert.equal(p.hasUserinfo, true);
  // utilizador:palavra-passe, com «porta» falsa no utilizador
  const q = parseUrl('https://cgd.pt:443@evil.example:8443/a');
  assert.equal(q.hostname, 'evil.example');
  assert.equal(q.hasUserinfo, true);
  assert.equal(classify('https://cgd.pt@evil.example/', 'cgd.pt'), 'userinfo');
  assert.equal(classify('https://cgd.pt:443@evil.example:8443/a', 'cgd.pt'), 'userinfo');
});

test('classify: «\\» antes do @ NÃO é userinfo (o browser trata-o como «/», o destino é cgd.pt)', () => {
  // Quem fizesse split por «@» no texto cru acusava um link que vai mesmo para cgd.pt.
  assert.equal(parseUrl('https://cgd.pt\\@evil.example/').hostname, 'cgd.pt');
  assert.equal(classify('https://cgd.pt\\@evil.example/', 'cgd.pt'), 'legit');
});

test('classify: userinfo é recusado mesmo com o host certo', () => {
  assert.equal(classify('https://utilizador@www.cgd.pt/', 'cgd.pt'), 'userinfo');
});

test('parseUrl: maiúsculas, ponto final, porta e formas unicode equivalentes normalizam para o mesmo host', () => {
  for (const url of [
    'HTTPS://WWW.CGD.PT./entrar',
    'https://www.cgd.pt:8443/entrar',
    'https://www.cgd.pt:443/entrar',
    'https://ｗｗｗ.ｃｇｄ.pt/entrar', // largura total: o browser normaliza para ascii
    'https://www.cgd。pt/entrar', // ponto ideográfico
    'https://www.%63gd.pt/entrar',
  ]) {
    const p = parseUrl(url);
    assert.equal(p.hostname, 'www.cgd.pt', url);
    assert.equal(classify(url, 'cgd.pt'), 'legit', url);
  }
});

test('classify: «%2e» no host é um ponto real (cgd.pt%2eevil.example vai para evil.example)', () => {
  const url = 'https://cgd.pt%2eevil.example/';
  assert.equal(parseUrl(url).hostname, 'cgd.pt.evil.example');
  assert.equal(classify(url, 'cgd.pt'), 'subdomain');
});

test('parseUrl: IPs em qualquer notação são IP, não um nome', () => {
  assert.equal(classify('http://203.0.113.45/ctt', 'ctt.pt'), 'ip');
  assert.equal(classify('https://0x7f.1/', 'ctt.pt'), 'ip'); // → 127.0.0.1
  assert.equal(classify('https://3395723527/', 'ctt.pt'), 'ip'); // decimal → 202.102.161.7
  assert.equal(classify('http://[2001:db8::1]/', 'ctt.pt'), 'ip');
  assert.equal(parseUrl('https://3395723527/').hostname, '202.102.161.7');
});

test('parseUrl: o que não é um URL web completo falha fechado (null / invalid)', () => {
  for (const bad of [
    'javascript:alert(1)',
    'data:text/html,x',
    'ftp://cgd.pt/',
    'cgd.pt:443/x', // lido como esquema «cgd.pt:»
    'www.cgd.pt', // sem esquema
    '//www.cgd.pt/',
    'https://a..b/',
    'https://exa mple.pt/',
    'https:///',
    '',
    null,
    undefined,
    42,
  ]) {
    assert.equal(parseUrl(bad), null, String(bad));
    assert.equal(classify(bad, 'cgd.pt'), 'invalid', String(bad));
  }
});

test('classify: domínio esperado inválido é erro de programação, não «sem relação»', () => {
  assert.throws(() => classify('https://cgd.pt/', 'não é um domínio'), RangeError);
  assert.throws(() => classify('https://cgd.pt/', '203.0.113.1'), RangeError);
});

// ---------- Domínio registável ----------

test('registável: sufixos de vários rótulos (gov.pt) não deixam qualquer *.gov.pt passar por Finanças', () => {
  const finan = 'portaldasfinancas.gov.pt';
  assert.equal(parseUrl('https://www.portaldasfinancas.gov.pt/').registrable, finan);
  assert.equal(classify('https://sitfiscal.portaldasfinancas.gov.pt/', finan), 'legit');
  // Com «últimos dois rótulos» o registável de ambos seria gov.pt.
  assert.notEqual(classify('https://outro-organismo.gov.pt/', finan), 'legit');
  assert.notEqual(classify('https://www.gov.pt/', finan), 'legit');
});

test('registável: nome.github.io é de «nome» (cgd.pt.github.io não é da CGD nem do github.io)', () => {
  const p = parseUrl('https://cgd.pt.github.io/');
  assert.equal(p.registrable, 'pt.github.io');
  assert.deepEqual(p.subLabels, ['cgd']);
  assert.equal(classify('https://cgd.pt.github.io/', 'cgd.pt'), 'subdomain');
});

test('classify: o fim do domínio é comparado por rótulos, não por texto (notcgd.pt != cgd.pt)', () => {
  for (const url of ['https://notcgd.pt/', 'https://xcgd.pt/', 'https://cgd.pt.example/', 'https://www.cgd.ptx/']) {
    assert.notEqual(classify(url, 'cgd.pt'), 'legit', url);
  }
});

// ---------- Classificação dos truques ----------

test('classify: um vetor por truque, com os exemplos reais', () => {
  const vectors = [
    ['https://www.cgd.pt/', 'cgd.pt', 'legit'],
    ['https://cgd.pt.login-seguro.example/', 'cgd.pt', 'subdomain'],
    ['https://cgd.login-seguro.example/', 'cgd.pt', 'subdomain'],
    ['https://cgd-pt.example/', 'cgd.pt', 'typosquat'],
    ['https://seguro-cgd.example/', 'cgd.pt', 'typosquat'],
    ['https://www.paypa1.com/', 'paypal.com', 'typosquat'], // 1 no lugar de l
    ['https://www.paypall.com/', 'paypal.com', 'typosquat'], // letra a mais
    ['https://rnicrosoftonline.com/', 'microsoftonline.com', 'typosquat'], // rn → m
    ['https://www.cgd.top/', 'cgd.pt', 'tld'],
    ['https://www.portaldasfinancas.top/', 'portaldasfinancas.gov.pt', 'tld'],
    ['http://www.cgd.pt/', 'cgd.pt', 'http'],
    ['https://reembolsos.example/portaldasfinancas.gov.pt/entrar', 'portaldasfinancas.gov.pt', 'path'],
    ['https://reembolsos.example/entrar?next=https://www.cgd.pt', 'cgd.pt', 'path'],
    ['https://bit.ly/4kQz9Tm', 'cgd.pt', 'shortener'],
    ['https://xn--pple-43d.com/', 'apple.com', 'homograph'],
    ['https://www.sapo.pt/', 'cgd.pt', 'other'],
  ];
  for (const [url, domain, expected] of vectors) {
    assert.equal(classify(url, domain), expected, `${url} vs ${domain}`);
  }
});

test('classify: precedência — o truque mais grave ganha quando há vários', () => {
  // encurtador cujo caminho menciona a marca: é o encurtador que esconde o destino
  assert.equal(classify('https://bit.ly/cgd', 'cgd.pt'), 'shortener');
  // IP com a marca no caminho
  assert.equal(classify('https://203.0.113.9/cgd.pt', 'cgd.pt'), 'ip');
  // @ com marca certa antes e punycode depois
  assert.equal(classify('https://cgd.pt@xn--pple-43d.com/', 'cgd.pt'), 'userinfo');
});

test('classify: um domínio sem relação não é acusado de typosquatting', () => {
  // 'sapo' vs 'cgd', 'cinema' vs 'ctt': distância e substrings não podem disparar em nomes distintos
  assert.equal(classify('https://www.sapo.pt/', 'cgd.pt'), 'other');
  assert.equal(classify('https://www.cinema.pt/', 'ctt.pt'), 'other');
});

// ---------- Punycode ----------

test('punycodeDecode: vetores RFC 3492 e IDN reais', () => {
  assert.equal(punycodeDecode('egbpdaj6bu4bxfgehfvwxn'), 'ليهمابتكلموشعربي؟'); // RFC 3492 (A)
  assert.equal(punycodeDecode('pple-43d'), 'аpple'); // «а» cirílico
  assert.equal(punycodeDecode('bcher-kva'), 'bücher');
  assert.equal(toUnicodeHost('xn--pple-43d.com'), 'аpple.com');
  assert.equal(toUnicodeHost('www.xn--bcher-kva.example'), 'www.bücher.example');
});

test('punycodeDecode: concorda com o domainToUnicode do Node em IDN reais', () => {
  for (const host of ['münchen.de', 'portaldasfinanças.com', 'пример.рф', '日本語.jp', 'xn--pple-43d.com']) {
    const ascii = new URL(`https://${host}/`).hostname;
    assert.equal(toUnicodeHost(ascii), domainToUnicode(ascii), host);
  }
});

test('punycodeDecode: entrada malformada falha fechada, sem exceção nem ciclo infinito', () => {
  for (const bad of ['!!', 'zzzzzzzzzzzzzzzzzzzz', 'abé-cd', '9999999999999999']) {
    assert.equal(punycodeDecode(bad), null, bad);
  }
  // o rótulo inválido fica como está em vez de desaparecer
  assert.equal(toUnicodeHost('xn--!!.example'), 'xn--!!.example');
});

test('nonAsciiChars: aponta o código e o alfabeto do carácter enganador', () => {
  assert.deepEqual(nonAsciiChars('аpple.com'), [{ char: 'а', code: 'U+0430', script: 'cyrillic' }]);
  assert.deepEqual(nonAsciiChars('gіthub.com'), [{ char: 'і', code: 'U+0456', script: 'cyrillic' }]);
  assert.deepEqual(nonAsciiChars('portaldasfinanças'), [{ char: 'ç', code: 'U+00E7', script: 'latin' }]);
  assert.deepEqual(nonAsciiChars('ααα'), [{ char: 'α', code: 'U+03B1', script: 'greek' }]); // sem repetidos
  assert.deepEqual(nonAsciiChars('apple.com'), []);
});

test('ponta a ponta: аpple.com (a cirílico) vira xn--pple-43d.com e lê-se de volta', () => {
  const raw = 'https://аpple.com/';
  assert.notEqual(raw, 'https://apple.com/');
  const p = parseUrl(raw);
  assert.equal(p.hostname, 'xn--pple-43d.com');
  assert.equal(classify(raw, 'apple.com'), 'homograph');
  assert.equal(toUnicodeHost(p.hostname), 'аpple.com');
});

// ---------- Rondas ----------

const scenario = {
  id: 't',
  prompt: 'p',
  note: 'n',
  domain: 'cgd.pt',
  legit: 'https://www.cgd.pt/',
  decoys: ['https://cgd.pt.evil.example/', 'https://www.cgd-pt.example/', 'https://www.cgd.top/'],
};

test('buildRound: o índice da resposta aponta para o link legítimo depois de baralhar', () => {
  for (let seed = 1; seed <= 200; seed++) {
    const r = buildRound(scenario, seeded(seed));
    assert.equal(r.options.length, 4);
    assert.equal(r.options[r.answer].url, scenario.legit, `seed ${seed}`);
    assert.equal(r.options.filter((o) => o.trick === 'legit').length, 1);
  }
});

test('buildRound: a ordem varia (não serve sempre a mesma posição)', () => {
  const positions = new Set();
  for (let seed = 1; seed <= 200; seed++) positions.add(buildRound(scenario, seeded(seed)).answer);
  assert.deepEqual([...positions].sort(), [0, 1, 2, 3]);
});

test('buildRound: recusa cenários com zero ou dois links legítimos', () => {
  // isco que afinal é um subdomínio do domínio verdadeiro → duas respostas certas
  const two = { ...scenario, decoys: ['https://app.cgd.pt/', ...scenario.decoys.slice(1)] };
  assert.throws(() => buildRound(two), /2 links legítimos/);
  // legítimo com erro de escrita → nenhuma resposta certa
  const none = { ...scenario, legit: 'http://www.cgd.pt/' };
  assert.throws(() => buildRound(none), /0 links legítimos/);
});

test('pickRounds: cenários distintos, todos usados quando count == tamanho do banco', () => {
  const pool = Array.from({ length: 12 }, (_, i) => ({ ...scenario, id: `s${i}` }));
  for (const seed of [1, 2, 3]) {
    const rounds = pickRounds(pool, 12, seeded(seed));
    assert.deepEqual(rounds.map((r) => r.id).sort(), pool.map((s) => s.id).sort());
  }
  const ten = pickRounds(pool, ROUNDS, seeded(9));
  assert.equal(new Set(ten.map((r) => r.id)).size, ROUNDS);
});

test('pickRounds: extremos do gerador aleatório (0 e quase 1) não produzem rondas em falta', () => {
  const pool = Array.from({ length: 12 }, (_, i) => ({ ...scenario, id: `s${i}` }));
  for (const rng of [() => 0, () => 0.9999999999]) {
    const rounds = pickRounds(pool, 12, rng);
    assert.equal(new Set(rounds.map((r) => r.id)).size, 12);
    for (const r of rounds) assert.equal(r.options[r.answer].trick, 'legit');
  }
});

test('pickRounds: pedir mais rondas do que cenários é erro (não repete cenários)', () => {
  const pool = Array.from({ length: 5 }, (_, i) => ({ ...scenario, id: `s${i}` }));
  assert.equal(pickRounds(pool, 5, seeded(1)).length, 5);
  assert.throws(() => pickRounds(pool, 6, seeded(1)), RangeError);
});

// ---------- Pontuação e armazenamento ----------

test('rate: fronteiras exatas dos escalões (10, 8, 5)', () => {
  assert.equal(rate(10, 10), 'perfect');
  assert.equal(rate(9, 10), 'good');
  assert.equal(rate(8, 10), 'good');
  assert.equal(rate(7, 10), 'ok');
  assert.equal(rate(5, 10), 'ok');
  assert.equal(rate(4, 10), 'low');
  assert.equal(rate(0, 10), 'low');
});

// ---------- Conteúdo real (content/link-game) ----------

const pt = require('../../content/link-game/pt/scenarios.json');
const en = require('../../content/link-game/en/scenarios.json');

test('conteúdo: PT e EN têm os mesmos cenários, URLs e truques (só o texto muda)', () => {
  assert.deepEqual(en.map((s) => s.id), pt.map((s) => s.id));
  for (const [i, p] of pt.entries()) {
    const e = en[i];
    assert.equal(e.domain, p.domain, p.id);
    assert.equal(e.legit, p.legit, p.id);
    assert.deepEqual(e.decoys, p.decoys, p.id);
    assert.notEqual(e.prompt, p.prompt, `${p.id}: prompt EN igual ao PT (por traduzir?)`);
    assert.notEqual(e.note, p.note, `${p.id}: nota EN igual à PT (por traduzir?)`);
  }
});

test('conteúdo: há cenários que cheguem para um jogo e os ids são únicos', () => {
  assert.ok(pt.length >= ROUNDS, `${pt.length} cenários < ${ROUNDS} rondas`);
  assert.equal(new Set(pt.map((s) => s.id)).size, pt.length);
});

test('conteúdo: cada cenário tem 1 link legítimo + 3 iscos, e cada isco usa o truque declarado', () => {
  for (const s of pt) {
    assert.equal(classify(s.legit, s.domain), 'legit', `${s.id}: o legítimo não é legítimo`);
    assert.equal(s.decoys.length, 3, s.id);
    for (const d of s.decoys) {
      assert.equal(classify(d.url, s.domain), d.trick, `${s.id}: ${d.url}`);
      assert.ok(TRICKS.includes(d.trick), `${s.id}: truque desconhecido ${d.trick}`);
    }
    const hrefs = [s.legit, ...s.decoys.map((d) => d.url)].map((u) => new URL(u).href);
    assert.equal(new Set(hrefs).size, 4, `${s.id}: links repetidos`);
    assert.doesNotThrow(() => buildRound(s), s.id);
    assert.ok(s.prompt.length > 0 && s.note.length > 0, s.id);
  }
});

test('conteúdo: os iscos são ASCII (punycode já aplicado) e os homógrafos descodificam para Unicode', () => {
  // Se o texto mostrado trouxesse o carácter cirílico cru, o isco ficaria visualmente
  // idêntico ao legítimo e a ronda seria impossível de decidir.
  for (const s of pt) {
    for (const u of [s.legit, ...s.decoys.map((d) => d.url)]) {
      assert.match(u, /^[\x20-\x7e]+$/, `${s.id}: ${u}`);
    }
    for (const d of s.decoys.filter((x) => x.trick === 'homograph')) {
      const host = parseUrl(d.url).hostname;
      assert.ok(nonAsciiChars(toUnicodeHost(host)).length > 0, `${s.id}: punycode inválido em ${host}`);
    }
  }
});

test('conteúdo: todos os truques anunciados aparecem em vários cenários', () => {
  const count = Object.fromEntries(TRICKS.map((t) => [t, 0]));
  for (const s of pt) for (const d of s.decoys) count[d.trick]++;
  for (const t of TRICKS) assert.ok(count[t] >= 3, `${t}: só ${count[t]} cenário(s)`);
});

test('ui: PT e EN têm texto para todos os truques e as mesmas chaves', () => {
  const keys = (o) => Object.keys(o).sort();
  for (const lang of ['pt', 'en']) {
    const g = ui[lang].tools['link-game'];
    for (const t of [...TRICKS, 'legit', 'other']) {
      assert.ok(g.tricks[t]?.name && g.tricks[t]?.text, `${lang}: falta o truque ${t}`);
    }
    assert.equal(g.rules.length, 3, `${lang}: são 3 regras`);
    for (const r of ['perfect', 'good', 'ok', 'low']) assert.ok(g.rating[r], `${lang}: rating ${r}`);
  }
  assert.deepEqual(keys(ui.en.tools['link-game']), keys(ui.pt.tools['link-game']));
  assert.deepEqual(keys(ui.en.tools['link-game'].tricks), keys(ui.pt.tools['link-game'].tricks));
});
