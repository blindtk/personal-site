// Testes da lógica pura do Worker (node --test, sem rede nem Cloudflare).
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  escapeHtml, sanitizeText, normalizeCountry, normalizeAsn,
} from '../src/lib/sanitize.js';
import { mergeFirewall7d } from '../src/lib/firewall.js';
import {
  normalizeVitals, emptyVitalsBucket, addVitals, mergeVitalsBuckets, vitalsStats,
} from '../src/lib/vitals.js';
import { nextState, dailySalt, clientHash } from '../src/lib/ratelimit.js';
import { underCap } from '../src/lib/kvcap.js';
import { normalizePrefix, parseRanges } from '../src/lib/pwned.js';
import {
  issuerLabel, isExpectedIssuer, parseExpectedIssuers, normalizeCtEntry, parseCtEntries, ctStats,
  DEFAULT_EXPECTED_ISSUERS,
} from '../src/lib/ct.js';
import { parseCfStats, firewallBreakdown, firewallDetailBreakdown, asnNames, withAsnNames } from '../src/lib/cf-analytics.js';
import { serverView, normalizeIp } from '../src/lib/mirror.js';
import { edgeKey, edgeGetJSON, edgePutJSON } from '../src/lib/edgecache.js';
import worker from '../src/index.js';

test('escapeHtml cobre os cinco caracteres', () => {
  assert.equal(escapeHtml(`<img src=x onerror="a">'&`), '&lt;img src=x onerror=&quot;a&quot;&gt;&#39;&amp;');
});

test('sanitizeText remove controlos, tags e trunca', () => {
  assert.equal(sanitizeText('hello\x00\x07 <b>world</b>'), 'hello bworld/b');
  assert.equal(sanitizeText('a'.repeat(200), 10), `${'a'.repeat(9)}…`);
  assert.equal(sanitizeText(42), '');
});

test('sanitizeText: texto com exatamente maxLen chars não é truncado', () => {
  assert.equal(sanitizeText('a'.repeat(10), 10), 'a'.repeat(10));
  assert.equal(sanitizeText('a'.repeat(11), 10), `${'a'.repeat(9)}…`);
});

test('sanitizeText: truncar não parte um emoji (par de surrogates) ao meio', () => {
  // o corte cai entre as duas metades do 😀: sai o emoji inteiro, não meio
  assert.equal(sanitizeText('a😀cd', 3), 'a…');
  // o corte cai logo a seguir ao emoji: fica inteiro
  assert.equal(sanitizeText('a😀cd', 4), 'a😀…');
  // surrogate solto na entrada (JSON de fora) não chega ao cliente
  assert.equal(sanitizeText('a\uD83Db'), 'a\uFFFDb');
});

test('sanitizeText remove controlos C1 e controlos bidi', () => {
  // C1: U+0080 e U+009F são os extremos do intervalo; U+009B é o CSI
  assert.equal(sanitizeText('a\u0080b\u009Bc\u009Fd'), 'a b c d');
  // U+00A0 (NBSP) é o primeiro a seguir ao C1: não é controlo, \s colapsa-o
  assert.equal(sanitizeText('a\u00A0b'), 'a b');
  // RLO num user-agent inverteria visualmente o resto no painel
  assert.equal(sanitizeText('curl\u202E1.8/exe'), 'curl1.8/exe');
  assert.equal(sanitizeText('\u200E\u200F\u061C\u202A\u202D\u2066\u2069x'), 'x');
});

test('rate limit: janela fixa bloqueia ao atingir o máximo', () => {
  const cfg = { now: 1000, windowMs: 60_000, max: 2 };
  const s1 = nextState(null, cfg);
  assert.equal(s1.allowed, true);
  const s2 = nextState(s1.state, cfg);
  assert.equal(s2.allowed, true);
  const s3 = nextState(s2.state, cfg);
  assert.equal(s3.allowed, false);
  assert.ok(s3.retryAfterSec > 0);
  // nova janela liberta
  const s4 = nextState(s3.state, { ...cfg, now: 1000 + 60_001 });
  assert.equal(s4.allowed, true);
});

test('rate limit: a janela reinicia no ms exato em que termina, nem antes', () => {
  const cfg = { now: 1000, windowMs: 60_000, max: 1 };
  const cheio = nextState(nextState(null, cfg).state, cfg);
  assert.equal(cheio.allowed, false);
  assert.equal(nextState(cheio.state, { ...cfg, now: 1000 + 59_999 }).allowed, false);
  assert.equal(nextState(cheio.state, { ...cfg, now: 1000 + 60_000 }).allowed, true);
});

test('dailySalt roda por dia UTC', () => {
  const a = dailySalt('sec', Date.parse('2026-07-15T23:00:00Z'));
  const b = dailySalt('sec', Date.parse('2026-07-16T01:00:00Z'));
  assert.notEqual(a, b);
});

// ---------- pwned: k-anonimato (validação de prefixo + parse dos ranges) ----------

test('normalizePrefix: só 5 hex, em maiúsculas', () => {
  assert.equal(normalizePrefix('5baa6'), '5BAA6');
  assert.equal(normalizePrefix('ABCDE'), 'ABCDE');
  assert.equal(normalizePrefix('5BAA'), ''); // 4 dígitos
  assert.equal(normalizePrefix('5BAA61'), ''); // 6 dígitos
  assert.equal(normalizePrefix('5BAAG'), ''); // G não é hex
  assert.equal(normalizePrefix(''), '');
  assert.equal(normalizePrefix(null), '');
  assert.equal(normalizePrefix(12345), '');
});

test('parseRanges: parseia SUFIXO:CONTAGEM, mantém padding (0), descarta lixo', () => {
  const A = 'A'.repeat(35);
  const B = 'b'.repeat(35); // minúsculas → normaliza para maiúsculas
  const body = [
    `${A}:3`,
    `${B}:0`, // padding do Add-Padding — mantém-se
    'GGGG:1', // sufixo demasiado curto e não-hex → cai
    `${'C'.repeat(35)}:-4`, // contagem negativa → cai
    `${'D'.repeat(35)}:xx`, // contagem não numérica → cai
    `${'E'.repeat(34)}:5`, // 34 chars (idx do ':' ≠ 35) → cai
  ].join('\r\n');
  const out = parseRanges(body);
  assert.deepEqual(out, [[A, 3], ['B'.repeat(35), 0]]);
});

test('parseRanges: input inválido e respeito pelo limite', () => {
  assert.deepEqual(parseRanges(42), []);
  assert.deepEqual(parseRanges(''), []);
  const many = Array.from({ length: 10 }, (_, i) => `${'F'.repeat(35)}:${i + 1}`).join('\n');
  assert.equal(parseRanges(many, 3).length, 3);
});

test('pwned-range: prefixo válido relaia os sufixos parseados do HIBP', async () => {
  const env = { KV: fakeKV() };
  const A = 'A'.repeat(35);
  const orig = globalThis.fetch;
  let calledUrl = '';
  globalThis.fetch = async (url) => {
    calledUrl = String(url);
    return { ok: true, status: 200, text: async () => `${A}:7\r\n${'B'.repeat(35)}:0\r\n` };
  };
  try {
    const res = await runFetch(fakeRequest('/api/pwned-range?prefix=5baa6'), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.deepEqual(data.suffixes, [[A, 7], ['B'.repeat(35), 0]]);
    assert.match(calledUrl, /\/range\/5BAA6$/); // prefixo normalizado para maiúsculas
  } finally {
    globalThis.fetch = orig;
  }
});

test('pwned-range: prefixo inválido → 400 sem tocar no upstream', async () => {
  const env = { KV: fakeKV() };
  const orig = globalThis.fetch;
  let hit = false;
  globalThis.fetch = async () => { hit = true; return { ok: true, status: 200, text: async () => '' }; };
  try {
    const res = await runFetch(fakeRequest('/api/pwned-range?prefix=nope'), env);
    assert.equal(res.status, 400);
    assert.equal(hit, false, 'prefixo inválido não pode chegar ao HIBP');
  } finally {
    globalThis.fetch = orig;
  }
});

test('pwned-range: rate limit por cliente devolve 429', async () => {
  const env = { KV: fakeKV() };
  const ip = '203.0.113.60';
  const id = await clientHash(ip, dailySalt(undefined));
  env.KV.store.set(`rl:pwned:${id}`, JSON.stringify({ count: 20, windowStart: Date.now() }));
  const res = await runFetch(fakeRequest('/api/pwned-range?prefix=5BAA6', { ip }), env);
  assert.equal(res.status, 429);
  assert.ok(res.headers.get('retry-after'));
});

// ---------- validação de input (Sessão 6, tarefa 1/5) ----------

test('normalizeCountry: só aceita 2 letras, resto vira XX', () => {
  assert.equal(normalizeCountry('ru'), 'RU');
  assert.equal(normalizeCountry('US'), 'US');
  assert.equal(normalizeCountry('T1'), 'XX'); // Tor exit (letra+dígito)
  assert.equal(normalizeCountry('ATTACKER'), 'XX'); // cabeçalho forjado
  assert.equal(normalizeCountry(''), 'XX');
  assert.equal(normalizeCountry(null), 'XX');
  assert.equal(normalizeCountry(42), 'XX');
});

test('normalizeAsn: inteiro no espaço 32-bit ou null', () => {
  assert.equal(normalizeAsn(64512), 64512);
  assert.equal(normalizeAsn(1), 1);
  assert.equal(normalizeAsn(4_294_967_294), 4_294_967_294);
  assert.equal(normalizeAsn(0), null);
  assert.equal(normalizeAsn(-5), null);
  assert.equal(normalizeAsn(1.5), null);
  assert.equal(normalizeAsn(undefined), null);
});

test('normalizeAsn: aceita a string de dígitos do clientAsn da Cloudflare', () => {
  // O `request.cf.asn` (Espelho) é número, mas o `clientAsn` do
  // firewallEventsAdaptive vem como string — só se aceitar número, todos os
  // `fw:<dia>` ficavam com byAsn {} (foi o que aconteceu em produção).
  assert.equal(normalizeAsn('64512'), 64512);
  assert.equal(normalizeAsn(' 32613 '), 32613);
  assert.equal(normalizeAsn('4294967294'), 4_294_967_294);
  assert.equal(normalizeAsn('0'), null);
  assert.equal(normalizeAsn('4294967295'), null); // fora do espaço 32-bit
  assert.equal(normalizeAsn('AS64512'), null); // já prefixado não é um ASN cru
  assert.equal(normalizeAsn('-5'), null);
  assert.equal(normalizeAsn('12.5'), null);
  assert.equal(normalizeAsn(''), null);
});

// ---------- cap de escritas ao KV (tarefa 6) ----------

test('underCap: bloqueia ao teto e reinicia por janela', () => {
  const cfg = { now: 1000, windowMs: 60_000, max: 2 };
  const s1 = underCap(null, cfg);
  assert.equal(s1.allowed, true);
  assert.equal(s1.state.count, 1);
  const s2 = underCap(s1.state, cfg);
  assert.equal(s2.allowed, true);
  assert.equal(s2.state.count, 2);
  const s3 = underCap(s2.state, cfg);
  assert.equal(s3.allowed, false);
  assert.equal(s3.state.count, 2); // não incrementa acima do teto
  // nova janela liberta e reinicia a contagem
  const s4 = underCap(s3.state, { ...cfg, now: 1000 + 60_001 });
  assert.equal(s4.allowed, true);
  assert.equal(s4.state.count, 1);
});

// ---------- hashing do rate limit por IP+rota (tarefa 2) ----------

test('clientHash: isola por IP e por salt, hex de 16 chars', async () => {
  const salt = dailySalt('sec', Date.parse('2026-07-16T12:00:00Z'));
  const a = await clientHash('203.0.113.7', salt);
  const b = await clientHash('198.51.100.9', salt);
  const c = await clientHash('203.0.113.7', dailySalt('sec', Date.parse('2026-07-17T12:00:00Z')));
  assert.notEqual(a, b); // IPs diferentes → chaves diferentes
  assert.notEqual(a, c); // dia (salt) diferente → chave diferente
  assert.match(a, /^[0-9a-f]{16}$/);
});

// ---------- ipguard: validação de IP público (ADR 0020) ----------

// ---------- integração: fetch() do Worker sem rede ----------

function fakeKV() {
  const store = new Map();
  return {
    store,
    async get(key, type) {
      const v = store.get(key);
      if (v === undefined) return null;
      return type === 'json' ? JSON.parse(v) : v;
    },
    async put(key, value) { store.set(key, value); },
    async delete(key) { store.delete(key); },
  };
}

function fakeRequest(path, { ip, country, asn, method = 'GET' } = {}) {
  const h = new Map([
    ['cf-connecting-ip', ip],
    ['cf-ipcountry', country],
  ]);
  return {
    url: `https://danielmala.co${path}`,
    method,
    headers: { get: (k) => h.get(String(k).toLowerCase()) ?? null },
    cf: { asn, country },
  };
}

async function runFetch(request, env) {
  const tasks = [];
  const ctx = { waitUntil: (p) => tasks.push(p) };
  const res = await worker.fetch(request, env, ctx);
  await Promise.allSettled(tasks); // deixa o trabalho em background (ctx.waitUntil) terminar
  return res;
}

async function runScheduled(env) {
  const tasks = [];
  const ctx = { waitUntil: (p) => tasks.push(p) };
  await worker.scheduled({}, env, ctx);
  await Promise.allSettled(tasks);
}

// ---------- cabeçalhos de segurança das respostas do Worker ----------
// O _headers do Pages não cobre as rotas do Worker — cada resposta tem de
// trazer nosniff + CSP 'none' por si.

test('respostas da API trazem nosniff e CSP none', async () => {
  const env = { KV: fakeKV() };
  const res = await runFetch(fakeRequest('/api/health'), env);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('content-security-policy'), "default-src 'none'");
});

// ---------- cache: stale-while-revalidate ----------

test('cache expirada serve o valor stale e renova em background', async () => {
  const env = { KV: fakeKV() };
  const now = Date.now();
  // valor logicamente expirado, mas ainda presente no KV (janela stale)
  env.KV.store.set('cache:vitals', JSON.stringify({ data: { stale: 42 }, exp: now - 1000 }));

  const res = await runFetch(fakeRequest('/api/vitals'), env);
  const body = await res.json();
  assert.equal(body.stale, 42); // resposta imediata = stale

  // depois do waitUntil, a cache foi renovada (exp no futuro, dados frescos)
  const refreshed = JSON.parse(env.KV.store.get('cache:vitals'));
  assert.ok(refreshed.exp > now, 'refresh em background devia ter renovado o exp');
  assert.equal(refreshed.data.stale, undefined); // recalculado a partir dos histogramas
});

// ---------- rate limit: teto global de escritas do próprio limiter ----------
// Achado da revisão de segurança de 2026-07: um cliente dentro do limite
// por rota (ex.: 30/min em /api/mirror) força uma escrita KV por pedido —
// sem este cap, ~43 mil escritas/dia SÓ NESTA ROTA, muito acima do teto de
// ~1.000/dia da conta inteira no plano Free, esgotando o orçamento que o
// vitals e as caches também precisam.
//
// ATUALIZADO 2026-07-29 (achado A1 da revisão de segurança de 2026-07-29, não publicada): a
// versão original deste teste afirmava `res.status === 200` com o cap
// esgotado — ou seja, com o orçamento de escrita no teto, QUALQUER pedido
// nessa rota passava a ser aceite indefinidamente (o estado por-cliente
// nunca mais era persistido, por isso a janela ficava congelada). Bastavam
// ~300 pedidos triviais (10 min a 30/min num único IP em /api/mirror ou
// /api/vitals, sem precisar de distribuir por várias origens) para desligar
// o rate limit da rota inteira até à meia-noite UTC. Corrigido para falhar
// FECHADO: com o cap esgotado, a rota devolve 429 (sem gastar nenhuma
// escrita extra — o 429 continua "grátis") até o cap global reabrir.

test('rate limit: cap global diário no teto falha fechado (429) sem escrever nada', async () => {
  const kv = fakeKV();
  const env = { KV: kv };
  const now = Date.now();
  // rlcap:d:<dia> — o "d:" vem de dayKey() (mesmo padrão dos outros contadores)
  const capKey = `rlcap:d:${new Date(now).toISOString().slice(0, 10)}`;
  // pré-carrega o cap GLOBAL do rate limiter já no teto (max=300)
  kv.store.set(capKey, JSON.stringify({ count: 300, windowStart: now }));

  let puts = 0;
  const origPut = kv.put.bind(kv);
  kv.put = async (...args) => { puts += 1; return origPut(...args); };

  const logs = [];
  const origError = console.error;
  console.error = (...a) => logs.push(a.map(String).join(' '));
  let res;
  try {
    res = await runFetch(fakeRequest('/api/mirror', { ip: '203.0.113.99' }), env);
  } finally {
    console.error = origError;
  }
  assert.equal(res.status, 429); // A1: falhar fechado, não deixar passar tudo
  assert.ok(res.headers.get('retry-after'), 'devia trazer retry-after mesmo no caminho do cap global');
  assert.equal(puts, 0, 'com o cap global no teto, nenhuma escrita adicional (nem a do cap) deve acontecer');
  assert.ok(logs.some((l) => l.includes('ratelimit_write_cap_exhausted')), 'devia avisar ruidosamente do cap esgotado');
});

test('rate limit: cap global esgotado bloqueia TODOS os clientes da rota, não só quem o esgotou', async () => {
  // A1: o cap é global (não por-cliente) — um segundo IP, nunca antes visto
  // nesta rota, também tem de ser recusado enquanto o orçamento do dia
  // estiver esgotado. Prova que a falha fechada não depende do estado
  // (inexistente) desse cliente específico.
  const kv = fakeKV();
  const env = { KV: kv };
  const now = Date.now();
  const capKey = `rlcap:d:${new Date(now).toISOString().slice(0, 10)}`;
  kv.store.set(capKey, JSON.stringify({ count: 300, windowStart: now }));

  const res = await runFetch(fakeRequest('/api/mirror', { ip: '198.51.100.200' }), env);
  assert.equal(res.status, 429);
});

test('rate limit: abaixo do teto global escreve normalmente e o cap acumula', async () => {
  const env = { KV: fakeKV() };
  const res = await runFetch(fakeRequest('/api/mirror', { ip: '203.0.113.98' }), env);
  assert.equal(res.status, 200);
  const capKey = [...env.KV.store.keys()].find((k) => k.startsWith('rlcap:'));
  assert.ok(capKey, 'devia ter criado o contador do cap global');
  assert.equal(JSON.parse(env.KV.store.get(capKey)).count, 2); // 2 escritas por pedido aceite
  const rlKey = [...env.KV.store.keys()].find((k) => k.startsWith('rl:mirror:'));
  assert.ok(rlKey, 'devia ter persistido o estado por-cliente também');
});

test('RATE_SALT em falta: regista aviso ruidoso mas o pedido continua a ser servido', async () => {
  const env = { KV: fakeKV() }; // sem RATE_SALT
  const logs = [];
  const origError = console.error;
  console.error = (...a) => logs.push(a.map(String).join(' '));
  try {
    const res = await runFetch(fakeRequest('/api/mirror', { ip: '203.0.113.97' }), env);
    assert.equal(res.status, 200);
    assert.ok(logs.some((l) => l.includes('rate_salt_missing')), 'devia avisar da falta do segredo');
  } finally {
    console.error = origError;
  }
});

// ---------- vigia CT: parse do crt.sh e endpoint /api/ct ----------

// Entrada realista do JSON do crt.sh (campos que a lib usa).
function crtshEntry(over = {}) {
  return {
    issuer_ca_id: 295810,
    issuer_name: "C=US, O=Let's Encrypt, CN=R11",
    common_name: 'danielmala.co',
    name_value: 'danielmala.co\n*.danielmala.co',
    id: 130000001,
    entry_timestamp: '2026-07-02T09:00:00.123',
    not_before: '2026-07-02T08:00:00',
    not_after: '2026-09-30T08:00:00',
    serial_number: '04a1b2c3d4e5f60718293a4b5c6d7e8f9012',
    ...over,
  };
}

const CT_NOW = Date.parse('2026-07-17T12:00:00Z');
const CT_OPTS = { domain: 'danielmala.co', now: CT_NOW };

// Os testes do endpoint correm com o relógio real (o /api/ct filtra à janela
// de CT_WINDOW_DAYS a partir de Date.now()), por isso as datas do fixture
// têm de ser relativas a agora — datas fixas expiram e o teste parte sozinho.
function recentCrtshEntry() {
  const crtshDate = (ms) => new Date(ms).toISOString().replace(/Z$/, ''); // crt.sh: sem timezone
  const now = Date.now();
  return crtshEntry({
    entry_timestamp: crtshDate(now - 86400_000),
    not_before: crtshDate(now - 86400_000 - 3600_000),
    not_after: crtshDate(now + 89 * 86400_000),
  });
}

test('issuerLabel: DN do crt.sh → rótulo curto sanitizado', () => {
  assert.equal(issuerLabel("C=US, O=Let's Encrypt, CN=R11"), "Let's Encrypt R11");
  assert.equal(issuerLabel('C=US, O=Google Trust Services, CN=WE1'), 'Google Trust Services WE1');
  assert.equal(issuerLabel('CN=Só CN'), 'Só CN');
  assert.equal(issuerLabel('O=Mesmo, CN=Mesmo'.replace('Mesmo, CN=Mesmo', 'Igual, CN=Igual')), 'Igual');
  assert.equal(issuerLabel('lixo sem DN <b>'), 'lixo sem DN b'); // sanitizado, nunca markup
  assert.equal(issuerLabel(null), '');
});

test('isExpectedIssuer: substring sem caso, contra a allowlist', () => {
  assert.equal(isExpectedIssuer("let's encrypt r11", DEFAULT_EXPECTED_ISSUERS), true);
  assert.equal(isExpectedIssuer('Google Trust Services WE1', DEFAULT_EXPECTED_ISSUERS), true);
  assert.equal(isExpectedIssuer('Encryption Everywhere DV', DEFAULT_EXPECTED_ISSUERS), false);
});

test('parseExpectedIssuers: CSV do env ou a lista por omissão', () => {
  assert.deepEqual(parseExpectedIssuers("Let's Encrypt, ZeroSSL"), ["Let's Encrypt", 'ZeroSSL']);
  assert.deepEqual(parseExpectedIssuers(''), DEFAULT_EXPECTED_ISSUERS);
  assert.deepEqual(parseExpectedIssuers(undefined), DEFAULT_EXPECTED_ISSUERS);
});

test('normalizeCtEntry: só nomes do domínio, sanitizados; fora do domínio → null', () => {
  const cert = normalizeCtEntry(
    crtshEntry({ name_value: 'danielmala.co\n*.danielmala.co\nevil.com\nDANIELMALA.CO' }),
    { domain: 'danielmala.co', expectedIssuers: DEFAULT_EXPECTED_ISSUERS },
  );
  assert.deepEqual(cert.names, ['*.danielmala.co', 'danielmala.co']); // evil.com fora, sem duplicados
  assert.equal(cert.expected, true);
  // "danielmala.co.evil.com" NÃO pertence ao domínio (o sufixo é evil.com)
  const forged = normalizeCtEntry(
    crtshEntry({ name_value: 'danielmala.co.evil.com' }),
    { domain: 'danielmala.co', expectedIssuers: DEFAULT_EXPECTED_ISSUERS },
  );
  assert.equal(forged, null);
});

test('parseCtEntries: dedupe pré-cert/folha, janela de 90d, ordenação e classificação', () => {
  const entries = [
    crtshEntry(), // folha
    crtshEntry({ id: 130000002 }), // pré-certificado: mesmo serial → dedupe
    crtshEntry({
      entry_timestamp: '2026-07-16T10:00:00', not_before: '2026-07-16T09:00:00',
      serial_number: '0badc0ffee', issuer_name: 'C=US, O=DigiCert Inc, CN=Encryption Everywhere DV TLS CA',
      name_value: 'webmail.danielmala.co', common_name: 'webmail.danielmala.co',
    }),
    crtshEntry({
      entry_timestamp: '2026-01-02T09:00:00', not_before: '2026-01-02T08:00:00',
      serial_number: '00ancient',
    }), // fora da janela de 90 dias
  ];
  const certs = parseCtEntries(entries, CT_OPTS);
  assert.equal(certs.length, 2);
  // mais recente primeiro, e é o inesperado
  assert.equal(certs[0].issuer, 'DigiCert Inc Encryption Everywhere DV TLS CA');
  assert.equal(certs[0].expected, false);
  assert.deepEqual(certs[0].names, ['webmail.danielmala.co']);
  assert.equal(certs[1].expected, true);
  assert.equal('serial' in certs[0], false); // o serial não segue para o cliente

  const stats = ctStats(certs);
  assert.deepEqual(stats, { total: 2, issuerCount: 2, nameCount: 3, unexpected: 1 });
});

test('parseCtEntries: datas sem timezone parseiam como UTC (determinístico)', () => {
  const [cert] = parseCtEntries([crtshEntry()], CT_OPTS);
  assert.equal(cert.notBefore, Date.parse('2026-07-02T08:00:00Z'));
  assert.equal(cert.loggedAt, Date.parse('2026-07-02T09:00:00.123Z'));
});

test('/api/ct: junta as duas queries do crt.sh, deduplica e devolve o sumário', async () => {
  const env = { KV: fakeKV(), SCAN_TARGET: 'https://danielmala.co/' };
  const orig = globalThis.fetch;
  const urls = [];
  globalThis.fetch = async (url) => {
    urls.push(String(url));
    // as duas queries devolvem o mesmo certificado — a dedupe trata da sobreposição
    return { ok: true, status: 200, json: async () => [recentCrtshEntry()] };
  };
  try {
    const res = await runFetch(fakeRequest('/api/ct'), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.domain, 'danielmala.co');
    assert.equal(data.certs.length, 1);
    assert.equal(data.summary.unexpected, 0);
    assert.equal(urls.length, 2);
    assert.ok(urls.some((u) => u.includes('q=danielmala.co')), 'query do apex');
    assert.ok(urls.some((u) => u.includes(encodeURIComponent('%.danielmala.co'))), 'query dos subdomínios');
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/ct: uma query falhada degrada para a outra; as duas → 502', async () => {
  const env = { KV: fakeKV(), SCAN_TARGET: 'https://danielmala.co/' };
  const orig = globalThis.fetch;
  let call = 0;
  globalThis.fetch = async () => {
    call += 1;
    if (call === 1) throw new Error('timeout');
    return { ok: true, status: 200, json: async () => [recentCrtshEntry()] };
  };
  try {
    const res = await runFetch(fakeRequest('/api/ct'), env);
    assert.equal(res.status, 200); // parcial vale mais do que nada
    assert.equal((await res.json()).certs.length, 1);
  } finally {
    globalThis.fetch = orig;
  }

  const env2 = { KV: fakeKV(), SCAN_TARGET: 'https://danielmala.co/' };
  globalThis.fetch = async () => { throw new Error('down'); };
  try {
    const res = await runFetch(fakeRequest('/api/ct'), env2);
    assert.equal(res.status, 502); // erro genérico, painel mostra fallback
    assert.deepEqual(await res.json(), { error: 'upstream_error' });
  } finally {
    globalThis.fetch = orig;
  }
});

// ---------- Estado da Cloudflare (/api/cf-stats) ----------

function graphqlFixture({ zoneRows = [], workerRows = [] } = {}) {
  return {
    data: {
      viewer: {
        zones: [{ httpRequests1dGroups: zoneRows }],
        accounts: [{ workersInvocationsAdaptive: workerRows }],
      },
    },
  };
}

test('parseCfStats: soma vários dias e calcula os rácios', () => {
  const raw = graphqlFixture({
    zoneRows: [
      { sum: { requests: 100, cachedRequests: 60, bytes: 1_000_000, threats: 3 } },
      { sum: { requests: 200, cachedRequests: 150, bytes: 2_000_000, threats: 1 } },
    ],
    workerRows: [
      { sum: { requests: 50, errors: 2 } },
      { sum: { requests: 30, errors: 0 } },
    ],
  });
  const stats = parseCfStats(raw, { now: 1_753_200_000_000, windowDays: 7 });
  assert.deepEqual(stats.zone, {
    requests: 300, visitors: 0, cachedRequests: 210, cacheRatio: 210 / 300, bytes: 3_000_000, threats: 4,
    topCountries: [], riskByCountry: [], blockedByStatus: [], series: [],
    firewallByAction: [], firewallBySource: [], firewallByCountry: [],
    firewallByPath: [], firewallByUserAgent: [], firewallByAsn: [],
  });
  assert.deepEqual(stats.worker, { requests: 80, errors: 2, errorRatio: 2 / 80 });
  assert.equal(stats.windowDays, 7);
  assert.equal(stats.fetchedAt, 1_753_200_000_000);
});

test('parseCfStats: shape inesperado ou vazio degrada para zeros, nunca lança', () => {
  assert.deepEqual(parseCfStats({}).zone, {
    requests: 0, visitors: 0, cachedRequests: 0, cacheRatio: 0, bytes: 0, threats: 0,
    topCountries: [], riskByCountry: [], blockedByStatus: [], series: [],
    firewallByAction: [], firewallBySource: [], firewallByCountry: [],
    firewallByPath: [], firewallByUserAgent: [], firewallByAsn: [],
  });
  assert.deepEqual(parseCfStats(null).worker, { requests: 0, errors: 0, errorRatio: 0 });
  assert.deepEqual(parseCfStats({ data: { viewer: {} } }).zone.requests, 0);
  // campo `sum` em falta numa linha não rebenta a soma das outras
  const partial = graphqlFixture({ zoneRows: [{ sum: { requests: 10 } }, {}] });
  assert.equal(parseCfStats(partial).zone.requests, 10);
});

test('parseCfStats: série por dia, visitantes e risk score por país', () => {
  const raw = graphqlFixture({
    zoneRows: [
      {
        dimensions: { date: '2026-07-21' },
        uniq: { uniques: 40 },
        sum: {
          requests: 1000, cachedRequests: 700, bytes: 5_000_000, threats: 10,
          countryMap: [
            { clientCountryName: 'PT', requests: 800, threats: 1 },
            { clientCountryName: 'CN', requests: 200, threats: 90 }, // rácio alto
          ],
        },
      },
      {
        dimensions: { date: '2026-07-20' }, // ordem invertida de propósito
        uniq: { uniques: 35 },
        sum: {
          requests: 500, cachedRequests: 300, bytes: 2_000_000, threats: 4,
          countryMap: [
            { clientCountryName: 'XX', requests: 999, threats: 5 }, // XX fica sempre fora
            { clientCountryName: 'US', requests: 50, threats: 5 }, // < 100 pedidos: entra, mas lowSample
          ],
        },
      },
    ],
  });
  const zone = parseCfStats(raw).zone;
  assert.equal(zone.visitors, 75); // 40 + 35
  // série ordenada do mais antigo para o mais recente
  assert.deepEqual(zone.series.map((d) => d.date), ['2026-07-20', '2026-07-21']);
  assert.equal(zone.series[1].requests, 1000);
  assert.equal(zone.series[1].visitors, 40);
  // risk score: CN com 90/200 = 0.45 (confiante, 1.º); PT 1/800 (confiante);
  // US 5/50 = 0.1 (lowSample — < 100 pedidos), vem DEPOIS de PT apesar de ter
  // taxa mais alta: confiança ordena antes da taxa. XX nunca entra.
  assert.equal(zone.riskByCountry[0].country, 'CN');
  assert.ok(Math.abs(zone.riskByCountry[0].rate - 0.45) < 1e-9);
  assert.equal(zone.riskByCountry[0].lowSample, false);
  assert.ok(!zone.riskByCountry.some((r) => r.country === 'XX'));
  const us = zone.riskByCountry.find((r) => r.country === 'US');
  assert.ok(us, 'US já não é excluído por amostra pequena');
  assert.equal(us.lowSample, true);
  assert.ok(Math.abs(us.rate - 0.1) < 1e-9);
  const ptIndex = zone.riskByCountry.findIndex((r) => r.country === 'PT');
  const usIndex = zone.riskByCountry.findIndex((r) => r.country === 'US');
  assert.ok(ptIndex < usIndex, 'países com amostra suficiente vêm antes dos de amostra pequena');
});

test('parseCfStats: topCountries soma ameaças através dos dias, ordena e filtra XX/zero', () => {
  const raw = graphqlFixture({
    zoneRows: [
      {
        sum: {
          requests: 100, threats: 12,
          countryMap: [
            { clientCountryName: 'CN', requests: 40, threats: 5 },
            { clientCountryName: 'ru', requests: 20, threats: 3 }, // minúsculas normalizam
            { clientCountryName: 'PT', requests: 30, threats: 0 }, // sem ameaças → fora
            { clientCountryName: '??', requests: 5, threats: 9 }, // país inválido → XX → fora
          ],
        },
      },
      {
        sum: {
          requests: 50, threats: 6,
          countryMap: [
            { clientCountryName: 'CN', requests: 10, threats: 2 }, // acumula com o dia anterior
            { clientCountryName: 'US', requests: 40, threats: 4 },
          ],
        },
      },
    ],
  });
  const stats = parseCfStats(raw);
  assert.deepEqual(stats.zone.topCountries, [
    { country: 'CN', threats: 7 },
    { country: 'RU', threats: 3 },
    { country: 'US', threats: 4 },
  ].sort((a, b) => b.threats - a.threats));
});

test('parseCfStats: topCountries corta no limite (mais países do que o topo pedido)', () => {
  const countryMap = Array.from({ length: 15 }, (_, i) => ({
    clientCountryName: String.fromCharCode(65 + i, 65 + i), // AA, BB, CC...
    requests: 10,
    threats: 15 - i, // decrescente, para a ordenação ser previsível
  }));
  const raw = graphqlFixture({ zoneRows: [{ sum: { requests: 150, threats: 120, countryMap } }] });
  const stats = parseCfStats(raw);
  assert.equal(stats.zone.topCountries.length, 10);
  assert.equal(stats.zone.topCountries[0].country, 'AA');
  assert.equal(stats.zone.topCountries[0].threats, 15);
});

test('parseCfStats: blockedByStatus soma por código HTTP, só 4xx/5xx, ordena', () => {
  const raw = graphqlFixture({
    zoneRows: [
      {
        sum: {
          requests: 1000,
          responseStatusMap: [
            { edgeResponseStatus: 200, requests: 500 }, // < 400 → fora
            { edgeResponseStatus: 403, requests: 900 },
            { edgeResponseStatus: 503, requests: 100 },
            { edgeResponseStatus: 302, requests: 300 }, // redirect → fora
          ],
        },
      },
      {
        sum: {
          requests: 500,
          responseStatusMap: [
            { edgeResponseStatus: 403, requests: 474 }, // acumula com o dia anterior
            { edgeResponseStatus: 429, requests: 2 },
            { edgeResponseStatus: 404, requests: 0 }, // zero → fora
          ],
        },
      },
    ],
  });
  const stats = parseCfStats(raw);
  assert.deepEqual(stats.zone.blockedByStatus, [
    { key: '403', count: 1374 }, // 900 + 474
    { key: '503', count: 100 },
    { key: '429', count: 2 },
  ]);
});

test('parseCfStats: blockedByStatus corta no limite e degrada para [] sem o campo', () => {
  const responseStatusMap = Array.from({ length: 15 }, (_, i) => ({
    edgeResponseStatus: 400 + i, // 400, 401, 402… todos >= 400
    requests: 15 - i, // decrescente
  }));
  const raw = graphqlFixture({ zoneRows: [{ sum: { requests: 150, responseStatusMap } }] });
  const stats = parseCfStats(raw);
  assert.equal(stats.zone.blockedByStatus.length, 10);
  assert.deepEqual(stats.zone.blockedByStatus[0], { key: '400', count: 15 });
  // responseStatusMap ausente → []
  assert.deepEqual(parseCfStats(graphqlFixture({ zoneRows: [{ sum: { requests: 5 } }] })).zone.blockedByStatus, []);
});

// Helper: resposta da CF_FIREWALL_QUERY (firewallEventsAdaptive cru).
function firewallFixture(events) {
  return { data: { viewer: { zones: [{ firewallEventsAdaptive: events }] } } };
}

test('firewallBreakdown: agrega os eventos crus por ação e por origem, ordenado', () => {
  const raw = firewallFixture([
    { action: 'managed_challenge', source: 'firewallCustom' },
    { action: 'managed_challenge', source: 'firewallCustom' },
    { action: 'block', source: 'firewallCustom' },
    { action: 'block', source: 'ratelimit' },
    { action: 'block', source: 'ratelimit' },
    { action: 'js_challenge', source: 'bic' },
  ]);
  const fw = firewallBreakdown(raw);
  assert.deepEqual(fw.firewallByAction, [
    { key: 'block', count: 3 },
    { key: 'managed_challenge', count: 2 },
    { key: 'js_challenge', count: 1 },
  ]);
  assert.deepEqual(fw.firewallBySource, [
    { key: 'firewallCustom', count: 3 },
    { key: 'ratelimit', count: 2 },
    { key: 'bic', count: 1 },
  ]);
});

test('firewallBreakdown: pesa por sampleInterval (amostragem), falta/zero conta como 1', () => {
  const raw = firewallFixture([
    { action: 'block', source: 'firewallCustom', sampleInterval: 5 },
    { action: 'block', source: 'firewallCustom', sampleInterval: 5 },
    { action: 'managed_challenge', source: 'ratelimit' }, // sem sampleInterval → 1
    { action: 'skip', source: 'firewallCustom', sampleInterval: 0 }, // 0 → 1
  ]);
  const fw = firewallBreakdown(raw);
  assert.deepEqual(fw.firewallByAction, [
    { key: 'block', count: 10 }, // 5 + 5
    { key: 'managed_challenge', count: 1 },
    { key: 'skip', count: 1 },
  ]);
  assert.deepEqual(fw.firewallBySource, [
    { key: 'firewallCustom', count: 11 }, // 5 + 5 + 1
    { key: 'ratelimit', count: 1 },
  ]);
});

test('firewallBreakdown: campo em falta vira "unknown"; shape ausente/nulo degrada para []', () => {
  const fw = firewallBreakdown(firewallFixture([{ action: 'block' }, { source: 'ratelimit' }]));
  assert.deepEqual(fw.firewallByAction, [{ key: 'block', count: 1 }, { key: 'unknown', count: 1 }]);
  assert.deepEqual(fw.firewallBySource, [{ key: 'unknown', count: 1 }, { key: 'ratelimit', count: 1 }]);
  assert.deepEqual(firewallBreakdown({}).firewallByAction, []);
  assert.deepEqual(firewallBreakdown(null).firewallBySource, []);
});

test('firewallBreakdown: firewallByCountry cruza país com a ação dominante desse país', () => {
  const fw = firewallBreakdown(firewallFixture([
    { action: 'block', source: 'ratelimit', clientCountryName: 'NL' },
    { action: 'block', source: 'ratelimit', clientCountryName: 'NL' },
    { action: 'managed_challenge', source: 'firewallCustom', clientCountryName: 'NL' },
    { action: 'js_challenge', source: 'bic', clientCountryName: 'DE' },
    { action: 'block', source: 'ratelimit', clientCountryName: 'xx' }, // normaliza p/ 'XX' (sentinela): fora
  ]));
  assert.deepEqual(fw.firewallByCountry, [
    { country: 'NL', action: 'block', count: 2 }, // NL: block=2 domina sobre managed_challenge=1
    { country: 'DE', action: 'js_challenge', count: 1 },
  ]);
});

test('firewallDetailBreakdown: agrega por URL, user-agent e ASN, pesado por sampleInterval', () => {
  const raw = firewallFixture([
    { clientRequestPath: '/wp-login.php', userAgent: 'curl/8.0', clientAsn: 64512, sampleInterval: 5 },
    { clientRequestPath: '/wp-login.php', userAgent: 'curl/8.0', clientAsn: 64512, sampleInterval: 5 },
    { clientRequestPath: '/.env', userAgent: 'python-requests/2.31', clientAsn: 64512 }, // sem sampleInterval → 1
    { clientRequestPath: '/.env', userAgent: 'Mozilla/5.0', clientAsn: 4837 },
  ]);
  const fw = firewallDetailBreakdown(raw);
  assert.deepEqual(fw.firewallByPath, [
    { key: '/wp-login.php', count: 10 },
    { key: '/.env', count: 2 },
  ]);
  assert.deepEqual(fw.firewallByUserAgent, [
    { key: 'curl/8.0', count: 10 },
    { key: 'python-requests/2.31', count: 1 },
    { key: 'Mozilla/5.0', count: 1 },
  ]);
  assert.deepEqual(fw.firewallByAsn, [
    { key: 'AS64512', count: 11 },
    { key: 'AS4837', count: 1 },
  ]);
});

test('firewallDetailBreakdown: clientAsn em string (como a Cloudflare o devolve) conta na mesma', () => {
  // Regressão do bug que deixou todos os snapshots `fw:<dia>` de produção
  // com byAsn {} — a query de detalhe corria, mas o ASN era descartado.
  const fw = firewallDetailBreakdown(firewallFixture([
    { clientRequestPath: '/wp-login.php', userAgent: 'curl/8.0', clientAsn: '32613', sampleInterval: 5 },
    { clientRequestPath: '/.env', userAgent: 'curl/8.0', clientAsn: '32613' },
    { clientRequestPath: '/.env', userAgent: 'curl/8.0', clientAsn: 4837 }, // número continua a valer
  ]));
  assert.deepEqual(fw.firewallByAsn, [
    { key: 'AS32613', count: 6 },
    { key: 'AS4837', count: 1 },
  ]);
});

test('firewallDetailBreakdown: nunca processa clientIP (mesmo se viesse na resposta), sanitiza path/UA e ignora ASN inválido', () => {
  const fw = firewallDetailBreakdown(firewallFixture([
    { clientIP: '203.0.113.7', clientRequestPath: '/<script>x</script>', userAgent: 'a'.repeat(200), clientAsn: -1 },
    { clientRequestPath: '', userAgent: '', clientAsn: 0 },
  ]));
  assert.ok(!JSON.stringify(fw).includes('203.0.113.7'));
  assert.equal(fw.firewallByPath[0].key, '/scriptx/script'); // <> removidos por sanitizeText
  assert.equal(fw.firewallByUserAgent[0].key.length, 140); // truncado (139 + '…')
  assert.deepEqual(fw.firewallByAsn, []); // -1 e 0 são inválidos p/ normalizeAsn
});

test('asnNames/withAsnNames: junta a descrição à ASN, sanitiza e ignora ASN inválida ou descrição vazia', () => {
  const names = asnNames(firewallFixture([
    { clientAsn: '16509', clientASNDescription: 'AMAZON-02' },
    { clientAsn: 16509, clientASNDescription: 'outro nome' }, // a primeira vence
    { clientAsn: 4837, clientASNDescription: '<b>CHINA169</b>' },
    { clientAsn: 64512, clientASNDescription: '' },
    { clientAsn: -1, clientASNDescription: 'INVALIDA' },
  ]));
  assert.deepEqual([...names], [['AS16509', 'AMAZON-02'], ['AS4837', 'bCHINA169/b']]);
  assert.deepEqual(
    withAsnNames([{ key: 'AS16509', count: 3 }, { key: 'AS64512', count: 1 }], names),
    [{ key: 'AS16509', count: 3, name: 'AMAZON-02' }, { key: 'AS64512', count: 1 }],
  );
  assert.equal(asnNames(null).size, 0);
});

test('firewallDetailBreakdown: shape ausente/nulo degrada para listas vazias', () => {
  assert.deepEqual(firewallDetailBreakdown({}).firewallByPath, []);
  assert.deepEqual(firewallDetailBreakdown(null).firewallByUserAgent, []);
  assert.deepEqual(firewallDetailBreakdown(firewallFixture([])).firewallByAsn, []);
});

test('/api/cf-stats: o 2.º pedido (firewall) preenche firewallByAction/Source', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const isFw = JSON.parse(init.body).query.includes('firewallEventsAdaptive');
    if (isFw) {
      return { ok: true, json: async () => firewallFixture([
        { action: 'managed_challenge', source: 'firewallCustom' },
        { action: 'managed_challenge', source: 'firewallCustom' },
        { action: 'block', source: 'ratelimit' },
      ]) };
    }
    return { ok: true, json: async () => graphqlFixture({ zoneRows: [{ sum: { requests: 10, threats: 676 } }] }) };
  };
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats'), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.zone.threats, 676);
    assert.deepEqual(data.zone.firewallByAction, [
      { key: 'managed_challenge', count: 2 },
      { key: 'block', count: 1 },
    ]);
    assert.deepEqual(data.zone.firewallBySource, [
      { key: 'firewallCustom', count: 2 },
      { key: 'ratelimit', count: 1 },
    ]);
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/cf-stats: erro só no 2.º pedido (firewall) mantém o núcleo (sem 502)', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const isFw = JSON.parse(init.body).query.includes('firewallEventsAdaptive');
    if (isFw) return { ok: true, json: async () => ({ errors: [{ message: 'does not have access to the path' }] }) };
    return { ok: true, json: async () => graphqlFixture({ zoneRows: [{ sum: { requests: 10, threats: 5 } }] }) };
  };
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats'), env);
    assert.equal(res.status, 200); // núcleo intacto — NÃO 502
    const data = await res.json();
    assert.equal(data.zone.threats, 5);
    assert.deepEqual(data.zone.firewallByAction, []);
    assert.deepEqual(data.zone.firewallBySource, []);
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/cf-stats: o 3.º pedido (firewall detail) preenche firewallByPath/UserAgent/Asn', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const query = JSON.parse(init.body).query;
    if (query.includes('CfFirewallDetail')) {
      return { ok: true, json: async () => firewallFixture([
        { clientRequestPath: '/wp-login.php', userAgent: 'curl/8.0', clientAsn: 64512 },
        { clientRequestPath: '/wp-login.php', userAgent: 'curl/8.0', clientAsn: 64512 },
      ]) };
    }
    if (query.includes('firewallEventsAdaptive')) {
      return { ok: true, json: async () => firewallFixture([{ action: 'block', source: 'ratelimit' }]) };
    }
    return { ok: true, json: async () => graphqlFixture({ zoneRows: [{ sum: { requests: 10, threats: 676 } }] }) };
  };
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats'), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.deepEqual(data.zone.firewallByPath, [{ key: '/wp-login.php', count: 2 }]);
    assert.deepEqual(data.zone.firewallByUserAgent, [{ key: 'curl/8.0', count: 2 }]);
    assert.deepEqual(data.zone.firewallByAsn, [{ key: 'AS64512', count: 2 }]);
    // O 2.º pedido continua intacto — os dois pedidos de firewall são independentes.
    assert.deepEqual(data.zone.firewallByAction, [{ key: 'block', count: 1 }]);
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/cf-stats: erro só no 3.º pedido (firewall detail) não apaga firewallByAction/Source já preenchidos', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const orig = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const query = JSON.parse(init.body).query;
    if (query.includes('CfFirewallDetail')) {
      return { ok: true, json: async () => ({ errors: [{ message: 'schema drift' }] }) };
    }
    if (query.includes('firewallEventsAdaptive')) {
      return { ok: true, json: async () => firewallFixture([{ action: 'block', source: 'ratelimit' }]) };
    }
    return { ok: true, json: async () => graphqlFixture({ zoneRows: [{ sum: { requests: 10, threats: 5 } }] }) };
  };
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats'), env);
    assert.equal(res.status, 200); // núcleo E firewall-ação/origem intactos — NÃO 502
    const data = await res.json();
    assert.deepEqual(data.zone.firewallByAction, [{ key: 'block', count: 1 }]);
    assert.deepEqual(data.zone.firewallByPath, []);
    assert.deepEqual(data.zone.firewallByUserAgent, []);
    assert.deepEqual(data.zone.firewallByAsn, []);
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/threat-intel: funde snapshots fw:<dia> de vários dias em firewall7d.byCountry', async () => {
  const env = { KV: fakeKV() };
  const now = Date.now();
  const fwDayKey = (ms) => `fw:${new Date(ms).toISOString().slice(0, 10)}`;
  const DAY_MS = 86_400_000;
  // Hoje: NL domina com block=3. Ontem: NL também apareceu, mas com
  // managed_challenge=2 — a soma da semana (block=3, managed_challenge=2)
  // tem de continuar a apontar 'block' como a ação dominante de NL.
  env.KV.store.set(fwDayKey(now), JSON.stringify({
    byAction: { block: 3 }, bySource: { ratelimit: 3 },
    byCountry: { NL: { action: 'block', count: 3 }, DE: { action: 'js_challenge', count: 1 } },
    byAsn: { AS1000: 3 },
  }));
  env.KV.store.set(fwDayKey(now - DAY_MS), JSON.stringify({
    byAction: { managed_challenge: 2 }, bySource: { firewallCustom: 2 },
    byCountry: { NL: { action: 'managed_challenge', count: 2 } },
    byAsn: { AS1000: 2, AS2000: 1 },
  }));
  const res = await runFetch(fakeRequest('/api/threat-intel'), env);
  assert.equal(res.status, 200);
  const data = await res.json();
  assert.deepEqual(data.firewall7d.byAction, [{ key: 'block', count: 3 }, { key: 'managed_challenge', count: 2 }]);
  assert.deepEqual(data.firewall7d.byCountry, [
    { country: 'NL', action: 'block', count: 3 },
    { country: 'DE', action: 'js_challenge', count: 1 },
  ]);
  // AS1000 apareceu nos dois dias (3 + 2 = 5) — a soma da semana, não só o
  // último dia, é o que decide a ordenação.
  assert.deepEqual(data.firewall7d.byAsn, [{ key: 'AS1000', count: 5 }, { key: 'AS2000', count: 1 }]);
  // daily: 7 dias (mesmo os sem fotografia), do mais antigo ao mais
  // recente, hoje por último com o byAction cru desse dia.
  assert.equal(data.firewall7d.daily.length, 7);
  assert.equal(data.firewall7d.daily[6].date, new Date(now).toISOString().slice(0, 10));
  assert.deepEqual(data.firewall7d.daily[6].byAction, { block: 3 });
  assert.deepEqual(data.firewall7d.daily[5].byAction, { managed_challenge: 2 });
  assert.deepEqual(data.firewall7d.daily[0].byAction, {});
});

test('/api/cf-stats: 200 com o resumo quando a GraphQL API responde', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const orig = globalThis.fetch;
  let captured;
  globalThis.fetch = async (url, init) => {
    captured = { url: String(url), body: JSON.parse(init.body), auth: init.headers.authorization };
    return {
      ok: true,
      json: async () => graphqlFixture({
        zoneRows: [{ sum: { requests: 10, cachedRequests: 5, bytes: 1000, threats: 0 } }],
        workerRows: [{ sum: { requests: 4, errors: 0 } }],
      }),
    };
  };
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats'), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.zone.requests, 10);
    assert.equal(data.worker.requests, 4);
    assert.equal(captured.auth, 'Bearer tok');
    assert.equal(captured.body.variables.zoneTag, 'zone123');
    assert.equal(captured.body.variables.accountTag, 'acc456');
    assert.equal(captured.body.variables.scriptName, 'personal-site-worker');
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/cf-stats: sem CF_API_TOKEN/IDs configurados → 502 (painel mostra o fallback)', async () => {
  const env = { KV: fakeKV() };
  const res = await runFetch(fakeRequest('/api/cf-stats'), env);
  assert.equal(res.status, 502);
  assert.deepEqual(await res.json(), { error: 'upstream_error' });
});

test('/api/cf-stats?refresh=1: ignora a cache existente e escreve uma entrada nova', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  // cache antiga, ainda válida, sem o campo topCountries (shape pré-refresh)
  env.KV.store.set('cache:cfstats', JSON.stringify({
    data: { zone: { requests: 1 }, worker: {}, fetchedAt: 1 },
    exp: Date.now() + 3600_000,
  }));
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    json: async () => graphqlFixture({ zoneRows: [{ sum: { requests: 99, threats: 5 } }] }),
  });
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats?refresh=1', { ip: '203.0.113.10' }), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.zone.requests, 99); // veio do fetch novo, não da cache antiga
    const stored = JSON.parse(env.KV.store.get('cache:cfstats'));
    assert.equal(stored.data.zone.requests, 99); // a cache ficou atualizada
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/cf-stats: 200 devolve blockedByStatus a partir do responseStatusMap', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({
    ok: true,
    json: async () => graphqlFixture({
      zoneRows: [{ sum: { requests: 10, threats: 676, responseStatusMap: [
        { edgeResponseStatus: 200, requests: 1443 },
        { edgeResponseStatus: 403, requests: 1374 },
      ] } }],
    }),
  });
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats'), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.deepEqual(data.zone.blockedByStatus, [{ key: '403', count: 1374 }]); // 200 fica de fora
  } finally {
    globalThis.fetch = orig;
  }
});

test('/api/cf-stats?refresh=1: rate limit de 3/10min', async () => {
  const kv = fakeKV();
  let puts = 0;
  const origPut = kv.put.bind(kv);
  kv.put = async (...args) => { puts += 1; return origPut(...args); };
  const env = {
    KV: kv,
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const ip = '203.0.113.11';
  const id = await clientHash(ip, dailySalt(undefined));
  kv.store.set(`rl:cfstats:${id}`, JSON.stringify({ count: 3, windowStart: Date.now() }));

  const res = await runFetch(fakeRequest('/api/cf-stats?refresh=1', { ip }), env);
  assert.equal(res.status, 429);
  assert.ok(res.headers.get('retry-after'));
  assert.equal(puts, 0, 'um 429 não pode custar uma escrita KV');
});

// ---------- cap global dos refresh manuais (/api/cf-stats?refresh=1) ----------
// Achado da revisão de segurança 2026-07 (ronda 4, N2): o rate limit por
// cliente (3/10min) desta rota ainda permite até 432 escritas/dia por IP —
// sem cap global, a mesma classe de risco da lacuna #1 (rate limiter), só
// que aplicada tarde de mais a este caminho. O cap em si é global (não
// por-rota) por desenho — ver REFRESH_WRITE_CAP em src/index.js — para
// cobrir sem esforço extra qualquer outra rota de refresh manual futura.

test('/api/cf-stats?refresh=1: cap global no teto degrada para a cache existente, sem novo pedido à GraphQL API', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const now = Date.now();
  const capKey = `refreshcap:d:${new Date(now).toISOString().slice(0, 10)}`;
  env.KV.store.set(capKey, JSON.stringify({ count: 40, windowStart: now })); // teto em escritas (2 por refresh)
  env.KV.store.set('cache:cfstats', JSON.stringify({
    data: { zone: { requests: 7 }, worker: {}, fetchedAt: 1 },
    exp: now + 3600_000,
  }));

  const orig = globalThis.fetch;
  let fetched = false;
  globalThis.fetch = async () => { fetched = true; return { ok: true, json: async () => graphqlFixture({}) }; };
  try {
    const res = await runFetch(fakeRequest('/api/cf-stats?refresh=1', { ip: '203.0.113.204' }), env);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.zone.requests, 7); // veio da cache existente
    assert.equal(fetched, false, 'com o cap partilhado no teto, não deve repetir o pedido à GraphQL API');
  } finally {
    globalThis.fetch = orig;
  }
});

test('cap global dos refresh manuais: acumula entre pedidos, não é por-cliente', async () => {
  const env = {
    KV: fakeKV(),
    CF_API_TOKEN: 'tok', CF_ZONE_TAG: 'zone123', CF_ACCOUNT_ID: 'acc456', CF_WORKER_SCRIPT: 'personal-site-worker',
  };
  const orig = globalThis.fetch;
  globalThis.fetch = async () => ({ ok: true, json: async () => graphqlFixture({}) });
  try {
    const r1 = await runFetch(fakeRequest('/api/cf-stats?refresh=1', { ip: '203.0.113.202' }), env);
    assert.equal(r1.status, 200);
    const capKey = [...env.KV.store.keys()].find((k) => k.startsWith('refreshcap:'));
    assert.ok(capKey, 'devia ter criado o contador global do cap de refresh');
    assert.equal(JSON.parse(env.KV.store.get(capKey)).count, 2); // 2 escritas por refresh (contador + cache)

    // outro cliente (IP diferente, para não bater no rate limit por-cliente)
    const r2 = await runFetch(fakeRequest('/api/cf-stats?refresh=1', { ip: '203.0.113.203' }), env);
    assert.equal(r2.status, 200);
    assert.equal(
      JSON.parse(env.KV.store.get(capKey)).count,
      4,
      'o contador global acumula entre pedidos de clientes diferentes',
    );
  } finally {
    globalThis.fetch = orig;
  }
});

// ---------- Espelho (/api/mirror) ----------

test('serverView: sanitiza, valida país/ASN e devolve o IP de quem pediu', () => {
  const headers = new Map([
    ['user-agent', 'Mozilla/5.0 (X11; Linux) Chrome/126'],
    ['accept-language', 'pt-PT,pt;q=0.9,en;q=0.8'],
    ['referer', 'https://danielmala.co/ferramentas/'],
    ['cf-connecting-ip', '203.0.113.9'],
  ]);
  const get = (k) => headers.get(String(k).toLowerCase()) ?? null;
  const cf = {
    tlsVersion: 'TLSv1.3', tlsCipher: 'AEAD-AES128-GCM-SHA256', httpProtocol: 'HTTP/3',
    country: 'PT', asn: 3243, asOrganization: 'MEO', colo: 'LIS',
  };
  const v = serverView(get, cf);
  assert.equal(v.tlsVersion, 'TLSv1.3');
  assert.equal(v.httpProtocol, 'HTTP/3');
  assert.equal(v.country, 'PT');
  assert.equal(v.asn, 3243);
  assert.equal(v.asOrganization, 'MEO');
  assert.equal(v.refererPresent, true);
  assert.equal(v.ip, '203.0.113.9');
  assert.equal(v.ipVersion, 4);
  // O valor do referer nunca sai — só a presença.
  assert.ok(!JSON.stringify(v).includes('/ferramentas/'));
});

test('serverView: cf-connecting-ip forjado com HTML não é ecoado (fail-closed → null)', () => {
  const v = serverView((k) => (k === 'cf-connecting-ip' ? '<img src=x onerror=alert(1)>' : null));
  assert.equal(v.ip, null);
  assert.equal(v.ipVersion, null);
});

test('normalizeIp: IPv4 — limites dos octetos, zeros à esquerda e listas', () => {
  assert.deepEqual(normalizeIp('255.255.255.255'), { ip: '255.255.255.255', version: 4 });
  assert.deepEqual(normalizeIp('0.0.0.0'), { ip: '0.0.0.0', version: 4 });
  assert.equal(normalizeIp('256.0.0.1'), null);
  assert.equal(normalizeIp('192.0.2.01'), null); // octal ambíguo
  assert.equal(normalizeIp('192.0.2'), null);
  assert.equal(normalizeIp('192.0.2.1.5'), null);
  assert.equal(normalizeIp('192.0.2.1:443'), null);
  assert.equal(normalizeIp('192.0.2.1, 198.51.100.1'), null); // lista à X-Forwarded-For
  assert.equal(normalizeIp(' 192.0.2.1'), null);
  assert.equal(normalizeIp(''), null);
  assert.equal(normalizeIp(null), null);
});

test('normalizeIp: IPv6 — RFC 4291 (::, IPv4 embebido), contagem de grupos e zone ID', () => {
  assert.deepEqual(normalizeIp('2001:DB8::1'), { ip: '2001:db8::1', version: 6 });
  assert.deepEqual(normalizeIp('::'), { ip: '::', version: 6 });
  assert.deepEqual(normalizeIp('::ffff:192.0.2.1'), { ip: '::ffff:192.0.2.1', version: 6 });
  assert.deepEqual(normalizeIp('1:2:3:4:5:6:7:8'), { ip: '1:2:3:4:5:6:7:8', version: 6 });
  assert.deepEqual(normalizeIp('1:2:3:4:5:6:192.0.2.1'), { ip: '1:2:3:4:5:6:192.0.2.1', version: 6 });
  // Comprimento máximo textual de um IPv6 (45 chars) passa; 46 não.
  const max = 'ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255';
  assert.equal(max.length, 45);
  assert.deepEqual(normalizeIp(max), { ip: max, version: 6 });
  assert.equal(normalizeIp(`0${max}`), null);
  assert.equal(normalizeIp('1:2:3:4:5:6:7'), null); // 7 grupos sem ::
  assert.equal(normalizeIp('1:2:3:4:5:6:7:8:9'), null);
  assert.equal(normalizeIp('1:2:3:4::5:6:7:8'), null); // :: com 8 grupos explícitos
  assert.equal(normalizeIp('1::2::3'), null);
  assert.equal(normalizeIp('1:::2'), null);
  assert.equal(normalizeIp(':1:2:3:4:5:6:7'), null);
  assert.equal(normalizeIp('12345::1'), null);
  assert.equal(normalizeIp('1.2.3.4::1'), null); // IPv4 fora da cauda
  assert.equal(normalizeIp('::ffff:256.0.0.1'), null);
  assert.equal(normalizeIp('fe80::1%eth0'), null);
});

test('serverView: país forjado vira XX; ASN inválido vira null; campos vazios null', () => {
  const v = serverView(() => null, { country: 'ZZZ', asn: -1 });
  assert.equal(v.country, 'XX');
  assert.equal(v.asn, null);
  assert.equal(v.userAgent, null);
  assert.equal(v.refererPresent, false);
});

test('serverView: dnt e sec-gpc reconhecidos', () => {
  assert.equal(serverView((k) => (k === 'dnt' ? '1' : null)).dnt, 'dnt');
  assert.equal(serverView((k) => (k === 'sec-gpc' ? '1' : null)).dnt, 'gpc');
  assert.equal(serverView(() => null).dnt, 'unset');
});

test('/api/mirror: 200 com o IP de quem pediu, nada persistido, no-store, e rate limit ao fim de 30/min', async () => {
  const env = { KV: fakeKV(), RATE_SALT: 's' };
  const mkReq = () => ({
    url: 'https://danielmala.co/api/mirror',
    method: 'GET',
    headers: { get: (k) => (String(k).toLowerCase() === 'cf-connecting-ip' ? '198.51.100.7' : String(k).toLowerCase() === 'user-agent' ? 'UA/1.0' : null) },
    cf: { tlsVersion: 'TLSv1.3', country: 'PT', asn: 3243 },
  });
  const res = await runFetch(mkReq(), env);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('cache-control'), 'no-store');
  const body = await res.json();
  assert.equal(body.tlsVersion, 'TLSv1.3');
  assert.equal(body.ip, '198.51.100.7');
  // Devolvido, nunca guardado: nada no KV (chaves ou valores) contém o IP —
  // o rate limit usa só um hash.
  for (const [k, v] of env.KV.store) {
    assert.ok(!`${k}${JSON.stringify(v)}`.includes('198.51.100.7'), `IP persistido em ${k}`);
  }

  // Esgota o balde (já gastámos 1 de 30).
  let last;
  for (let i = 0; i < 40; i++) last = await runFetch(mkReq(), env);
  assert.equal(last.status, 429);
});

// ---------- Threat Intelligence (aggregate.js) ----------

// ---------- mergeFirewall7d (dashboard "Mitigação por dia") ----------

test('mergeFirewall7d: tops iguais ao antigo readFirewall7d embutido no index.js', () => {
  // Mesmo cenário do teste de integração '/api/threat-intel funde snapshots
  // fw:<dia>…' — NL domina hoje com block=3, ontem com managed_challenge=2;
  // a soma da semana continua a apontar 'block' como ação dominante de NL.
  const fw = mergeFirewall7d([
    {
      date: '2026-08-05',
      snap: {
        byAction: { block: 3 }, bySource: { ratelimit: 3 },
        byCountry: { NL: { action: 'block', count: 3 }, DE: { action: 'js_challenge', count: 1 } },
        byAsn: { AS1000: 3 },
      },
    },
    {
      date: '2026-08-04',
      snap: {
        byAction: { managed_challenge: 2 }, bySource: { firewallCustom: 2 },
        byCountry: { NL: { action: 'managed_challenge', count: 2 } },
        byAsn: { AS1000: 2, AS2000: 1 },
      },
    },
  ]);
  assert.deepEqual(fw.byAction, [{ key: 'block', count: 3 }, { key: 'managed_challenge', count: 2 }]);
  assert.deepEqual(fw.byCountry, [
    { country: 'NL', action: 'block', count: 3 },
    { country: 'DE', action: 'js_challenge', count: 1 },
  ]);
  assert.deepEqual(fw.byAsn, [{ key: 'AS1000', count: 5 }, { key: 'AS2000', count: 1 }]);
});

test('mergeFirewall7d: daily fica ordenado do mais antigo para o mais recente, com byAction cru por dia', () => {
  // Entradas passadas fora de ordem (o chamador não garante ordem) e um dia
  // sem fotografia (snap null) — tem de aparecer na mesma, com byAction {}.
  const fw = mergeFirewall7d([
    { date: '2026-08-03', snap: { byAction: { block: 5 } } },
    { date: '2026-08-05', snap: { byAction: { skip: 10, block: 1 } } },
    { date: '2026-08-04', snap: null },
  ]);
  assert.deepEqual(fw.daily, [
    { date: '2026-08-03', byAction: { block: 5 } },
    { date: '2026-08-04', byAction: {} },
    { date: '2026-08-05', byAction: { skip: 10, block: 1 } },
  ]);
});

test('mergeFirewall7d: entrada vazia não rebenta', () => {
  const fw = mergeFirewall7d([]);
  assert.deepEqual(fw.byAction, []);
  assert.deepEqual(fw.byCountry, []);
  assert.deepEqual(fw.daily, []);
});

// ---------- Core Web Vitals (vitals.js) ----------

test('normalizeVitals: aceita válidos, rejeita lixo', () => {
  assert.deepEqual(normalizeVitals({ lcp: 1800, cls: 0.05, inp: 120, ttfb: 300 }), { lcp: 1800, cls: 0.05, inp: 120, ttfb: 300 });
  // campos fora de intervalo caem; string numérica é aceite
  assert.deepEqual(normalizeVitals({ lcp: '2000', cls: -1, inp: 999999999 }), { lcp: 2000 });
  assert.equal(normalizeVitals({ foo: 1 }), null);
  assert.equal(normalizeVitals(null), null);
});

test('vitalsStats: p75 e classificação a partir do histograma', () => {
  const b = emptyVitalsBucket();
  // 4 amostras de LCP: 1000,1000,1000,3000 → p75 (cum≥3) cai no balde 1000 = "good"
  addVitals(b, { lcp: 1000 });
  addVitals(b, { lcp: 1000 });
  addVitals(b, { lcp: 1000 });
  addVitals(b, { lcp: 3000 });
  const stats = vitalsStats([b]);
  assert.equal(stats.samples, 4);
  assert.equal(stats.metrics.lcp.p75, 1000);
  assert.equal(stats.metrics.lcp.rating, 'good');
  // métrica sem amostras → null
  assert.equal(stats.metrics.cls, null);
});

test('vitalsStats: LCP mau classifica poor; merge soma histogramas', () => {
  const b1 = emptyVitalsBucket();
  for (let i = 0; i < 3; i++) addVitals(b1, { lcp: 6000 });
  const b2 = emptyVitalsBucket();
  addVitals(b2, { lcp: 6000 });
  const merged = mergeVitalsBuckets([b1, b2]);
  assert.equal(merged.count, 4);
  const stats = vitalsStats([b1, b2]);
  assert.equal(stats.metrics.lcp.rating, 'poor');
  assert.equal(stats.metrics.lcp.samples, 4);
});

// ---------- auditoria de segurança de 2026-09-25 (não publicada) ----------
// Regressões para os achados do audit: escritas KV a partir de pedidos
// anónimos têm de caber no orçamento diário da conta (~1.000/dia no Free).

/** Cache API falsa (Map por URL), com o mesmo contrato de match/put. */
function fakeEdgeCache() {
  const store = new Map();
  return {
    store,
    async match(url) {
      const v = store.get(String(url));
      return v === undefined ? undefined : new Response(v);
    },
    async put(url, res) { store.set(String(url), await res.text()); },
  };
}

/** Corre `fn` com `caches.default` definido (runtime Cloudflare) e repõe no fim. */
async function withEdgeCache(fn) {
  const cache = fakeEdgeCache();
  const had = Object.prototype.hasOwnProperty.call(globalThis, 'caches');
  const prev = globalThis.caches;
  globalThis.caches = { default: cache };
  try {
    return await fn(cache);
  } finally {
    if (had) globalThis.caches = prev;
    else delete globalThis.caches;
  }
}

/** Conta puts no KV falso, por prefixo da chave. */
function countingKV() {
  const kv = fakeKV();
  kv.puts = {};
  const orig = kv.put.bind(kv);
  kv.put = async (key, ...rest) => {
    const prefix = key.split(':')[0];
    kv.puts[prefix] = (kv.puts[prefix] ?? 0) + 1;
    return orig(key, ...rest);
  };
  kv.total = () => Object.values(kv.puts).reduce((a, b) => a + b, 0);
  return kv;
}

/** Date.now simulado durante `fn`. */
async function withClock(start, fn) {
  const orig = Date.now;
  let t = start;
  Date.now = () => t;
  try {
    return await fn({ advance: (ms) => { t += ms; }, now: () => t });
  } finally {
    Date.now = orig;
  }
}

test('underCap: `cost` conta escritas, não eventos', () => {
  const now = 1_000_000;
  const cfg = { now, windowMs: 1000, max: 10, cost: 4 };
  const a = underCap(null, cfg);
  assert.deepEqual(a, { allowed: true, state: { count: 4, windowStart: now } });
  const b = underCap(a.state, cfg);
  assert.equal(b.state.count, 8);
  // 8 + 4 > 10: recusado, contagem inalterada
  const c = underCap(b.state, cfg);
  assert.equal(c.allowed, false);
  assert.equal(c.state.count, 8);
  // sem cost continua a contar 1 (compatível)
  assert.equal(underCap(null, { now, windowMs: 1000, max: 1 }).state.count, 1);
});

test('cached: GETs públicos repetidos não passam do orçamento diário de escritas (achado médio)', async () => {
  // Reprodução do achado (então com /api/honeypot e /api/map, TTL 60s; hoje
  // /api/vitals, 120s, e /api/threat-intel): cada rota a cada 61s durante
  // 24h simuladas. Antes: ~3.500 puts `cache:*`, sem teto.
  const kv = countingKV();
  const env = { KV: kv, RATE_SALT: 'test' };
  await withClock(Date.parse('2026-09-25T00:00:30Z'), async ({ advance }) => {
    for (let i = 0; i < 24 * 60; i += 1) {
      for (const route of ['/api/vitals', '/api/threat-intel']) {
        const res = await runFetch(fakeRequest(route), env);
        assert.equal(res.status, 200);
      }
      advance(61_000);
      if (Date.now() >= Date.parse('2026-09-26T00:00:00Z')) break;
    }
  });
  // orçamento CACHE_WRITE_CAP = 80 escritas (contador incluído)
  assert.ok(kv.total() <= 80, `puts no KV: ${JSON.stringify(kv.puts)}`);
});

test('cached: com o orçamento esgotado serve o stale sem reescrever', async () => {
  const kv = countingKV();
  const env = { KV: kv };
  const now = Date.now();
  kv.store.set(`cachecap:d:${new Date(now).toISOString().slice(0, 10)}`, JSON.stringify({ count: 80, windowStart: now }));
  kv.store.set('cache:vitals', JSON.stringify({ data: { stale: 42 }, exp: now - 1000 }));
  const logs = [];
  const origError = console.error;
  console.error = (...a) => logs.push(a.map(String).join(' '));
  try {
    const res = await runFetch(fakeRequest('/api/vitals'), env);
    assert.equal((await res.json()).stale, 42);
  } finally {
    console.error = origError;
  }
  assert.equal(kv.total(), 0);
  assert.ok(logs.some((l) => l.includes('cache_write_cap_exhausted')));
});

test('scheduled: o cron aquece as caches mesmo com o orçamento dos pedidos esgotado', async () => {
  const kv = countingKV();
  const env = { KV: kv };
  const now = Date.now();
  kv.store.set(`cachecap:d:${new Date(now).toISOString().slice(0, 10)}`, JSON.stringify({ count: 80, windowStart: now }));
  await runScheduled(env);
  assert.ok(kv.store.has('cache:firewall7d'), 'o cron não passa pelo orçamento dos pedidos');
});

// ---------- ADR 0022: limpeza do que o honeypot interno deixou no KV ----------
// `iplist` guardava IPs de origem publicados (ADR 0020). Com o honeypot fora
// do Worker, o cron tem de os apagar — e, depois disso, não pode gastar
// escritas a cada tick (o teto da conta é ~1.000/dia).

test('scheduled: apaga iplist/recent/meta e a cache antiga de threat-intel (com `ips`)', async () => {
  const kv = countingKV();
  const env = { KV: kv };
  kv.store.set('iplist', JSON.stringify({ '203.0.113.9': { lastSeen: Date.now() } }));
  kv.store.set('recent', JSON.stringify([{ path: '/.env' }]));
  kv.store.set('meta', JSON.stringify({ firstScanTs: 1 }));
  kv.store.set('cache:map', JSON.stringify({ data: {}, exp: Date.now() + 60_000 }));
  kv.store.set('cache:threatintel', JSON.stringify({ data: { ips: [{ ip: '203.0.113.9' }] }, exp: Date.now() + 3600_000 }));
  await runScheduled(env);
  for (const key of ['iplist', 'recent', 'meta', 'cache:map', 'cache:threatintel']) {
    assert.equal(kv.store.has(key), false, key);
  }
  assert.ok(JSON.parse(kv.store.get('cache:firewall7d')).data.firewall7d);
});

test('scheduled: sem nada antigo para apagar, a limpeza não apaga a cache nova nem escreve', async () => {
  const kv = countingKV();
  const deletes = [];
  const origDelete = kv.delete.bind(kv);
  kv.delete = async (key) => { deletes.push(key); return origDelete(key); };
  const env = { KV: kv };
  const fresh = { data: { firewall7d: { byAction: [] } }, exp: Date.now() + 3600_000 };
  kv.store.set('cache:firewall7d', JSON.stringify(fresh));
  await runScheduled(env);
  assert.deepEqual(deletes, []);
  assert.deepEqual(JSON.parse(kv.store.get('cache:firewall7d')), fresh);
});

// O 1.º pedido depois do deploy chega antes do cron: as caches antigas (KV e
// Cache API), ainda dentro do TTL e com IPs, não podem ser servidas.
test('/api/threat-intel: caches de antes do ADR 0022 (KV e Cache API) nunca são servidas', async () => {
  await withEdgeCache(async (cache) => {
    const env = { KV: fakeKV() };
    const legacy = { ips: [{ ip: '203.0.113.9' }], firewall7d: {} };
    env.KV.store.set('cache:threatintel', JSON.stringify({ data: legacy, exp: Date.now() + 3600_000 }));
    const req = fakeRequest('/api/threat-intel');
    cache.store.set(new URL('/api/__cache/threatintel', req.url).href, JSON.stringify(legacy));
    const res = await runFetch(req, env);
    assert.equal(res.status, 200);
    assert.deepEqual(Object.keys(await res.json()), ['firewall7d']);
  });
});

test('/api/threat-intel: só a firewall, nunca IPs', async () => {
  const env = { KV: fakeKV() };
  env.KV.store.set('iplist', JSON.stringify({ '203.0.113.9': { lastSeen: Date.now() } }));
  const res = await runFetch(fakeRequest('/api/threat-intel'), env);
  assert.equal(res.status, 200);
  assert.deepEqual(Object.keys(await res.json()), ['firewall7d']);
});

test('rate limit: com Cache API o estado por-cliente não escreve no KV e continua a limitar', async () => {
  await withEdgeCache(async (cache) => {
    const kv = countingKV();
    const env = { KV: kv, RATE_SALT: 'test' };
    for (let i = 0; i < 30; i += 1) {
      const res = await runFetch(fakeRequest('/api/mirror', { ip: '203.0.113.50' }), env);
      assert.equal(res.status, 200);
    }
    const blocked = await runFetch(fakeRequest('/api/mirror', { ip: '203.0.113.50' }), env);
    assert.equal(blocked.status, 429);
    assert.ok(Number(blocked.headers.get('retry-after')) > 0);
    // outro cliente não é afetado (não há teto global a esgotar)
    const other = await runFetch(fakeRequest('/api/mirror', { ip: '203.0.113.51' }), env);
    assert.equal(other.status, 200);
    assert.equal(kv.total(), 0, `puts no KV: ${JSON.stringify(kv.puts)}`);
    assert.ok([...cache.store.keys()].every((k) => k.startsWith('https://danielmala.co/api/__cache/')));
  });
});

test('pwned-range: cache por prefixo na Cache API, sem escritas no KV', async () => {
  await withEdgeCache(async () => {
    const kv = countingKV();
    const env = { KV: kv, RATE_SALT: 'test' };
    const orig = globalThis.fetch;
    let upstream = 0;
    globalThis.fetch = async () => { upstream += 1; return { ok: true, status: 200, text: async () => 'ABCDEF0123456789ABCDEF0123456789ABC:3\r\n' }; };
    try {
      for (let i = 0; i < 2; i += 1) {
        const res = await runFetch(fakeRequest('/api/pwned-range?prefix=21BD1', { ip: '203.0.113.60' }), env);
        assert.equal(res.status, 200);
      }
    } finally {
      globalThis.fetch = orig;
    }
    assert.equal(upstream, 1, 'o 2.º pedido do mesmo prefixo vem da cache');
    assert.equal(kv.total(), 0);
  });
});

test('orçamento: um só IP, só por caminhos com teto, não passa das escritas diárias da conta (achado baixo)', async () => {
  // Reprodução do achado: 20 prefixos novos/min em /api/pwned-range durante
  // 16 min, do mesmo IP. Antes: 1.141 puts no KV (com os toques nos iscos do
  // honeypot interno, que saiu com o ADR 0022).
  await withEdgeCache(async () => {
    const kv = countingKV();
    const env = { KV: kv, RATE_SALT: 'test' };
    const orig = globalThis.fetch;
    globalThis.fetch = async () => ({ ok: true, status: 200, text: async () => '' });
    try {
      await withClock(Date.parse('2026-09-25T10:00:00Z'), async ({ advance }) => {
        let n = 0x10000;
        for (let m = 0; m < 16; m += 1) {
          for (let i = 0; i < 20; i += 1) {
            n += 1;
            await runFetch(fakeRequest(`/api/pwned-range?prefix=${n.toString(16).toUpperCase()}`, { ip: '8.8.8.8' }), env);
          }
          advance(61_000);
        }
      });
    } finally {
      globalThis.fetch = orig;
    }
    // rate limit e cache por prefixo vivem na Cache API: zero escritas no KV
    assert.equal(kv.total(), 0, `puts no KV: ${JSON.stringify(kv.puts)}`);
    assert.equal(kv.puts.rl ?? 0, 0);
    assert.equal(kv.puts.cache ?? 0, 0);
  });
});

test('edgecache: chave na origem do pedido, JSON ida e volta, lixo → null', async () => {
  const cache = fakeEdgeCache();
  const url = edgeKey('https://danielmala.co/api/mirror?x=1', 'rl:mirror:abc');
  assert.equal(url, 'https://danielmala.co/api/__cache/rl%3Amirror%3Aabc');
  await edgePutJSON(cache, url, { count: 1 }, 0.2);
  assert.deepEqual(await edgeGetJSON(cache, url), { count: 1 });
  cache.store.set(url, 'não é json');
  assert.equal(await edgeGetJSON(cache, url), null);
  assert.equal(await edgeGetJSON(cache, `${url}x`), null);
});

test('POST /api/vitals: falha do rate limiter dá o 204 uniforme, não uma exceção', async () => {
  const env = {
    RATE_SALT: 'test',
    KV: { async get() { throw new Error('kv down'); }, async put() { throw new Error('kv down'); } },
  };
  const req = { ...fakeRequest('/api/vitals', { method: 'POST', ip: '203.0.113.70' }), text: async () => '{}' };
  const origError = console.error;
  console.error = () => {};
  try {
    const res = await runFetch(req, env);
    assert.equal(res.status, 204);
  } finally {
    console.error = origError;
  }
});

// ---------- revisão CodeRabbit do PR #183: Cache API é best-effort ----------

test('edgeCached: falha da Cache API (match/put) não vira 502 — calcula e responde', async () => {
  const broken = {
    async match() { throw new Error('cache down'); },
    async put() { throw new Error('cache down'); },
  };
  const had = Object.prototype.hasOwnProperty.call(globalThis, 'caches');
  const prev = globalThis.caches;
  globalThis.caches = { default: broken };
  const origError = console.error;
  const logs = [];
  console.error = (...a) => logs.push(a.map(String).join(' '));
  try {
    const env = { KV: fakeKV() };
    const res = await runFetch(fakeRequest('/api/vitals'), env);
    assert.equal(res.status, 200);
    assert.equal(typeof (await res.json()), 'object');
    assert.ok(logs.some((l) => l.includes('edge_cache_read_failed')));
    assert.ok(logs.some((l) => l.includes('edge_cache_write_failed')));
  } finally {
    console.error = origError;
    if (had) globalThis.caches = prev;
    else delete globalThis.caches;
  }
});

test('rate limit: falha da Cache API cai no caminho KV (continua a limitar, não dá 502)', async () => {
  const broken = {
    async match() { throw new Error('cache down'); },
    async put() { throw new Error('cache down'); },
  };
  const had = Object.prototype.hasOwnProperty.call(globalThis, 'caches');
  const prev = globalThis.caches;
  globalThis.caches = { default: broken };
  const origError = console.error;
  console.error = () => {};
  try {
    const env = { KV: fakeKV(), RATE_SALT: 'test' };
    const ok = await runFetch(fakeRequest('/api/mirror', { ip: '203.0.113.80' }), env);
    assert.equal(ok.status, 200);
    assert.ok([...env.KV.store.keys()].some((k) => k.startsWith('rl:mirror:')), 'estado por-cliente foi para o KV');
  } finally {
    console.error = origError;
    if (had) globalThis.caches = prev;
    else delete globalThis.caches;
  }
});

test('threat-intel/ct/cf-stats também passam pela Cache API (sem KV em pedidos repetidos)', async () => {
  await withEdgeCache(async (cache) => {
    const env = { KV: countingKV() };
    const now = Date.now();
    env.KV.store.set('cache:ct', JSON.stringify({ data: { items: [] }, exp: now + 3600_000 }));
    let reads = 0;
    const origGet = env.KV.get.bind(env.KV);
    env.KV.get = async (...a) => { reads += 1; return origGet(...a); };
    await runFetch(fakeRequest('/api/ct'), env);
    const readsAfterFirst = reads;
    await runFetch(fakeRequest('/api/ct'), env);
    assert.equal(reads, readsAfterFirst, '2.º pedido servido pela Cache API, sem ler o KV');
    assert.ok([...cache.store.keys()].some((k) => k.endsWith('/api/__cache/ct')));
  });
});
