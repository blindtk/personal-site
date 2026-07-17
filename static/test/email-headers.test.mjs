import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  unfoldHeaders,
  stripComments,
  extractAddress,
  domainOf,
  domainsAligned,
  parseReceived,
  parseAuthResults,
  verdictClass,
  formatDelay,
  analyze,
} from '../src/scripts/email-headers.js';

// ---------------------------------------------------------------- unfold

test('unfoldHeaders: desdobra folding e pára no corpo', () => {
  const raw =
    'Subject: uma linha\r\n muito comprida\r\nFrom: a@example.org\r\n\r\nCorpo: nao e cabecalho\r\n';
  const h = unfoldHeaders(raw);
  assert.equal(h.length, 2);
  assert.deepEqual(h[0], { name: 'Subject', value: 'uma linha muito comprida' });
  assert.deepEqual(h[1], { name: 'From', value: 'a@example.org' });
});

test('unfoldHeaders: ignora a linha mbox "From " e aceita LF puro', () => {
  const h = unfoldHeaders('From x@y Sat Jan  3 01:05:34 1996\nTo: b@example.org\n');
  assert.equal(h.length, 1);
  assert.equal(h[0].name, 'To');
});

test('unfoldHeaders: input vazio ou sem cabeçalhos devolve []', () => {
  assert.deepEqual(unfoldHeaders(''), []);
  assert.deepEqual(unfoldHeaders('isto nao tem dois pontos'), []);
});

// ---------------------------------------------------------------- básicos

test('stripComments: remove comentários aninhados', () => {
  assert.equal(stripComments('pass (mx.example.org: domain (nested) ok) x'), 'pass x');
});

test('extractAddress + domainOf', () => {
  assert.equal(extractAddress('Daniel <Daniel@Example.ORG>'), 'daniel@example.org');
  assert.equal(extractAddress('bounce@esp.example.net (bounces)'), 'bounce@esp.example.net');
  assert.equal(extractAddress(null), null);
  assert.equal(domainOf('a@sub.example.org'), 'sub.example.org');
});

test('domainsAligned: relaxado (subdomínio conta)', () => {
  assert.ok(domainsAligned('mail.example.org', 'example.org'));
  assert.ok(domainsAligned('example.org', 'example.org'));
  assert.ok(!domainsAligned('example.org', 'example.net'));
});

test('verdictClass: mapeia tokens RFC 8601', () => {
  assert.equal(verdictClass('pass'), 'pass');
  assert.equal(verdictClass('fail'), 'fail');
  assert.equal(verdictClass('permerror'), 'fail');
  assert.equal(verdictClass('softfail'), 'soft');
  assert.equal(verdictClass('none'), 'none');
  assert.equal(verdictClass(null), 'none');
});

test('formatDelay', () => {
  assert.equal(formatDelay(42), '+42s');
  assert.equal(formatDelay(3700), '+1h 1m');
  assert.equal(formatDelay(-90), '-1m 30s');
  assert.equal(formatDelay(null), '—');
});

// ---------------------------------------------------------------- Received

test('parseReceived: estilo Postfix com IP no comentário', () => {
  const r = parseReceived(
    'from mail.example.org (mail.example.org [203.0.113.5]) by mx.example.net (Postfix) with ESMTPS id 4XYZ for <dest@example.net>; Tue, 1 Jul 2025 10:00:05 +0000',
  );
  assert.equal(r.from, 'mail.example.org');
  assert.deepEqual(r.fromIps, ['203.0.113.5']);
  assert.equal(r.hasPrivateIp, false);
  assert.equal(r.by, 'mx.example.net');
  assert.equal(r.proto, 'ESMTPS');
  assert.equal(r.tls, true);
  assert.equal(r.for, 'dest@example.net');
  assert.equal(r.date.toISOString(), '2025-07-01T10:00:05.000Z');
});

test('parseReceived: estilo Exchange (comentário no with, data com dia)', () => {
  const r = parseReceived(
    'from AS8PR07MB1234.eurprd07.prod.outlook.com (2603:10a6:20b::16) by DB9PR07MB5678.eurprd07.prod.outlook.com with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE) id 15.20.7677.24; Tue, 1 Jul 2025 10:01:00 +0000',
  );
  assert.equal(r.by, 'DB9PR07MB5678.eurprd07.prod.outlook.com');
  assert.equal(r.date.toISOString(), '2025-07-01T10:01:00.000Z');
});

test('parseReceived: primeiro hop sem cláusula from', () => {
  const r = parseReceived('by mail.example.org (Postfix, from userid 33) id ABC123; Tue, 1 Jul 2025 09:59:00 +0000');
  assert.equal(r.from, null);
  assert.equal(r.by, 'mail.example.org');
});

test('parseReceived: IP privado no hop de submissão', () => {
  const r = parseReceived(
    'from [192.168.1.50] (unknown [198.51.100.7]) by smtp.example.org with ESMTPSA id Q1; Tue, 1 Jul 2025 09:58:00 +0000',
  );
  assert.equal(r.hasPrivateIp, true);
  assert.ok(r.fromIps.includes('198.51.100.7'));
});

// ------------------------------------------------- Authentication-Results

test('parseAuthResults: RFC 8601 com props e comentários', () => {
  const a = parseAuthResults(
    'mx.google.com; spf=pass (google.com: domain of x@example.org designates 203.0.113.5 as permitted sender) smtp.mailfrom=x@example.org; dkim=pass header.i=@example.org header.d=example.org header.s=sel1; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=example.org',
  );
  assert.equal(a.authserv, 'mx.google.com');
  assert.equal(a.results.length, 3);
  const spf = a.results.find((r) => r.method === 'spf');
  assert.equal(spf.result, 'pass');
  assert.equal(spf.props['smtp.mailfrom'], 'x@example.org');
  const dkim = a.results.find((r) => r.method === 'dkim');
  assert.equal(dkim.props['header.d'], 'example.org');
});

// ---------------------------------------------------------------- analyze

const LEGIT = [
  'Delivered-To: dest@example.net',
  'Received: from mail-sor-f41.example.org (mail-sor-f41.example.org [203.0.113.41])',
  '        by mx.example.net with ESMTPS id abc123',
  '        for <dest@example.net>;',
  '        Tue, 1 Jul 2025 10:00:35 +0000',
  'Received: from smtp.example.org (smtp.example.org [203.0.113.5])',
  '        by mail-sor-f41.example.org with ESMTPS id def456;',
  '        Tue, 1 Jul 2025 10:00:05 +0000',
  'Received: from [10.0.0.7] (client.isp.example [198.51.100.7])',
  '        by smtp.example.org with ESMTPSA id ghi789;',
  '        Tue, 1 Jul 2025 10:00:00 +0000',
  'Authentication-Results: mx.example.net;',
  '        spf=pass smtp.mailfrom=sender@example.org;',
  '        dkim=pass header.d=example.org;',
  '        dmarc=pass header.from=example.org',
  'DKIM-Signature: v=1; a=rsa-sha256; d=example.org; s=sel1; h=from:to:subject;',
  '        bh=xxxx; b=yyyy',
  'Message-ID: <20250701.abc@smtp.example.org>',
  'Date: Tue, 1 Jul 2025 09:59:58 +0000',
  'From: Remetente <sender@example.org>',
  'To: dest@example.net',
  'Subject: Relatorio semanal',
  'Return-Path: <sender@example.org>',
].join('\n');

test('analyze: email legítimo — tudo pass, hops cronológicos, sem flags graves', () => {
  const r = analyze(LEGIT);
  assert.ok(r);
  assert.equal(r.summary.from, 'sender@example.org');
  assert.equal(r.summary.subject, 'Relatorio semanal');
  assert.equal(r.hops.length, 3);
  // Cronológico: o último Received do cabeçalho é o primeiro hop.
  assert.equal(r.hops[0].by, 'smtp.example.org');
  assert.equal(r.hops[2].by, 'mx.example.net');
  assert.equal(r.hops[1].delaySeconds, 5);
  assert.equal(r.hops[2].delaySeconds, 30);
  assert.equal(r.auth.spf.class, 'pass');
  assert.equal(r.auth.dkim.class, 'pass');
  assert.equal(r.auth.dmarc.class, 'pass');
  assert.equal(r.auth.dkim.domain, 'example.org');
  assert.ok(!r.flags.some((f) => f.level === 'bad'));
  assert.ok(!r.flags.some((f) => f.id === 'fromReturnMismatch'));
});

test('analyze: spoof — From forjado, SPF fail, Reply-To divergente', () => {
  const raw = [
    'Received: from bad.example.xyz (bad.example.xyz [203.0.113.99]) by mx.example.net with ESMTP id z1; Tue, 1 Jul 2025 10:00:00 +0000',
    'Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=x@bad.example.xyz; dkim=none; dmarc=fail header.from=bank.example.com',
    'From: "O Teu Banco" <alerta@bank.example.com>',
    'Reply-To: resposta@bad.example.xyz',
    'To: dest@example.net',
    'Subject: Conta suspensa',
    'Return-Path: <x@bad.example.xyz>',
    'Message-ID: <1@bad.example.xyz>',
  ].join('\n');
  const r = analyze(raw);
  const ids = r.flags.map((f) => f.id);
  assert.ok(ids.includes('authFail'));
  assert.ok(ids.includes('fromReturnMismatch'));
  assert.ok(ids.includes('replyToDivergent'));
  assert.equal(r.flags.find((f) => f.id === 'authFail' && f.params.method === 'SPF').level, 'bad');
  assert.equal(r.auth.spf.class, 'fail');
  assert.equal(r.auth.dmarc.class, 'fail');
});

test('analyze: Authentication-Results injetado — usa só o do topo e avisa', () => {
  const raw = [
    'Received: from bad.example.xyz (bad.example.xyz [203.0.113.99]) by mx.example.net with ESMTP id z1; Tue, 1 Jul 2025 10:00:00 +0000',
    'Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=x@bad.example.xyz',
    'Authentication-Results: forjado.example.xyz; spf=pass; dkim=pass; dmarc=pass',
    'From: alerta@bank.example.com',
    'Message-ID: <1@bad.example.xyz>',
  ].join('\n');
  const r = analyze(raw);
  assert.equal(r.auth.count, 2);
  assert.equal(r.auth.authserv, 'mx.example.net');
  assert.equal(r.auth.spf.class, 'fail'); // o injetado (pass) foi ignorado
  assert.ok(r.flags.some((f) => f.id === 'multipleAuth'));
});

test('analyze: timestamps a andar para trás geram flag hopBackwards', () => {
  const raw = [
    'Received: from b.example.org by c.example.net with ESMTP id x2; Tue, 1 Jul 2025 09:00:00 +0000',
    'Received: from a.example.org by b.example.org with ESMTP id x1; Tue, 1 Jul 2025 10:00:00 +0000',
    'From: a@example.org',
    'Message-ID: <1@example.org>',
  ].join('\n');
  const r = analyze(raw);
  assert.equal(r.hops[1].delaySeconds, -3600);
  assert.ok(r.flags.some((f) => f.id === 'hopBackwards'));
});

test('analyze: Received-SPF serve de fallback e ausências geram flags informativas', () => {
  const raw = [
    'Received-SPF: pass (mx.example.net: domain of x@example.org designates 203.0.113.5 as permitted sender)',
    'From: x@example.org',
    'Subject: sem received',
  ].join('\n');
  const r = analyze(raw);
  assert.equal(r.auth.spf.result, 'pass');
  assert.equal(r.auth.spf.source, 'received-spf');
  assert.ok(r.flags.some((f) => f.id === 'noMessageId'));
  assert.ok(r.flags.some((f) => f.id === 'noHops'));
});

test('analyze: DKIM pass mas de domínio não alinhado com o From', () => {
  const raw = [
    'Received: from esp.example.net by mx.example.org with ESMTPS id q1; Tue, 1 Jul 2025 10:00:00 +0000',
    'Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=b@esp.example.net; dkim=pass header.d=esp.example.net; dmarc=none',
    'From: news@marca.example.com',
    'Return-Path: <b@esp.example.net>',
    'Message-ID: <1@esp.example.net>',
  ].join('\n');
  const r = analyze(raw);
  assert.ok(r.flags.some((f) => f.id === 'dkimMisaligned'));
  assert.ok(r.flags.some((f) => f.id === 'fromReturnMismatch'));
});

test('analyze: texto sem cabeçalhos devolve null', () => {
  assert.equal(analyze('ola, isto e so texto'), null);
  assert.equal(analyze(''), null);
});
