import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createTerminal } from '../src/scripts/lab-terminal.js';

const ctxPt = {
  lang: 'pt',
  bio: ['linha1', 'linha2'],
  aboutMd: 'Titulo\n\nTexto sobre.',
  roadmap: ['item 1', 'item 2'],
  catalog: {
    totalRepos: 42,
    categories: [{
      name: 'Security tooling', count: 2,
      repos: [
        { stars: 100, name: 'foo', url: 'https://x/foo' },
        { stars: 50, name: 'bar', url: 'https://x/bar' },
      ],
    }],
  },
  projects: [{ slug: 'este-site', title: 'Este Site', url: '/projetos/este-site/' }],
  attack: { prod: 3, exp: 2, total: 5, techniques: [{ id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', level: 'prod' }] },
  evidence: { commitShort: 'abc1234' },
};

test('createTerminal (pt): comandos básicos — help/whoami/clear/vazio', async () => {
  const { exec } = createTerminal(ctxPt);
  assert.deepEqual(await exec(''), { lines: [] });
  assert.deepEqual(await exec('whoami'), { lines: ['linha1', 'linha2'] });
  assert.deepEqual(await exec('clear'), { clear: true });
  const help = await exec('help');
  assert.ok(help.lines.some((l) => l.includes('whoami')));
});

test('createTerminal (pt): ls esconde .flag sem -la, ls projetos lista slugs reais', async () => {
  const { exec } = createTerminal(ctxPt);
  assert.deepEqual(await exec('ls'), { lines: ['sobre.md  roadmap.txt  projetos/  ferramentas/'] });
  assert.deepEqual(await exec('ls -la'), { lines: ['.flag  sobre.md  roadmap.txt  projetos/  ferramentas/'] });
  assert.deepEqual(await exec('ls projetos'), { lines: ['este-site'] });
});

test('createTerminal (pt): cat — flag CTF, ficheiro real, ficheiro em falta, sem argumento', async () => {
  const { exec } = createTerminal(ctxPt);
  assert.deepEqual(await exec('cat .flag'), { lines: ['flag{wh04m1_l4b_pwn3d}'] });
  assert.deepEqual(await exec('cat sobre.md'), { lines: ['Titulo', '', 'Texto sobre.'] });
  assert.deepEqual(await exec('cat nope.txt'), { lines: ['cat: nope.txt: ficheiro não encontrado'] });
  assert.deepEqual(await exec('cat'), { lines: ['uso: cat <ficheiro>'] });
  // a flag também está acessível por um comando não listado no help
  assert.deepEqual(await exec('flag'), { lines: ['flag{wh04m1_l4b_pwn3d}'] });
});

test('createTerminal (pt): subnet delega em calcSubnet/subnet.js e formata as linhas', async () => {
  const { exec } = createTerminal(ctxPt);
  assert.deepEqual(await exec('subnet 192.168.1.10/24'), {
    lines: [
      'rede      192.168.1.0/24',
      'broadcast   192.168.1.255',
      'máscara     255.255.255.0',
      'wildcard    0.0.0.255',
      'hosts       254 (192.168.1.1 → 192.168.1.254)',
      'tipo        private',
    ],
  });
  assert.deepEqual(await exec('subnet nope'), { lines: ['CIDR inválido. Exemplo: subnet 192.168.1.10/24'] });
  assert.deepEqual(await exec('subnet'), { lines: ['uso: subnet <ip/cidr>'] });
});

test('createTerminal (pt): hash — md5 local e sha1 via WebCrypto, algoritmo desconhecido', async () => {
  const { exec } = createTerminal(ctxPt);
  assert.deepEqual(await exec('hash md5 abc'), { lines: ['900150983cd24fb0d6963f7d28e17f72'] }); // RFC 1321
  assert.deepEqual(await exec('hash sha1 abc'), { lines: ['a9993e364706816aba3e25717850c26c9cd0d89d'] }); // FIPS 180
  assert.deepEqual(await exec('hash zz abc'), { lines: ['algoritmo desconhecido. usa: md5 | sha1 | sha256 | sha512'] });
  assert.deepEqual(await exec('hash md5'), { lines: ['uso: hash <md5|sha1|sha256|sha512> <texto>'] });
});

test('createTerminal (pt): encode/decode delegam em encoding.js, formato inválido reporta erro', async () => {
  const { exec } = createTerminal(ctxPt);
  assert.deepEqual(await exec('encode base64 foo'), { lines: ['Zm9v'] }); // RFC 4648
  assert.deepEqual(await exec('decode base64 Zm9v'), { lines: ['foo'] });
  assert.deepEqual(await exec('encode bogus foo'), { lines: ['uso: encode <base64|url|hex> <texto>'] });
  assert.deepEqual(await exec('decode base64 %%'), { lines: ['entrada inválida para este formato'] });
});

test('createTerminal (pt): stars — resumo por categoria, filtro por substring, categoria em falta', async () => {
  const { exec } = createTerminal(ctxPt);
  assert.deepEqual(await exec('stars'), {
    lines: [
      '42 repos · 1 categorias:',
      '  Security tooling               2 repos',
      "usa 'stars <categoria>' para listar.",
    ],
  });
  assert.deepEqual(await exec('stars security'), {
    lines: [
      'Security tooling (2):',
      '  ★    100  foo  https://x/foo',
      '  ★     50  bar  https://x/bar',
    ],
  });
  assert.deepEqual(await exec('stars nope'), { lines: ['categoria não encontrada: nope'] });
});

test('createTerminal (pt): comandos-espelho do site (attack/projetos/honeypot/provas)', async () => {
  const { exec } = createTerminal(ctxPt);
  assert.deepEqual(await exec('attack'), {
    lines: [
      'cobertura MITRE ATT&CK — 3 em produção, 2 em lab (5 técnicas):',
      '  ● T1110   Brute Force  [Credential Access]',
      '● produção · ○ lab — heatmap completo em /attack',
    ],
  });
  assert.deepEqual(await exec('projetos'), { lines: ['1 projetos:', '  Este Site  →  /projetos/este-site/'] });
  const hp = await exec('honeypot');
  assert.ok(hp.lines.some((l) => l.includes('/perimetro')));
  assert.deepEqual(await exec('provas'), {
    lines: ['último commit: abc1234', 'scan aos cabeçalhos ao vivo e workflows em /provas'],
  });
});

test('createTerminal (pt): open válido devolve { open }, inválido dá uso; sudo/exit/desconhecido', async () => {
  const { exec } = createTerminal(ctxPt);
  assert.deepEqual(await exec('open subnets'), { open: 'subnets', lines: ['a abrir subnets…'] });
  assert.deepEqual(await exec('open bogus'), {
    lines: ['uso: open <subnets|hashes|encoder|passwords|email-headers|sobre|roadmap>'],
  });
  assert.deepEqual(await exec('sudo'), {
    lines: ['daniel is not in the sudoers file. This incident will be reported. 🙃'],
  });
  assert.deepEqual(await exec('exit'), { lines: ['não há saída. só há Lab. 😌'] });
  assert.deepEqual(await exec('zzz'), { lines: ["comando não encontrado: zzz (tenta 'help')"] });
});

test('createTerminal (en): mensagens em inglês e "about.md" em vez de "sobre.md"', async () => {
  const ctxEn = { ...ctxPt, lang: 'en' };
  const { exec } = createTerminal(ctxEn);
  assert.deepEqual(await exec('ls'), { lines: ['about.md  roadmap.txt  projetos/  ferramentas/'] });
  assert.deepEqual(await exec('cat about.md'), { lines: ['Titulo', '', 'Texto sobre.'] });
  assert.deepEqual(await exec('zzz'), { lines: ["command not found: zzz (try 'help')"] });
});
