/**
 * Motor do terminal do Lab — lógica pura (sem DOM) para ser testável em Node.
 *
 * createTerminal(ctx) devolve { exec }, onde exec(input) resolve para:
 *   { lines: string[] }  — texto a imprimir
 *   { clear: true }      — limpar o ecrã
 *   { open: string }     — pedir à UI para abrir uma janela/app
 */

import { calcSubnet, intToIp } from './subnet.js';
import { md5 } from './md5.js';
import { codecs } from './encoding.js';

// Flag de CTF: não aparece no help; descobre-se com `ls -la` + `cat .flag`.
const FLAG = 'flag{wh04m1_l4b_pwn3d}';

const APPS = ['subnets', 'hashes', 'encoder', 'passwords', 'email-headers', 'sobre', 'roadmap'];

async function sha(alg, text) {
  const bytes = new TextEncoder().encode(text);
  const buf = await globalThis.crypto.subtle.digest(alg, bytes);
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function createTerminal(ctx) {
  // ctx: { lang, bio, aboutMd, catalog, host }
  const pt = ctx.lang === 'pt';
  const t = {
    notFound: (cmd) => (pt ? `comando não encontrado: ${cmd} (tenta 'help')` : `command not found: ${cmd} (try 'help')`),
    fileNotFound: (f) => (pt ? `cat: ${f}: ficheiro não encontrado` : `cat: ${f}: no such file`),
    usage: (u) => (pt ? `uso: ${u}` : `usage: ${u}`),
    invalidCidr: pt ? 'CIDR inválido. Exemplo: subnet 192.168.1.10/24' : 'Invalid CIDR. Example: subnet 192.168.1.10/24',
    unknownAlg: pt ? 'algoritmo desconhecido. usa: md5 | sha1 | sha256 | sha512' : 'unknown algorithm. use: md5 | sha1 | sha256 | sha512',
    encodeErr: pt ? 'entrada inválida para este formato' : 'invalid input for this format',
    catNotFound: (c) => (pt ? `categoria não encontrada: ${c}` : `category not found: ${c}`),
    opening: (app) => (pt ? `a abrir ${app}…` : `opening ${app}…`),
    sudo: pt ? 'daniel is not in the sudoers file. This incident will be reported. 🙃' : 'daniel is not in the sudoers file. This incident will be reported. 🙃',
    help: [
      pt ? 'comandos disponíveis:' : 'available commands:',
      '  whoami                     ' + (pt ? '— quem sou' : '— who I am'),
      '  ls [-la]                   ' + (pt ? '— listar ficheiros' : '— list files'),
      `  cat <${pt ? 'ficheiro' : 'file'}>              ` + (pt ? '— mostrar um ficheiro' : '— print a file'),
      '  subnet <ip/cidr>           ' + (pt ? '— calcular subnet (ex: subnet 10.0.0.1/20)' : '— subnet math (e.g. subnet 10.0.0.1/20)'),
      '  hash <alg> <texto>         ' + (pt ? '— md5 | sha1 | sha256 | sha512' : '— md5 | sha1 | sha256 | sha512'),
      '  encode <fmt> <texto>       — base64 | url | hex',
      '  decode <fmt> <texto>       — base64 | url | hex',
      '  stars [categoria]          ' + (pt ? '— catálogo de estrelas do GitHub' : '— GitHub stars catalog'),
      '  attack [--list]            ' + (pt ? '— cobertura MITRE ATT&CK' : '— MITRE ATT&CK coverage'),
      '  projetos                   ' + (pt ? '— listar projetos do site' : '— list the site projects'),
      '  honeypot                   ' + (pt ? '— o que o honeypot apanha' : '— what the honeypot catches'),
      '  provas                     ' + (pt ? '— transparência verificável' : '— verifiable transparency'),
      `  open <${APPS.join('|')}>`,
      '  clear · help',
    ],
  };

  async function exec(raw) {
    const input = raw.trim();
    if (!input) return { lines: [] };
    const [cmd, ...rest] = input.split(/\s+/);
    const arg = rest.join(' ');

    switch (cmd) {
      case 'help':
        return { lines: t.help };

      case 'whoami':
        return { lines: ctx.bio };

      case 'ls': {
        // `ls projetos` (ou projects) lista os slugs dos projetos reais.
        const target = rest.find((a) => !a.startsWith('-'));
        if (target === 'projetos' || target === 'projetos/' || target === 'projects' || target === 'projects/') {
          const slugs = (ctx.projects ?? []).map((p) => p.slug);
          return { lines: [slugs.length ? slugs.join('  ') : '—'] };
        }
        const all = rest.includes('-la') || rest.includes('-a') || rest.includes('-al');
        const files = [pt ? 'sobre.md' : 'about.md', 'roadmap.txt', 'projetos/', 'ferramentas/'];
        if (all) files.unshift('.flag');
        return { lines: [files.join('  ')] };
      }

      case 'cat': {
        if (!arg) return { lines: [t.usage('cat <ficheiro>')] };
        if (arg === '.flag') return { lines: [FLAG] };
        if (arg === 'sobre.md' || arg === 'about.md') return { lines: ctx.aboutMd.split('\n') };
        if (arg === 'roadmap.txt') return { lines: ctx.roadmap };
        return { lines: [t.fileNotFound(arg)] };
      }

      case 'clear':
        return { clear: true };

      case 'subnet': {
        if (!arg) return { lines: [t.usage('subnet <ip/cidr>')] };
        const r = calcSubnet(arg);
        if (!r) return { lines: [t.invalidCidr] };
        return {
          lines: [
            `${pt ? 'rede' : 'network'}      ${intToIp(r.network)}/${r.prefix}`,
            `broadcast   ${intToIp(r.broadcast)}`,
            `${pt ? 'máscara' : 'netmask'}     ${intToIp(r.mask)}`,
            `wildcard    ${intToIp(r.wildcard)}`,
            `hosts       ${r.hosts.toLocaleString()} (${intToIp(r.firstHost)} → ${intToIp(r.lastHost)})`,
            `${pt ? 'tipo' : 'type'}        ${r.kind}${r.special ? ` · ${r.special}` : ''}`,
          ],
        };
      }

      case 'hash': {
        const [alg, ...txt] = rest;
        const text = txt.join(' ');
        if (!alg || !text) return { lines: [t.usage('hash <md5|sha1|sha256|sha512> <texto>')] };
        const a = alg.toLowerCase();
        if (a === 'md5') return { lines: [md5(new TextEncoder().encode(text))] };
        const map = { sha1: 'SHA-1', sha256: 'SHA-256', sha512: 'SHA-512' };
        if (!map[a]) return { lines: [t.unknownAlg] };
        return { lines: [await sha(map[a], text)] };
      }

      case 'encode':
      case 'decode': {
        const [fmt, ...txt] = rest;
        const text = txt.join(' ');
        if (!fmt || !text) return { lines: [t.usage(`${cmd} <base64|url|hex> <texto>`)] };
        const codec = codecs[fmt.toLowerCase()];
        if (!codec) return { lines: [t.usage(`${cmd} <base64|url|hex> <texto>`)] };
        try {
          return { lines: [codec[cmd === 'encode' ? 'encode' : 'decode'](text)] };
        } catch {
          return { lines: [t.encodeErr] };
        }
      }

      case 'stars': {
        if (!arg) {
          const lines = ctx.catalog.categories.map(
            (c) => `  ${c.name.padEnd(28)} ${String(c.count).padStart(3)} repos`,
          );
          return {
            lines: [
              `${ctx.catalog.totalRepos} repos · ${ctx.catalog.categories.length} ${pt ? 'categorias' : 'categories'}:`,
              ...lines,
              pt ? "usa 'stars <categoria>' para listar." : "use 'stars <category>' to list.",
            ],
          };
        }
        const q = arg.toLowerCase();
        const cat = ctx.catalog.categories.find((c) => c.name.toLowerCase().includes(q));
        if (!cat) return { lines: [t.catNotFound(arg)] };
        const lines = cat.repos
          .slice(0, 25)
          .map((r) => `  ★ ${String(r.stars).padStart(6)}  ${r.name}  ${r.url}`);
        if (cat.repos.length > 25) lines.push(`  … +${cat.repos.length - 25}`);
        return { lines: [`${cat.name} (${cat.count}):`, ...lines] };
      }

      // Comandos que espelham secções reais do site (assinatura do terminal
      // como interface unificadora). Todos os dados são estáticos e reais —
      // nada aqui inventa números que dependam de um backend ainda por ligar.
      case 'attack': {
        const a = ctx.attack;
        if (!a || !a.techniques?.length) return { lines: [pt ? 'sem dados ATT&CK.' : 'no ATT&CK data.'] };
        const head = pt
          ? `cobertura MITRE ATT&CK — ${a.prod} em produção, ${a.exp} em lab (${a.total} técnicas):`
          : `MITRE ATT&CK coverage — ${a.prod} in production, ${a.exp} in lab (${a.total} techniques):`;
        const rows = a.techniques.map(
          (te) => `  ${te.level === 'prod' ? '●' : '○'} ${te.id.padEnd(7)} ${te.name}  [${te.tactic}]`,
        );
        return { lines: [head, ...rows, pt ? '● produção · ○ lab — heatmap completo em /attack' : '● production · ○ lab — full heatmap at /attack'] };
      }

      case 'projetos':
      case 'projects': {
        const list = ctx.projects ?? [];
        if (!list.length) return { lines: [pt ? 'sem projetos.' : 'no projects.'] };
        const rows = list.map((p) => `  ${p.title}  →  ${p.url}`);
        return {
          lines: [pt ? `${list.length} projetos:` : `${list.length} projects:`, ...rows],
        };
      }

      case 'honeypot': {
        return {
          lines: pt
            ? [
                'honeypot — endpoints-isco que registam scan automático (só metadados:',
                'país, ASN e path; nenhum IP é armazenado).',
                'o painel ao vivo precisa do Worker publicado — código e garantia de',
                'privacidade no repositório. detalhes em /honeypot',
              ]
            : [
                'honeypot — decoy endpoints that log automated scanning (metadata',
                'only: country, ASN and path; no IP is ever stored).',
                'the live panel needs the Worker published — code and privacy',
                'guarantee in the repo. details at /honeypot',
              ],
        };
      }

      case 'provas':
      case 'evidence': {
        const e = ctx.evidence;
        const lines = [];
        if (e?.commitShort) {
          lines.push(pt ? `último commit: ${e.commitShort}` : `latest commit: ${e.commitShort}`);
          if (e.commitUrl) lines.push(`  ${e.commitUrl}`);
        }
        lines.push(
          pt
            ? 'scan aos cabeçalhos ao vivo e workflows em /provas'
            : 'live header scan and workflows at /evidence',
        );
        return { lines };
      }

      case 'open': {
        if (!APPS.includes(arg)) return { lines: [t.usage(`open <${APPS.join('|')}>`)] };
        return { open: arg, lines: [t.opening(arg)] };
      }

      case 'sudo':
        return { lines: [t.sudo] };

      // Não listado em `help` nem em APPS — descobre-se a jogar (ls -la /
      // cat .flag já revelam o mesmo valor; isto é só outro caminho até lá).
      case 'flag':
        return { lines: [FLAG] };

      case 'exit':
        return { lines: [pt ? 'não há saída. só há Lab. 😌' : "there's no exit. only Lab. 😌"] };

      default:
        return { lines: [t.notFound(cmd)] };
    }
  }

  return { exec };
}
