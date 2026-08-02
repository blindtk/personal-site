// Verifica a higiene DNS do domínio de produção (SPF, DMARC, CAA, DNSSEC)
// contra o que está documentado em docs/dns-tls.md — fonte de verdade
// versionada em .github/expected-dns.json, mesmo padrão do
// expected-headers.json. Usa `dig` (não a API dns/ do Node): é o único jeito
// simples de ver a flag `ad` (Authenticated Data) da validação DNSSEC — o
// módulo dns/promises do Node fala com o resolver do SO e não expõe as
// flags da resposta, só os registos já resolvidos.
//
// Duas classes de achado, por desenho (ver comentário no CAA abaixo):
//   - regressão de algo já confirmado correto em docs/dns-tls.md (SPF,
//     DMARC, DNSSEC) → ::error::, falha o job;
//   - lacuna já conhecida e documentada como por-fazer (CAA, hoje) →
//     ::warning::, não falha o job por um TODO que já está registado; passa
//     a ::error:: no dia em que os registos existirem mas não baterem certo
//     com a lista esperada (isso já seria uma regressão nova).
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const cfgPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'expected-dns.json');
const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
const { domain } = cfg;

let hardFailures = 0;
let softFailures = 0;

function dig(args) {
  // args nunca inclui input externo — domain/resolvers vêm só do JSON
  // versionado no repo — mas execFileSync (array de argumentos, sem shell)
  // é a forma correta de qualquer forma.
  try {
    return execFileSync('dig', args, { encoding: 'utf8', timeout: 10_000 });
  } catch (err) {
    return `DIG_ERROR: ${err?.message ?? String(err)}`;
  }
}

// Um valor de TXT pode vir fatiado em várias strings quoted na mesma linha
// (limite de 255 bytes por string do RFC 1035) — junta-as antes de procurar
// `v=spf1`/`v=DMARC1`.
function joinQuotedStrings(line) {
  const parts = [...line.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
  return parts.join('');
}

function digTxt(name) {
  const out = dig(['+short', 'TXT', name]);
  if (out.startsWith('DIG_ERROR')) return { error: out };
  return {
    lines: out.split('\n').map((l) => l.trim()).filter(Boolean).map(joinQuotedStrings),
  };
}

console.log(`A verificar higiene DNS de ${domain}\n`);

// --- SPF ---------------------------------------------------------------
{
  const { lines, error } = digTxt(domain);
  if (error) {
    console.error(`::error::SPF: falha a consultar TXT ${domain} — ${error}`);
    hardFailures += 1;
  } else {
    const spfRecords = lines.filter((l) => l.startsWith('v=spf1'));
    if (spfRecords.length === 0) {
      console.error(`::error::SPF: nenhum registo TXT v=spf1 em ${domain} (docs/dns-tls.md confirma -all — isto é uma regressão, não estava assim).`);
      hardFailures += 1;
    } else if (spfRecords.length > 1) {
      // RFC 7208: mais de um registo SPF é inválido por definição, resolvers tratam como PermError.
      console.error(`::error::SPF: ${spfRecords.length} registos v=spf1 em ${domain} (RFC 7208 permite só um) — ${JSON.stringify(spfRecords)}`);
      hardFailures += 1;
    } else if (cfg.spf.requireHardFail && !spfRecords[0].endsWith('-all')) {
      console.error(`::error::SPF regrediu de -all (falha estrita) para algo mais permissivo: "${spfRecords[0]}"`);
      hardFailures += 1;
    } else {
      console.log(`ok  SPF: ${spfRecords[0]}`);
    }
  }
}

// --- DMARC ---------------------------------------------------------------
{
  const dmarcName = `_dmarc.${domain}`;
  const { lines, error } = digTxt(dmarcName);
  if (error) {
    console.error(`::error::DMARC: falha a consultar TXT ${dmarcName} — ${error}`);
    hardFailures += 1;
  } else {
    const dmarcRecord = lines.find((l) => l.startsWith('v=DMARC1'));
    const policy = /(?:^|;)\s*p=([a-z]+)/i.exec(dmarcRecord ?? '')?.[1]?.toLowerCase();
    if (!dmarcRecord || !policy) {
      console.error(`::error::DMARC: nenhum registo v=DMARC1 válido em ${dmarcName} (docs/dns-tls.md confirma p=reject — isto é uma regressão).`);
      hardFailures += 1;
    } else if (!cfg.dmarc.allowedPolicies.includes(policy)) {
      console.error(`::error::DMARC: política "${policy}" fora do esperado (${cfg.dmarc.allowedPolicies.join('/')}) — "${dmarcRecord}"`);
      hardFailures += 1;
    } else {
      console.log(`ok  DMARC: ${dmarcRecord}`);
    }
  }
}

// --- CAA -------------------------------------------------------------
{
  const out = dig(['+short', 'CAA', domain]);
  if (out.startsWith('DIG_ERROR')) {
    console.error(`::error::CAA: falha a consultar ${domain} — ${out}`);
    hardFailures += 1;
  } else {
    const records = out.split('\n').map((l) => l.trim()).filter(Boolean);
    // Normaliza espaços e a caixa da tag antes de comparar — resolvedores
    // diferentes podem formatar o mesmo registo com espaçamento distinto
    // (achado do CodeRabbit no PR #155: uma diferença cosmética não devia
    // fazer o job falhar).
    const normalize = (r) => r.replace(/\s+/g, ' ').trim().replace(/^(\d+)\s+(\S+)/, (_, flag, tag) => `${flag} ${tag.toLowerCase()}`);
    const expected = cfg.caa.expected.map(normalize);
    const actual = records.map(normalize);
    const actualSet = new Set(actual);
    const missing = expected.filter((v) => !actualSet.has(v));

    if (records.length === 0) {
      // `dig +short` fica em silêncio tanto para NODATA como para
      // SERVFAIL/timeout — sem distinguir os dois, uma falha de resolução
      // real passava disfarçada de "lacuna conhecida" (achado do CodeRabbit
      // no PR #155). Repete sem +short só para ler o `status:`.
      const full = dig(['CAA', domain]);
      const status = /;; ->>HEADER<<-.*status:\s*(\w+)/.exec(full)?.[1];
      if (status !== 'NOERROR') {
        console.error(`::error::CAA: consulta a ${domain} devolveu status ${status ?? 'desconhecido'} (não NOERROR) — falha de resolução.`);
      } else {
        // Já NÃO é a lacuna conhecida (achado do CodeRabbit no PR #156,
        // confirmado): docs/dns-tls.md regista os 7 registos como criados e
        // confirmados em produção a 2026-08-02 — "sem CAA nenhum" hoje é uma
        // regressão total (alguém apagou tudo), não o TODO antigo.
        console.error('::error::CAA: nenhum registo CAA em produção — os 7 documentados em docs/dns-tls.md §1 foram confirmados a existir (2026-08-02); isto é uma regressão, não a lacuna antiga.');
      }
      hardFailures += 1;
    } else if (missing.length > 0) {
      console.error(`::error::CAA: falta(m) ${missing.length} registo(s) da lista documentada em docs/dns-tls.md §1 — ${JSON.stringify(missing)}`);
      hardFailures += 1;
    } else {
      console.log(`ok  CAA: os ${expected.length} registo(s) documentados estão presentes`);
    }

    if (records.length > 0) {
      // Subconjunto, não igualdade exata: a Cloudflare injeta CAs próprias
      // (diversificação do Universal SSL) na resposta autoritativa, fora da
      // lista editável no dashboard — confirmado em produção (2026-08-02,
      // comodoca.com/digicert.com apareceram sem ninguém os ter adicionado
      // manualmente). Mas só os extras JÁ CONHECIDOS (allowedExtra em
      // expected-dns.json) ficam como aviso — qualquer outro extra é uma CA
      // não autorizada a emitir para o domínio, o que o CAA existe
      // precisamente para impedir (achado do CodeRabbit no PR #156,
      // confirmado: um "extra" sem allowlist deixava passar qualquer CA nova
      // sem falhar o job).
      const expectedSet = new Set(expected);
      const allowedExtraSet = new Set((cfg.caa.allowedExtra ?? []).map(normalize));
      const extra = actual.filter((v) => !expectedSet.has(v));
      const knownExtra = extra.filter((v) => allowedExtraSet.has(v));
      const unexpectedExtra = extra.filter((v) => !allowedExtraSet.has(v));
      if (unexpectedExtra.length > 0) {
        console.error(`::error::CAA: ${unexpectedExtra.length} registo(s) extra NÃO reconhecido(s) — fora da lista documentada e fora da diversificação conhecida da Cloudflare — ${JSON.stringify(unexpectedExtra)}`);
        hardFailures += 1;
      }
      if (knownExtra.length > 0) {
        console.log(`::warning::CAA: ${knownExtra.length} registo(s) extra conhecido(s) da Cloudflare (Universal SSL) — ${JSON.stringify(knownExtra)}`);
        softFailures += 1;
      }
    }
  }
}

// --- DNSSEC --------------------------------------------------------------
for (const resolver of cfg.dnssec.resolvers) {
  const out = dig([`@${resolver}`, domain, 'DNSKEY', '+dnssec']);
  if (out.startsWith('DIG_ERROR')) {
    console.error(`::error::DNSSEC (@${resolver}): falha a consultar DNSKEY — ${out}`);
    hardFailures += 1;
    continue;
  }
  const flagsLine = /;; flags:([^;]*);/.exec(out)?.[1] ?? '';
  const hasAd = flagsLine.split(/\s+/).includes('ad');
  // `;; ANSWER:` nunca aparece literalmente — a contagem vem na própria
  // linha de flags (`...; QUERY: 1, ANSWER: 2, ...`); e procurar "DNSKEY"
  // solto no output apanhava a QUESTION SECTION (sempre presente, mesmo com
  // zero respostas), o que fazia uma resposta autenticada NODATA passar como
  // "DNSKEY validado" (achado do CodeRabbit no PR #155, confirmado — testado
  // com um vetor NODATA real). Conta a partir do header e só aceita DNSKEY
  // fora de linhas de comentário/pergunta (que começam por `;`).
  const answerCount = Number(/,\s*ANSWER:\s*(\d+)/.exec(out)?.[1] ?? 0);
  const hasDnskey = answerCount > 0 && out.split('\n').some((l) => !l.startsWith(';') && /\bIN\s+DNSKEY\b/.test(l));
  if (!hasAd || !hasDnskey) {
    console.error(`::error::DNSSEC (@${resolver}): resposta sem a flag "ad" e/ou sem DNSKEY — cadeia de confiança não validada (docs/dns-tls.md §4 confirma "ad" nos dois resolvedores; isto é uma regressão).`);
    hardFailures += 1;
  } else {
    console.log(`ok  DNSSEC (@${resolver}): flag "ad" presente, DNSKEY validado`);
  }
}

console.log('');
if (softFailures > 0) console.log(`${softFailures} aviso(s) — lacuna(s) já documentada(s), ver acima.`);
if (hardFailures > 0) {
  console.error(`::error::${hardFailures} verificação(ões) de DNS falharam.`);
  process.exit(1);
}
console.log('Todas as verificações de DNS (exceto avisos já documentados, se algum) passaram.');
