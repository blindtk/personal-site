// Fecha o loop deteção → alerta que faltava (discutido numa revisão de
// segurança, 2026-07-29): os dashboards do honeypot/threat-intel/CT/CF são
// só PULL — mostram dados quando alguém abre a página de propósito, mas
// nada avisa ninguém quando algo parte. Isto é a peça que falta: verifica
// os endpoints de leitura do Worker e devolve exit 1 se algo estiver
// genuinamente errado, para o workflow (invariants.yml) poder abrir uma
// Issue que chega ao dono do repo sem ele ter de ir procurar.
//
// Alvo, mesmo padrão do check-headers.mjs:
//   1. TARGET_URL — input manual do workflow_dispatch
//   2. PROD_URL   — constante em scripts/lib/target.mjs (porquê em código e
//      não no `url` do expected-headers.json: ver o topo desse módulo)
// (sem DEPLOY_URL: este script não corre em deployment_status, só agendado
// e à mão — o alvo é sempre a produção, nunca uma preview.)
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  configUrlMismatch,
  isProductionConfigured,
  isTrustedTarget,
  resolveTarget,
} from './lib/target.mjs';

const cfgPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'expected-headers.json');
const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));

const mismatch = configUrlMismatch(cfg.url);
if (mismatch) {
  console.error(`::error::check-invariants: ${mismatch}`);
  process.exit(1);
}

if (!process.env.TARGET_URL && !isProductionConfigured(cfg.url)) {
  // Mesma decisão do check-headers.mjs: enquanto a Access bloquear pedidos
  // não autenticados, não há nada real para verificar — um erro aqui
  // mascararia a Access com "produção está partida". ::warning:: (não
  // ::notice::) para ficar visível na lista de execuções.
  console.log('::warning::check-invariants: URL de produção por definir em .github/expected-headers.json — verificação IGNORADA (nada foi verificado nesta execução).');
  process.exit(0);
}

const targetUrl = resolveTarget(process.env.TARGET_URL);
if (targetUrl === null) {
  console.error('::error::check-invariants: alvo não é um URL válido (TARGET_URL).');
  process.exit(1);
}
const target = targetUrl.href;

const ACCESS_CLIENT_ID = process.env.ACCESS_CLIENT_ID || '';
const ACCESS_CLIENT_SECRET = process.env.ACCESS_CLIENT_SECRET || '';
const accessHeaders = ACCESS_CLIENT_ID && ACCESS_CLIENT_SECRET
  ? { 'CF-Access-Client-Id': ACCESS_CLIENT_ID, 'CF-Access-Client-Secret': ACCESS_CLIENT_SECRET }
  : {};

// Segredo do bypass da regra WAF "CI headers check" (docs/cloudflare-
// deploy.md §5, regra 2) — ver o comentário equivalente em
// check-headers.mjs. Esta cobertura era o achado que faltava: a regra WAF
// só reconhecia o User-Agent "headers-check" (só check-headers.mjs), nunca
// o deste script — depois do lançamento, este workflow cairia na política
// de país e passaria a reportar produção partida por causa do próprio WAF,
// não de um invariante real. O mesmo segredo cobre os dois scripts.
const CI_WAF_TOKEN = process.env.CI_WAF_TOKEN || '';
const wafHeaders = CI_WAF_TOKEN ? { 'x-ci-waf-token': CI_WAF_TOKEN } : {};

// Mesma razão e mesma lógica do fetchSameOrigin em check-headers.mjs:
// CF-Access-Client-Id/Secret não são despidos pelo Fetch spec em redirects
// cross-origin, ao contrário de Authorization.
async function fetchSameOrigin(url, opts, maxRedirects = 5) {
  let current = new URL(url);
  const originalOrigin = current.origin;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    // eslint-disable-next-line no-await-in-loop -- saltos são sequenciais (cada um depende do Location do anterior)
    const res = await fetch(current, { ...opts, redirect: 'manual' });
    const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
    if (!location) return res;
    const next = new URL(location, current);
    if (next.origin !== originalOrigin) return res;
    current = next;
  }
  return fetch(current, { ...opts, redirect: 'manual' });
}

// Mesma allowlist do check-headers.mjs (scripts/lib/target.mjs), aplicada
// aqui por consistência: TARGET_URL só vem de workflow_dispatch manual (sem
// DEPLOY_URL neste script — ver comentário no topo), mas os segredos só
// devem sair para HTTPS e a origem de produção, ou para um preview do
// projeto Cloudflare Pages deste site (nunca qualquer *.pages.dev).
const trustedHost = isTrustedTarget(targetUrl);
const sendAccessHeaders = trustedHost ? accessHeaders : {};
const sendWafHeaders = trustedHost ? wafHeaders : {};
if (!trustedHost && (accessHeaders['CF-Access-Client-Id'] || wafHeaders['x-ci-waf-token'])) {
  console.log(`::warning::check-invariants: alvo (${targetUrl.origin}) fora da allowlist de produção/preview — segredos de Access/WAF NÃO enviados.`);
}

const UPSTREAM_TIMEOUT_MS = 8000;
const headers = { 'user-agent': 'check-invariants (GitHub Actions; personal-site)', ...sendAccessHeaders, ...sendWafHeaders };

async function checkJson(path) {
  const url = new URL(path, target);
  try {
    const res = await fetchSameOrigin(url, { headers, signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) });
    if (res.status === 429) {
      // Rate limit a bloquear-nos é a proteção a funcionar, não uma falha —
      // seria irónico marcar como "produção partida" o próprio controlo que
      // a revisão de segurança pediu para reforçar (achado A1).
      return { path, ok: true, status: 429, note: 'rate limited (comportamento esperado)' };
    }
    if (!res.ok) return { path, ok: false, status: res.status, note: `HTTP ${res.status}` };
    let body;
    try {
      body = await res.json();
    } catch {
      return { path, ok: false, status: res.status, note: 'resposta não é JSON válido' };
    }
    return { path, ok: true, status: res.status, body };
  } catch (err) {
    return { path, ok: false, status: null, note: err?.message ?? String(err) };
  }
}

// /api/health é o único invariante CRÍTICO: não depende de nenhum upstream
// de terceiros (NVD/CISA/crt.sh/HIBP/GraphQL da Cloudflare) — se falhar, o
// Worker em si está fora do ar, não é uma API externa lenta.
const CRITICAL = ['/api/health'];

// Leituras seguras (GET, sem efeitos secundários, sem consumir orçamento de
// escrita nenhum — ver dynamic/PLAN.md sobre os caps diários). Falhas aqui
// entram no relatório mas só falham o job se ACOMPANHADAS de /api/health
// também falhar, ou se mais de uma destas falhar ao mesmo tempo (um único
// feed a montante instável não deve acordar ninguém às 3h; duas ou mais
// rotas diferentes a partir ao mesmo tempo já cheira a problema real do
// Worker, não a um upstream específico em baixo).
const INFORMATIONAL = [
  '/api/honeypot', '/api/map',
  '/api/vitals', '/api/ct', '/api/cf-stats', '/api/mirror',
];

const results = await Promise.all([...CRITICAL, ...INFORMATIONAL].map(checkJson));

let hardFailures = 0;
let softFailures = 0;
for (const r of results) {
  const isCritical = CRITICAL.includes(r.path);
  if (r.ok) {
    if (r.path === '/api/health' && r.body?.ok !== true) {
      console.error(`::error::${r.path}: HTTP 200 mas corpo inesperado (${JSON.stringify(r.body)})`);
      hardFailures += 1;
      continue;
    }
    console.log(`ok  ${r.path} (HTTP ${r.status}${r.note ? `, ${r.note}` : ''})`);
  } else if (isCritical) {
    console.error(`::error::${r.path} (crítico): ${r.note}`);
    hardFailures += 1;
  } else {
    console.log(`::warning::${r.path}: ${r.note}`);
    softFailures += 1;
  }
}

// Duas ou mais rotas informativas em baixo ao mesmo tempo deixam de ser
// "um upstream específico está instável" e passam a ser um sinal de que
// algo no próprio Worker partiu (ex.: uma alteração ao cached()/getJSON
// partilhado por todas as rotas).
if (softFailures >= 2) {
  console.error(`::error::${softFailures} rotas informativas falharam ao mesmo tempo — já não parece um upstream isolado.`);
  hardFailures += 1;
}

if (hardFailures > 0) {
  console.error(`::error::${hardFailures} invariante(s) crítico(s) falharam.`);
  process.exit(1);
}
console.log('Todos os invariantes críticos passaram.');
