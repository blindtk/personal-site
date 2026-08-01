// Verifica que a produção serve os headers de segurança esperados
// (.github/expected-headers.json) e falha se algum faltar ou regredir.
// Alvo, por ordem de prioridade:
//   1. TARGET_URL  — input manual do workflow_dispatch
//   2. DEPLOY_URL  — environment_url do evento deployment_status (Pages)
//   3. url         — valor versionado no expected-headers.json
import { readFileSync, appendFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const cfgPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'expected-headers.json');
const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
const target = process.env.TARGET_URL || process.env.DEPLOY_URL || cfg.url;

// Credenciais opcionais de um Cloudflare Access Service Token (ver
// docs/cloudflare-deploy.md). Enquanto a Access continuar ativa à frente
// do site, um pedido sem estas credenciais recebe a página de login em vez
// da resposta real — daí `url` continuar SET-ME até uma das duas coisas
// acontecer: a Access ser desligada no lançamento, OU estes dois secrets
// serem configurados no repo (Settings → Secrets → Actions:
// ACCESS_CLIENT_ID, ACCESS_CLIENT_SECRET — Service Token criado em
// dash.cloudflare.com → Zero Trust → Access → Service Auth). Sem os
// secrets, ambas ficam '' e o comportamento é idêntico ao anterior.
const ACCESS_CLIENT_ID = process.env.ACCESS_CLIENT_ID || '';
const ACCESS_CLIENT_SECRET = process.env.ACCESS_CLIENT_SECRET || '';
const accessHeaders = ACCESS_CLIENT_ID && ACCESS_CLIENT_SECRET
  ? { 'CF-Access-Client-Id': ACCESS_CLIENT_ID, 'CF-Access-Client-Secret': ACCESS_CLIENT_SECRET }
  : {};

// Segredo do bypass da regra WAF "CI headers check" (docs/cloudflare-
// deploy.md §5, regra 2) — substitui o match por User-Agent
// ("headers-check"), que era uma string pública documentada no próprio
// repo: qualquer pedido de fora podia copiá-la e saltar a política de país
// (regras 4/5), a única proteção real depois do lançamento. Um segredo
// rodável fecha isso. Sem ele, o header não é enviado e o comportamento é
// idêntico ao anterior (a regra WAF, uma vez migrada para verificar este
// header, deixa de dar Skip — o pedido volta a cair na política de país,
// exatamente como qualquer outro visitante).
const CI_WAF_TOKEN = process.env.CI_WAF_TOKEN || '';
const wafHeaders = CI_WAF_TOKEN ? { 'x-ci-waf-token': CI_WAF_TOKEN } : {};

/**
 * fetch() que segue redirects à mão, só enquanto ficam na MESMA origem do
 * pedido inicial — mesmo motivo e mesma lógica do fetchSameOrigin em
 * dynamic/worker/src/index.js (runScan): ao contrário de Authorization, o
 * Fetch spec não despe CF-Access-Client-Id/Secret em redirects
 * cross-origin. Sem isto, um 3xx para outra origem reenviaria as
 * credenciais da Access para esse destino. Sem Access Service Token
 * configurado, `opts.headers` nunca as contém, por isso o risco só existe
 * a partir do dia em que estes dois secrets forem definidos.
 */
async function fetchSameOrigin(url, opts, maxRedirects = 5) {
  let current = new URL(url);
  const originalOrigin = current.origin;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    // eslint-disable-next-line no-await-in-loop -- saltos são sequenciais (cada um depende do Location do anterior)
    const res = await fetch(current, { ...opts, redirect: 'manual' });
    const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
    if (!location) return res;
    const next = new URL(location, current);
    if (next.origin !== originalOrigin) return res; // não segue para fora da origem — credenciais da Access não vazam
    current = next;
  }
  return fetch(current, { ...opts, redirect: 'manual' });
}

if (!target || target.startsWith('SET-ME')) {
  // ::warning:: (não ::notice::) de propósito — achado da revisão de
  // segurança 2026-07 (ronda 4, N3): este caminho corria em produção há 13
  // dias seguidos, sempre verde, sem verificar nada (a Access bloqueia
  // qualquer pedido não autenticado — ver docs/cloudflare-deploy.md). Um
  // ::notice:: não aparece na lista de anotações do run nem no resumo por
  // omissão; um ::warning:: sim (triângulo amarelo, visível na lista de
  // execuções). Não resolve a causa raiz (precisa de um Access Service
  // Token para o CI, ou desligar a Access — decisão do dono do repo, ver
  // docs/cloudflare-deploy.md), mas impede que o job continue a passar por
  // "tudo bem" quando não verificou nada.
  console.log('::warning::check-headers: URL de produção por definir em .github/expected-headers.json — verificação IGNORADA (nada foi verificado nesta execução).');
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      '## ⚠️ check-headers: nada foi verificado\n\n' +
        `\`url\` em \`.github/expected-headers.json\` continua \`SET-ME\` — este job saiu sem tocar em produção. ` +
        'Ver docs/cloudflare-deploy.md (Access Service Token, ou desligar a Access no lançamento).\n',
    );
  }
  process.exit(0);
}

console.log(`A verificar ${target}${accessHeaders['CF-Access-Client-Id'] ? ' (com Access Service Token)' : ''}${wafHeaders['x-ci-waf-token'] ? ' (com CI_WAF_TOKEN)' : ''}`);
const res = await fetchSameOrigin(target, {
  headers: { 'user-agent': 'headers-check (GitHub Actions; personal-site)', ...accessHeaders, ...wafHeaders },
});
console.log(`HTTP ${res.status}`);
if (!res.ok) {
  console.error(`::error::check-headers: resposta ${res.status} de ${target}`);
  console.error(`cf-ray: ${res.headers.get('cf-ray')}, cf-mitigated: ${res.headers.get('cf-mitigated')}, server: ${res.headers.get('server')}`);
  const bodyText = await res.text();
  const title = /<title>([^<]*)<\/title>/i.exec(bodyText)?.[1];
  if (title) console.error(`título da resposta: ${title}`);
  process.exit(1);
}

let failures = 0;
for (const [name, required] of Object.entries(cfg.headers)) {
  const value = res.headers.get(name);
  if (value === null) {
    console.error(`::error::Header em falta: ${name}`);
    failures += 1;
    continue;
  }
  const missing = required.filter((part) => !value.toLowerCase().includes(part.toLowerCase()));
  if (missing.length > 0) {
    console.error(`::error::Header ${name} regrediu — falta ${missing.map((m) => JSON.stringify(m)).join(', ')} (valor atual: ${value})`);
    failures += 1;
  } else {
    console.log(`ok  ${name}: ${value}`);
  }
}

if (failures > 0) {
  console.error(`::error::${failures} header(s) em falta ou regredidos.`);
  process.exit(1);
}
console.log('Todos os headers esperados presentes.');
