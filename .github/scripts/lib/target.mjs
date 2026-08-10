// Alvo dos checks contra produção (headers, invariantes, Observatory),
// resolvido a partir das constantes deste módulo — nunca de dados lidos de
// um ficheiro.
//
// Porque é que a origem de produção vive aqui e não no `url` do
// .github/expected-headers.json (onde era escolhida até agora): o alvo
// destes scripts é também o destino a que eles anexam segredos
// (CF-Access-Client-Id/Secret, x-ci-waf-token). Enquanto a allowlist que
// autoriza o envio saía do mesmo ficheiro que escolhia o alvo, a
// verificação e o valor verificado tinham a mesma fonte: uma linha alterada
// no JSON movia as duas ao mesmo tempo e a allowlist aprovava o novo
// destino. Com a origem fixada em código, o JSON deixa de decidir para onde
// vai o pedido — fica com o que é o seu papel: a lista de headers
// esperados, o interruptor de "produção já é verificável" (`url` a SET-ME =
// nada a verificar, ver docs/cloudflare-deploy.md §3 e §7) e uma
// verificação de coerência com a constante (divergir falha o job, em vez de
// mudar o destino em silêncio).
//
// É também o que o CodeQL apontava em js/file-access-to-http ("File data in
// outbound network request", alertas #11/#12 em check-headers.mjs): o URL
// que chegava ao fetch() derivava do readFileSync do JSON. O caminho de
// dados ficheiro → rede deixa de existir — o alvo por omissão é uma
// constante, e o `url` do JSON só é comparado, nunca seguido.
export const PROD_URL = 'https://danielmala.co/';
export const PROD_ORIGIN = new URL(PROD_URL).origin;

// Previews do projeto Cloudflare Pages deste site (docs/cloudflare-deploy.md
// §2) — nunca qualquer *.pages.dev, que é um domínio partilhado onde
// qualquer conta gratuita pode registar um projeto e receber assim os
// segredos.
export const PAGES_PROJECT_HOST = 'personal-site-4fm.pages.dev';

/**
 * Produção já é verificável? `url` a SET-ME no expected-headers.json
 * significa que ainda não (Access à frente do site a devolver a página de
 * login a qualquer pedido não autenticado).
 */
export function isProductionConfigured(cfgUrl) {
  return typeof cfgUrl === 'string' && cfgUrl !== '' && !cfgUrl.startsWith('SET-ME');
}

/**
 * Coerência entre o `url` versionado no JSON e o PROD_URL acima. Devolve
 * uma mensagem se divergirem (o chamador falha o job) ou null se estiverem
 * de acordo. Sem isto, mudar o domínio só no JSON passava a ser um no-op
 * silencioso: os scripts continuariam a verificar o domínio antigo.
 *
 * A mensagem nunca interpola o valor lido em bruto — só o hostname
 * derivado do URL, que não pode conter newlines nem `::` e portanto não
 * consegue forjar um comando de workflow no log do runner.
 */
export function configUrlMismatch(cfgUrl) {
  if (!isProductionConfigured(cfgUrl)) return null;
  let parsed;
  try {
    parsed = new URL(cfgUrl);
  } catch {
    return '`url` em .github/expected-headers.json não é um URL válido.';
  }
  if (parsed.origin !== PROD_ORIGIN) {
    return `\`url\` em .github/expected-headers.json aponta para ${parsed.protocol}//${parsed.hostname} `
      + `mas a origem de produção fixada em .github/scripts/lib/target.mjs é ${PROD_ORIGIN} — `
      + 'atualiza os dois (a constante é a que decide o alvo dos pedidos).';
  }
  return null;
}

/**
 * O alvo pode receber os segredos de Access/WAF? Só HTTPS na porta por
 * omissão, e só a origem de produção ou um preview do projeto Cloudflare
 * Pages deste site. Cobre o alvo inicial; os saltos de redirect ficam
 * cobertos pelo fetchSameOrigin de cada script.
 */
export function isTrustedTarget(url) {
  if (url.protocol !== 'https:' || url.port !== '') return false;
  if (url.origin === PROD_ORIGIN) return true;
  return url.hostname === PAGES_PROJECT_HOST || url.hostname.endsWith(`.${PAGES_PROJECT_HOST}`);
}

/**
 * Resolve o alvo por ordem de prioridade, ignorando candidatos vazios:
 * inputs do workflow (TARGET_URL/DEPLOY_URL) primeiro, PROD_URL por
 * omissão. Devolve null se um candidato explícito não for um URL válido —
 * um input manual mal escrito dava antes um stack trace do Node em vez de
 * uma mensagem.
 */
export function resolveTarget(...candidates) {
  const raw = candidates.find((c) => typeof c === 'string' && c !== '') ?? PROD_URL;
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}
