// Política de URLs para dados que vêm de fora do código (catálogo gerado por
// bot, frontmatter, JSON de links/certificados) e acabam em `href`. Pura e sem
// DOM, para ser testada em Node com vetores reais.
//
// Porquê: `z.url()` aceita qualquer esquema (inclui `javascript:`), e o que
// hoje impede que isso execute é a CSP (`script-src 'self'` + Trusted Types) —
// um cabeçalho que já deixou de ser servido em produção numa altura (ver o
// histórico de static/public/_headers). A política tem de valer no build, não
// só no browser.

/** true se `value` é um URL https sem credenciais embebidas (`https://a@b`). */
export function isHttpsUrl(value) {
  if (typeof value !== 'string') return false;
  try {
    const u = new URL(value);
    return u.protocol === 'https:' && u.username === '' && u.password === '';
  } catch {
    return false;
  }
}

/** true se `value` é exatamente https://github.com/<dono>/<repo> (sem caminho, query ou fragmento). */
export function isGithubRepoUrl(value) {
  return typeof value === 'string' && /^https:\/\/github\.com\/[^/\s?#@]+\/[^/\s?#@]+$/.test(value);
}

/** Lança, com a origem e o URL, se algum dos `urls` não for https. */
export function assertHttpsUrls(urls, source) {
  for (const url of urls) {
    if (!isHttpsUrl(url)) throw new Error(`${source}: URL não-https ou inválido: ${JSON.stringify(url)}`);
  }
}
