// HTML do 404 dos paths-isco — desenhado para ser visualmente indistinguível
// do 404 real do site (static/src/pages/404.astro): mesma piada de terminal,
// mesmo texto, mesma paleta escura/mono. Antes disto, o Worker devolvia texto
// simples sem estilo nenhum — um "tell" na direção errada (mais fácil de
// distinguir dos 404 reais do site, não mais difícil).
//
// Autocontido de propósito (CSS inline, sem <script>, sem pedir nada à
// rede): um scanner não pode usar isto para diferenciar o path-isco de
// qualquer outro 404 do site, e o Worker continua puro/testável sem
// depender dos nomes de ficheiro (hashed) que o build do Astro gera.
//
// As cores replicam os design tokens de static/src/styles/global.css — não
// há como partilhar o CSS gerado no build (nomes de ficheiro mudam a cada
// build), por isso os valores estão fixos aqui. Se a paleta mudar lá,
// atualizar aqui também.

export const NOT_FOUND_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'";

export function renderNotFoundHtml() {
  return `<!doctype html>
<html lang="pt">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>404</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 4rem 1.25rem; max-width: 40rem; margin-inline: auto;
    background: #0a0d11; color: #dbe4ef; line-height: 1.6;
    font-family: ui-monospace, 'JetBrains Mono', 'Fira Code', 'SF Mono', Menlo,
      Consolas, 'Liberation Mono', monospace;
  }
  h1 { font-size: 2.5rem; margin: 0 0 1rem; }
  p { color: #8593a5; margin: 0 0 0.75rem; }
  pre {
    background: #111620; border: 1px solid #1e2734; border-radius: 8px;
    padding: 1rem 1.25rem; overflow-x: auto; color: #dbe4ef;
  }
  a { color: #3ddc84; text-decoration: none; }
  a:hover { text-decoration: underline; }
</style>
</head>
<body>
  <h1>404</h1>
  <p>O caminho que procuras não existe (ou ainda não foi construído).</p>
  <p lang="en">The path you are looking for does not exist (or has not been built yet).</p>
  <pre>~$ cd /404
bash: cd: /404: No such file or directory</pre>
  <p>
    <a href="/">→ voltar ao início</a> ·
    <a href="/en/" lang="en">→ back to home</a>
  </p>
</body>
</html>
`;
}
