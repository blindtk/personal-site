# ADR 0001 — CSP sem `unsafe-inline`, sem hashes: eliminar o inline em vez de o catalogar

**Estado:** aceite e em produção (`static/public/_headers`).

## Contexto

Uma CSP estrita (`default-src 'self'`, sem `unsafe-inline`) precisa de alguma
forma de autorizar os `<script>`/`<style>` que o próprio site produz. O Astro,
por omissão, inlina CSS pequeno e scripts *hoisted* pequenos diretamente no
HTML de cada página.

A primeira abordagem foi o mecanismo nativo do Astro
(`security.csp` / hashes SHA-256 por bloco inline): calcular um hash por
`<script>`/`<style>` inline no build e uni-los num único header. Funcionou até
ao site crescer: cada página combina o script/estilo partilhado com o
específico dela num só bloco inline — o número de hashes cresce com o número
de **combinações** página × script, não com o número de scripts reais. Ao fim
de ~50 páginas, a linha do header ultrapassava os 2000 caracteres máximos por
header do Cloudflare Pages, e o Pages **descartava o header CSP inteiro em
produção** — sem aviso, sem erro de build, só ausência silenciosa do header
mais importante do site.

## Decisão

Eliminar o inline em vez de o catalogar. Dois levers no `astro.config.mjs`:

- `build.inlineStylesheets: 'never'` — todo o CSS vira `<link>` externo.
- `vite.build.assetsInlineLimit: 0` — todo o `<script>` *hoisted* vira
  `<script src="/_astro/…">` externo.

Com zero `<script>`/`<style>` inline no site inteiro, `'self'` já é tão
restrito quanto uma lista de hashes — mas com um header de tamanho fixo
(~395 caracteres) que não volta a crescer com mais páginas ou ferramentas.

**Exceção única:** o `<script type="application/ld+json">` (schema.org
Person) em `BaseLayout.astro`. JSON-LD não tem equivalente fiável a `<link>`
externo em crawlers, e o parser HTML aplica `script-src`/`script-src-elem` a
qualquer `<script>` independentemente do `type` — por isso este bloco tem um
único hash SHA-256 do seu conteúdo exato, em vez de reabrir
`unsafe-inline`. Cresce por *variante de conteúdo* (se PT e EN alguma vez
divergirem), não por página.

## Consequências

- CSP inclui `require-trusted-types-for 'script'` + `trusted-types 'none'`:
  só é honesto porque todo o DOM é construído via `createElement`/
  `textContent`, nunca `innerHTML`/`eval` — o zero-inline e o Trusted Types
  reforçam-se mutuamente.
- A CSP passou a viver inteiramente em `static/public/_headers` (linha
  estática, não gerada no build) — fonte de verdade única, sem passo de build
  a manter sincronizado.
- Custo: qualquer novo `<script>`/`<style>` inline introduzido por engano
  parte a página em vez de silenciosamente abrir a política (falha alto,
  não baixo — comportamento desejado).
