---
title: 'Este site'
description: 'Monorepo com site estático em Astro, conteúdo em markdown e ferramentas client-side.'
tags: ['astro', 'typescript', 'cloudflare']
order: 1
---

Site pessoal bilingue construído com Astro: calculadora de subnets, gerador
de hashes e mais — as ferramentas correm no browser, e o pouco que precisa
mesmo de servidor vive num Worker isolado, à parte.

Bilingue por construção: o conteúdo (markdown/JSON) vive separado do código
e alimenta as duas versões (PT/EN) a partir das mesmas componentes — sem
duplicar lógica entre idiomas.

A segurança moldou o design desde o início: Content-Security-Policy
estrita sem 'unsafe-inline', cabeçalhos de segurança e uma política de
divulgação responsável publicada. O porquê de cada camada está em
[Segurança](/seguranca/); as provas — commit, scan aos cabeçalhos ao vivo,
workflows — são verificáveis em [Provas](/provas/).

## Decisões de arquitetura

**Porquê Astro sem framework client-side.** Zero React/Vue/Svelte por
omissão — as páginas nascem sem JavaScript, e as ilhas que precisam de
interatividade (as ferramentas de rede, o Lab) não carregam runtime de
hidratação nenhum. Isto não é só uma escolha de performance: torna a CSP
estrita sem `'unsafe-inline'` fácil de manter, porque não há um framework a
injetar estilo ou script inline em tempo de execução por trás das costas —
e porque escrevo os meus próprios `<script>` como ficheiros externos, nunca
inline, `script-src 'self'` e `style-src 'self'` chegam sem precisar de uma
única hash. (Já tentei o caminho inverso — hashes SHA-256 por script/estilo
inline — mas o número de hashes cresce com o número de páginas, e ao fim de
umas dezenas a Content-Security-Policy passa dos 2000 caracteres que o
Cloudflare Pages aceita por linha de cabeçalho; eliminar o inline em vez de
o catalogar resolve na raiz.)

**Porquê monorepo com o Worker separado do estático.** O `static/` (este
site) mantém o modelo de ameaça descrito na página de
[Segurança](/seguranca/) o mais simples possível: sem backend, sem base de
dados, sem input de utilizador que chegue a um servidor. As funcionalidades
que precisam mesmo de servidor — honeypot, mapa de tráfego, self-scan de
cabeçalhos, ticker de threat intel — vivem isoladas num Cloudflare Worker
(`dynamic/worker/`), publicado à parte. Isso significa que o site estático
continua a funcionar (e a cumprir a promessa de "sem backend") mesmo que o
Worker esteja em baixo ou nem sequer publicado — as secções que dependem
dele degradam com graça em vez de partir o resto.
