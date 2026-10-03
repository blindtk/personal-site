---
title: 'Este site'
description: 'Site pessoal gerido como sistema de produção: CSP estrita e provas verificáveis.'
tags: ['astro', 'typescript', 'cloudflare']
order: 1
---

### Astro, sem framework no browser

As páginas são geradas no build e chegam ao browser sem JavaScript. As partes
interativas (as ferramentas e o Lab) usam scripts pequenos, sem React, Vue ou
outro runtime de hidratação.

Não foi só por performance. Sem um framework a injetar estilos ou scripts
inline, a Content-Security-Policy pode ficar em `script-src 'self'` e
`style-src 'self'`, sem `'unsafe-inline'` e sem uma única hash. Experimentei
primeiro o contrário, com uma hash SHA-256 por cada script e estilo inline,
mas o número de hashes crescia com o número de páginas e ao fim de umas
dezenas a CSP já passava dos 2000 caracteres que o Cloudflare Pages aceita por
linha de cabeçalho. Tirar o código inline resolveu o problema na origem.

### Um Worker à parte para o que precisa de servidor

O site não tem backend, base de dados nem input de visitantes que chegue a um
servidor, o que deixa o modelo de ameaça muito simples. As poucas funções que
precisam mesmo de servidor vivem num Cloudflare Worker publicado
separadamente, que não guarda dados pessoais. Se o Worker estiver em baixo, o
site continua a funcionar e cada painel que depende dele diz que está
indisponível, em vez de partir a página.

### Conteúdo separado do código, nas duas línguas

Os textos vivem em Markdown e JSON, fora do código, e as páginas em português
e em inglês saem dos mesmos componentes. Assim nenhuma lógica é escrita duas
vezes, e uma página nunca existe só numa das línguas.
