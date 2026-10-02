---
title: 'Este site'
description: 'Um site pessoal gerido como sistema de produção: threat model, CSP estrita, provas verificáveis.'
tags: ['astro', 'typescript', 'cloudflare']
order: 1
---

Como foi feito este site, e porquê. O sistema a funcionar — o que está em
vigor, o que acontece ao vivo e as provas — está na secção
[Este site](/este-site/); aqui ficam as decisões por trás dele.

## O que é

Um site pessoal bilingue (PT/EN), estático, com ferramentas de rede e
segurança que correm no browser. O pouco que precisa mesmo de servidor — o
verificador de passwords, o espelho, o vigia de certificados e os painéis
de Cloudflare e Performance — vive num Cloudflare Worker isolado, à parte
do site.

O conteúdo (markdown/JSON) vive separado do código e alimenta as duas
línguas a partir das mesmas componentes, sem duplicar lógica entre PT e EN.

A segurança moldou o desenho desde o início: Content-Security-Policy
estrita sem `'unsafe-inline'`, cabeçalhos de segurança e uma política de
divulgação responsável publicada. O que está em vigor e porquê está em
[Segurança](/este-site/seguranca/); o que se pode verificar — commit,
cabeçalhos ao vivo, workflows — está em [Provas](/este-site/provas/).

## Decisões de arquitetura

**Porquê Astro sem framework no browser.** Zero React/Vue/Svelte por
omissão — as páginas nascem sem JavaScript, e as partes que precisam de
interatividade (as ferramentas, o Lab) não carregam runtime de hidratação
nenhum. Não é só uma escolha de performance: torna a CSP estrita sem
`'unsafe-inline'` fácil de manter, porque não há um framework a injetar
estilo ou script inline em tempo de execução — e, como os meus próprios
`<script>` são ficheiros externos, nunca inline, `script-src 'self'` e
`style-src 'self'` chegam sem uma única hash. (Tentei primeiro o caminho
inverso — uma hash SHA-256 por script/estilo inline —, mas o número de
hashes cresce com o número de páginas, e ao fim de umas dezenas a CSP passa
dos 2000 caracteres que o Cloudflare Pages aceita por linha de cabeçalho.
Eliminar o inline em vez de o catalogar resolve na raiz.)

**Porquê o Worker à parte do site estático.** O site em si fica sem
backend, sem base de dados e sem input de visitantes que chegue a um
servidor — o modelo de ameaça descrito em [Segurança](/este-site/seguranca/)
mantém-se o mais simples possível. O que precisa mesmo de servidor vive
isolado no Worker, publicado à parte, e não guarda dados pessoais. Se o
Worker estiver em baixo, o site continua a funcionar: as partes que
dependem dele dizem que estão indisponíveis em vez de partir o resto. O
resultado ao vivo está em [Cloudflare](/este-site/cloudflare/) e
[Performance](/este-site/performance/).
