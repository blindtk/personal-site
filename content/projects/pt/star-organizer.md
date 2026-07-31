---
title: 'star-organizer'
description: 'Organiza as estrelas do GitHub num catálogo navegável por categorias — gerado automaticamente no repo de origem, vendorizado à mão para este site.'
tags: ['github', 'automação', 'curadoria']
order: 3
---

Ferramenta que transforma a lista caótica de estrelas do GitHub num catálogo
organizado por categorias. Gera `catalog/catalog.json`, que alimenta a
biblioteca navegável no separador [Links](/links/) deste site.

## Decisões técnicas

O `star_organizer.py` corre no repo `github-stars`, separado deste, com uma
GitHub Action semanal (e a pedido) que gera `catalog/catalog.json` e comita a
versão atualizada — mas `github-stars` é um repo **privado**, e
`raw.githubusercontent.com` não serve ficheiros de repos privados sem
autenticação (devolve 404, indistinguível de "o ficheiro não existe"). O
desenho original — ler o catálogo em build time diretamente do raw do GitHub
— não funciona por causa disso.

A solução atual, enquanto isso não muda: o `catalog.json` gerado é
vendorizado à mão para `content/catalog.json` neste repo, e
`static/src/lib/catalog.ts` importa-o como um import estático — sem pedido de
rede. Um `content/catalog.json` em falta ou com schema inválido **falha o
build**, de propósito: nunca há um fallback silencioso para dados de
exemplo. O próximo passo, já no roadmap do [Lab](/lab/), é ler o catálogo via
API do GitHub autenticada com um token, o que permite manter `github-stars`
privado e voltar a sincronizar sem intervenção manual.
