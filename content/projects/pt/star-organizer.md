---
title: 'star-organizer'
description: 'As estrelas do GitHub numa base de conhecimento por categorias, em Markdown e JSON, atualizada todas as semanas.'
tags: ['python', 'github-actions', 'automação', 'curadoria']
order: 3
---

Uma CLI em Python que pega nas estrelas de qualquer utilizador do GitHub e
as transforma numa base de conhecimento arrumada: um ficheiro Markdown por
categoria, com front-matter YAML pronto para o Obsidian, e um
`catalog.json` com o mesmo conteúdo para outras ferramentas consumirem. É
esse JSON que alimenta a biblioteca navegável em [Links](/links/) e o
comando `stars` do terminal do [Lab](/lab/). Nada está preso a uma pessoa:
muda o `--user` e as regras e serve para outra conta.

## Como decide a categoria

As regras vivem num ficheiro editável, `categories.yaml`. Para cada
repositório, cada categoria ganha pontos: 3 por *topic* que corresponda, 2
por palavra-chave no nome, descrição ou *topics* e 1 pela linguagem. Só
reclama o repositório a partir de 2 pontos, para que a linguagem sozinha
nunca chegue (senão todo o Python acabava no mesmo sítio). A categoria com
mais pontos fica como principal; as outras que passem o limiar viram
*tags* secundárias.

À volta disto, três mecanismos fecham os casos difíceis:

- **Subcategorias** para as categorias grandes (a de ferramentas de IA, por
  exemplo, divide-se em agentes, servidores MCP, RAG, inferência local…).
- **Nenhum repositório fica de fora**: o que não encaixa em regra nenhuma
  vai para uma categoria de recurso ("Misc & Other") em vez de uma pilha de
  "por classificar".
- **Overrides** fixam à mão os repositórios sem descrição ou com *topics*
  enganadores, com cada grupo comentado no próprio ficheiro.

As regras são revistas contra os dados reais: na revisão de setembro de
2026 todos os repositórios foram verificados à mão, não só os novos. O
método é reconstruir a colocação de tudo e comparar categoria *e*
subcategoria com a execução anterior antes de publicar. Assim fica claro
que repositórios cada alteração de regra move.

## Automação

Uma GitHub Action reconstrói o catálogo todas as segundas-feiras (e a
pedido) e só faz commit se algo mudou. Está endurecida: actions fixadas
por SHA, dependências de um lockfile com hashes, checkout sem guardar o
token, e o token com permissão de escrita entregue só ao `git push` final. Cada PR
passa por testes unitários, `ruff`, `bandit` e `pip-audit`, e por
`gitleaks`, `zizmor` e `actionlint`.

## Ligação a este site

O catálogo gerado chega a este repositório como um *pull request* aberto por
uma GitHub App, que só altera `content/catalog.json`; depois de revisto e
integrado, o site importa-o de forma estática, sem pedido de rede. Um ficheiro em falta
ou com schema inválido **falha o build**, de propósito: nunca há um recurso
silencioso a dados de exemplo.
