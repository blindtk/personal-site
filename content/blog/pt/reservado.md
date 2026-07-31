---
title: 'Reservado'
description: 'Placeholder de rascunho — mantém a coleção "blog" com pelo menos uma entrada para que o Astro não a trate como inexistente, sem publicar nada. Ver static/src/layouts/BaseLayout.astro.'
pubDate: 2026-07-31
tags: []
draft: true
---

Este ficheiro existe só para que a coleção `blog` tenha pelo menos uma
entrada — sem isto, `getCollection('blog', ...)` avisa em cada build que a
coleção "não existe ou está vazia", porque o Astro nunca chega a registar a
coleção no content store quando o glob não encontra ficheiro nenhum.

`draft: true` garante que nunca aparece em nenhuma lista nem rota pública
(o filtro `!e.data.draft` já usado em `BaseLayout.astro`, `HomePage.astro` e
nas rotas de `/blog/` trata disto). Quando houver o primeiro post real,
este ficheiro pode ser apagado.
