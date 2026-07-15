---
title: 'Este site'
description: 'Monorepo com site estático em Astro, conteúdo em markdown e ferramentas client-side.'
tags: ['astro', 'typescript', 'cloudflare']
repo: 'https://github.com/blindtk/personal-site'
order: 1
---

Site pessoal bilingue construído com Astro: calculadora de subnets, gerador
de hashes e mais — tudo a correr no browser, sem backend.

Bilingue por construção: o conteúdo (markdown/JSON) vive separado do código
e alimenta as duas versões (PT/EN) a partir das mesmas componentes — sem
duplicar lógica entre idiomas.

A segurança foi tratada como parte do design, não um extra: Content-Security-Policy
estrita sem 'unsafe-inline', cabeçalhos de segurança e uma política de
divulgação responsável publicada. Detalhes em [Segurança](/seguranca/).
