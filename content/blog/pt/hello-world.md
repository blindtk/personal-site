---
title: 'Hello, world'
description: 'O primeiro post deste blog: porquê um site pessoal, e como isto está construído.'
pubDate: 2026-07-13
tags: ['meta']
draft: true
---

Este é o primeiro post do blog — o clássico `hello world` que existe para provar
que o pipeline funciona: escrevo markdown em `content/blog/`, faço push, e o
site reconstrói-se sozinho.

## Porquê um site pessoal?

Três razões:

1. **Notas para o meu eu do futuro.** Metade do que aprendo em redes e
   segurança evapora-se se não o escrever.
2. **Portfólio vivo.** Mais útil que um CV estático.
3. **Um laboratório.** O [Lab](/lab/) vai crescer com ferramentas que precisam
   de backend — DNS lookup, whois, e afins.

## Como substituir este post

Apaga este ficheiro (`content/blog/pt/hello-world.md`) e cria o teu:

```markdown
---
title: 'O meu primeiro post a sério'
description: 'Um resumo de uma linha que aparece nas listagens.'
pubDate: 2026-08-01
tags: ['redes', 'linux']
---

O conteúdo vai aqui, em markdown normal.
```

O nome do ficheiro define o URL: `o-meu-post.md` → `/blog/o-meu-post/`.
Se quiseres a versão inglesa, cria o ficheiro gémeo em `content/blog/en/`
com o **mesmo nome** — o seletor PT/EN liga os dois automaticamente.
