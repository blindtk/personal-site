---
title: 'Hello, world'
description: 'The first post on this blog: why a personal site, and how it is built.'
pubDate: 2026-07-13
tags: ['meta']
---

This is the first post on the blog — the classic `hello world` that exists to
prove the pipeline works: I write markdown in `content/blog/`, push, and the
site rebuilds itself.

## Why a personal site?

Three reasons:

1. **Notes for future me.** Half of what I learn about networking and security
   evaporates if I don't write it down.
2. **A living portfolio.** More useful than a static CV.
3. **A laboratory.** The [Lab](/en/lab/) will grow with tools that need a
   backend — DNS lookup, whois, and friends.

## How to replace this post

Delete this file (`content/blog/en/hello-world.md`) and create your own:

```markdown
---
title: 'My first real post'
description: 'A one-line summary shown in listings.'
pubDate: 2026-08-01
tags: ['networking', 'linux']
---

Content goes here, in plain markdown.
```

The file name defines the URL: `my-post.md` → `/en/blog/my-post/`.
For the Portuguese version, create the twin file in `content/blog/pt/` with
the **same name** — the PT/EN switcher links them automatically.
