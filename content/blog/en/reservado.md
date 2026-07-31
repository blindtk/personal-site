---
title: 'Reserved'
description: 'Draft placeholder — keeps the "blog" collection non-empty so Astro does not treat it as missing, without publishing anything. See static/src/layouts/BaseLayout.astro.'
pubDate: 2026-07-31
tags: []
draft: true
---

This file exists only so the `blog` collection has at least one entry —
without it, `getCollection('blog', ...)` warns on every build that the
collection "does not exist or is empty," because Astro never registers the
collection in the content store when the glob matches no files at all.

`draft: true` guarantees it never shows up in any list or public route (the
`!e.data.draft` filter already used in `BaseLayout.astro`, `HomePage.astro`,
and the `/blog/` routes handles this). Once there is a first real post, this
file can be deleted.
