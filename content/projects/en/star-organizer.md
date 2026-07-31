---
title: 'star-organizer'
description: 'Organises GitHub stars into a browsable catalog by category — generated automatically in the source repo, hand-vendored into this site.'
tags: ['github', 'automation', 'curation']
order: 3
---

A tool that turns the chaotic list of GitHub stars into a catalog organised by
category. It emits `catalog/catalog.json`, which feeds the browsable
library in this site's [Links](/en/links/) tab.

## Technical decisions

`star_organizer.py` runs in the separate `github-stars` repo, with a weekly
(and on-demand) GitHub Action that generates `catalog/catalog.json` and
commits the updated version — but `github-stars` is a **private** repo, and
`raw.githubusercontent.com` won't serve files from private repos without
authentication (it returns a 404, indistinguishable from "the file doesn't
exist"). The original design — reading the catalog straight from GitHub's
raw content at build time — doesn't work because of that.

The current fix, until that changes: the generated `catalog.json` is
hand-vendored into `content/catalog.json` in this repo, and
`static/src/lib/catalog.ts` imports it as a static import — no network
request. A missing or schema-invalid `content/catalog.json` **fails the
build**, on purpose: there's never a silent fallback to sample data. The
next step, already on the [Lab](/en/lab/) roadmap, is reading the catalog via
an authenticated GitHub API call with a token, which keeps `github-stars`
private and restores automatic syncing without manual intervention.
