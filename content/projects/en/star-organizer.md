---
title: 'star-organizer'
description: 'GitHub stars as a knowledge base by category — Markdown and JSON, refreshed every week.'
tags: ['python', 'github-actions', 'automation', 'curation']
order: 3
---

A Python CLI that takes any GitHub user's stars and turns them into a tidy
knowledge base: one Markdown file per category, with YAML front-matter
ready for Obsidian, plus a `catalog.json` with the same content for other
tools to consume. That JSON is what feeds the browsable library in
[Links](/en/links/) and the `stars` command in the [Lab](/en/lab/)
terminal. Nothing is tied to one person: change `--user` and the rules and
it works for another account.

## How it picks a category

The rules live in an editable file, `categories.yaml`. For each
repository, every category earns points — 3 per matching topic, 2 per
keyword in the name, description or topics, 1 for the language — and only
claims the repository from 2 points up, so language alone is never enough
(otherwise every Python repo would land in the same place). The
highest-scoring category becomes the primary one; any other that clears
the threshold becomes a secondary tag.

Around that, three mechanisms close the hard cases:

- **Subcategories** for the large categories (AI tooling, for instance,
  splits into agents, MCP servers, RAG, local inference…).
- **No repo left behind**: anything no rule matches goes to a fallback
  category ("Misc & Other") instead of an "unsorted" pile.
- **Overrides** pin by hand the repositories with no description or
  misleading topics — each group commented in the file itself.

The rules are checked against real data: in the September 2026 re-tune
every repository was reviewed by hand, not just the new ones. The method —
rebuild every placement and diff category *and* subcategory against the
previous run before publishing — shows exactly which repositories each
rule change moves.

## Automation, on the homelab

A GitHub Action rebuilds the catalog every Monday (and on demand) and only
commits when something changed. It runs on a self-hosted runner on a
Raspberry Pi 5 in the [homelab](/en/projects/homelab/) — and, being a
persistent shared runner, it is hardened as one: actions pinned by SHA,
dependencies from a hashed lockfile, a checkout that doesn't keep the
token, and the write-scoped token handed only to the final `git push`.
Every PR runs unit tests, `ruff`, `bandit` and `pip-audit`, plus
`gitleaks`, `zizmor` and `actionlint`.

## How it reaches this site

The `github-stars` repository is **private**, and
`raw.githubusercontent.com` won't serve files from private repositories
without authentication — it returns a 404, indistinguishable from "the
file doesn't exist". So the generated `catalog.json` is copied by hand into
`content/catalog.json` in this repository, and `static/src/lib/catalog.ts`
imports it statically, with no network request. A missing or
schema-invalid file **fails the build**, on purpose: there is never a silent
fallback to sample data. The next step, on the [Lab](/en/lab/) roadmap, is
reading the catalog through the GitHub API with a token, keeping the
repository private and dropping the manual copy.
