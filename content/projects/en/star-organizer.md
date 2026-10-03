---
title: 'star-organizer'
description: 'My GitHub stars, organised by category in Markdown and JSON.'
tags: ['python', 'github-actions']
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
repository, every category earns points: 3 per matching topic, 2 per
keyword in the name, description or topics, and 1 for the language. It only
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
  misleading topics, with each group commented in the file itself.

The rules are checked against real data: in the September 2026 re-tune
every repository was reviewed by hand, not just the new ones. The method is to
rebuild every placement and diff category *and* subcategory against the
previous run before publishing, which shows exactly which repositories each
rule change moves.

## Automation

A GitHub Action rebuilds the catalog every Monday (and on demand) and only
commits when something changed. It is hardened: actions pinned by SHA,
dependencies from a hashed lockfile, a checkout that doesn't keep the
token, and the write-scoped token handed only to the final `git push`.
Every PR runs unit tests, `ruff`, `bandit` and `pip-audit`, plus
`gitleaks`, `zizmor` and `actionlint`.

## How it reaches this site

The generated catalog reaches this repository as a pull request opened by a
GitHub App, touching only `content/catalog.json`; once reviewed and merged,
the site imports it statically, with no network request. A
missing or schema-invalid file **fails the build**, on purpose: there is never
a silent fallback to sample data.
