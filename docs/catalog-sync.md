# Catalog sync — how `content/catalog.json` is kept up to date

`content/catalog.json` (the `/links` catalog and the Lab `stars` command)
is generated outside this repo, from my GitHub stars, and arrives here as
a **pull request** opened by a GitHub App (`stars-catalog-sync[bot]`).
The site never fetches anything at build time: the build imports the
vendored JSON statically and fails on a bad schema
(`static/src/lib/catalog.ts`).

## What the PR contains

Only `content/catalog.json`. Before opening it, the generator builds this
site with the new file, so a catalog that would break the build never
reaches a PR. A PR is opened only when the catalog differs from the one
here beyond its `generatedAt` timestamp; star counts shift often, so in
practice that is most weeks.

## Why a PR and not a direct push

`main` is behind a ruleset (PR + Code Owners review, required checks) and
the OpenSSF Scorecard badge reads the review history: direct bot commits
would count as unreviewed changes and lower the **Code-Review** check. A PR
keeps the ruleset without any bypass actor, runs the full CI on the exact
file, and the merge is a real review. The PR is authored by a GitHub App,
not by a personal token, so the repo owner can approve it.

The vendored file also keeps the build offline and deterministic: no
token and no GitHub API dependency in the deploy.

## Reviewing it

The diff is one JSON file (per-repo star counts, plus added or removed
repos). Check that the changed files are only `content/catalog.json`, wait
for the required checks, approve and squash-merge. The Cloudflare build
runs on merge as for any other change.

## Manual update

Replacing `content/catalog.json` by hand and opening a PR still works;
the build fails with a clear error if the schema is wrong.

## Failure modes

| What breaks | What happens |
| --- | --- |
| The generator's schema changes | No PR is opened; the current file stays live. |
| The new file passes the shape check but breaks the site | The build step fails before the PR is opened; nothing changes here. |
| A PR is left unmerged | The next run refreshes the same PR with the newest catalog. |
| The App's credentials are revoked or wrong | No PR is opened; the last merged catalog stays live. |
