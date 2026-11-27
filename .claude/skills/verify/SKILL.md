---
name: verify
description: Verify a change to this repo before committing or opening a PR — picks the checks that match the diff (static build/check/tests, Worker tests and dry-run deploy, a browser smoke of the built pages), runs them, and reports evidence. Use after any code or content change here, and before saying a change works.
---

# verify — personal-site

The goal is evidence that the change works, not a claim that it does. Run
the checks that match the diff, cheapest first, and report what each one
printed.

## 1. Pick the checks from the diff

`git diff --name-only origin/main...HEAD` (plus uncommitted files), then:

| Touched | Run (from the repo root) |
| --- | --- |
| `static/**`, `content/**` | `cd static && npm ci --ignore-scripts` (once per session) → `npm run build` → `npm run check` → `npm run test` |
| `static/src/scripts/*.js` (tools logic) | the above, plus known vectors for the logic you changed (CLAUDE.md → Tools) |
| any page, component, style or content | the browser smoke below, on the routes you changed |
| `dynamic/worker/**` | `cd dynamic/worker && npm ci --ignore-scripts` (once) → `npm test` → `npx wrangler deploy --dry-run` |
| `.github/workflows/**` | read the workflow diff against CLAUDE.md and the repo's workflow ADRs; nothing runs it locally — say so |
| docs only | nothing to run — say so |

`npm run build` must finish with no errors **and no new warnings** (CLAUDE.md).

## 2. Run the change, not just the tests

For anything a visitor sees, build and open it:

```bash
cd static && npm run build && cd ..
node .claude/skills/verify/scripts/page-smoke.cjs / /en/ <changed routes, PT and EN>
```

It serves `static/dist`, opens each route at desktop and mobile width, and
fails on a non-200 route, a missing local asset, a JS error or horizontal
scroll. `/api/` and other origins are blocked on purpose: a page must still
load when the Worker is down. Then **look at the screenshots** it saved for
the routes you changed — layout and copy are what the script cannot judge.
A new page needs both languages (CLAUDE.md → Before finishing).

The smoke was checked against planted bugs (a deleted stylesheet, a thrown
error, a 3000px element, a missing route): each one fails it.

## 3. Rules while fixing

- **Three rounds, then stop.** If a check still fails after three fix
  attempts, stop and report: the check, the output, what you tried, what you
  think is wrong. Do not keep going.
- **Never make a check pass by changing the check**: no skipping, no
  `.only`/`.skip`, no loosened assertion, no retry loop, no `sleep`.
- **A flaky test is a bug with a cause** — usually the clock, order, a port
  or the network. Find it and fix it there (example: `intel.test.mjs` pins
  the clock with `t.mock.timers` because its fixture is dated). If you can't
  find the cause, say so; don't delete or retry quietly.
- **Not run is not passed.** List every check that did not run and why.

## 4. Report and stamp

End with a short list: each check, PASS/FAIL/NOT RUN, and the line that
proves it (`# pass 176`, `55 page(s) built`, `ok: 4 route(s)…`). Put the
same in the commit message as a trailer, so unverified commits can be found
later:

```
Verified: static build+check+test, worker test+dry-run, page-smoke (/, /en/)
```

or `Verified: none — <why>` when nothing could run.
