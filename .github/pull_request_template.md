<!--
PR template for this repo. Fill in the sections that apply and delete the
ones that don't make sense for this change. Project context in CLAUDE.md.
-->

## Context
<!-- What motivated the change and the problem it solves. -->

## Changes
<!-- Bullet points. Note the area touched: content/, static/, or dynamic/. -->
-

## Validation
<!-- Check only what applies to this change. -->
- [ ] `cd static && npm run build` passes with no errors or new warnings
- [ ] If tools were touched, logic was tested with known vectors (`node --test`)
- [ ] If a new page was added, created **both** versions (PT + EN) and the pair in `routes.ts`
- [ ] If `dynamic/worker/` was touched, ran `npm test` and `npx wrangler deploy --dry-run` (see `dynamic/PLAN.md`)
- [ ] If `csp-report.js` or `sanitize.js` was touched, ran the local fuzz harnesses (see `CONTRIBUTING.md`)

## Notes
<!-- Decisions, trade-offs, what was left out, follow-ups. Delete if not applicable. -->
