# Contributing

This is a personal project with a single maintainer (Daniel Malaco), but
the repository is public and contributions are welcome — from a typo fix
to an architecture suggestion.

## Before touching code

Read [`CLAUDE.md`](CLAUDE.md): it defines the project's conventions (the
monorepo's three areas — `content/`, `static/`, `dynamic/` —, the PT/EN
bilingual rule, where UI strings live, etc.). A change that doesn't follow
those conventions won't be accepted as-is, even if the logic is correct.

## Reporting a bug

Open an [Issue](https://github.com/blindtk/personal-site/issues) with:

- what you expected to happen vs. what happened;
- steps to reproduce;
- if it's visual, a screenshot helps more than a long description.

**Security vulnerabilities never go in a public Issue** — follow the
process in [`.github/SECURITY.md`](.github/SECURITY.md).

## Proposing a change

1. Fork the repository and create a branch from `main`.
2. Make the change following `CLAUDE.md`'s conventions.
3. Run `cd static && npm run build` — it has to pass with no errors or
   new warnings before you open the PR.
4. If you touched `dynamic/worker/` or the tools in `/ferramentas/`, also
   run `node --test` and validate the logic with known vectors. If the
   change was specifically in `dynamic/worker/`, also confirm it still
   packages with `cd dynamic/worker && npx wrangler deploy --dry-run` (see
   [`dynamic/PLAN.md`](dynamic/PLAN.md) — the real deploy stays manual).
5. If you touched `dynamic/worker/src/lib/csp-report.js` or
   `sanitize.js`, also run the fuzzing harnesses locally
   (`.clusterfuzzlite/fuzz/`) for a few seconds, to confirm they still
   compile and run without crashing:
   ```bash
   npx --yes -p @jazzer.js/core@4.0.0 jazzer .clusterfuzzlite/fuzz/csp_report_fuzz.js --sync -- -max_total_time=5
   npx --yes -p @jazzer.js/core@4.0.0 jazzer .clusterfuzzlite/fuzz/sanitize_fuzz.js --sync -- -max_total_time=5
   ```
6. Open the Pull Request — the template
   (`.github/pull_request_template.md`) guides what to include. CI
   (build, tests, static analysis) runs automatically; it has to pass
   before any merge.

There's no CLA process or prior approval required to start working — but
for large changes or ones that shift architecture, open an Issue first to
propose the idea, so no work is wasted if the direction isn't the intended
one.

## License

By contributing, you agree that your contribution is distributed under
the project's own license ([MIT](LICENSE)).
