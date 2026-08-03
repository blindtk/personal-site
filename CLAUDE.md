# CLAUDE.md — project conventions

Personal site monorepo. Three areas with rigid responsibilities:

- `content/` — markdown/JSON content. **Never** put code here.
- `static/` — Astro static site. Reads `content/` via loaders (`glob`, JSON import).
- `dynamic/` — backend (Cloudflare Worker in `dynamic/worker/`: honeypot,
  traffic map, self-scan, ticker). Pure logic in `src/lib/*` tested with
  `node --test` (run before any PR that touches this). New tools only with
  an explicit decision from the repo owner (see `dynamic/PLAN.md`).

## Commands

```bash
cd static
npm run dev       # development
npm run build     # production build (must pass with no errors before any PR)
npm run preview   # serve the build locally
```

## Architecture rules

1. **Bilingual by construction.** Every page exists in PT (`/`) and EN (`/en/`).
   Routes in `static/src/pages/` are *thin* (3 lines): they import a
   component from `src/components/pages/` and pass `lang`. All logic lives
   in the shared component — never duplicate logic between PT and EN.
2. **UI strings** all go in `static/src/i18n/ui.ts` (PT and EN together,
   same structure). Zero hardcoded strings in components.
3. **New routes** register in `static/src/i18n/routes.ts` (PT/EN pair) —
   this is what feeds the nav and the language selector.
4. **Content per language** follows the pattern `content/<collection>/pt/…` +
   `content/<collection>/en/…` with the **same filename** on both sides
   (this is how the PT/EN selector links the versions).
5. **Personal/configurable data** (name, handle, email, domain, socials)
   only in `static/src/config.ts`.

## Tools in `/ferramentas/`

- Pure logic (no DOM) lives in `static/src/scripts/*.js` so it can be
  tested in Node; components in `src/components/tools/*.astro` only do the
  DOM wiring.
- Most are **100% client-side**: no network calls, no backend dependency.
  The three exceptions (`pwned` — password breach check via k-anonymity;
  `self-scan` of headers; `mirror` — what the server sees about you) talk
  to the Worker in `dynamic/worker/` — they live in the same index, but
  with a "requires server" badge (`ToolsIndexPage.astro`/`ToolPage.astro`,
  a `kind` key per tool), never hidden as if they were client-side. New
  tools that need a server follow the same pattern — decision recorded in
  `dynamic/PLAN.md`.
- When changing logic, validate with known vectors (e.g. RFC 1321 MD5,
  `/24` and `/31` networks) — run with
  `node --input-type=module -e "import(...)"` or similar.

## Style

- Single global CSS in `static/src/styles/global.css` with custom properties
  (`--bg`, `--accent`, …). Use the variables, not literal colors.
- Aesthetic: dark, technical, sober, terminal-green accent (`--accent`) and
  amber (`--accent-2`) for the Lab/warnings. Mobile-first.
- European Portuguese (not Brazilian) in all `content/` editorial copy —
  the site's PT pages, blog posts, and page copy. Documentation in `docs/`,
  `dynamic/PLAN.md`, and this file are in English; see the note in
  `README.md`'s Contributing section for the reasoning.

## Before finishing any change

1. `cd static && npm run build` — must complete with no errors or new warnings.
2. If you touched the tools, test the logic with known vectors.
3. If you added a new page, create **both** versions (PT + EN) and the pair in
   `routes.ts`.

## PR flow

- **A merged PR is closed: never add new commits to it.** New work is
  **always a new PR** — restart the branch from `main`
  (`git checkout -B <branch> origin/main`) and open a new PR. Never stack on
  top of already-merged history.
- Ideally, **keep one PR open** until the feature is confirmed (you can test
  from the branch without merging: `git checkout <branch> && cd dynamic/worker &&
  npx wrangler deploy`), instead of opening several PRs in a row.
