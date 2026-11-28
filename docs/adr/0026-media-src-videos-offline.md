# ADR 0026 — Explainer videos rendered offline from `media-src/`

**Status:** accepted (2026-11-28).

## Context

Two things on the site are easier to show than to read:

- the honeypot pipeline (`/projetos/threat-intel/`);
- the path from a commit to production (`/este-site/provas/`).

Both are sequences with parallel steps. A video does that with zero
JavaScript at runtime, but its source is code (HTML, CSS and a GSAP
timeline) and it needs a renderer. CLAUDE.md gives the repository three
areas with rigid roles (`content/`, `static/`, `dynamic/`), and none of them
fits a render tool:

- `static/` must not grow a Chrome + FFmpeg toolchain;
- `content/` must hold no code.

Tools considered (the analysis is kept outside this public repository):

- **HyperFrames (Apache-2.0).** Compositions are plain HTML and CSS, so they
  reuse the site's own colour tokens, and the animations are GSAP, like the
  site's (ADR 0025). Chosen.
- **Remotion.** React compositions, and a licence that is free only for
  individuals and small companies.
- **anything2explainer and onetake.** PolyForm Noncommercial, which is a
  questionable fit for a professional portfolio.

## Decision

1. **`media-src/` is a fourth, offline-only area.**
   - It holds the films (`films/<name>/index.html`) and the scripts that
     prepare and render them.
   - It is never built or run in CI, and `static/` never imports from it.
   - Its own `package.json` pins `hyperframes` and `gsap` to exact versions.
2. **Everything a film states comes from the repository.**
   `scripts/prepare.mjs` copies:
   - the `:root` tokens from `static/src/styles/global.css`;
   - GSAP from `node_modules`, never a CDN;
   - for the CI film, the workflow names read from `.github/workflows` (the
     ones triggered by `pull_request` and the post-deploy `check_run` ones),
     written into the film's HTML between markers so the diff shows when
     they change.
3. **Output goes to `static/public/video/`:** one H.264 MP4 per film, no
   audio track, `faststart`, plus a WebP poster.
   - Both films came out at ~200 KB per minute of flat graphics.
   - AV1/WebM came out the same size, so it is not shipped.
   - The binaries are committed: small, and rarely re-rendered.
4. **Captions are content.** They live in `content/video/{pt,en}/<film>.vtt`.
   - A static endpoint serves them at `/video/<film>.<lang>.vtt`.
   - The component renders the same cues as an on-page transcript.
   - Tests check that each film has both languages with identical cue
     timings.
5. **On-screen labels are language-neutral technical names** (`ssh`,
   `feed.json`, `Worker`, the workflow names). The narrative is in the
   captions, so one file serves PT and EN.
6. **The CLI's usage telemetry is always off** (`HYPERFRAMES_NO_TELEMETRY=1`
   and `DO_NOT_TRACK=1` in `scripts/env.mjs`). No HeyGen account, cloud render
   or share is used.
7. **Playback rules** (`VideoExplainer.astro`):
   - `preload="none"`; controls always shown.
   - Never sound: the files have no audio track.
   - The one looping clip is muted and plays only while on screen, with the
     tab visible and no `prefers-reduced-motion`. A manual pause is
     respected.

## Consequences

- **No CSP change.** `<video>`, `<track>` and the poster are same-origin and
  covered by `default-src` and `img-src` (ADR 0025).
- **Re-rendering needs Node 22+, FFmpeg (libx264, libwebp) and a Chrome**
  (`npm run render` in `media-src/`). A content change to a film is a
  re-render plus a commit of the new MP4.
- **Lockfile scanning.** OSV-Scanner and Dependency Review see
  `media-src/package-lock.json`. Its packages (Puppeteer, an HTTP server
  for the preview) never reach visitors, but a vulnerability in them still
  shows up in CI, and that is the intended behaviour.
- **The films can drift from reality**, for example a workflow renamed
  without a re-render. The CI film's names come from a script, so the fix is
  to re-render. The honeypot film states only what
  `content/projects/*/threat-intel.md` states.
