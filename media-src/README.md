# media-src — source of the site's explainer videos

Offline tool (ADR 0026): HTML + CSS + GSAP compositions rendered to MP4 with
[HyperFrames](https://github.com/heygen-com/hyperframes). Nothing here runs
in CI or is imported by `static/`; the output files are committed to
`static/public/video/`.

| Film | Where it plays | Length |
| --- | --- | --- |
| `films/honeypot-pipeline/` | `/projetos/threat-intel/` (+EN) | 48 s |
| `films/ci-pipeline/` | `/este-site/provas/#h-workflows` (+EN), muted loop | 18 s |

Captions (PT/EN) are content: `content/video/{pt,en}/<film>.vtt`. Keep the
cue timings identical in both languages (`static/test/vtt.test.mjs` checks)
and in step with the film's timeline.

## Render

Needs Node 22+, FFmpeg with libx264 and libwebp, and Chrome (set `HF_BROWSER`
if it isn't at `/usr/bin/google-chrome`).

```bash
cd media-src
npm ci --ignore-scripts
npm run check        # prepare + hyperframes check (lint, runtime, layout)
npm run render       # prepare + render → static/public/video/<film>.{mp4,webp}
node scripts/render.mjs ci-pipeline   # one film only
```

`scripts/prepare.mjs` runs first every time: it copies the site's colour
tokens and GSAP into each film's `assets/` (git-ignored) and regenerates the
CI film's workflow lanes from `.github/workflows`. Commit the regenerated
`films/ci-pipeline/index.html` together with the new MP4.

**Telemetry:** the HyperFrames CLI sends usage counters by default.
`scripts/env.mjs` sets `HYPERFRAMES_NO_TELEMETRY=1` and `DO_NOT_TRACK=1` for
every call; if you run `npx hyperframes` by hand, set them yourself.

## Rules for a film

- Silent: no audio track.
- On-screen text is technical names only; the narrative goes in the captions.
- Every claim must already be stated on the site (the project page, the
  README or the workflows).
- Colours come from `assets/tokens.css` (the site's `:root`), never literals.
