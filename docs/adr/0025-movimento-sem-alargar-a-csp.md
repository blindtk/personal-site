# ADR 0025 — Motion without widening the CSP; GSAP as the first third-party client library

**Status:** accepted (2026-11-28). First applied in the "Your request, step
by step" section of `/este-site/` (`src/components/site/RequestPath.astro`),
then in the Evidence page's live `curl -sI`, the home hero's amber trace and
the Homelab project's 3D scene.

## Context

The site wants motion that explains or proves something: the path a request
takes, the headers actually served, how the honeypot pipeline works. It must
not decorate. The obvious candidates each collide with the CSP in
`static/public/_headers` (ADR 0001):

- **three.js with compressed glTF.** `DRACOLoader` and `KTX2Loader` always
  start their decoders as workers built from a `Blob`.
- **PlayCanvas.** It sorts Gaussian splats in a `Blob` worker and weighs
  ~289 KB gz before any content.
- **GSAP's SplitText.** `revert()` writes to `innerHTML`.
- **MengTo/threeui components.** They render as `<iframe srcdoc>` documents
  that load Tailwind, GSAP and Iconify from CDNs.

Opening `worker-src` is not enough on its own. Under
`require-trusted-types-for 'script'`, the `Worker` constructor is a
`TrustedScriptURL` sink: `new Worker('/w.js')` and `new Worker(blobUrl)` are
both blocked even with `worker-src 'self' blob:`. Any worker therefore also
needs a named Trusted Types policy in place of `trusted-types 'none'`.
`'wasm-unsafe-eval'` is the only cheap addition; it is enough for
`WebAssembly.compile`.

All of this was checked in Chromium on 2026-11-28 against a page served with
this site's policy. The process and measurements are kept outside this public
repository.

## Decision

1. **Motion uses only techniques that fit the current policy:** CSS, WAAPI,
   GSAP *core* (without SplitText), SVG and same-origin `<video>`. The CSP does
   not change.
2. **GSAP is the first third-party library served to visitors.**
   - Installed from npm (`gsap`, a dependency of `static/`).
   - Imported from `gsap/gsap-core`, without the CSSPlugin (~20 KB gz instead
     of ~28 KB). Only SVG attributes are animated, which keeps style changes
     out of the picture.
   - Loaded with `import()` only where it is used: wide screens, no
     `prefers-reduced-motion`, and only when the section nears the viewport.
     Every other page and visitor pays nothing.
   - Never loaded from a CDN.
3. **Licence notices ship with the code.**
   `vite.build.rolldownOptions.output.comments.legal` keeps the
   `/*! … @license … */` comments that the minifier would otherwise strip.
   GSAP's standard "no charge" licence, like MIT, expects the copyright notice
   to travel with the code.
4. **Video is not served by this policy decision alone.** Pre-rendered video
   is served from `static/public/`. `media-src` is not added because
   `default-src 'self'` already covers `<video>` and `<track>`.
5. **The expensive additions stay closed.** `'wasm-unsafe-eval'`,
   `worker-src` with anything but `'none'`, and a named Trusted Types policy
   wait for a feature that has no alternative. Opening any of them needs its
   own ADR, with the
   `expected-headers.json` update (which pins `worker-src 'none'`) in the same
   change.

## Consequences

- The CSP stays at 370 characters and `verify-headers` is unchanged.
- **3D is procedural** or uses uncompressed glTF (`KHR_mesh_quantization`),
  with no decoders. The first use is the Homelab project's "Try the rule"
  scene (`src/components/homelab/`). It uses `three`: boxes and lines, flat
  colours from the CSS variables and no lights. It is loaded with `import()`
  only when the visitor clicks "View in 3D" (~131 KB gz). The explanation
  itself (pick two segments, read what the firewall does) is plain HTML and
  JS and works without WebGL.
- **`three` is 0.x, and every minor can break the API.** Renovate gets a
  rule to give it (and `@types/three`) its own PR instead of the grouped
  non-major one. `chunkSizeWarningLimit` sits just above its chunk, so any
  other chunk that grows still warns.
- **Every motion feature keeps a static final state.** Reduced motion, narrow
  screens, a failed `import()` or no JavaScript all get it. The text in the
  HTML is the content; the animation only marks where the reader is.
- **`/este-site/` now calls `/api/mirror` once per visitor who scrolls to the
  section.** The route is already rate-limited (30/min per client) and stores
  nothing beyond the rate-limit hash (ADR 0023).
- **Renovate picks up `gsap` with no extra configuration.** The 4.x major,
  in beta at the time of writing, will arrive as its own PR.
