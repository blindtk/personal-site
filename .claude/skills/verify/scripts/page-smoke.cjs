#!/usr/bin/env node
// Browser smoke over the built site (static/dist): serves it locally, opens
// each route at desktop and mobile width, and fails on a JS error, a missing
// local asset, horizontal scroll, or a route that does not answer 200.
// Saves full-page screenshots for a human/agent to look at: what a script
// cannot judge is how it looks.
//
//   node .claude/skills/verify/scripts/page-smoke.cjs [route ...]
//   (default routes: / /en/ /ferramentas/ /en/tools/)
//   SMOKE_OUT=<dir> sets the screenshot folder (default: a new temp dir).
//
// Needs `cd static && npm run build` first. Uses the preinstalled
// Playwright (require('playwright')). Requests to other origins and to /api/
// (the Worker, same origin in production) are aborted and not counted: the
// page must still load without JS errors when the API is down.
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');

const dist = path.resolve(__dirname, '../../../../static/dist');
if (!fs.existsSync(path.join(dist, 'index.html'))) {
  console.error(`no build at ${dist} — run: cd static && npm run build`);
  process.exit(2);
}
const routes = process.argv.slice(2).length ? process.argv.slice(2) : ['/', '/en/', '/ferramentas/', '/en/tools/'];
const out = process.env.SMOKE_OUT || fs.mkdtempSync(path.join(os.tmpdir(), 'site-smoke-'));
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.webp': 'image/webp', '.woff2': 'font/woff2', '.json': 'application/json', '.xml': 'application/xml', '.txt': 'text/plain', '.ico': 'image/x-icon' };

const server = http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  let f = path.join(dist, p);
  if (!f.startsWith(dist)) { res.writeHead(403); return res.end(); }
  if (fs.existsSync(f) && fs.statSync(f).isDirectory()) f = path.join(f, 'index.html');
  else if (!path.extname(f) && fs.existsSync(f + '.html')) f += '.html';
  if (!fs.existsSync(f)) { res.writeHead(404); return res.end('not found'); }
  res.writeHead(200, { 'content-type': types[path.extname(f)] || 'application/octet-stream' });
  fs.createReadStream(f).pipe(res);
});

server.listen(0, '127.0.0.1', async () => {
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch();
  const problems = [];
  for (const route of routes) {
    for (const [vp, viewport] of [['desktop', { width: 1280, height: 800 }], ['mobile', { width: 390, height: 844 }]]) {
      const ctx = await browser.newContext({ viewport });
      const page = await ctx.newPage();
      const tag = `${route} (${vp})`;
      await page.route('**/*', (r) => { const u = r.request().url(); return u.startsWith(base) && !u.startsWith(base + '/api/') ? r.continue() : r.abort(); });
      page.on('pageerror', (e) => problems.push(`${tag}: JS error — ${e.message}`));
      page.on('response', (r) => { if (r.url().startsWith(base) && r.status() >= 400) problems.push(`${tag}: ${r.status()} for ${r.url().slice(base.length)}`); });
      const res = await page.goto(base + route, { waitUntil: 'load' });
      if (!res || res.status() !== 200) { problems.push(`${tag}: route answered ${res && res.status()}`); await ctx.close(); continue; }
      const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      if (overflow > 1) problems.push(`${tag}: horizontal scroll of ${overflow}px`);
      const name = (route.replace(/\//g, '_').replace(/^_|_$/g, '') || 'home') + `-${vp}.png`;
      await page.screenshot({ path: path.join(out, name), fullPage: true });
      await ctx.close();
    }
  }
  await browser.close();
  server.close();
  console.log(`screenshots in ${out}`);
  if (problems.length) { console.log([...new Set(problems)].map((p) => 'FAIL: ' + p).join('\n')); process.exit(1); }
  console.log(`ok: ${routes.length} route(s) × desktop/mobile — 200, no JS errors, no missing local assets, no horizontal scroll`);
});
