// Closes the detection → alert loop that was missing (discussed in a
// security review, 2026-07-29): the honeypot/threat-intel/CT/CF dashboards
// are PULL only — they show data when someone deliberately opens the page,
// but nothing warns anyone when something breaks. This is the missing piece:
// it checks the Worker's read endpoints and returns exit 1 if something is
// genuinely wrong, so the workflow (invariants.yml) can open an Issue that
// reaches the repo owner without them having to go looking.
//
// Target, same pattern as check-headers.mjs:
//   1. TARGET_URL — manual workflow_dispatch input
//   2. PROD_URL   — constant in scripts/lib/target.mjs (why in code and not
//      in the `url` of expected-headers.json: see the top of that module)
// (no DEPLOY_URL: this script does not run on deployment_status, only
// scheduled and by hand — the target is always production, never a preview.)
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  configUrlMismatch,
  isProductionConfigured,
  isTrustedTarget,
  resolveTarget,
} from './lib/target.mjs';

const cfgPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'expected-headers.json');
const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));

const mismatch = configUrlMismatch(cfg.url);
if (mismatch) {
  console.error(`::error::check-invariants: ${mismatch}`);
  process.exit(1);
}

if (!process.env.TARGET_URL && !isProductionConfigured(cfg.url)) {
  // Same decision as check-headers.mjs: while Access blocks unauthenticated
  // requests there is nothing real to check — an error here would mask
  // Access as "production is broken". ::warning:: (not ::notice::) so it
  // stays visible in the run list.
  console.log('::warning::check-invariants: production URL not set in .github/expected-headers.json — check SKIPPED (nothing was verified in this run).');
  process.exit(0);
}

const targetUrl = resolveTarget(process.env.TARGET_URL);
if (targetUrl === null) {
  console.error('::error::check-invariants: target is not a valid URL (TARGET_URL).');
  process.exit(1);
}
const target = targetUrl.href;

const ACCESS_CLIENT_ID = process.env.ACCESS_CLIENT_ID || '';
const ACCESS_CLIENT_SECRET = process.env.ACCESS_CLIENT_SECRET || '';
const accessHeaders = ACCESS_CLIENT_ID && ACCESS_CLIENT_SECRET
  ? { 'CF-Access-Client-Id': ACCESS_CLIENT_ID, 'CF-Access-Client-Secret': ACCESS_CLIENT_SECRET }
  : {};

// Secret for the "CI headers check" WAF rule bypass (docs/cloudflare-
// deploy.md §5, rule 2) — see the equivalent comment in check-headers.mjs.
// This coverage was the missing finding: the WAF rule only recognised the
// "headers-check" User-Agent (check-headers.mjs only), never this script's —
// after launch this workflow would fall into the country policy and start
// reporting production as broken because of the WAF itself, not because of a
// real invariant. The same secret covers both scripts.
const CI_WAF_TOKEN = process.env.CI_WAF_TOKEN || '';
const wafHeaders = CI_WAF_TOKEN ? { 'x-ci-waf-token': CI_WAF_TOKEN } : {};

// Same reason and same logic as fetchSameOrigin in check-headers.mjs:
// CF-Access-Client-Id/Secret are not stripped by the Fetch spec on
// cross-origin redirects, unlike Authorization.
async function fetchSameOrigin(url, opts, maxRedirects = 5) {
  let current = new URL(url);
  const originalOrigin = current.origin;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    // eslint-disable-next-line no-await-in-loop -- hops are sequential (each depends on the previous Location)
    const res = await fetch(current, { ...opts, redirect: 'manual' });
    const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
    if (!location) return res;
    const next = new URL(location, current);
    if (next.origin !== originalOrigin) return res;
    current = next;
  }
  return fetch(current, { ...opts, redirect: 'manual' });
}

// Same allowlist as check-headers.mjs (scripts/lib/target.mjs), applied here
// for consistency: TARGET_URL only comes from a manual workflow_dispatch (no
// DEPLOY_URL in this script — see the comment at the top), but the secrets
// must only go out over HTTPS and to the production origin, or to a preview
// of this site's Cloudflare Pages project (never any *.pages.dev).
const trustedHost = isTrustedTarget(targetUrl);
const sendAccessHeaders = trustedHost ? accessHeaders : {};
const sendWafHeaders = trustedHost ? wafHeaders : {};
if (!trustedHost && (accessHeaders['CF-Access-Client-Id'] || wafHeaders['x-ci-waf-token'])) {
  console.log(`::warning::check-invariants: target (${targetUrl.origin}) outside the production/preview allowlist — Access/WAF secrets NOT sent.`);
}

const UPSTREAM_TIMEOUT_MS = 8000;
const headers = { 'user-agent': 'check-invariants (GitHub Actions; personal-site)', ...sendAccessHeaders, ...sendWafHeaders };

async function checkJson(path) {
  const url = new URL(path, target);
  try {
    const res = await fetchSameOrigin(url, { headers, signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS) });
    if (res.status === 429) {
      // A rate limit blocking us is the protection working, not a failure —
      // it would be ironic to mark as "production broken" the very control
      // the security review asked to strengthen (finding A1).
      return { path, ok: true, status: 429, note: 'rate limited (expected behaviour)' };
    }
    if (!res.ok) return { path, ok: false, status: res.status, note: `HTTP ${res.status}` };
    let body;
    try {
      body = await res.json();
    } catch {
      return { path, ok: false, status: res.status, note: 'response is not valid JSON' };
    }
    return { path, ok: true, status: res.status, body };
  } catch (err) {
    return { path, ok: false, status: null, note: err?.message ?? String(err) };
  }
}

// /api/health is the only CRITICAL invariant: it depends on no third-party
// upstream (NVD/CISA/crt.sh/HIBP/Cloudflare GraphQL) — if it fails, the
// Worker itself is down, it is not a slow external API.
const CRITICAL = ['/api/health'];

// Safe reads (GET, no side effects, consuming no write budget at all — see
// dynamic/PLAN.md on the daily caps). Failures here go into the report but
// only fail the job if ACCOMPANIED by /api/health failing too, or if more
// than one of these fails at the same time (a single flaky upstream feed
// should not wake anyone at 3am; two or more different routes breaking at
// once already smells like a real Worker problem, not one specific upstream
// being down).
const INFORMATIONAL = [
  '/api/honeypot', '/api/map',
  '/api/vitals', '/api/ct', '/api/cf-stats', '/api/mirror',
];

const results = await Promise.all([...CRITICAL, ...INFORMATIONAL].map(checkJson));

let hardFailures = 0;
let softFailures = 0;
for (const r of results) {
  const isCritical = CRITICAL.includes(r.path);
  if (r.ok) {
    if (r.path === '/api/health' && r.body?.ok !== true) {
      console.error(`::error::${r.path}: HTTP 200 but unexpected body (${JSON.stringify(r.body)})`);
      hardFailures += 1;
      continue;
    }
    console.log(`ok  ${r.path} (HTTP ${r.status}${r.note ? `, ${r.note}` : ''})`);
  } else if (isCritical) {
    console.error(`::error::${r.path} (critical): ${r.note}`);
    hardFailures += 1;
  } else {
    console.log(`::warning::${r.path}: ${r.note}`);
    softFailures += 1;
  }
}

// Two or more informational routes down at the same time stop being "one
// specific upstream is flaky" and become a signal that something in the
// Worker itself broke (e.g. a change to the cached()/getJSON shared by every
// route).
if (softFailures >= 2) {
  console.error(`::error::${softFailures} informational routes failed at the same time — this no longer looks like an isolated upstream.`);
  hardFailures += 1;
}

if (hardFailures > 0) {
  console.error(`::error::${hardFailures} critical invariant(s) failed.`);
  process.exit(1);
}
console.log('All critical invariants passed.');
