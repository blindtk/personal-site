// Queries the public Mozilla HTTP Observatory API
// (observatory-api.mdn.mozilla.net) against production — a second grading
// grid, independent from check-headers.mjs: the latter only confirms the
// presence/exact value of each header already decided; the Observatory also
// tests cookies, the redirect chain, cross-origin isolation, etc. against its
// own public rubric, and may catch something our list does not cover. Free
// API, no key, built on purpose for CI/CD (rate limit of 1 scan/host/minute —
// returns a cached result if exceeded).
// See https://github.com/mdn/mdn-http-observatory.
//
// Target, same pattern as check-headers.mjs:
//   1. TARGET_URL — manual workflow_dispatch input
//   2. PROD_URL   — constant in scripts/lib/target.mjs (why in code and not
//      in the `url` of expected-headers.json: see the top of that module)
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { configUrlMismatch, isProductionConfigured, resolveTarget } from './lib/target.mjs';

const cfgPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'expected-headers.json');
const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));

const mismatch = configUrlMismatch(cfg.url);
if (mismatch) {
  console.error(`::error::check-observatory: ${mismatch}`);
  process.exit(1);
}

if (!process.env.TARGET_URL && !isProductionConfigured(cfg.url)) {
  console.log('::warning::check-observatory: production URL not set in .github/expected-headers.json — check SKIPPED (nothing was verified in this run).');
  process.exit(0);
}

const targetUrl = resolveTarget(process.env.TARGET_URL);
if (targetUrl === null) {
  console.error('::error::check-observatory: target is not a valid URL (TARGET_URL).');
  process.exit(1);
}
const host = targetUrl.host;
const API_URL = `https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${encodeURIComponent(host)}`;

// The timeout avoids blocking the job for hours if the API hangs — without
// it, a hang was bounded only by GitHub Actions' default timeout (360 min),
// not by anything this script controls. One retry covers the Observatory's
// already documented transient 500 on the first scan of a new host
// (CodeRabbit finding in PR #155, confirmed) — since the target is always the
// same host, this usually only matters on the very first run.
const REQUEST_TIMEOUT_MS = 30_000;

async function requestScan(attempt = 1) {
  let res;
  try {
    res = await fetch(API_URL, { method: 'POST', signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  } catch (err) {
    if (attempt < 2) {
      console.log(`::warning::check-observatory: request failed on attempt ${attempt} (${err?.message ?? err}) — retrying…`);
      return requestScan(attempt + 1);
    }
    console.error(`::error::check-observatory: API request failed — ${err?.message ?? err}`);
    process.exit(1);
  }
  // Only retries on 5xx — a 4xx (e.g. invalid host) is final, the request
  // would keep failing the same way, and retrying only delayed the job with
  // no real chance of success (CodeRabbit finding in PR #155, confirmed).
  if (!res.ok && res.status >= 500 && attempt < 2) {
    console.log(`::warning::check-observatory: API responded HTTP ${res.status} on attempt ${attempt} — retrying…`);
    return requestScan(attempt + 1);
  }
  return res;
}

console.log(`Requesting a Mozilla HTTP Observatory scan for ${host}…`);
const res = await requestScan();
if (!res.ok) {
  console.error(`::error::check-observatory: API responded HTTP ${res.status} (${host})`);
  process.exit(1);
}

const result = await res.json();

if (result.error) {
  // The Observatory itself could not evaluate the target (e.g. DNS, timeout)
  // — this is a real check failure, not a "low grade".
  console.error(`::error::check-observatory: the Observatory could not evaluate ${host} — ${result.error}`);
  process.exit(1);
}

const grade = String(result.grade ?? '?');
console.log(`Observatory: ${host} → grade ${grade} (score ${result.score}, ${result.tests_passed}/${result.tests_quantity} tests passed)`);
console.log(`Details: ${result.details_url}`);

if (result.status_code && result.status_code !== 200) {
  console.log(`::warning::Observatory saw HTTP ${result.status_code} instead of 200 when requesting ${host} — this may be an unexpected redirect or the scanner being blocked.`);
}

// Production already goes through check-headers.mjs (exact headers) — a
// grade below A here flags something that list does not cover; D/F is treated
// as a serious regression (fails the job), B/C as a warning (worth a look,
// not urgent).
const band = grade[0];
if (band === 'D' || band === 'F') {
  console.error(`::error::Observatory grade ${grade} for ${host} — see ${result.details_url}.`);
  process.exit(1);
}
if (band === 'B' || band === 'C') {
  console.log(`::warning::Observatory grade ${grade} for ${host} (below A) — see ${result.details_url}.`);
}

console.log('Observatory check complete.');
