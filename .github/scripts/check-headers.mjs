// Checks that production serves the expected security headers
// (.github/expected-headers.json) and fails if any is missing or regressed.
// Target, in order of priority:
//   1. TARGET_URL  — manual workflow_dispatch input
//   2. DEPLOY_URL  — environment_url of the deployment_status event (Pages)
//   3. PROD_URL    — constant in scripts/lib/target.mjs (no longer the `url`
//      from expected-headers.json: the request target, and the allowlist that
//      authorises sending secrets to it, must not both come out of the same
//      data file — see the comment at the top of that module)
import { readFileSync, appendFileSync } from 'node:fs';
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

// Optional credentials for a Cloudflare Access Service Token (see
// docs/cloudflare-deploy.md). While Access stays enabled in front of the
// site, a request without these credentials gets the login page instead of
// the real response — hence `url` staying SET-ME until one of two things
// happens: Access being disabled at launch, OR these two secrets being
// configured in the repo (Settings → Secrets → Actions: ACCESS_CLIENT_ID,
// ACCESS_CLIENT_SECRET — Service Token created at dash.cloudflare.com →
// Zero Trust → Access → Service Auth). Without the secrets both are '' and
// the behaviour is identical to before.
const ACCESS_CLIENT_ID = process.env.ACCESS_CLIENT_ID || '';
const ACCESS_CLIENT_SECRET = process.env.ACCESS_CLIENT_SECRET || '';
const accessHeaders = ACCESS_CLIENT_ID && ACCESS_CLIENT_SECRET
  ? { 'CF-Access-Client-Id': ACCESS_CLIENT_ID, 'CF-Access-Client-Secret': ACCESS_CLIENT_SECRET }
  : {};

// Secret for the "CI headers check" WAF rule bypass (docs/cloudflare-
// deploy.md §5, rule 2) — replaces the User-Agent match ("headers-check"),
// which was a public string documented in the repo itself: any outside
// request could copy it and skip the country policy (rules 4/5), the only
// real protection after launch. A rotatable secret closes that. Without it
// the header is not sent and the behaviour is identical to before (the WAF
// rule, once migrated to check this header, stops issuing Skip — the
// request falls back to the country policy, exactly like any other
// visitor).
const CI_WAF_TOKEN = process.env.CI_WAF_TOKEN || '';
const wafHeaders = CI_WAF_TOKEN ? { 'x-ci-waf-token': CI_WAF_TOKEN } : {};

/**
 * fetch() that follows redirects by hand, only while they stay on the SAME
 * origin as the initial request — same logic as fetchSameOrigin in
 * check-invariants.mjs: unlike Authorization, the Fetch spec does not strip
 * CF-Access-Client-Id/Secret on cross-origin redirects. Without this, a 3xx
 * to another origin would resend the Access credentials to that
 * destination. With no Access Service Token configured `opts.headers` never
 * carries them, so the risk only exists from the day those two secrets are
 * set.
 */
async function fetchSameOrigin(url, opts, maxRedirects = 5) {
  let current = new URL(url);
  const originalOrigin = current.origin;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    // eslint-disable-next-line no-await-in-loop -- hops are sequential (each depends on the previous Location)
    const res = await fetch(current, { ...opts, redirect: 'manual' });
    const location = res.status >= 300 && res.status < 400 ? res.headers.get('location') : null;
    if (!location) return res;
    const next = new URL(location, current);
    if (next.origin !== originalOrigin) return res; // does not follow off-origin — Access credentials do not leak
    current = next;
  }
  return fetch(current, { ...opts, redirect: 'manual' });
}

// Neutralises newlines/ANSI/control chars before printing data coming from
// the HTTP response (title, headers): without this, a forged value could
// inject a new line starting with `::` and the runner would read it as a
// workflow command (::set-output::, ::add-mask::, …) instead of log text.
function sanitizeForLog(value, maxLen = 200) {
  const str = String(value ?? 'null').slice(0, maxLen);
  // eslint-disable-next-line no-control-regex -- intentional removal of control chars/ANSI
  return str.replace(/[\x00-\x1f\x7f]/g, '?').replace(/::/g, ': :');
}

// Only the first bytes are needed to extract <title> — res.text() loaded the
// whole response into memory, and the target (production, behind WAF/Access)
// is in practice third-party controlled for a block page: a deliberately
// huge body would slow the job down or exhaust the runner's memory.
async function readBodyPrefix(res, maxBytes = 4096) {
  const reader = res.body?.getReader();
  if (!reader) return '';
  const chunks = [];
  let received = 0;
  while (received < maxBytes) {
    // eslint-disable-next-line no-await-in-loop -- sequential reads from the same stream
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
  }
  await reader.cancel().catch(() => {});
  return Buffer.concat(chunks.map((c) => Buffer.from(c)), received).subarray(0, maxBytes).toString('utf8');
}

// The JSON's `url` no longer picks the target, but it still has to agree
// with the constant — silently diverging would mean checking one domain and
// documenting another.
const mismatch = configUrlMismatch(cfg.url);
if (mismatch) {
  console.error(`::error::check-headers: ${mismatch}`);
  process.exit(1);
}

const explicitTarget = process.env.TARGET_URL || process.env.DEPLOY_URL || '';
if (!explicitTarget && !isProductionConfigured(cfg.url)) {
  // ::warning:: (not ::notice::) on purpose — finding from the 2026-07
  // security review (round 4, N3): this path ran in production for 13 days
  // straight, always green, checking nothing (Access blocks any
  // unauthenticated request — see docs/cloudflare-deploy.md). A ::notice::
  // shows up neither in the run's annotation list nor in the summary by
  // default; a ::warning:: does (yellow triangle, visible in the run list).
  // It does not fix the root cause (that needs an Access Service Token for
  // CI, or disabling Access — repo owner's call, see
  // docs/cloudflare-deploy.md), but it stops the job from continuing to
  // pass as "all good" when it checked nothing.
  console.log('::warning::check-headers: production URL not set in .github/expected-headers.json — check SKIPPED (nothing was verified in this run).');
  if (process.env.GITHUB_STEP_SUMMARY) {
    appendFileSync(
      process.env.GITHUB_STEP_SUMMARY,
      '## ⚠️ check-headers: nothing was verified\n\n' +
        `\`url\` in \`.github/expected-headers.json\` is still \`SET-ME\` — this job exited without touching production. ` +
        'See docs/cloudflare-deploy.md (Access Service Token, or disabling Access at launch).\n',
    );
  }
  process.exit(0);
}

// Secrets only go out over HTTPS and to the production origin or a preview
// of this site's Cloudflare Pages project — allowlist in
// scripts/lib/target.mjs (isTrustedTarget). This matters mostly for
// DEPLOY_URL, which comes from deployment_status.environment_url: an event
// normally created only by Cloudflare Pages' GitHub integration, but which
// the Deployments API lets any app/token with `deployments: write` on the
// repo fire with whatever environment_url it likes. fetchSameOrigin above
// covers the redirect hops; this covers the initial target.
const targetUrl = resolveTarget(process.env.TARGET_URL, process.env.DEPLOY_URL);
if (targetUrl === null) {
  console.error('::error::check-headers: target is not a valid URL (TARGET_URL/DEPLOY_URL).');
  process.exit(1);
}
const target = targetUrl.href;
const trustedHost = isTrustedTarget(targetUrl);
const sendAccessHeaders = trustedHost ? accessHeaders : {};
const sendWafHeaders = trustedHost ? wafHeaders : {};
if (!trustedHost && (accessHeaders['CF-Access-Client-Id'] || wafHeaders['x-ci-waf-token'])) {
  console.log(`::warning::check-headers: target (${targetUrl.origin}) outside the production/preview allowlist — Access/WAF secrets NOT sent.`);
}

console.log(`Checking ${target}${sendAccessHeaders['CF-Access-Client-Id'] ? ' (with Access Service Token)' : ''}${sendWafHeaders['x-ci-waf-token'] ? ' (with CI_WAF_TOKEN)' : ''}`);
const res = await fetchSameOrigin(target, {
  headers: { 'user-agent': 'headers-check (GitHub Actions; personal-site)', ...sendAccessHeaders, ...sendWafHeaders },
});
console.log(`HTTP ${res.status}`);
if (!res.ok) {
  console.error(`::error::check-headers: response ${res.status} from ${target}`);
  console.error(
    `cf-ray: ${sanitizeForLog(res.headers.get('cf-ray'))}, ` +
      `cf-mitigated: ${sanitizeForLog(res.headers.get('cf-mitigated'))}, ` +
      `server: ${sanitizeForLog(res.headers.get('server'))}`,
  );
  const bodyPrefix = await readBodyPrefix(res);
  const title = /<title>([^<]*)<\/title>/i.exec(bodyPrefix)?.[1];
  if (title) console.error(`response title: ${sanitizeForLog(title)}`);
  process.exit(1);
}

let failures = 0;
for (const [name, required] of Object.entries(cfg.headers)) {
  const value = res.headers.get(name);
  if (value === null) {
    console.error(`::error::Missing header: ${name}`);
    failures += 1;
    continue;
  }
  const missing = required.filter((part) => !value.toLowerCase().includes(part.toLowerCase()));
  if (missing.length > 0) {
    console.error(`::error::Header ${name} regressed — missing ${missing.map((m) => JSON.stringify(m)).join(', ')} (current value: ${value})`);
    failures += 1;
  } else {
    console.log(`ok  ${name}: ${value}`);
  }
}

if (failures > 0) {
  console.error(`::error::${failures} header(s) missing or regressed.`);
  process.exit(1);
}
console.log('All expected headers present.');
