// Target for the checks against production (headers, invariants,
// Observatory), resolved from the constants in this module — never from data
// read out of a file.
//
// Why the production origin lives here and not in the `url` of
// .github/expected-headers.json (where it used to be chosen): the target of
// these scripts is also the destination they attach secrets to
// (CF-Access-Client-Id/Secret, x-ci-waf-token). While the allowlist
// authorising that came out of the same file that chose the target, the
// check and the value being checked had a single source: one changed line in
// the JSON moved both at once and the allowlist approved the new
// destination. With the origin pinned in code, the JSON no longer decides
// where the request goes — it keeps what is actually its job: the list of
// expected headers, the "production is checkable yet" switch (`url` at
// SET-ME = nothing to check, see docs/cloudflare-deploy.md §3 and §7) and a
// consistency check against the constant (diverging fails the job instead of
// silently moving the destination).
//
// It is also what CodeQL flagged as js/file-access-to-http ("File data in
// outbound network request", alerts #11/#12 in check-headers.mjs): the URL
// reaching fetch() derived from the readFileSync of the JSON. The file →
// network data path is gone — the default target is a constant, and the
// JSON's `url` is only compared against it, never followed.
export const PROD_URL = 'https://danielmala.co/';
export const PROD_ORIGIN = new URL(PROD_URL).origin;

// Previews of this site's Cloudflare Pages project
// (docs/cloudflare-deploy.md §2) — never any *.pages.dev, a shared domain
// where any free account can register a project and receive the secrets that
// way.
export const PAGES_PROJECT_HOST = 'personal-site-4fm.pages.dev';

/**
 * Is production checkable yet? `url` at SET-ME in expected-headers.json
 * means it is not (Access in front of the site returning the login page to
 * any unauthenticated request).
 */
export function isProductionConfigured(cfgUrl) {
  return typeof cfgUrl === 'string' && cfgUrl !== '' && !cfgUrl.startsWith('SET-ME');
}

/**
 * Consistency between the `url` versioned in the JSON and PROD_URL above.
 * Returns a message if they diverge (the caller fails the job) or null if
 * they agree. Without this, changing the domain only in the JSON would
 * become a silent no-op: the scripts would keep checking the old domain.
 *
 * The message never interpolates the raw value read from the file — only the
 * hostname derived from the URL, which cannot contain newlines or `::` and
 * therefore cannot forge a workflow command in the runner's log.
 */
export function configUrlMismatch(cfgUrl) {
  if (!isProductionConfigured(cfgUrl)) return null;
  let parsed;
  try {
    parsed = new URL(cfgUrl);
  } catch {
    return '`url` in .github/expected-headers.json is not a valid URL.';
  }
  if (parsed.origin !== PROD_ORIGIN) {
    return `\`url\` in .github/expected-headers.json points at ${parsed.protocol}//${parsed.hostname} `
      + `but the production origin pinned in .github/scripts/lib/target.mjs is ${PROD_ORIGIN} — `
      + 'update both (the constant is the one that decides where requests go).';
  }
  return null;
}

/**
 * May the target receive the Access/WAF secrets? Only HTTPS on the default
 * port, and only the production origin or a preview of this site's
 * Cloudflare Pages project. This covers the initial target; the redirect
 * hops are covered by each script's fetchSameOrigin.
 */
export function isTrustedTarget(url) {
  if (url.protocol !== 'https:' || url.port !== '') return false;
  if (url.origin === PROD_ORIGIN) return true;
  return url.hostname === PAGES_PROJECT_HOST || url.hostname.endsWith(`.${PAGES_PROJECT_HOST}`);
}

/**
 * Resolves the target in order of priority, skipping empty candidates:
 * workflow inputs (TARGET_URL/DEPLOY_URL) first, PROD_URL by default.
 * Returns null if an explicit candidate is not a valid URL — a mistyped
 * manual input used to produce a Node stack trace instead of a message.
 */
export function resolveTarget(...candidates) {
  const raw = candidates.find((c) => typeof c === 'string' && c !== '') ?? PROD_URL;
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}
