// Neutralises newlines/ANSI/control chars before printing data that comes from
// outside the repo (HTTP responses, third-party APIs, DNS, testssl output):
// without this, a forged value could inject a new line starting with `::` and
// the runner would read it as a workflow command (::add-mask::, ::error::,
// ::stop-commands::, …) instead of log text. Shared by every check-*.mjs.
export function sanitizeForLog(value, maxLen = 200) {
  const str = String(value ?? 'null').slice(0, maxLen);
  // eslint-disable-next-line no-control-regex -- intentional removal of control chars/ANSI
  return str.replace(/[\x00-\x1f\x7f-\x9f\u2028\u2029]/g, '?').replace(/::/g, ': :');
}
