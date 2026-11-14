# Intel sync — how `content/intel-summary.json` arrives

The Threat Intel project page (`/projetos/threat-intel/`,
`/en/projects/threat-intel/`) shows a small "what the sensor saw" panel:
totals, the most seen ATT&CK techniques and the most tried usernames for
the last window. The numbers come from the external honeypot
(`honeypot-vps-infra`, [ADR 0019](adr/0019-external-cowrie-honeypot-vps.md)),
which stays a separate project
([ADR 0022](adr/0022-retire-internal-honeypot.md)). This site only renders a
vendored JSON file: no fetch at build time, no request from the browser.

**Status:** the site side is in place. The job that generates the file and
opens the pull request lives in the honeypot repository and is still to be
built. Until the first file is merged the panel is not rendered at all —
there is never sample data in its place.

## Contract

`content/intel-summary.json`, every field required:

```json
{
  "generatedAt": "2026-11-10T06:00:00Z",
  "windowDays": 7,
  "totals": { "events": 0, "sources": 0, "sessions": 0 },
  "techniques": [{ "id": "T1110.001", "name": "Brute Force: Password Guessing", "count": 0 }],
  "usernames": [{ "name": "root", "count": 0 }]
}
```

| Field | Rule |
| --- | --- |
| `generatedAt` | End of the window, ISO 8601 in UTC (`…Z`), not more than 1 h in the future |
| `windowDays` | Integer, 1 to 31 |
| `totals.*` | Integers ≥ 0. `sources` is a **count** of distinct source addresses, never the addresses |
| `techniques` | At most 10 rows, unique `id` matching `T1234` or `T1234.001`, `name` ≤ 80 printable ASCII characters |
| `usernames` | At most 10 rows, unique `name` ≤ 32 printable ASCII characters |
| any `count` | Integer ≥ 0 |

The validator is `static/src/scripts/intel-summary.js`
(`static/test/intel-summary.test.mjs`); the loader is
`static/src/lib/intel.ts`.

## Privacy boundary

Only aggregates cross into this repository. The generator must apply the
honeypot's own publication rules before writing the file (for usernames,
the same multi-ASN, multi-network, multi-day threshold it uses for
credential pairs). As a second line, this site **fails the build** if any
`name` contains something shaped like an IPv4 or IPv6 address, so an
address cannot be published here by a generator bug. Passwords are not part
of the contract.

## Why a PR and not a fetch

Same reasons as the stars catalog ([catalog-sync.md](catalog-sync.md)): the
build stays offline and deterministic, `main` keeps its ruleset with no
bypass actor, and every change to what the page claims is a reviewed diff
of one JSON file. A browser-side fetch to `intel.danielmala.co` would also
need `connect-src` opened beyond `'self'`.

## Staleness

The panel always prints the window and its end date. A summary older than
30 days at build time is not rendered: a stalled pipeline makes the panel
disappear instead of showing an old week as recent. A build only happens on
a push, so a quiet repository can still serve a summary up to 30 days old
plus the time since its last build; the date on the panel is what keeps
that honest.

## Failure modes

| What breaks | What happens |
| --- | --- |
| No file yet, or the file is removed | The panel is not rendered; the page is otherwise unchanged. |
| The file does not match the contract | The build fails with the field named in the error. |
| A name looks like an IP address | The build fails. |
| The generator stops running | The last merged summary stays until it is 30 days old, then the panel disappears on the next build. |

## Manual update

Write the file by hand from the sensor's report, open a PR with only
`content/intel-summary.json`, and let CI build it.
