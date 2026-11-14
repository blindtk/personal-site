# Intel sync — how the honeypot summary reaches the site

The Threat Intel project page (`/projetos/threat-intel/`,
`/en/projects/threat-intel/`) has a "what the sensor saw" panel: published
addresses, sessions started in the last 7 days, credential pairs, captured
files, the most seen ATT&CK techniques and the tooling the sensor
recognised. The numbers come from the external honeypot
(`honeypot-vps-infra`, [ADR 0019](adr/0019-external-cowrie-honeypot-vps.md)),
which stays a separate project
([ADR 0022](adr/0022-retire-internal-honeypot.md)).

Nothing is committed to this repository to refresh the panel, and the site
is not redeployed for it.

## The path

```
sensor (every feed run)            this site's Worker                 browser
intel.danielmala.co/history.json → */30 cron, fetch when 6 h old → GET /api/intel
  one row of aggregates per day     reduce → KV intel:summary          same-origin
```

1. **The sensor publishes `history.json`** with each feed run: one row per
   UTC day holding counts only (addresses published, sessions started, per
   technique how many addresses it was seen from, recognised campaigns).
   The honeypot repo defines it as the archive that keeps no indicator
   (`feed/lib/history.py`). It is about 6 KB and grows by one row a day.
2. **The Worker's `*/30` cron** reads the stored summary and fetches the
   file only when that summary is 6 hours old: 4 KV writes a day, one KV
   read on the other ticks. It tries `https://intel.danielmala.co/history.json`
   first and the same Pages project's `*.pages.dev` address second.
3. **`GET /api/intel`** only reads KV, behind the data-center Cache API
   (30 minutes). It takes no visitor input and never calls the sensor.
4. **The page** fetches `/api/intel` (same origin, so `connect-src 'self'`
   is unchanged), validates the response again and fills the panel. Until
   then, and whenever the Worker has nothing, it shows a line of text with
   a link to `intel.danielmala.co`.

Code: `dynamic/worker/src/lib/intel.js` (reduction and fetch),
`dynamic/worker/src/index.js` (`refreshIntel`, the route),
`static/src/scripts/intel-summary.js` and
`static/src/components/IntelSummary.astro`.

## Why `history.json` and not `feed.json`

`feed.json` holds every published address and is about 18 MB. Parsing it
would not fit the Free plan's 10 ms of CPU, and it would bring addresses
into this site's Worker for no reason. `history.json` is small and already
free of indicators by the sensor's own design, so the privacy boundary is
drawn by the publisher and then enforced again here.

## Privacy boundary

Only counts, ATT&CK technique ids matching `T1234` or `T1234.001`, and
campaign names matching `^[a-z0-9][a-z0-9-]{0,31}$` leave
`summarizeHistory`. Anything else in the file is dropped, so an address
cannot be stored in KV or served by `/api/intel` even if the upstream file
changed shape. The Worker test suite pins this with a hostile document.

## Freshness

| Stage | Limit |
| --- | --- |
| Collection | every 6 hours |
| Last archived day | no summary if it is more than 3 days old, or in the future |
| KV value | expires after 3 days without a successful collection |
| Page | hides a summary whose day is more than 4 days old |

A sensor that stops publishing therefore makes the panel fall back to its
text line within about 3 days, instead of showing an old day as current.

## Failure modes

| What breaks | What happens |
| --- | --- |
| The zone's WAF refuses the Worker's request to the custom domain | The second source (`*.pages.dev`) is used. |
| Both sources fail, or return something that is not the archive | `intel_fetch_failed` in the Worker logs; the last good summary stays until it expires. |
| The archive's shape changes | Fields that no longer validate come back as `null` (shown as "—") or are dropped; without a valid address count for the last day there is no summary. |
| The Worker is down | The page keeps its build-time text and link. |

## What the honeypot repository must keep

`history.json` at the site root, with `days[].day` (`YYYY-MM-DD`),
`addresses`, and optionally `sessions_started`, `credential_pairs`,
`artifacts`, `usernames`, `addresses_not_scanners`, `techniques` (id →
count) and `campaigns` (list of slugs). Renaming one of the optional fields
empties that figure here; renaming `day` or `addresses` removes the panel.
