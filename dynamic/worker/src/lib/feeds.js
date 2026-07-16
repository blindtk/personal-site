// Feeds de threat intel para o ticker SOC: CISA KEV + NVD (CVEs críticos
// recentes). As funções de PARSE (puras, testáveis) estão separadas das de
// FETCH (rede). Tudo o que sai daqui já passou por normalizeTickerItem.

import { normalizeTickerItem, sanitizeText } from './sanitize.js';
import { techniquesForText } from './attack-map.js';

/** Parse do JSON da CISA KEV → itens normalizados, mais recentes primeiro. */
export function parseKev(json, limit = 12) {
  const vulns = Array.isArray(json?.vulnerabilities) ? json.vulnerabilities : [];
  return vulns
    .slice()
    .sort((a, b) => String(b.dateAdded ?? '').localeCompare(String(a.dateAdded ?? '')))
    .slice(0, limit)
    .map((v) =>
      normalizeTickerItem({
        id: v.cveID,
        source: 'kev',
        severity: 'KEV',
        title: `${sanitizeText(v.vendorProject ?? '', 40)} ${sanitizeText(v.product ?? '', 40)}`.trim(),
        // técnica inferida do nome/descrição da vuln (não do título mostrado)
        techniques: techniquesForText(`${v.vulnerabilityName ?? ''} ${v.shortDescription ?? ''}`),
      }),
    )
    .filter(Boolean);
}

/** Parse da resposta da API 2.0 do NVD → críticos normalizados. */
export function parseNvd(json, limit = 12) {
  const items = Array.isArray(json?.vulnerabilities) ? json.vulnerabilities : [];
  const out = [];
  for (const item of items) {
    const cve = item?.cve;
    if (!cve) continue;
    const metrics = cve.metrics?.cvssMetricV31 ?? cve.metrics?.cvssMetricV30 ?? [];
    const primary = metrics.find((m) => m.type === 'Primary') ?? metrics[0];
    const cvss = primary?.cvssData;
    if (!cvss || cvss.baseSeverity !== 'CRITICAL') continue;
    const desc = (cve.descriptions ?? []).find((d) => d.lang === 'en')?.value ?? '';
    const normalized = normalizeTickerItem({
      id: cve.id,
      source: 'nvd',
      severity: `CRIT ${Number(cvss.baseScore).toFixed(1)}`,
      title: desc,
      techniques: techniquesForText(desc),
    });
    if (normalized) out.push(normalized);
    if (out.length >= limit) break;
  }
  return out;
}

/** Intercala duas listas (KEV, NVD) preservando alternância e sem repetir CVE. */
export function mergeFeeds(kev, nvd, limit = 16) {
  const seen = new Set();
  const out = [];
  const max = Math.max(kev.length, nvd.length);
  for (let i = 0; i < max && out.length < limit; i += 1) {
    for (const item of [kev[i], nvd[i]]) {
      if (item && !seen.has(item.id)) {
        seen.add(item.id);
        out.push(item);
      }
    }
  }
  return out.slice(0, limit);
}

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** Últimos N dias em ISO (para a janela do NVD). */
function isoDaysAgo(days, now = Date.now()) {
  return new Date(now - days * 86400_000).toISOString().slice(0, 23);
}

/** Busca e normaliza o ticker. Degrada para KEV-only se o NVD falhar. */
export async function fetchTicker(env, { limit = 16 } = {}) {
  const headers = { 'user-agent': 'personal-site-worker (threat-intel ticker)' };
  const kevItems = await fetch(KEV_URL, { headers, cf: { cacheTtl: 3600 } })
    .then((r) => (r.ok ? r.json() : null))
    .then((j) => (j ? parseKev(j) : []))
    .catch(() => []);

  const nvdUrl =
    'https://services.nvd.nist.gov/rest/json/cves/2.0' +
    `?cvssV3Severity=CRITICAL&pubStartDate=${isoDaysAgo(7)}&pubEndDate=${isoDaysAgo(0)}&resultsPerPage=20`;
  const nvdHeaders = env?.NVD_API_KEY ? { ...headers, apiKey: env.NVD_API_KEY } : headers;
  const nvdItems = await fetch(nvdUrl, { headers: nvdHeaders, cf: { cacheTtl: 3600 } })
    .then((r) => (r.ok ? r.json() : null))
    .then((j) => (j ? parseNvd(j) : []))
    .catch(() => []);

  return { items: mergeFeeds(kevItems, nvdItems, limit), fetchedAt: Date.now() };
}
