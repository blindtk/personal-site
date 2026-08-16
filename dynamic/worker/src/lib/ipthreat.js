// Lista de ameaças do honeypot indexada por IP (ADR 0020,
// docs/adr/0020-honeypot-public-ip.md) — separada dos buckets anónimos
// existentes (lib/aggregate.js), que continuam sem IP e a alimentar os
// painéis públicos exatamente como antes. Pura e testável, sem I/O.

/** Lista vazia. */
export function emptyIpList() {
  return {};
}

/**
 * Regista/atualiza uma deteção para um IP já validado como público (ver
 * lib/ipguard.js — a validação é responsabilidade de quem chama, não
 * desta função). Acumula país/ASN mais recentes e as técnicas vistas
 * (sem repetir). Muta e devolve `ipList`.
 */
export function recordIpSighting(ipList, { ip, now, country, asn, technique }) {
  const prev = ipList[ip];
  const techniques = prev?.techniques ? [...prev.techniques] : [];
  if (technique && !techniques.includes(technique)) techniques.push(technique);
  ipList[ip] = {
    firstSeen: prev?.firstSeen ?? now,
    lastSeen: now,
    count: (prev?.count ?? 0) + 1,
    country: country ?? prev?.country ?? 'XX',
    asn: asn ?? prev?.asn ?? null,
    techniques,
  };
  return ipList;
}

/**
 * Remove entradas sem nova deteção há mais de `maxAgeMs` — ADR 0020: 30
 * dias, mais conservador que os 60-90 da VPS externa (docs/external-honeypot-vps.md
 * §3), porque os scanners HTTP que este honeypot apanha têm mais chance
 * de correr em IoT/routers domésticos comprometidos do que os de força
 * bruta SSH da VPS. Devolve uma lista NOVA (nunca muta a recebida) mais
 * quantas entradas saíram, para o chamador só escrever no KV quando algo
 * mudou de facto.
 */
export function pruneExpiredIps(ipList, { now, maxAgeMs }) {
  const next = {};
  let prunedCount = 0;
  for (const [ip, entry] of Object.entries(ipList ?? {})) {
    if (now - (entry?.lastSeen ?? 0) > maxAgeMs) {
      prunedCount += 1;
      continue;
    }
    next[ip] = entry;
  }
  return { list: next, prunedCount };
}

/**
 * Forma pública ordenada (mais recente primeiro), para /api/threat-intel.
 * O campo `ip` só existe aqui — em todo o resto do Worker (buckets,
 * `recent`, Registo) os eventos continuam sem IP, por decisão explícita
 * (ADR 0020), não por omissão.
 */
export function ipThreatList(ipList, { limit = 200 } = {}) {
  return Object.entries(ipList ?? {})
    .map(([ip, entry]) => ({
      ip,
      firstSeen: entry?.firstSeen ?? null,
      lastSeen: entry?.lastSeen ?? null,
      count: entry?.count ?? 0,
      country: entry?.country ?? 'XX',
      asn: entry?.asn ?? null,
      techniques: Array.isArray(entry?.techniques) ? entry.techniques : [],
    }))
    .sort((a, b) => (b.lastSeen ?? 0) - (a.lastSeen ?? 0))
    .slice(0, limit);
}
