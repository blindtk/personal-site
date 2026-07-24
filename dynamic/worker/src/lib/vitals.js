// RUM (Real User Monitoring) de Core Web Vitals — lógica pura e testável.
// Recebe amostras {lcp,cls,inp,ttfb} de visitantes reais (medidas no browser
// com PerformanceObserver, ver static/public/js/vitals.js) e acumula-as em
// HISTOGRAMAS diários no KV. Nunca guarda a amostra individual, nem IP, nem
// User-Agent, nem URL — só a contagem por balde. O p75 (o percentil que a
// Google usa para classificar os Web Vitals) sai do histograma acumulado.
//
// Primeira parte (first-party): ao contrário do beacon de RUM da Cloudflare
// (script de terceiros), isto respeita a CSP estrita e o "sem trackers" do
// site — é código próprio e só produz agregados.

export const VITALS_METRICS = ['lcp', 'cls', 'inp', 'ttfb'];

// Limiares oficiais dos Core Web Vitals (bom / a-melhorar / mau), no p75.
// CLS é adimensional; os restantes em ms. TTFB é diagnóstico (não é CWV
// "core", mas explica o LCP) — limiares da doc web.dev.
export const VITALS_THRESHOLDS = {
  lcp: { good: 2500, poor: 4000 },
  cls: { good: 0.1, poor: 0.25 },
  inp: { good: 200, poor: 500 },
  ttfb: { good: 800, poor: 1800 },
};

// Bordas superiores de cada balde do histograma (valor ≤ borda cai no balde).
// Uma borda extra "overflow" (index = length) apanha tudo acima da última.
export const VITALS_BUCKETS = {
  lcp: [1000, 1500, 2000, 2500, 3000, 3500, 4000, 5000, 6000, 8000],
  cls: [0.02, 0.05, 0.1, 0.15, 0.2, 0.25, 0.35, 0.5, 0.75, 1],
  inp: [50, 100, 150, 200, 300, 400, 500, 700, 1000, 1500],
  ttfb: [100, 200, 400, 600, 800, 1200, 1800, 2500, 4000, 6000],
};

// Intervalos aceites por métrica — rejeita valores forjados/absurdos antes de
// entrarem no histograma. (LCP/INP/TTFB em ms; CLS adimensional.)
const RANGES = {
  lcp: [0, 120000],
  cls: [0, 100],
  inp: [0, 120000],
  ttfb: [0, 120000],
};

/**
 * Valida uma amostra crua do beacon → { lcp?, cls?, inp?, ttfb? } só com os
 * campos válidos, ou null se nenhum for válido. Nunca lança.
 */
export function normalizeVitals(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const out = {};
  let any = false;
  for (const m of VITALS_METRICS) {
    const v = Number(raw[m]);
    if (Number.isFinite(v) && v >= RANGES[m][0] && v <= RANGES[m][1]) {
      out[m] = v;
      any = true;
    }
  }
  return any ? out : null;
}

/** Histograma diário vazio: um array de contagens (baldes+1) por métrica. */
export function emptyVitalsBucket() {
  const b = { count: 0 };
  for (const m of VITALS_METRICS) b[m] = new Array(VITALS_BUCKETS[m].length + 1).fill(0);
  return b;
}

function bucketIndex(value, edges) {
  for (let i = 0; i < edges.length; i++) if (value <= edges[i]) return i;
  return edges.length; // overflow
}

/** Conta uma amostra (já normalizada) no histograma diário. */
export function addVitals(bucket, sample) {
  let counted = false;
  for (const m of VITALS_METRICS) {
    if (typeof sample?.[m] === 'number') {
      const idx = bucketIndex(sample[m], VITALS_BUCKETS[m]);
      if (!Array.isArray(bucket[m])) bucket[m] = new Array(VITALS_BUCKETS[m].length + 1).fill(0);
      bucket[m][idx] = (bucket[m][idx] ?? 0) + 1;
      counted = true;
    }
  }
  if (counted) bucket.count = (bucket.count ?? 0) + 1;
  return bucket;
}

/** Soma vários histogramas diários num só. Ignora nulos. */
export function mergeVitalsBuckets(buckets) {
  const out = emptyVitalsBucket();
  for (const b of buckets) {
    if (!b) continue;
    out.count += b.count ?? 0;
    for (const m of VITALS_METRICS) {
      const arr = b[m];
      if (!Array.isArray(arr)) continue;
      for (let i = 0; i < out[m].length; i++) out[m][i] += arr[i] ?? 0;
    }
  }
  return out;
}

function rating(metric, value) {
  const t = VITALS_THRESHOLDS[metric];
  if (value <= t.good) return 'good';
  if (value <= t.poor) return 'needs-improvement';
  return 'poor';
}

/**
 * Percentil a partir de um histograma: devolve o valor representativo (borda
 * superior) do balde onde a contagem acumulada atinge `p`. Balde de overflow
 * → última borda com flag. Total 0 → null.
 */
function percentileFromHistogram(counts, edges, p = 0.75) {
  const total = counts.reduce((a, b) => a + b, 0);
  if (total === 0) return null;
  const target = total * p;
  let cum = 0;
  for (let i = 0; i < counts.length; i++) {
    cum += counts[i];
    if (cum >= target) {
      const overflow = i >= edges.length;
      return { value: overflow ? edges[edges.length - 1] : edges[i], overflow, samples: total };
    }
  }
  return null;
}

/**
 * Resumo para GET /api/vitals a partir dos histogramas diários (7d). Para
 * cada métrica: p75, classificação (good/needs-improvement/poor) e nº de
 * amostras. `samples` global = total de páginas com pelo menos uma métrica.
 */
export function vitalsStats(buckets = []) {
  const merged = mergeVitalsBuckets(buckets);
  const metrics = {};
  for (const m of VITALS_METRICS) {
    const pctile = percentileFromHistogram(merged[m], VITALS_BUCKETS[m]);
    metrics[m] = pctile
      ? { p75: pctile.value, overflow: pctile.overflow, samples: pctile.samples, rating: rating(m, pctile.value) }
      : null;
  }
  return { samples: merged.count, metrics };
}
