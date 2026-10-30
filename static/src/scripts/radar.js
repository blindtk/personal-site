// Radar — lógica pura (sem DOM) da página /radar/: valida o documento que o
// Worker serve em /api/radar e separa-o pelos separadores Tudo/Alertas/
// Notícias. O Worker já sanitiza tudo; isto é a segunda camada, do lado de
// quem renderiza: um item sem título, sem link https: ou sem data válida não
// chega ao DOM (que, de qualquer forma, só usa textContent).

import { isHttpsUrl } from './safe-url.js';

/**
 * Documento de /api/radar → { generated, sources, items }, com cada item já
 * ligado à sua fonte (`type`, `name`, `lang`). Qualquer forma inesperada (um
 * `{ error }` de um 429/502, null, lixo) dá listas vazias em vez de lançar.
 *   generated — Date | null
 *   sources   — [{ id, name, type, lang, ok }]
 *   items     — [{ title, url, date: Date, source, type, lang }]
 */
export function normalizeRadar(doc) {
  const generatedMs = typeof doc?.generated === 'string' ? Date.parse(doc.generated) : NaN;
  const sources = (Array.isArray(doc?.sources) ? doc.sources : [])
    .filter((s) => typeof s?.id === 'string' && typeof s.name === 'string' && (s.type === 'alert' || s.type === 'news'))
    .map((s) => ({ id: s.id, name: s.name, type: s.type, lang: typeof s.lang === 'string' ? s.lang : '', ok: s.ok === true }));
  const byId = new Map(sources.map((s) => [s.id, s]));
  const items = [];
  for (const it of Array.isArray(doc?.items) ? doc.items : []) {
    const src = byId.get(it?.s);
    const ms = typeof it?.d === 'string' ? Date.parse(it.d) : NaN;
    if (!src || typeof it.t !== 'string' || it.t === '' || !isHttpsUrl(it.u) || !Number.isFinite(ms)) continue;
    items.push({ title: it.t, url: it.u, date: new Date(ms), source: src.name, type: src.type, lang: src.lang });
  }
  items.sort((a, b) => b.date - a.date);
  return { generated: Number.isFinite(generatedMs) ? new Date(generatedMs) : null, sources, items };
}

/** Itens de um separador: 'all', 'alert' ou 'news'. */
export function itemsFor(items, tab) {
  return tab === 'all' ? items : items.filter((it) => it.type === tab);
}
