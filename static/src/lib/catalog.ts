/**
 * Catálogo de estrelas do GitHub (repo blindtk/github-stars).
 *
 * É lido em BUILD TIME a partir do raw do GitHub. Se o ficheiro ainda não
 * existir (ou falhar a rede), devolve null e o site usa fallbacks estáticos —
 * o badge "live" só aparece quando os dados vêm mesmo do JSON.
 *
 * Nota: como o fetch é em build time, o site só reflete um catálogo novo
 * quando é reconstruído (push, ou deploy hook do Cloudflare Pages disparado
 * pela Action do github-stars).
 */

export interface CatalogRepo {
  name: string;
  url: string;
  stars: number;
  language: string | null;
  description: string | null;
  tags: string[];
}

export interface CatalogCategory {
  name: string;
  count: number;
  repos: CatalogRepo[];
}

export interface Catalog {
  generatedAt: string;
  user: string;
  totalRepos: number;
  categories: CatalogCategory[];
}

// CATALOG_URL pode ser substituído por env var (útil em dev/testes).
const CATALOG_URL =
  process.env.CATALOG_URL ??
  'https://raw.githubusercontent.com/blindtk/github-stars/main/catalog/catalog.json';

let cached: Catalog | null | undefined;

export async function getCatalog(): Promise<Catalog | null> {
  if (cached !== undefined) return cached;
  try {
    const res = await fetch(CATALOG_URL, { signal: AbortSignal.timeout(10_000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const data = (await res.json()) as Catalog;
    if (
      typeof data.generatedAt !== 'string' ||
      typeof data.totalRepos !== 'number' ||
      !Array.isArray(data.categories)
    ) {
      throw new Error('schema inesperado');
    }
    cached = data;
  } catch (err) {
    console.warn(`[catalog] indisponível (${err}); a usar fallback estático.`);
    cached = null;
  }
  return cached;
}
