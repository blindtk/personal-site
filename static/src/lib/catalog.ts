/**
 * Catálogo de estrelas do GitHub.
 *
 * O catálogo é gerado fora deste repo (a partir de um repo privado), por isso,
 * em vez de um fetch em build time, vive vendorizado em content/catalog.json
 * (output do star-organizer). O schema é o que a
 * interface `Catalog` abaixo descreve; `assertCatalogShape` valida-o em
 * runtime.
 *
 * Sincronização: o catálogo chega aqui como PR aberto por uma GitHub App
 * (só `content/catalog.json`) — ver docs/catalog-sync.md. Para atualizar à
 * mão, substitui o ficheiro e abre um PR; o `npm run build` falha com um
 * erro claro se o schema estiver errado.
 *
 * Por ser um import estático, um content/catalog.json em falta ou malformado
 * falha o build de imediato — nunca mostramos dados de exemplo como reais.
 */
import rawCatalog from '../../../content/catalog.json';
import { isGithubRepoUrl } from '../scripts/safe-url.js';

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

const SCHEMA_HINT = 'ver a interface Catalog em static/src/lib/catalog.ts.';

const isNullableString = (v: unknown) => v === null || typeof v === 'string';

function assertCatalogShape(data: unknown): asserts data is Catalog {
  const d = data as Partial<Catalog> | null | undefined;
  if (
    typeof d?.generatedAt !== 'string' ||
    typeof d?.user !== 'string' ||
    typeof d?.totalRepos !== 'number' ||
    !Array.isArray(d?.categories)
  ) {
    throw new Error(`content/catalog.json tem um schema inesperado — ${SCHEMA_HINT}`);
  }
  // O ficheiro é gerado por um bot (PR com content/catalog.json) e os campos
  // dos repos vêm de terceiros: validam-se um a um, e `url` tem de ser mesmo
  // um repo do GitHub — vai direto para um `href`.
  for (const cat of d.categories) {
    if (typeof cat?.name !== 'string' || typeof cat?.count !== 'number' || !Array.isArray(cat?.repos)) {
      throw new Error(`content/catalog.json: categoria inválida — ${SCHEMA_HINT}`);
    }
    for (const r of cat.repos) {
      if (
        typeof r?.name !== 'string' ||
        !isGithubRepoUrl(r?.url) ||
        !Number.isFinite(r?.stars) ||
        !isNullableString(r?.language) ||
        !isNullableString(r?.description) ||
        !Array.isArray(r?.tags) ||
        r.tags.some((tag: unknown) => typeof tag !== 'string')
      ) {
        throw new Error(
          `content/catalog.json: repo inválido em "${cat.name}" (${JSON.stringify(r?.url)}) — o url tem de ser https://github.com/<dono>/<repo>; ${SCHEMA_HINT}`,
        );
      }
    }
  }
}

assertCatalogShape(rawCatalog);
const catalog: Catalog = rawCatalog;

export function getCatalog(): Catalog {
  return catalog;
}
