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

function assertCatalogShape(data: unknown): asserts data is Catalog {
  const d = data as Partial<Catalog> | null | undefined;
  if (
    typeof d?.generatedAt !== 'string' ||
    typeof d?.user !== 'string' ||
    typeof d?.totalRepos !== 'number' ||
    !Array.isArray(d?.categories)
  ) {
    throw new Error(
      'content/catalog.json tem um schema inesperado — ver a interface Catalog em static/src/lib/catalog.ts.',
    );
  }
}

assertCatalogShape(rawCatalog);
const catalog: Catalog = rawCatalog;

export function getCatalog(): Catalog {
  return catalog;
}
