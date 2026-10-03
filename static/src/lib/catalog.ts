/**
 * Catálogo de estrelas do GitHub (repo blindtk/github-stars).
 *
 * github-stars é um repo privado, e raw.githubusercontent.com
 * não serve ficheiros de repos privados sem autenticação — por isso, em vez
 * de um fetch em build time, o catálogo vive vendorizado em
 * content/catalog.json (output do star-organizer). O schema é o que a
 * interface `Catalog` abaixo descreve; `assertCatalogShape` valida-o em
 * runtime.
 *
 * Sincronização: a Action semanal do github-stars faz push de
 * `catalog/catalog.json` para `content/catalog.json` diretamente em `main`
 * (só esse ficheiro, via deploy key) — ver docs/catalog-sync.md. Para
 * atualizar à mão, copia o ficheiro e faz commit; o `npm run build` falha
 * com um erro claro se o schema tiver mudado do outro lado.
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
