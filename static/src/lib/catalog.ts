/**
 * Catálogo de estrelas do GitHub (repo blindtk/github-stars).
 *
 * TEMPORÁRIO: github-stars é um repo privado, e raw.githubusercontent.com
 * não serve ficheiros de repos privados sem autenticação — por isso, em vez
 * de um fetch em build time, o catálogo vive vendorizado em
 * content/catalog.json (copiado à mão do output do star-organizer, sem
 * sincronização automática ainda). O schema é o que a interface `Catalog`
 * abaixo descreve; `assertCatalogShape` valida-o em runtime.
 *
 * Para atualizar: copia o `catalog/catalog.json` gerado pela Action semanal
 * do github-stars para `content/catalog.json` neste repo e faz commit — o
 * `npm run build` falha com um erro claro se o schema tiver mudado do outro
 * lado.
 *
 * Próximo passo (roadmap do Lab, `cat roadmap.txt` em `/lab/`): ler
 * `catalog.json` via API do GitHub autenticada
 * (`api.github.com/repos/blindtk/github-stars/contents/...` com um token
 * guardado como secret no Cloudflare Pages), para manter github-stars
 * privado e fechar o ciclo sem intervenção manual.
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
