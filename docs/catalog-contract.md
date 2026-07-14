# Contrato do `catalog.json` (integração github-stars ↔ personal-site)

Este site consome o catálogo de estrelas do GitHub gerado pelo
**blindtk/github-stars** (`star-organizer`) para as stats "LIVE" da homepage,
a biblioteca navegável em `/links/`, e o comando `stars` do Lab.

> **Estado:** `github-stars` já gera `catalog/catalog.json` no schema abaixo,
> com uma GitHub Action semanal a mantê-lo atualizado — mas `github-stars` é
> um **repo privado**, e `raw.githubusercontent.com` não serve ficheiros de
> repos privados sem autenticação (devolve 404, indistinguível de "o ficheiro
> não existe"). Por isso, o desenho original deste documento — um `fetch` em
> build time ao raw do GitHub — **não funciona** e foi abandonado.
>
> **Solução atual (temporária):** o `catalog.json` real é vendorizado à mão em
> `content/catalog.json` neste repo, e `static/src/lib/catalog.ts` importa-o
> estaticamente (sem rede). Atualizar o catálogo é copiar o ficheiro gerado
> por `github-stars` para cá e fazer commit — não há sincronização automática
> ainda. O próximo passo (documentado no roadmap do Lab) é ler
> `catalog.json` via **API do GitHub autenticada**
> (`api.github.com/repos/blindtk/github-stars/contents/...` com um token),
> o que permite manter `github-stars` privado e voltar a atualizar sem
> intervenção manual.

## Onde o site lê

`static/src/lib/catalog.ts` faz `import rawCatalog from '../../../content/catalog.json'`.
Por ser um import estático, um `content/catalog.json` em falta ou com schema
inválido **falha o build** com um erro claro — nunca há fallback para dados
de exemplo.

## Schema exigido

```jsonc
{
  "generatedAt": "2026-07-10T09:00:00Z",   // ISO 8601 (UTC). Data mostrada como "atualizado".
  "user": "blindtk",
  "totalRepos": 128,                        // inteiro; nº total de repos curados
  "categories": [
    {
      "name": "Security",                   // nome legível da categoria
      "count": 42,                          // == categories[i].repos.length
      "repos": [
        {
          "name": "aquasecurity/trivy",     // owner/repo
          "url": "https://github.com/aquasecurity/trivy",
          "stars": 22000,                   // inteiro
          "language": "Go",                 // string ou null
          "description": "…",               // string ou null
          "tags": ["scanner", "containers"] // array de strings (pode ser [])
        }
      ]
    }
  ]
}
```

Campos e tipos são validados de forma defensiva no site; extras são ignorados,
por isso podes acrescentar metadados sem partir nada. Só estes é que são usados.

## Estado no repo github-stars

Já feito: `star_organizer.py` emite `catalog/catalog.json` no formato acima em
todo o run, e `.github/workflows/catalog.yml` corre semanalmente (cron) e a
pedido (`workflow_dispatch`), re-correndo a ferramenta para `blindtk` e fazendo
commit do catálogo em `main` só se houver mudanças.

## Como atualizar o catálogo vendorizado (até haver sync automática)

1. No repo `github-stars`, confirma que `catalog/catalog.json` está atualizado
   em `main` (a Action trata disto semanalmente).
2. Copia esse ficheiro para `content/catalog.json` neste repo e faz commit.
3. `npm run build` falha se o schema estiver errado — é o sinal de que algo
   mudou no lado do github-stars e este contrato precisa de revisão.

## Próximo passo: sincronização automática

Ler `catalog.json` via API do GitHub autenticada em vez de vendorizar à mão:

- Endpoint: `GET api.github.com/repos/blindtk/github-stars/contents/catalog/catalog.json`
  com `Authorization: Bearer <token>` (conteúdo vem em base64).
- Requer um token com leitura do repo, guardado como secret no Cloudflare
  Pages (build-time env var) — `github-stars` mantém-se privado.
- Depois disto, um deploy hook no fim da Action do `github-stars` (POST ao
  *Deploy Hook* do Cloudflare Pages) volta a fechar o ciclo sem intervenção
  manual.

Isto está no roadmap do Lab (`roadmap.txt` — abre `/lab/` e usa `cat
roadmap.txt`, ou o comando `open roadmap`).
