# Contrato do `catalog.json` (integração github-stars ↔ personal-site)

Este site consome, **em build time**, o ficheiro
`catalog/catalog.json` publicado no repo **blindtk/github-stars** (via raw do
GitHub). É o que torna honestas as stats "LIVE" da homepage e alimenta a
biblioteca navegável em `/links/`.

> **Estado:** o lado do site (consumo, fallback, biblioteca, comando `stars`
> do Lab) está implementado e testado. Falta a metade que vive no repo
> github-stars — o `star-organizer` emitir este ficheiro e uma GitHub Action
> que o mantém atualizado. Isso **não foi feito** porque este ambiente não teve
> acesso ao repo privado github-stars. Este documento é o contrato a cumprir lá.

## Onde o site lê

`static/src/lib/catalog.ts`:

```
https://raw.githubusercontent.com/blindtk/github-stars/main/catalog/catalog.json
```

Se o URL devolver 404 ou JSON inválido, o site degrada com elegância: sem
badge "LIVE", stat de fallback ("4 ferramentas client-side"), e `/links/`
mostra um aviso "catálogo ainda não publicado". Ou seja: publicar o ficheiro é
seguro e aditivo — nada parte enquanto ele não existe.

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

## O que falta implementar no repo github-stars

1. **Emitir `catalog/catalog.json`** a partir do star-organizer, no formato
   acima (além do que já gera). O `generatedAt` deve ser o instante da geração.
2. **GitHub Action** (ver `docs/github-stars-workflow.yml` neste repo como
   ponto de partida): correr semanalmente (`cron`) e a pedido
   (`workflow_dispatch`), re-correr a ferramenta para o utilizador `blindtk`, e
   fazer commit do catálogo **apenas se houver mudanças**.
3. **(Opcional) Deploy hook:** como o site lê em build time, um catálogo novo
   só aparece quando o site é reconstruído. Se o site estiver em Cloudflare
   Pages, a Action pode terminar com um `curl` ao *Deploy Hook* do projeto para
   forçar rebuild. Caso contrário, o próximo push ao personal-site chega.
