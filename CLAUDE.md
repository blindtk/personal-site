# CLAUDE.md — convenções do projeto

Monorepo do site pessoal. Três áreas com papéis rígidos:

- `content/` — markdown/JSON de conteúdo. **Nunca** pôr código aqui.
- `static/` — site estático Astro. Lê `content/` via loaders (`glob`, import JSON).
- `dynamic/` — backend (Cloudflare Worker em `dynamic/worker/`: honeypot,
  mapa de tráfego, self-scan, ticker). Lógica pura em `src/lib/*` testada com
  `node --test` (correr antes de qualquer PR que toque aqui). Ferramentas
  novas só com decisão explícita do dono do repo (ver `dynamic/PLAN.md`).

## Comandos

```bash
cd static
npm run dev       # desenvolvimento
npm run build     # build de produção (tem de passar sem erros antes de qualquer PR)
npm run preview   # servir o build localmente
```

## Regras de arquitetura

1. **Bilingue por construção.** Cada página existe em PT (`/`) e EN (`/en/`).
   As rotas em `static/src/pages/` são *finas* (3 linhas): importam uma
   componente de `src/components/pages/` e passam `lang`. Toda a lógica vive
   na componente partilhada — nunca duplicar lógica entre PT e EN.
2. **Strings de UI** vão todas para `static/src/i18n/ui.ts` (PT e EN juntos,
   mesma estrutura). Zero strings hardcoded em componentes.
3. **Rotas novas** registam-se em `static/src/i18n/routes.ts` (par PT/EN) —
   é isto que alimenta a nav e o seletor de idioma.
4. **Conteúdo por idioma** segue o padrão `content/<coleção>/pt/…` +
   `content/<coleção>/en/…` com o **mesmo nome de ficheiro** nos dois lados
   (é assim que o seletor PT/EN liga as versões).
5. **Dados pessoais/configuráveis** (nome, handle, email, domínio, redes)
   só em `static/src/config.ts`.

## Ferramentas em `/ferramentas/`

- A lógica pura (sem DOM) vive em `static/src/scripts/*.js` para poder ser
  testada em Node; as componentes em `src/components/tools/*.astro` só fazem
  a ligação ao DOM.
- A maioria é **100% client-side**: sem chamadas de rede, sem depender de
  backend. As três exceções (`pwned` — password comprometida por k-anonimato;
  `self-scan` de cabeçalhos; `mirror` — o que o servidor vê de ti) falam com o
  Worker em `dynamic/worker/` — vivem no mesmo
  índice, mas com o badge "requer servidor" (`ToolsIndexPage.astro`/
  `ToolPage.astro`, chave `kind` por ferramenta), nunca escondidas como se
  fossem client-side. Novas ferramentas que precisem de servidor seguem o
  mesmo padrão — decisão registada em `dynamic/PLAN.md`.
- Ao alterar lógica, validar com vetores conhecidos (ex.: MD5 de RFC 1321,
  redes /24 e /31) — correr com
  `node --input-type=module -e "import(...)"` ou similar.

## Estilo

- CSS global único em `static/src/styles/global.css` com custom properties
  (`--bg`, `--accent`, …). Usar as variáveis, não cores literais.
- Estética: escuro, técnico, sóbrio, acento verde-terminal (`--accent`) e
  âmbar (`--accent-2`) para o Lab/avisos. Mobile-first.
- Português europeu (não brasileiro) em todo o conteúdo PT.

## Antes de terminar qualquer alteração

1. `cd static && npm run build` — tem de completar sem erros nem warnings novos.
2. Se mexeste nas ferramentas, testa a lógica com vetores conhecidos.
3. Se adicionaste página nova, cria as **duas** versões (PT + EN) e o par em
   `routes.ts`.

## Fluxo de PRs

- **Um PR merged está fechado: nunca se lhe juntam commits novos.** Trabalho
  novo é **sempre um PR novo** — reiniciar a branch a partir do `main`
  (`git checkout -B <branch> origin/main`) e abrir novo PR. Nunca empilhar por
  cima de história já merged.
- Idealmente, **manter um PR aberto** até a feature estar confirmada (dá para
  testar da branch sem merge: `git checkout <branch> && cd dynamic/worker &&
  npx wrangler deploy`), para não andar a abrir vários PRs seguidos.
