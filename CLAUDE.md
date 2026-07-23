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

## Fluxo de PRs e branches

Regras para features que precisam de várias voltas de feedback (ex.: validar
uma query contra a API real em produção):

1. **Um PR por feature, mantido aberto até estar confirmado.** Itera-se na
   mesma branch/PR; o merge é **um só, no fim**. Não fazer merge de commits
   intermédios ou de diagnóstico — foi assim que o painel de ameaças ficou uma
   vez com a versão errada no `main` (um merge apanhou um commit de andaime
   antes do fix real).
2. **Testar a partir da branch sem merge.** O deploy do Worker é manual
   (`cd dynamic/worker && npx wrangler deploy`), por isso dá para fazer
   `git checkout <branch>` e deployar/ver ao vivo sem tocar no `main`. Confirmar
   primeiro, mergear depois.
3. **Se um PR JÁ foi merged e aparece trabalho novo**, a história dessa branch
   está fechada: **nunca** empilhar por cima. Reiniciar a branch a partir do
   `main` (mesmo nome, `git checkout -B <branch> origin/main`), aplicar o
   trabalho novo (cherry-pick/commits) e abrir um **PR novo**. É a rede de
   segurança, não o fluxo normal — o normal é a regra 1.
4. **Andaimes de diagnóstico** (campos temporários numa resposta para depurar)
   removem-se antes do merge final; nunca ficam no `main`.
