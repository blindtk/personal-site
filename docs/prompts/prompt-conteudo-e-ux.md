# Prompt — análise e melhoria do conteúdo e da experiência (UX/UI)

Prompt reutilizável para pedir a um agente que **analise todo o conteúdo do
site e toda a experiência de utilização**, proponha melhorias e — depois de
aprovado o plano — as aplique em PRs pequenos. Ao contrário de
[`prompt-consistencia-textual.md`](prompt-consistencia-textual.md) (só
relatório, só texto), este cobre **conteúdo + UX/UI** e prevê uma fase de
implementação.

Copia o bloco abaixo como pedido a um agente.

---

## Prompt

> **Tarefa:** Analisa todo o conteúdo deste site e toda a experiência de
> utilização (UX/UI), e melhora ambos. O site é o portefólio técnico de um
> engenheiro de segurança: tem de ser claro para quem chega pela primeira
> vez (recrutador, par técnico, curioso) e, ao mesmo tempo, provar
> competência pelo próprio rigor. Trabalha em **três fases** e **pára no
> fim da Fase 2** à espera da minha aprovação.
>
> Antes de tudo, lê `CLAUDE.md`, `README.md`, `docs/architecture.md`,
> `docs/backlog.md` e `docs/adr/0001-csp-sem-inline.md`. As regras do
> projeto são restrições duras, não sugestões.
>
> ### Fase 1 — Auditoria (só leitura)
>
> **Corre o site:** `cd static && npm ci && npm run build && npm run preview`.
> Percorre-o num browser (Playwright/Chromium já instalado) em **390px**
> (telemóvel), **768px** e **1440px**, em PT e EN. Tira capturas de ecrã das
> páginas principais para fundamentar os achados.
>
> **A. Conteúdo** — lê tudo:
> - `content/pages/` (`sobre.md`/`about.md`), `content/projects/pt|en/`,
>   `content/blog/pt|en/`, `content/*.json` (texto visível incluído).
> - `static/src/i18n/ui.ts` — onde vive a maior parte do texto "de página".
> - `static/src/config.ts` — fonte única de nome, cargo, email, redes.
>
> Avalia:
> 1. **Proposta de valor.** Em 5 segundos na Home, percebe-se quem é, o que
>    faz e porque interessa? O CTA principal é óbvio?
> 2. **Clareza e concisão.** Frases longas, jargão sem contexto, parágrafos
>    que repetem o que outra página já diz, texto que fala da implementação
>    quando o leitor queria o resultado.
> 3. **Arquitetura de informação.** A ordem Home → Sobre → Projetos →
>    Ferramentas → "Este site" (Segurança, Honeypot, Cloudflare, Provas,
>    Performance) → Lab conta uma história? Há páginas a mais, a menos, ou
>    no sítio errado? A nav (`BaseLayout.astro`, `routes.ts`) reflete isso?
> 4. **Lacunas.** Ex.: o blog só tem `reservado.md`; projetos sem resultado
>    concreto; ferramentas sem explicação de "para que serve" e "quando usar".
> 5. **Paridade PT/EN, coerência factual e tom.** Mesmo ficheiro dos dois
>    lados, mesma estrutura em `ui.ts`, factos iguais a `config.ts`.
>    **Português europeu** (nunca PT-BR), registo consistente entre páginas.
> 6. **SEO e partilha.** `<title>`, meta description, `og:*`, `hreflang`,
>    headings em hierarquia correta, texto de links descritivo.
>
> **B. UX/UI** — lê `static/src/styles/global.css`,
> `static/src/layouts/BaseLayout.astro`, `static/src/components/**` e
> `static/public/js/`. Avalia:
> 1. **Hierarquia visual e tipografia.** Escala de títulos, comprimento de
>    linha de leitura, espaçamento vertical, densidade dos painéis/dashboards.
> 2. **Navegação.** Menu móvel (`nav.js`), dropdown "Este site", estado
>    ativo, seletor PT/EN, breadcrumbs/"voltar" nas subpáginas, rodapé.
> 3. **Consistência do design system.** Componentes que fazem o mesmo de
>    formas diferentes (cartões, chips, badges, botões, tabelas);
>    cores literais em vez das variáveis (`--bg`, `--accent`, …); CSS morto
>    ou duplicado em `global.css`.
> 4. **Mobile-first.** Scroll horizontal, alvos de toque < 44px, tabelas e
>    gráficos que não cabem, barra sticky de tabs.
> 5. **Acessibilidade (WCAG 2.2 AA).** Contraste (verifica `--muted` e
>    `--faint` sobre `--bg`/`--bg-raise`), foco visível, ordem de tabulação,
>    `aria-*` nos widgets/tabs/ferramentas, `prefers-reduced-motion`,
>    informação transmitida só por cor (verde/âmbar), alt text.
> 6. **Estados.** Carregamento (`Skeleton.astro`), erro e vazio nos widgets
>    que dependem do Worker (Ticker, HostMap, CtWatch, `pwned`, `mirror`);
>    o badge "requer servidor" é claro?
> 7. **Ferramentas (`/ferramentas/`).** Cada uma: instruções, exemplo
>    pré-preenchido, feedback ao copiar, mensagens de erro úteis, layout
>    input→output legível em telemóvel.
> 8. **Performance percebida.** Corre Lighthouse (mobile) nas páginas
>    principais; regista LCP, CLS, INP e peso de JS/CSS.
>
> ### Fase 2 — Relatório e plano (depois pára)
>
> Escreve o relatório em `docs/audits/conteudo-ux-<AAAA-MM-DD>.md`:
> - **Resumo executivo** (≤ 10 linhas): os 5 problemas que mais custam ao
>   visitante.
> - **Achados**, agrupados em Conteúdo / UX-UI, cada um com
>   `ficheiro:linha` (ou página + captura), dimensão, problema numa frase,
>   correção proposta, e **impacto × esforço** (alto/médio/baixo).
> - **Plano** em lotes independentes, cada lote = um PR revisível
>   (ex.: "1. Home e proposta de valor", "2. Contraste e foco",
>   "3. Navegação móvel", "4. Ferramentas: estados e mensagens",
>   "5. Limpeza de `global.css`"). Ordena por impacto/esforço.
> - O que **não** recomendas mudar e porquê (a estética escura e técnica é
>   intencional — melhora-a, não a substituas).
>
> **Não alteres código nem conteúdo nesta fase.** Mostra-me o relatório e
> espera que eu aprove (ou corte) lotes.
>
> ### Fase 3 — Implementação (só lotes aprovados)
>
> Um lote de cada vez, no mesmo branch/PR enquanto não confirmar (regra de
> `CLAUDE.md`: idealmente um PR aberto até a feature estar confirmada).
> Restrições **inegociáveis**:
>
> - **CSP estrita** (`static/public/_headers`): `script-src 'self'`,
>   `style-src 'self'` sem `unsafe-inline`, `trusted-types 'none'`,
>   `font-src 'self'`. Logo: **nada de `<script>`/`<style>` inline nem
>   atributos `style="…"`**, nada de `innerHTML` (usa `textContent`/
>   `createElement`), nada de fontes ou scripts de CDN. JS de página vai
>   para `static/public/js/` ou para scripts processados pelo Astro.
>   `static/test/csp-inline.test.mjs` tem de continuar a passar.
> - **Bilingue por construção:** rotas em `src/pages/` continuam finas
>   (3 linhas); lógica só nas componentes partilhadas de
>   `src/components/pages/`; strings de UI **só** em `ui.ts` (PT e EN na
>   mesma estrutura); conteúdo editorial sempre nos **dois** idiomas com o
>   mesmo nome de ficheiro; dados pessoais só em `config.ts`; novas rotas
>   registadas em `routes.ts`.
> - **Estilo:** um único `global.css` com custom properties; usa as
>   variáveis, não cores literais. Se precisares de um token novo
>   (espaçamento, tipo), adiciona-o a `:root` e usa-o em todo o lado.
>   Mobile-first. Sem frameworks CSS/JS novos.
> - **Ferramentas:** lógica pura continua em `static/src/scripts/*.js`;
>   se lhe tocares, valida com vetores conhecidos (RFC 1321, redes `/24` e
>   `/31`, etc.) e corre `cd static && npm test`.
> - **Nada de afirmações novas sem prova.** O site trata as suas próprias
>   alegações de segurança como um ativo (`docs/threat-model.md`): qualquer
>   texto novo sobre o que o site faz tem de corresponder ao código.
> - Não inventes factos pessoais (cargos, certificações, números). Onde
>   faltar informação, deixa um `TODO` explícito no relatório e pergunta-me.
>
> **Antes de cada push:**
> 1. `cd static && npm run build` — sem erros nem warnings novos.
> 2. `cd static && npm test` e, se tocaste em `dynamic/`,
>    `cd dynamic/worker && node --test`.
> 3. Capturas antes/depois (390px e 1440px) das páginas alteradas, e
>    Lighthouse mobile sem regressões em Performance/Acessibilidade.
> 4. Confirma PT **e** EN de cada página alterada.
>
> No fim de cada lote, resume: o que mudou, capturas antes/depois, métricas,
> e o que fica para o lote seguinte.
