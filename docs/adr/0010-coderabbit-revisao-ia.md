# ADR 0010 — CodeRabbit para revisão de PR por IA, não Copilot Code Review nem Strix em CI

**Estado:** aceite e em produção (`.coderabbit.yaml`).

## Contexto

Com o repositório público e a um ritmo de PRs elevado, uma revisão de PR
assistida por IA tem retorno real — mas há três opções com perfis muito
diferentes:

- **GitHub Copilot Code Review** — zero setup, nativo do GitHub, mas
  claramente mais superficial: bom em estilo e bugs óbvios, fraco em
  raciocínio cross-file e lógica específica de segurança.
- **Strix** (agente autónomo de pentest) — a opção mais interessante em
  abstrato, mas o valor de um agente autónomo escala com a complexidade da
  superfície de ataque, e a deste site é deliberadamente mínima (sem auth,
  sem base de dados, sem sessões). A classe de bug mais interessante do
  sistema (esgotamento de orçamento de escrita do KV) exige ler o código-
  fonte e raciocinar sobre quotas do plano Free — precisamente o tipo de
  falha de lógica de negócio que um prober autónomo não encontra a sondar.
  Custo por corrida ($2–10, não determinístico) e risco de alucinação
  altos para o valor esperado.
- **CodeRabbit** — lê o diff **e** o contexto do repositório; a
  característica que define este código é que a intenção vive nos
  comentários (porque `routes` tem de vir antes de `[vars]` no TOML, porque
  o cap é diário e não por hora), e uma IA que lê esse contexto consegue
  assinalar quando uma mudança contradiz um invariante já declarado — algo
  que nem um prober black-box nem um revisor de diff superficial conseguem.

## Decisão

Ativar CodeRabbit em todos os PRs (grátis em repo público), com
`.coderabbit.yaml` calibrado por pasta em vez de genérico —
`path_instructions` que lembram o orçamento de escrita do KV em
`dynamic/worker/`, a paridade de chaves PT/EN em `i18n/`, a proibição de
sinks de DOM XSS em `static/src/scripts/`, e a regra de rotas finas em
`static/src/pages/`. **Não** ativar Copilot Code Review a par (duplicar
comentário de IA só treina a ignorar ambos) nem correr Strix em CI —
reservado para uma corrida manual, única, pós-lançamento, documentada como
experiência e não como controlo recorrente.

## Consequências

- Um segundo revisor automatizado, gratuito, calibrado ao vocabulário e às
  invariantes reais deste repositório — não um linter genérico.
- Perfil de "profile: chill" e `poem: false` para reduzir verbosidade por
  omissão (sem isso, CodeRabbit comenta em decisões de estilo já tomadas).
- `content/**` excluído da revisão (`path_filters`) — é conteúdo editorial,
  não código, regra do CLAUDE.md.
- Raciocínio completo da comparação entre as três opções em
  [`docs/security-review-2026-07-29.md`](../security-review-2026-07-29.md) §5.
