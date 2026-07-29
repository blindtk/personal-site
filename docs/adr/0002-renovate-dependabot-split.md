# ADR 0002 — Renovate para *version updates*, Dependabot só para *security updates*

**Estado:** aceite e em produção (`renovate.json5`).

## Contexto

Duas ferramentas de gestão de dependências ativas ao mesmo tempo é
normalmente um erro — colidem, abrem PRs duplicados para a mesma
dependência, e ninguém sabe qual delas é "a fonte de verdade". A escolha óbvia
seria uma ou outra, não as duas.

Mas têm cobertura diferente por design: o Renovate só abre PR para
dependências **diretas** do `package.json` (o que está no lockfile por
escolha). O Dependabot *security updates* consegue reagir a uma vulnerabilidade
em qualquer nível da árvore, incluindo dependências **transitivas** — puxadas
pelo `wrangler` em `dynamic/worker/` (ex.: `sharp`/`libvips`), nunca
declaradas diretamente neste repositório.

## Decisão

- **Renovate**: todas as *version updates* de rotina e majors. `group:allNonMajor`
  agrupa tudo o que não é major num único PR semanal; majors ficam separados
  para revisão com calma. `minimumReleaseAge: 3 days` — janela de segurança
  contra pacotes comprometidos publicados e retirados pouco depois.
- **Dependabot**: **só** *security updates* (nunca *version updates* — colidiria
  com o Renovate). Cobre exatamente a lacuna do Renovate: vulnerabilidades em
  dependências transitivas que nenhum `package.json` deste repo lista.

## Consequências

- Sem colisão: cada ferramenta tem uma responsabilidade exclusiva e não
  sobreposta.
- `prConcurrentLimit: 3` mantém o volume de PRs gerível à velocidade real do
  repositório.
- Se o Dependabot alguma vez começar a abrir PRs de *version update* (ex.: uma
  mudança de configuração da app "Dependabot" no GitHub), isso é um sinal de
  regressão desta decisão — verificar `Settings → Code security → Dependabot`
  no repositório.
