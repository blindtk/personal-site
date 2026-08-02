# ADR 0009 — Repositório público, não privado

**Estado:** aceite e executado (2026-07-31).

## Contexto

O repositório ficou privado durante o desenvolvimento. Mas o propósito
declarado deste projeto é ser lido por estranhos a decidir se contratam o
autor — um portefólio privado é uma contradição em termos. Concretamente:
o site em produção linka de volta para o repositório (`SITE.repo` em
`config.ts`, página Provas); enquanto privado, esses links devolviam 404 a
qualquer visitante, quebrando o próprio mecanismo de credibilidade do site.

Manter privado tinha vantagens reais: zero risco de disclosure, sem ruído
de Issues externas, controlo total. Mas também um custo concreto no GitHub
Free: Actions minutes limitados (2.000/mês, e o repo já estava acima
dessa quota), CodeQL, secret scanning + push protection, Dependency Review,
artifact attestations e OpenSSF Scorecard — todos exigem GHAS (pago) em
repo privado, e são grátis em repo público.

## Decisão

Tornar o repositório público (2026-07-31), depois de uma checklist de
pré-publicação: substituir o email pessoal exposto em `config.ts` por um
alias no domínio, rodar `RATE_SALT` e `CF_API_TOKEN`, e confirmar (via
`gitleaks detect` sobre o histórico completo) que nenhum segredo real
alguma vez entrou em git. **Histórico preservado por inteiro** — sem
squash, sem reescrita, sem reiniciar noutro repositório: os 132 PRs
mostram o próprio processo de encontrar e corrigir erros (ex.: o fail-open
→ fail-closed do rate limit, [ADR 0003](0003-rate-limit-kv-vs-nativo.md)),
que é mais persuasivo do que qualquer código limpo de origem única.

## Consequências

- Seis capacidades passam de pagas para grátis (CodeQL, secret scanning,
  Dependency Review, attestations, Scorecard, CodeRabbit) — ativadas nos
  dias seguintes (`96ecfd8`, `641bf07`).
- Impacto de segurança avaliado como **líquido positivo, não negativo**: a
  superfície de ataque real (conta Cloudflare, endpoints do Worker) já
  estava exposta à internet independentemente da visibilidade do
  repositório; tornar o código legível não a alarga.
- **Trade-off aceite:** os cinco paths-isco do honeypot (`DECOYS` em
  `src/index.js`) ficam publicamente documentados — mas são os paths
  standard que qualquer scanner de commodity já sonda às cegas, então
  explicá-los não custa nada e demonstra a técnica em vez de a esconder
  (ver "Why so much for a personal site?" no README).
- Raciocínio completo, checklist e análise de risco em
  [`docs/public-repo-decision.md`](../public-repo-decision.md) (registo
  histórico da decisão, não documento vivo).
