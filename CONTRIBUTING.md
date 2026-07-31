# Contribuir

Este é um projeto pessoal com um único mantenedor (Daniel Malaco), mas o
repositório é público e contribuições são bem-vindas — desde uma correção
de typo até uma sugestão de arquitetura.

## Antes de mexer em código

Lê o [`CLAUDE.md`](CLAUDE.md): define as convenções do projeto (as três
áreas do monorepo — `content/`, `static/`, `dynamic/` —, a regra
bilingue PT/EN, onde vivem as strings de UI, etc.). Uma alteração que não
siga essas convenções não vai ser aceite tal como está, mesmo que a lógica
esteja correta.

## Reportar um bug

Abre uma [Issue](https://github.com/blindtk/personal-site/issues) com:

- o que esperavas que acontecesse vs. o que aconteceu;
- passos para reproduzir;
- se for visual, um screenshot ajuda mais do que uma descrição longa.

**Vulnerabilidades de segurança nunca vão numa Issue pública** — segue o
processo em [`.github/SECURITY.md`](.github/SECURITY.md).

## Propor uma alteração

1. Faz fork do repositório e cria uma branch a partir de `main`.
2. Faz a alteração seguindo as convenções do `CLAUDE.md`.
3. Corre `cd static && npm run build` — tem de passar sem erros nem
   warnings novos antes de abrires o PR.
4. Se mexeste em `dynamic/worker/` ou nas ferramentas de `/ferramentas/`,
   corre também `node --test` e valida a lógica com vetores conhecidos.
5. Se mexeste em `dynamic/worker/src/lib/csp-report.js` ou `sanitize.js`,
   corre também os harnesses de fuzzing localmente (`.clusterfuzzlite/fuzz/`)
   por alguns segundos, para confirmar que continuam a compilar e a correr
   sem crashar:
   ```bash
   npx --yes -p @jazzer.js/core jazzer .clusterfuzzlite/fuzz/csp_report_fuzz.js --sync -- -max_total_time=5
   npx --yes -p @jazzer.js/core jazzer .clusterfuzzlite/fuzz/sanitize_fuzz.js --sync -- -max_total_time=5
   ```
6. Abre o Pull Request — o modelo (`.github/pull_request_template.md`)
   guia o que incluir. A CI (build, testes, análise estática) corre
   automaticamente; tem de passar antes de qualquer merge.

Não há um processo de CLA nem de aprovação prévia para começar a
trabalhar — mas para alterações grandes ou que mudem arquitetura, abre
uma Issue primeiro a propor a ideia, para não haver trabalho desperdiçado
se a direção não for a pretendida.

## Licença

Ao contribuir, aceitas que a tua contribuição seja distribuída sob a
mesma licença do projeto ([MIT](LICENSE)).
