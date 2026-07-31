# Pinado por digest (era :latest flutuante — falha o Pinned-Dependencies do
# OpenSSF Scorecard, e sem pin um rebuild upstream podia mudar o comportamento
# do fuzzer sem nenhuma alteração deste repo). Renovate segue o digest a
# partir daqui (dockerfile manager, incluído em config:recommended).
FROM gcr.io/oss-fuzz-base/base-builder-javascript@sha256:2e218dedc1603f15e34cec784030789e06db1df8eb5356f0a8e27285619ac8c2

# Só copiamos o que os harnesses precisam (lib/ com as funções puras a
# fuzzar, e os próprios harnesses) — não o monorepo inteiro. A estrutura
# relativa replica o repo real (dynamic/worker/... e .clusterfuzzlite/fuzz/
# ficam nos mesmos caminhos uns dos outros), para os imports em fuzz/*.js
# funcionarem sem alterações entre o teste local (node --test/jazzer direto
# no repo) e o build aqui dentro do container.
COPY dynamic/worker/package.json $SRC/repo/dynamic/worker/package.json
COPY dynamic/worker/src/lib $SRC/repo/dynamic/worker/src/lib
COPY .clusterfuzzlite/fuzz $SRC/repo/.clusterfuzzlite/fuzz

# package.json/package-lock.json na raiz do "repo" sintético (não dentro de
# .clusterfuzzlite/): é onde o compile_javascript_fuzzer espera encontrar
# node_modules/@jazzer.js/core depois do `npm ci` no build.sh. O
# "type": "module" aqui já cobre .clusterfuzzlite/fuzz/*.js por herança
# (nearest ancestor package.json), tal como dynamic/worker/package.json
# cobre dynamic/worker/src/lib/*.js.
COPY .clusterfuzzlite/package.json $SRC/repo/package.json
COPY .clusterfuzzlite/package-lock.json $SRC/repo/package-lock.json
COPY .clusterfuzzlite/build.sh $SRC/

WORKDIR $SRC/repo
