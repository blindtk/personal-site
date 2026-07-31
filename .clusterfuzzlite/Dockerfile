FROM gcr.io/oss-fuzz-base/base-builder-javascript

# Só copiamos o que os harnesses precisam (lib/ com as funções puras a
# fuzzar, e os próprios harnesses) — não o monorepo inteiro. A estrutura
# relativa replica o repo real (dynamic/worker/... e .clusterfuzzlite/fuzz/
# ficam nos mesmos caminhos uns dos outros), para os imports em fuzz/*.js
# funcionarem sem alterações entre o teste local (node --test/jazzer direto
# no repo) e o build aqui dentro do container.
COPY dynamic/worker/package.json $SRC/repo/dynamic/worker/package.json
COPY dynamic/worker/src/lib $SRC/repo/dynamic/worker/src/lib
COPY .clusterfuzzlite/package.json $SRC/repo/.clusterfuzzlite/package.json
COPY .clusterfuzzlite/fuzz $SRC/repo/.clusterfuzzlite/fuzz
COPY .clusterfuzzlite/build.sh $SRC/

WORKDIR $SRC/repo
