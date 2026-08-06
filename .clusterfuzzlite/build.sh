#!/bin/bash -eu

# package.json + package-lock.json (copiados de .clusterfuzzlite/ pelo
# Dockerfile) fixam @jazzer.js/core e toda a árvore de dependências
# transitivas — `npm ci` não resolve nada de novo a cada build, ao
# contrário de `npm install`. Sem isto, um release do Jazzer.js (ou de
# qualquer dependência transitiva) podia partir o build semanal sem
# nenhuma alteração deste repo.
npm ci --ignore-scripts

compile_javascript_fuzzer repo .clusterfuzzlite/fuzz/sanitize_fuzz.js --sync
