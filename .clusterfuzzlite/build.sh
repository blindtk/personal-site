#!/bin/bash -eu

# package.json mínimo na raiz do "projeto" copiado ($SRC/repo) só para o
# `npm install` ter onde escrever o node_modules que o wrapper do
# compile_javascript_fuzzer espera encontrar em <project>/node_modules/
# @jazzer.js/core. Os ficheiros fuzzados (dynamic/worker/ e
# .clusterfuzzlite/) já trazem os seus próprios package.json com
# "type": "module", que é o que importa para o parser interpretar
# corretamente o import/export ES module.
npm init -y >/dev/null
npm install --save-dev @jazzer.js/core

compile_javascript_fuzzer repo .clusterfuzzlite/fuzz/csp_report_fuzz.js --sync
compile_javascript_fuzzer repo .clusterfuzzlite/fuzz/sanitize_fuzz.js --sync
