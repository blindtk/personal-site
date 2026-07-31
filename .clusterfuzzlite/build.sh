#!/bin/bash -eu

# package.json mínimo na raiz do "projeto" copiado ($SRC/repo) só para o
# `npm install` ter onde escrever o node_modules que o wrapper do
# compile_javascript_fuzzer espera encontrar em <project>/node_modules/
# @jazzer.js/core. Os ficheiros fuzzados (dynamic/worker/ e
# .clusterfuzzlite/) já trazem os seus próprios package.json com
# "type": "module", que é o que importa para o parser interpretar
# corretamente o import/export ES module.
# Versão fixa (não "latest") — este container é reconstruído do zero em
# cada run do cron, sem lockfile a fixar nada; sem isto, um release do
# Jazzer.js podia partir o build semanal sem nenhuma alteração deste repo.
npm init -y >/dev/null
npm install --save-dev @jazzer.js/core@4.0.0

compile_javascript_fuzzer repo .clusterfuzzlite/fuzz/csp_report_fuzz.js --sync
compile_javascript_fuzzer repo .clusterfuzzlite/fuzz/sanitize_fuzz.js --sync
