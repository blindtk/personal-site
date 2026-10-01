#!/bin/bash -eu

# package.json + package-lock.json (copiados de .clusterfuzzlite/ pelo
# Dockerfile) fixam @jazzer.js/core e toda a árvore de dependências
# transitivas — `npm ci` não resolve nada de novo a cada build, ao
# contrário de `npm install`. Sem isto, um release do Jazzer.js (ou de
# qualquer dependência transitiva) podia partir o build semanal sem
# nenhuma alteração deste repo.
npm ci --ignore-scripts

# Addon nativo do Jazzer.js. Com --ignore-scripts o install script do
# @jazzer.js/fuzzer (prebuild-install) não corre, por isso o binário vem
# daqui: o prebuild oficial da release v2.1.0, fixado por SHA-256 (o
# prebuild-install não verifica integridade nenhuma). Fica-se pelo 2.1.0
# porque o 4.0.0 traz prebuilds compilados contra glibc 2.38 e a imagem
# do run_fuzzers (clusterfuzzlite-run-fuzzers:v1, Ubuntu 20.04) só tem a
# 2.31 — o harness falhava a arrancar com "GLIBC_2.32 not found". Este
# prebuild só precisa de GLIBC_2.29.
#
# O 2.1.0 arrasta cmake-js -> tar@6 (vulnerável); o package.json força
# tar 7.5.22 via overrides. O cmake-js só seria usado pelo install script
# (compilar o addon de raiz), que nunca corre aqui, por isso a API nova do
# tar não importa.
#
# Limitação conhecida: o 2.1.0 só instrumenta CommonJS (hook no require),
# e o sanitize.js é ESM — o libFuzzer corre sem feedback de cobertura
# (mutação às cegas). Chega para o objetivo deste harness (ver
# ci-fuzzing.yml: "não lança exceção", reconhecimento pelo Scorecard), não
# para fuzzing guiado. Voltar ao 4.x quando a imagem do run_fuzzers
# tiver glibc >= 2.38.
JAZZER_PREBUILD_URL=https://github.com/CodeIntelligenceTesting/jazzer.js/releases/download/v2.1.0/fuzzer-v2.1.0-napi-v4-linux-x64.tar.gz
JAZZER_PREBUILD_SHA256=b1683ce8bc7178bed0d654ae7bde1a7dbe99deac5a4441e706251378eada8889
curl -sSLf -o /tmp/jazzer-prebuild.tgz "$JAZZER_PREBUILD_URL"
echo "$JAZZER_PREBUILD_SHA256  /tmp/jazzer-prebuild.tgz" | sha256sum -c -
tar xzf /tmp/jazzer-prebuild.tgz -C node_modules/@jazzer.js/fuzzer

compile_javascript_fuzzer repo .clusterfuzzlite/fuzz/sanitize_fuzz.js --sync
