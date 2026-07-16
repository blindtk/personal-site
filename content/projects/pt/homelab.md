---
title: 'Homelab'
description: 'Cluster k3s em Raspberry Pi, em casa — o terreno onde testo tudo antes de chegar perto de produção.'
tags: ['kubernetes', 'k3s', 'raspberry-pi', 'homelab']
order: 3
---

Em casa mantenho um cluster [k3s](https://k3s.io/) — a distribuição leve do
Kubernetes, pensada para hardware modesto e ARM — a correr em Raspberry Pi.
É o mesmo homelab que já mencionei no [Sobre](/sobre/): a cobaia para tudo o
que quero experimentar antes de chegar perto de produção.

<svg class="diagram-homelab" viewBox="0 0 640 220" role="img" aria-label="Topologia simplificada do homelab: cluster k3s com control-plane e agentes, isolado da produção">
  <defs>
    <marker id="homelab-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path class="diagram-arrowhead" d="M0,0 L10,5 L0,10 z"></path>
    </marker>
  </defs>
  <rect class="diagram-boundary" x="20" y="24" width="380" height="168" rx="8"></rect>
  <text class="diagram-label" x="34" y="44">homelab</text>
  <rect class="diagram-node" x="165" y="76" width="110" height="46" rx="6"></rect>
  <text class="diagram-node-title" x="220" y="97" text-anchor="middle">control-plane</text>
  <text class="diagram-node-sub" x="220" y="111" text-anchor="middle">k3s server · Pi</text>
  <rect class="diagram-node" x="60" y="150" width="100" height="40" rx="6"></rect>
  <text class="diagram-node-title" x="110" y="172" text-anchor="middle">agente</text>
  <text class="diagram-node-sub" x="110" y="184" text-anchor="middle">k3s agent · Pi</text>
  <rect class="diagram-node" x="270" y="150" width="100" height="40" rx="6"></rect>
  <text class="diagram-node-title" x="320" y="172" text-anchor="middle">agente</text>
  <text class="diagram-node-sub" x="320" y="184" text-anchor="middle">k3s agent · Pi</text>
  <path class="diagram-edge" d="M192,122 L110,150"></path>
  <path class="diagram-edge" d="M248,122 L320,150"></path>
  <rect class="diagram-node diagram-node--prod" x="470" y="99" width="130" height="46" rx="6"></rect>
  <text class="diagram-node-title" x="535" y="120" text-anchor="middle">produção</text>
  <text class="diagram-node-sub" x="535" y="134" text-anchor="middle">fora do homelab</text>
  <path class="diagram-edge diagram-edge--dashed" d="M400,122 L465,122"></path>
  <text class="diagram-caption" x="432" y="110" text-anchor="middle">testar primeiro</text>
</svg>

*Topologia simplificada e ilustrativa — o número real de nós varia; o que
interessa aqui é a relação entre o cluster e a produção, não um inventário.*

## O que corre lá

Não há uma lista fixa — é essa a natureza de um terreno de testes: passam por
lá as ferramentas deste site antes de irem para o browser de outra pessoa,
configurações que quero validar antes de as levar para o trabalho, e
montagens de infraestrutura ofensiva para lab e CTFs (o heatmap em
[Attack](/attack/) mapeia essa prática à técnica *Acquire Infrastructure* do
MITRE ATT&CK, ao nível "experiência pontual / lab"). O denominador comum é
sempre o mesmo: nada toca produção sem primeiro passar por aqui.

## Porquê k3s

Um Raspberry Pi não tem o footprint para um Kubernetes "a sério" — o k3s
existe exatamente para isto: a mesma API do Kubernetes, com o etcd, os
controllers legacy e as dependências desnecessárias cortadas para caber em
hardware ARM de baixo consumo. Ganho a prática dos padrões que interessam em
produção — multi-nó, scheduling, resiliência a perder um nó — num ambiente
barato o suficiente para partir sem custar nada.

## Decisões técnicas

- **Cluster, não um Pi isolado.** Um único nó testa "corre o container";
  vários nós testam o que falha de verdade em produção — perder um nó,
  agendar em falta de recursos, tolerar reinícios.
- **Isolamento deliberado da produção.** O homelab não tem acesso a nada que
  importe fora dele; é um ambiente descartável por construção, para poder
  ser destruído e reconstruído sem cerimónia.
- **Sem exposição pública fixa.** Ainda não há um subdomínio a apontar para
  o homelab (ver `docs/dns-tls.md` neste repo) — decide-se se e quando fizer
  sentido, sem comprometer entretanto a política de HSTS preload do domínio
  principal.
