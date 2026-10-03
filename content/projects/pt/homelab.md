---
title: 'Homelab'
description: 'A minha infraestrutura pessoal, segmentada por função, automatizada e verificada.'
tags: ['homelab', 'segmentação', 'automação', 'raspberry-pi']
order: 4
---

Em casa mantenho uma pequena infraestrutura pessoal, feita de alguns
Raspberry Pi e um portátil. Serve para praticar, em ponto pequeno, o que faço
no trabalho: segmentação de rede, acesso remoto controlado, automação e
verificação. O desenho e as decisões estão documentados num repositório
próprio.

<svg class="diagram-homelab" viewBox="0 0 640 170" role="img" aria-label="Esquema simplificado do homelab: quatro segmentos por função (dados, cópias, experiências e administração) separados por uma firewall">
  <rect class="diagram-boundary" x="20" y="20" width="600" height="130" rx="8"></rect>
  <text class="diagram-label" x="34" y="40">firewall · segmentos por função</text>
  <rect class="diagram-node" x="39" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="98" y="98" text-anchor="middle">dados</text>
  <rect class="diagram-node" x="187" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="246" y="98" text-anchor="middle">cópias</text>
  <rect class="diagram-node" x="335" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="394" y="98" text-anchor="middle">experiências</text>
  <rect class="diagram-node diagram-node--prod" x="483" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="542" y="98" text-anchor="middle">administração</text>
</svg>

## Como penso nela

- **Separar por função.** Cada máquina tem um papel e vive num segmento
  próprio, para que um comprometimento só alcance o que esse papel permite.
- **Verificar, não assumir.** Cada regra de rede tem um mecanismo que a
  impõe e um teste que a confirma, e esse teste corre de forma automática.
- **Configuração como código.** As máquinas configuram-se com scripts
  versionados, aplicados pelo CI.
- **Segredos fora do repositório.** Nenhum segredo entra no git, e há um
  scanner a garanti-lo.
- **Decisões registadas.** Cada escolha tem o seu registo, com o contexto e
  o porquê, para que daqui a um ano eu perceba o que decidi.
