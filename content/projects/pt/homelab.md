---
title: 'Homelab'
description: 'Rede doméstica com princípios zero trust: Raspberry Pi, segmentação e GitOps com Flux.'
tags: ['flux', 'docker', 'k3s']
order: 4
---

O meu homelab é uma pequena rede doméstica feita de três Raspberry Pi, uma
firewall, um switch, access points e portáteis. Serve para praticar, em
ponto pequeno, o que faço no trabalho: segmentação de rede, acesso remoto
controlado, automação e verificação. O desenho e as decisões estão
documentados num repositório próprio.

<svg class="diagram-homelab" viewBox="0 0 640 214" role="img" aria-label="Esquema simplificado do homelab: uma firewall que liga quatro segmentos (vault, archive, workshop e bench) e bloqueia tudo por omissão">
  <rect class="diagram-node" x="40" y="20" width="560" height="44" rx="6"></rect>
  <text class="diagram-node-title" x="320" y="47" text-anchor="middle">firewall · deny all por omissão</text>
  <path class="diagram-edge" d="M80,64 L80,110"></path>
  <rect class="diagram-node" x="12" y="110" width="136" height="84" rx="6"></rect>
  <text class="diagram-node-title" x="80" y="146" text-anchor="middle">vault</text>
  <text class="diagram-node-sub" x="80" y="164" text-anchor="middle">o que não se perde</text>
  <path class="diagram-edge" d="M240,64 L240,110"></path>
  <rect class="diagram-node" x="172" y="110" width="136" height="84" rx="6"></rect>
  <text class="diagram-node-title" x="240" y="146" text-anchor="middle">archive</text>
  <text class="diagram-node-sub" x="240" y="164" text-anchor="middle">cópia do que importa</text>
  <path class="diagram-edge" d="M400,64 L400,110"></path>
  <rect class="diagram-node" x="332" y="110" width="136" height="84" rx="6"></rect>
  <text class="diagram-node-title" x="400" y="146" text-anchor="middle">workshop</text>
  <text class="diagram-node-sub" x="400" y="164" text-anchor="middle">para testar e partir</text>
  <path class="diagram-edge" d="M560,64 L560,110"></path>
  <rect class="diagram-node diagram-node--prod" x="492" y="110" width="136" height="84" rx="6"></rect>
  <text class="diagram-node-title" x="560" y="146" text-anchor="middle">bench</text>
  <text class="diagram-node-sub" x="560" y="164" text-anchor="middle">de onde giro tudo</text>
</svg>

*Os segmentos só comunicam através da firewall, que bloqueia tudo o que não tenha uma regra explícita.*

## Zero trust por omissão

Nenhuma máquina confia noutra só por estar na mesma rede. A firewall nega
todo o tráfego entre segmentos por omissão (deny all) e só abre o que cada
função precisa, com uma regra explícita. Cada Raspberry Pi tem um
papel (vault, archive ou workshop) e vive no seu segmento, e os portáteis
formam o bench, de onde administro.

## O que usa

- **Firewall, switch e access points.** A firewall impõe as fronteiras entre
  segmentos, e o switch e os access points levam as VLANs até às máquinas.
- **Tailscale.** A VPN em malha para o acesso remoto.
- **Docker.** Os serviços correm em contentores, geridos com Compose, cada um
  com o seu utilizador.
- **Gestor de passwords.** Auto-alojado.
- **Runners do GitHub Actions.** O CI próprio.
- **k3s.** Um Kubernetes leve, para aprender e testar.

## Como o mantenho

- **Verificar, não assumir.** Cada regra de rede tem um mecanismo que a
  impõe e um teste que a confirma, e esse teste corre de forma automática.
- **Configuração como código.** As máquinas configuram-se com scripts
  versionados, aplicados pelo CI.
- **Segredos fora do repositório.** Nenhum segredo entra no git, e há um
  scanner a garanti-lo.
- **Decisões registadas.** Cada escolha tem o seu registo, com o contexto e
  o porquê, para que daqui a um ano eu perceba o que decidi.
