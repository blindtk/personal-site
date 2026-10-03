---
title: 'Homelab'
description: 'A minha rede doméstica com zero trust por omissão: Raspberry Pi, firewall com deny all, VPN em malha e CI próprio.'
tags: ['homelab', 'zero-trust', 'k3s', 'tailscale']
order: 4
---

O meu homelab é uma pequena rede doméstica feita de três Raspberry Pi, uma
firewall, um switch, access points e portáteis. Serve para praticar, em
ponto pequeno, o que faço no trabalho: segmentação de rede, acesso remoto
controlado, automação e verificação. O desenho e as decisões estão
documentados num repositório próprio.

<svg class="diagram-homelab" viewBox="0 0 640 170" role="img" aria-label="Esquema simplificado do homelab: quatro segmentos por função (dados, cópias, experiências e administração) separados por uma firewall com deny all por omissão">
  <rect class="diagram-boundary" x="20" y="20" width="600" height="130" rx="8"></rect>
  <text class="diagram-label" x="34" y="40">firewall · deny all por omissão</text>
  <rect class="diagram-node" x="39" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="98" y="98" text-anchor="middle">dados</text>
  <rect class="diagram-node" x="187" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="246" y="98" text-anchor="middle">cópias</text>
  <rect class="diagram-node" x="335" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="394" y="98" text-anchor="middle">experiências</text>
  <rect class="diagram-node diagram-node--prod" x="483" y="64" width="118" height="60" rx="6"></rect>
  <text class="diagram-node-title" x="542" y="98" text-anchor="middle">administração</text>
</svg>

## Zero trust por omissão

Nenhuma máquina confia noutra só por estar na mesma rede. A firewall nega
todo o tráfego entre segmentos por omissão (deny all) e só abre o que cada
função precisa, com uma regra explícita. O acesso remoto passa por uma VPN em
malha, em vez de portas abertas para a Internet. Cada Raspberry Pi tem um
papel e vive no seu segmento, e os portáteis são a administração.

## O que usa

- **Firewall, switch e access points.** A firewall impõe as fronteiras entre
  segmentos, e o switch e os access points levam as VLANs até às máquinas.
- **Tailscale.** A VPN em malha para o acesso remoto, com as permissões
  definidas por ACL.
- **Docker.** Os serviços correm em contentores, geridos com Compose, cada um
  com o seu utilizador.
- **Vaultwarden.** O gestor de credenciais, auto-alojado e num segmento só
  dele, sem exposição à Internet.
- **Runners do GitHub Actions.** O CI próprio, que também aplica as
  configurações nas máquinas. Executa código de terceiros, como as
  dependências dos workflows, por isso fica no segmento que posso partir sem
  perder nada.
- **k3s.** Um Kubernetes leve para aprender e testar, longe do que é
  insubstituível.

## Como o mantenho

- **Verificar, não assumir.** Cada regra de rede tem um mecanismo que a
  impõe e um teste que a confirma, e esse teste corre de forma automática.
- **Configuração como código.** As máquinas configuram-se com scripts
  versionados, aplicados pelo CI.
- **Segredos fora do repositório.** Nenhum segredo entra no git, e há um
  scanner a garanti-lo.
- **Decisões registadas.** Cada escolha tem o seu registo, com o contexto e
  o porquê, para que daqui a um ano eu perceba o que decidi.
