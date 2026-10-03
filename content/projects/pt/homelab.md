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

<svg class="diagram-homelab" viewBox="0 0 640 214" role="img" aria-label="Esquema simplificado do homelab: uma firewall que liga quatro segmentos (dados, cópias, experiências e administração) e bloqueia tudo por omissão">
  <rect class="diagram-node" x="40" y="20" width="560" height="44" rx="6"></rect>
  <text class="diagram-node-title" x="320" y="47" text-anchor="middle">firewall · deny all por omissão</text>
  <path class="diagram-edge" d="M80,64 L80,110"></path>
  <rect class="diagram-node" x="12" y="110" width="136" height="84" rx="6"></rect>
  <text class="diagram-node-title" x="80" y="146" text-anchor="middle">dados</text>
  <text class="diagram-node-sub" x="80" y="164" text-anchor="middle">o que não pode perder-se</text>
  <path class="diagram-edge" d="M240,64 L240,110"></path>
  <rect class="diagram-node" x="172" y="110" width="136" height="84" rx="6"></rect>
  <text class="diagram-node-title" x="240" y="146" text-anchor="middle">cópias</text>
  <text class="diagram-node-sub" x="240" y="164" text-anchor="middle">cópia do que importa</text>
  <path class="diagram-edge" d="M400,64 L400,110"></path>
  <rect class="diagram-node" x="332" y="110" width="136" height="84" rx="6"></rect>
  <text class="diagram-node-title" x="400" y="146" text-anchor="middle">experiências</text>
  <text class="diagram-node-sub" x="400" y="164" text-anchor="middle">onde se testa e se parte</text>
  <path class="diagram-edge" d="M560,64 L560,110"></path>
  <rect class="diagram-node diagram-node--prod" x="492" y="110" width="136" height="84" rx="6"></rect>
  <text class="diagram-node-title" x="560" y="146" text-anchor="middle">administração</text>
  <text class="diagram-node-sub" x="560" y="164" text-anchor="middle">de onde giro tudo</text>
</svg>

*Os segmentos só comunicam através da firewall, que bloqueia tudo o que não tenha uma regra explícita.*

## Zero trust por omissão

Nenhuma máquina confia noutra só por estar na mesma rede. A firewall nega
todo o tráfego entre segmentos por omissão (deny all) e só abre o que cada
função precisa, com uma regra explícita. Cada Raspberry Pi tem um
papel e vive no seu segmento, e os portáteis são a administração.

## O que usa

- **Firewall, switch e access points.** A firewall impõe as fronteiras entre
  segmentos, e o switch e os access points levam as VLANs até às máquinas.
- **Tailscale.** A VPN em malha para o acesso remoto, com as permissões
  definidas por ACL.
- **Docker.** Os serviços correm em contentores, geridos com Compose, cada um
  com o seu utilizador.
- **Vaultwarden.** O gestor de credenciais, auto-alojado e num segmento só
  dele.
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
