---
title: 'Homelab'
description: 'A minha infraestrutura pessoal, separada por função, onde cada regra de rede tem um teste que a verifica.'
tags: ['homelab', 'segmentação', 'raspberry-pi', 'gitops']
order: 4
---

Em casa mantenho uma pequena infraestrutura pessoal, feita de três
Raspberry Pi e um portátil. Não é uma montra de serviços. É o sítio onde
desenho e opero, em ponto pequeno, o que faço no trabalho: segmentação,
acesso remoto controlado, automação e verificação. O desenho, as decisões e o
estado de cada parte estão documentados num repositório próprio.

<svg class="diagram-homelab" viewBox="0 0 640 230" role="img" aria-label="Esquema simplificado do homelab: quatro segmentos (cofre, cópia, oficina e bancada) separados por uma firewall, com o cofre sem acesso à cópia">
  <defs>
    <marker id="homelab-arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
      <path class="diagram-arrowhead" d="M0,0 L10,5 L0,10 z"></path>
    </marker>
  </defs>
  <rect class="diagram-boundary" x="20" y="24" width="600" height="182" rx="8"></rect>
  <text class="diagram-label" x="34" y="44">firewall · fronteiras entre segmentos</text>
  <rect class="diagram-node" x="39" y="76" width="118" height="64" rx="6"></rect>
  <text class="diagram-node-title" x="98" y="104" text-anchor="middle">cofre</text>
  <text class="diagram-node-sub" x="98" y="120" text-anchor="middle">o insubstituível</text>
  <rect class="diagram-node" x="187" y="76" width="118" height="64" rx="6"></rect>
  <text class="diagram-node-title" x="246" y="104" text-anchor="middle">cópia</text>
  <text class="diagram-node-sub" x="246" y="120" text-anchor="middle">sobrevive ao cofre</text>
  <rect class="diagram-node" x="335" y="76" width="118" height="64" rx="6"></rect>
  <text class="diagram-node-title" x="394" y="104" text-anchor="middle">oficina</text>
  <text class="diagram-node-sub" x="394" y="120" text-anchor="middle">código de terceiros</text>
  <rect class="diagram-node diagram-node--prod" x="483" y="76" width="118" height="64" rx="6"></rect>
  <text class="diagram-node-title" x="542" y="104" text-anchor="middle">bancada</text>
  <text class="diagram-node-sub" x="542" y="120" text-anchor="middle">admin · chaves</text>
  <path class="diagram-edge diagram-edge--dashed" d="M157,112 L185,112"></path>
  <text class="diagram-caption" x="171" y="100" text-anchor="middle">✕</text>
  <text class="diagram-caption" x="39" y="170">✕ o cofre nunca inicia ligações para a cópia</text>
  <text class="diagram-caption" x="39" y="188">acesso remoto só por VPN em malha</text>
</svg>

*Esquema simplificado. Mostra o papel de cada segmento e a regra que mais
importa, não um inventário.*

## Como está organizado

A rede de casa está dividida em segmentos, cada um com uma função e um tipo
de risco próprio.

| Segmento | Para que serve |
| --- | --- |
| Cofre | Guarda o que não se pode perder nem substituir. |
| Cópia | Guarda a cópia que sobrevive ao cofre, e que o cofre não alcança. |
| Oficina | Corre código que eu não escrevi, como o CI, e as experiências com k3s. Nada aqui é insubstituível. |
| Bancada | É onde administro, onde faço o laboratório de máquinas virtuais descartáveis e onde vivem as chaves de administração, longe dos servidores. |

Todas as máquinas são minhas, por isso a separação não é por desconfiança.
É por causa do que um comprometimento alcançaria. O que corre código de
terceiros fica no segmento que posso partir sem perder nada.

## O que decidi, e porquê

- **Uma regra só conta se alguém a verificar.** Cada fronteira entre
  segmentos tem um mecanismo que a impõe e um comando que a testa, e a
  verificação corre todos os dias. O teste também tem de falhar quando o
  mecanismo não existe: uma ligação recusada porque nada está à escuta não
  prova restrição nenhuma, por isso espero que a ligação esgote o tempo.
- **Uma réplica fiel não é uma cópia de segurança.** Um espelho dos
  repositórios copiava também um `push --force` que apagasse histórico. Por
  isso a réplica não apaga o que o original já não tem, e a cópia a sério
  fica noutro segmento.
- **Nada exposto.** O acesso remoto às máquinas faz-se por uma VPN em malha,
  e o desenho não prevê nada público.
- **Segredos fora do git.** Nenhum segredo entra no repositório, e há um
  scanner de segredos no CI desde o primeiro commit.
- **Atualizações de segurança automáticas, reinício à mão.** Os pacotes de
  segurança instalam-se sozinhos, mas nenhuma máquina reinicia sem eu
  decidir.
- **O estado vive num sítio só.** Um plano diz o que está feito, a meio,
  adiado e por fazer, com a prova de cada coisa, e cada decisão tem o seu
  registo. Uma linha de documentação que não corresponda à máquina é pior do
  que nenhuma, por isso o que descreve o que existe leva a data e a forma
  como foi verificado.

## Em que ponto está

Feitos: a segmentação da rede e o acesso remoto, o segmento do cofre com
réplicas automáticas dos repositórios, a verificação diária das fronteiras e
as atualizações de segurança. Em construção: o cluster k3s com GitOps (Flux)
na oficina, um utilizador por runner de CI e as cópias de segurança.
