---
title: 'Threat Intel'
description: 'Um honeypot SSH e HTTP numa VPS à parte e o feed público de ameaças que sai dele, enriquecido e mapeado para ATT&CK.'
tags: ['ssh', 'threat-intel', 'mitre-attack', 'python', 'oracle-cloud']
order: 2
---

Um sensor de verdade, exposto à Internet sem proxy à frente, numa máquina
que não tem nada a ver com este site: uma VPS na Oracle Cloud, em
recursos Always Free, configurada inteiramente como código no repositório
`honeypot-vps-infra`. O que apanha é tratado, enriquecido e publicado em
[intel.danielmala.co](https://intel.danielmala.co/): relatório, dossiês,
uma página por endereço e por artefacto, e um feed legível por máquinas.

## O que corre na VPS

- **Acesso SSH** na porta 22: uma shell emulada por completo, nunca uma
  shell real. O login só passa depois de 2 a 5 credenciais diferentes, e a
  que "funcionou" continua a funcionar, como numa máquina comprometida a
  sério; aceitar tudo à primeira seria o sinal mais fácil de que aquilo é
  um honeypot. No sistema de ficheiros falso há credenciais-isco (AWS,
  `.env`, histórico de bash) geradas na altura de cada instalação, nunca
  guardadas no repositório.
- **Um labirinto HTTP** nas portas 80/443: texto gerado sem fim, com links
  que só levam a mais texto, para prender crawlers e scanners. Tem tetos
  de ligações, bytes e tempo, para não ser a própria VPS a esgotar-se
  primeiro.
- **portlogger e endlessh**: registo e tarpit nas portas que os scanners de
  serviços cloud procuram (Docker, Redis, Elasticsearch, RDP, VNC) e um
  tarpit na porta 23 e noutras secundárias, que segura a ligação a pingar
  um banner.

## Do registo ao feed

Os eventos dos serviços entram numa base de estado e saem, a cada
15 minutos, como `feed.json`/`feed.txt`, uma exportação MISP, um bundle
STIX 2.1 e o relatório em HTML. Pelo caminho:

- **ATT&CK por comando, não por palavra-chave solta**: o acesso SSH capta
  o que o atacante escreve, por isso cada padrão (`curl … | sh`, `chmod +x`,
  `crontab`, mineradores, leitura de `.ssh/id_rsa`…) mapeia para a técnica
  que lhe corresponde. Sem padrão claro, não há técnica: nunca um palpite.
- **Enriquecimento com regras explícitas**: dez fontes (RDAP, AbuseIPDB,
  GreyNoise, ThreatFox, OTX, Shodan, ANY.RUN…), cada uma com o que pode e
  não pode concluir. O Shodan, por exemplo, nunca decide se um IP é
  malicioso. Um desacordo resolve-se pela fiabilidade de cada fonte, e o
  que falta diz que falta.
- **Malware**: os ficheiros que os atacantes tentam descarregar ficam
  presos com limites de tamanho e de ritmo, e o hash é consultado em
  serviços de análise (MalwareBazaar, VirusTotal…). Submeter a própria
  amostra é opcional e tem regras apertadas. A página do artefacto mostra
  o hash e o veredicto, nunca a amostra.
- **Dossiês que agrupam comportamento, não pessoas**: endereços ligados
  pelos mesmos hashes (uma chave SSH reutilizada, os mesmos artefactos)
  ficam juntos, publicados como inferência que o leitor pode rejeitar,
  sem nomes de campanha nem de atores.

## Privacidade e retenção

Um IP é um dado pessoal, mesmo quando é quase sempre infraestrutura de
botnet. A base legal é interesse legítimo (RGPD, art. 6.º, n.º 1, al. f)),
com salvaguardas: um endereço sai da publicação ao fim de 75 dias sem nova
deteção e da base de dados ao fim de 365; endereços privados e reservados
nunca entram; um IP visto uma única vez de forma passiva não é publicado.
Pares utilizador/password só são publicados quando vêm de pelo menos 5 ASN
**e** 5 redes /24 diferentes, ao longo de pelo menos 3 dias. Sem dados de
ASN, falha fechado e não publica nada.

## Operação

A VPS é descartável: a Oracle pode recuperar uma instância Always Free, por
isso tudo o que é preciso para a reconstruir do zero está no repositório
(`provision.sh` idempotente e Terraform opcional). A base de estado é
cifrada com `age` e copiada para fora da máquina em cada execução. O CI
corre as cinco suites de testes, `pip-audit` sobre lockfiles com hashes (os
mesmos que a VPS instala), SBOM, `ruff`, `bandit`, `shellcheck` e
verificações de que a documentação bate certo com o código. As páginas
publicadas não têm JavaScript nenhum, com uma CSP que não permite scripts.
