---
title: 'Sobre mim'
---

Sou o **Daniel Malaco**, **Information Security Engineer** no Porto. Desde
2020 trabalho na Ascendi, onde desenho e opero a segurança de infraestrutura
rodoviária. O trabalho cobre o ciclo todo: firewalls, SIEM, proteção de
endpoints, gestão de identidades, threat intelligence e resposta a incidentes. Tanto desenho o controlo como analiso o evento que ele
apanha.

Cheguei à segurança pelas redes. Entre 2017 e 2020 desenhei, instalei e
comissionei redes IP em projetos de metro e ferrovia: o metro de Doha, o VLT
de Santos e os metros ligeiros de Odense e Bergen. Num sistema de transporte,
uma falha de rede não é um simples incómodo: os comboios param e milhares de
pessoas ficam à espera. Foi aí que aprendi a desenhar com redundância, a documentar
para quem vem a seguir e a testar tudo em laboratório antes de tocar em
produção.

Em 2020 passei a olhar para as redes do lado de quem as ataca. Na Hardsecure
instalei firewalls e fiz testes de intrusão internos, à procura das
vulnerabilidades antes de alguém as explorar. É essa forma de pensar que levo
hoje para o trabalho defensivo. Também a treino fora do trabalho: fiz o SANS
SEC504, acompanho os summits de DFIR e ransomware da SANS e já ganhei quatro
CTFs, o primeiro em Lisboa, em 2022. As fotos estão no fim desta página.

Gosto de construir as ferramentas que uso. As deste site correm no browser, e
em casa tenho um homelab, segmentado por função, onde experimento
o que quero testar antes de chegar perto de produção. O próprio site faz parte
disso: é estático, bilingue, não tem trackers e a forma como está protegido
está explicada em [Este site](/este-site/).

## Percurso

Abre cada função para ver o detalhe.

<details>
<summary>Information Security Engineer · Ascendi <span>nov 2020 → presente</span></summary>

- **Contexto:** segurança da infraestrutura rodoviária da Ascendi, em
  Portugal.
- **Papel:** desenho, implementação e operação da arquitetura de segurança da
  informação; gestão de pedidos e incidentes em ITSM.
- **Tecnologias:** NGFW, AV/EDR, análise de vulnerabilidades, SIEM, IAM, WAF e
  gateway de email (SEG).
- **No dia a dia:** manter seguras as redes, os sistemas e as aplicações com
  políticas e procedimentos, detetar ameaças e vulnerabilidades e pôr em
  prática os controlos que as mitigam, a partir da monitorização e da análise
  de eventos de segurança.
- **Referência externa:** a Fortinet publicou um [caso de estudo sobre a
  Ascendi](https://www.fortinet.com/customers/ascendi) que descreve a
  infraestrutura de segurança que ajudei a construir. O artigo cita o Head of
  IT e não me nomeia, mas fiz parte da equipa que fez esse trabalho.

</details>

<details>
<summary>Cyber Security Engineer · Hardsecure <span>fev 2020 → set 2020</span></summary>

- **Contexto:** implementação de firewalls e testes de
  intrusão internos.
- **Papel:** instalação, configuração e suporte de NGFW.
- **Tecnologias:** NGFW, scanning e enumeração de redes.
- **Resultado:** vulnerabilidades encontradas nas redes antes de serem
  exploradas.

</details>

<details>
<summary>Systems Engineer · Efacec <span>jan 2019 → fev 2020</span></summary>

**Odense Letbane** (Dinamarca)

- **Contexto:** projeto do metro ligeiro de Odense.
- **Papel:** desenho, instalação e comissionamento das redes IP e da
  segurança.
- **Método:** requisitos de sistema, documentos de desenho e instalação,
  staging em laboratório, procedimentos de teste e comissionamento.
- **Resultado:** a rede IP e a camada de segurança passaram do desenho ao
  comissionamento, com staging em laboratório, testes e entrega documentada à
  equipa de operação.

**Bergen D42** (Noruega)

- **Contexto:** projeto do metro ligeiro de Bergen, troço D42.
- **Papel:** desenho, instalação e comissionamento das redes IP e da
  segurança.
- **Método:** o mesmo de Odense, dos requisitos de sistema ao
  comissionamento.
- **Resultado:** desenho, instalação e comissionamento do troço D42
  documentados a partir dos requisitos de sistema, prontos para a linha entrar
  em serviço.

</details>

<details>
<summary>Junior Consultant · Altran / Network Engineer · Thales <span>jan 2017 → dez 2018</span></summary>

**Metro de Doha** (Qatar)

- **Contexto:** projeto do metro de Doha, construído de raiz.
- **Papel:** desenho, instalação e comissionamento das redes IP e do sistema
  BBRS, o WiFi móvel que acompanha os comboios.
- **Tecnologias:** redes IP, BBRS, ambientes ferroviários e de metro.

**VLT Santos** (Brasil)

- **Contexto:** projeto do VLT (veículo leve sobre trilhos) de Santos.
- **Papel:** desenho, instalação e comissionamento das redes IP e do BBRS.
- **Resultado:** a mesma stack ferroviária de Doha adaptada a um sistema
  urbano de VLT.

</details>

## Formação

- **Mestrado em Engenharia Eletrotécnica e de Computadores** na FEUP
  (Faculdade de Engenharia da Universidade do Porto), 2009 a 2016, com
  especialização em Redes e Serviços de Comunicação.

## Certificações

Tenho certificações da Fortinet, da SANS, da Microsoft, da CyberDefenders e
de outras entidades. A lista completa, com o estado de cada uma e verificação
independente no Credly, está em **[Certificações](/certificacoes/)**.

## Cobertura ATT&CK

O **[heatmap ATT&CK](/attack/)** mostra, tática a tática, as técnicas do MITRE
ATT&CK que cubro do lado defensivo e a ferramenta ou experiência por trás de
cada uma.

## Competências

| Área | Detalhe |
| --- | --- |
| Perímetro | NGFW, WAF, Security Email Gateway (SEG) |
| Endpoint | Antivírus (AV), Endpoint Detection & Response (EDR) |
| Identidade | IAM, Active Directory |
| Deteção e resposta | SIEM, análise de vulnerabilidades (VA), testes de intrusão |
| Resiliência | Business Continuity Planning (BCP) |
| Linguagens | Python, Bash, PowerShell, Golang, C/C++ |
| Plataformas | Linux, Windows, AWS, Azure, Rapid7 InsightVM, ServiceNow |

## Referenciais

Uso estes referenciais como ferramentas de trabalho: para estruturar
decisões, priorizar controlos e falar a mesma língua que auditores,
fornecedores e reguladores. A tabela diz onde cada um entra e com que
profundidade.

| Referencial | Onde entra no trabalho | Profundidade |
| --- | --- | --- |
| ISO 27001 | Base para as políticas e procedimentos de segurança e para organizar os controlos técnicos por domínio. | Referência |
| NIS2 | Enquadramento regulatório do setor em que trabalho, a infraestrutura crítica de transportes. Orienta as prioridades de controlo e de reporte. | Enquadramento |
| CIS Controls & Benchmarks | Base para o hardening de sistemas e equipamentos de rede, e para verificar configurações. | Aplicado |
| CISA CPG | Termo de comparação para priorizar os controlos de base em infraestrutura crítica. | Referência |
| OWASP Top 10 | Vocabulário comum para classificar o que a análise de vulnerabilidades e os testes internos encontram, e para afinar regras de WAF. | Aplicado |
| MITRE ATT&CK | Mapear a cobertura de deteção e estruturar a análise de incidentes. O detalhe, técnica a técnica, está no [heatmap](/attack/). | Aplicado |

*Aplicado* quer dizer uso corrente nos controlos que opero. *Referência* quer
dizer que o consulto no desenho e na priorização, sem um processo formal
associado. *Enquadramento* é o contexto regulatório do setor, não um programa
que eu conduza. Nenhuma linha quer dizer certificação, auditoria formal ou
conformidade declarada.
