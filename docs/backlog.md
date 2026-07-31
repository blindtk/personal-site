# Backlog — ideias analisadas, não implementadas

Três sessões de análise editorial/técnica produziram propostas detalhadas
que nunca foram aceites nem implementadas. Este ficheiro substitui os
documentos originais (~2200 linhas em `docs/proposals/`, removidos
2026-07-31 para reduzir o número de ficheiros em `docs/`) por um resumo
curto de cada ideia — o raciocínio completo fica preservado no histórico
do git, se algum dia for preciso.

## 1. Reorganizar a secção Perímetro (Deteções / Telemetria)

`PerimeterPage.astro` mistura hoje registo editorial (texto que se lê uma
vez) com dashboards ao vivo (números que mudam a cada minuto) nas mesmas 5
tabs. Proposta: separar em 3 páginas — Perímetro (editorial, com 4 stat
cards fixos), Deteções (regras Sigma) e Telemetria (dashboards ao vivo).
Sem esta separação, a página mais argumentativa do site muda de conteúdo
constantemente, o que contradiz a tese de rigor documental do repositório.

## 2. Nova página "Mapeamento de controlos"

Proposta de uma subpágina em «Este Site» que traduz os controlos já
existentes (CSP, rate limiting, honeypot, CI) para o vocabulário de
frameworks públicos (OWASP Top 10, CIS Controls, CISA CPG, MITRE ATT&CK) —
uma camada de indexação, não uma alegação nova de conformidade. Regra de
ouro proposta: cada linha da tabela ou aponta para outra página deste
site, ou não entra.

## 3. Evolução do honeypot

Análise crítica do honeypot atual — o que já funciona bem (sensor puro,
404 uniforme, zero PII), o que é hoje demasiado básico (poucos paths-isco,
sem variação de família de ataque), e o que seria excesso para um site
pessoal (imitar interfaces reais, servir conteúdo falso interativo).
Também aponta uma correção ao mapeamento ATT&CK de `content/honeypot-
attack.json` (técnicas por família de path, não por path individual) e
sugere fechar a lacuna de observabilidade entre o que a Cloudflare
bloqueia e o que chega ao Worker. Fica deliberadamente sem detalhe
operacional aqui — ver histórico do git para a análise completa, incluindo
os seis condicionantes estruturais (orçamento de escrita do KV, limite de
regras WAF do plano Free) que qualquer expansão tem de respeitar.

---

Se alguma destas ideias for aceite, o trabalho é implementá-la a sério
(rota nova, chave i18n, teste) — não expandir de novo este resumo.
