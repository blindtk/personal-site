---
title: 'Honeypot'
description: 'Endpoints-isco que registam o scan automático da Internet — o IP de origem é publicado por decisão explícita, correlacionados com MITRE ATT&CK e CISA KEV.'
tags: ['cloudflare-workers', 'honeypot', 'threat-intel', 'mitre-attack']
order: 2
---

Alguns paths que nenhum humano visita de propósito — `/wp-login.php`,
`/.env`, `/.git/config`, `/admin`, `/phpmyadmin/` — existem neste site só por
uma razão: são isco. Quem lhes toca é, por definição, um scanner automático.
Um Cloudflare Worker regista a tentativa (só metadados) e devolve o 404 de
sempre, indistinguível de um path que nunca existisse. O resultado ao vivo
está no painel [Honeypot](/este-site/honeypot/) — o que a Cloudflare
bloqueia na zona inteira está à parte, na [Cloudflare](/este-site/cloudflare/).

## Porque vive no Worker, não no site estático

A regra do monorepo é simples: o `static/` fica 100% cliente (ver
[Este site](/projetos/este-site/)), e o honeypot é uma das exceções que
precisa mesmo de servidor — alguém tem de ver o pedido chegar. Por isso vive
isolado num Cloudflare Worker em `dynamic/worker/` — o primeiro código real
dessa área — publicado à parte. Se o Worker estiver em baixo, o site estático
não nota: o painel degrada com graça em vez de partir.

## Privacidade — duas posturas, por desenho

O painel Cloudflare (tráfego da zona inteira, que inclui todos os
visitantes legítimos) continua sem guardar IP nenhum: só país
(`cf-ipcountry`), ASN e o path-isco, com o timestamp arredondado a 5
minutos — o arredondamento é anonimização, não arrumação, e a única coisa
derivada do IP nesse caminho é a chave de rate limit, um SHA-256 truncado
com salt que roda ao dia, guardada só durante a janela do limite. Isto
está coberto por teste (`test/logic.test.mjs`).

Os eventos do próprio honeypot são diferentes, por uma decisão posterior
e explícita: o IP de origem passa a ser guardado numa lista à parte
(nunca misturada com os buckets anónimos acima) e publicado, para
cruzar deteções com um segundo honeypot (Cowrie, numa VPS externa) que
existe precisamente para publicar isto. Só entram IPs públicos e
válidos — gamas privadas, reservadas e de documentação são excluídas
antes de qualquer escrita. As entradas expiram ao fim de 30 dias sem
nova deteção — mais conservador do que a lista irmã da VPS (60–90 dias):
os scanners HTTP que este honeypot apanha têm mais chance de correr em
routers ou câmaras domésticas comprometidas do que os de força bruta
SSH, por isso um IP visto aqui tem mais chance de ser de uma casa real.
Quem se reconhecer numa entrada pode pedir a remoção — o contacto está
na página [Contactos](/contactos/).

## Correlação: honeypot ↔ ATT&CK ↔ threat intel

Cada path-isco está classificado com a técnica MITRE ATT&CK que melhor o
descreve — os mesmos IDs do [heatmap ATT&CK](/attack/). E quando uma dessas
técnicas aparece a ser explorada agora no catálogo CISA KEV, o painel acende a
correlação: o alvejamento automático que este site apanha deixa de ser teórico
e liga-se a um CVE ativo. É a mesma ideia do resto do site — não acredites,
verifica — aplicada a tráfego hostil real.
