---
title: 'Honeypot'
description: 'Endpoints-isco que registam o scan automático da Internet — só metadados, sem IPs, correlacionados com MITRE ATT&CK e CISA KEV.'
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

## Privacidade por construção

**Nenhum IP é armazenado.** Cada evento guarda só país (`cf-ipcountry`), ASN e
o path-isco, com o timestamp arredondado a 5 minutos — e o arredondamento é
anonimização: sem o instante preciso não dá para cruzar ASN+path+tempo com
logs de terceiros. A única coisa derivada do IP é a chave de rate limit, um
SHA-256 truncado com salt que roda, guardado só durante a janela do limite e
nunca ligado aos eventos. Isto não é uma promessa: está coberto por teste
(`test/logic.test.mjs` garante que o IP nunca aparece no KV nem nos logs).

## Correlação: honeypot ↔ ATT&CK ↔ threat intel

Cada path-isco está classificado com a técnica MITRE ATT&CK que melhor o
descreve — os mesmos IDs do [heatmap ATT&CK](/attack/). E quando uma dessas
técnicas aparece a ser explorada agora no catálogo CISA KEV, o painel acende a
correlação: o alvejamento automático que este site apanha deixa de ser teórico
e liga-se a um CVE ativo. É a mesma ideia do resto do site — não acredites,
verifica — aplicada a tráfego hostil real.
