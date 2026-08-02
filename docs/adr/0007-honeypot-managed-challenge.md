# ADR 0007 — Paths-isco do honeypot atrás de Managed Challenge: proteção sobre observabilidade total

**Estado:** aceite e em produção (regra 3, WAF da zona `danielmala.co`).

## Contexto

Os cinco paths-isco do honeypot (`/wp-login.php`, `/.env`, `/admin`,
`/phpmyadmin/`, `/.git/config` — `DECOYS` em `dynamic/worker/src/index.js`)
existem para observar scanning hostil: quanto mais tráfego bruto chegar ao
Worker, mais rico é o dataset do painel Threat Intelligence. A opção óbvia
para maximizar esse dataset seria deixá-los completamente abertos — sujeitos
só à política geográfica geral (regras 4/5), como qualquer outro path do
site.

## Decisão

Criar uma regra WAF dedicada (regra 3, avaliada **antes** da política de
país) que aplica `Managed Challenge` aos cinco paths-isco para **qualquer**
visitante, independentemente de país — decisão explícita do dono do repo:
os iscos não ficam abertos ao mundo sem alguma barreira, mesmo sendo apenas
um sensor que devolve 404 indistinguível.

## Consequências

- **Consequência a assumir, não um efeito colateral:** um Managed Challenge
  existe precisamente para filtrar bots automatizados — que é exatamente o
  tráfego que o honeypot existe para observar. Enquanto esta regra estiver
  ativa, o honeypot só regista quem *resolve* o desafio (um browser real com
  JS, nalguns casos scanners avançados com automação tipo-browser), não o
  scanning de massa indiscriminado que domina a Internet.
- Troca deliberada de amplitude de dataset por uma garantia de segurança
  mais simples de justificar ("nenhum visitante chega a um path-isco sem
  barreira nenhuma") do que de maximizar sinal para um painel.
- Ver [`docs/backlog.md`](../backlog.md) para ideias de evolução do
  honeypot que reconsideram este trade-off (proteção vs. observabilidade);
  nenhuma aprovada para implementação até hoje.
