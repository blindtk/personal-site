# ADR 0004 — Zero-PII no honeypot e nos analytics, por escolha, não por limitação do plano

**Estado:** aceite e em produção.

## Contexto

O honeypot (`dynamic/worker/src/index.js`, `recordHoneypot`) e o painel
"Estado da Cloudflare" (`cf-analytics.js`) precisam de agregar tráfego hostil
por país/ASN/técnica/path para os dashboards de Threat Intelligence terem
algum conteúdo. A tentação óbvia seria guardar o IP — é o campo mais útil para
correlacionar ataques.

## Decisão

**Nunca guardar o IP**, em lado nenhum:

- `recordHoneypot` nunca lê `cf-connecting-ip` — só o `lib/ratelimit.js` o vê,
  e mesmo aí só como hash truncado e salteado (`clientHash`), com o salt a
  rodar automaticamente todos os dias (impossível reidentificar o mesmo IP
  entre dias a partir da chave de rate limit).
- O timestamp de cada evento do honeypot é arredondado a uma janela de 5 min
  (`floorToWindow`) — impede correlação por instante preciso com logs de
  terceiros.
- No dataset cru de firewall da Cloudflare (`firewallEventsAdaptive`), o
  campo `clientIP` **está disponível** — é literalmente o que provou, numa
  correção documentada em `dynamic/PLAN.md`, que o texto antigo do painel
  estava errado ao dizer que certos detalhes exigiam um dataset Pro+. Mesmo
  disponível, `clientIP` nunca é pedido nem processado.

Ou seja: zero-PII aqui não é "o plano Free não deixa" — é uma escolha
deliberada, feita mesmo quando o dado estava ao alcance da mão.

## Consequências

- O honeypot não consegue distinguir dois eventos do mesmo atacante entre
  dias, nem correlacionar IP com outras fontes — trade-off aceite: o objetivo
  é mostrar *padrões* de ataque (país, ASN, técnica, path, hora do dia), não
  construir um dossier por atacante.
- Reforça a postura de privacidade do site: nenhum visitante — hostil ou
  legítimo — tem o IP persistido em lado nenhum do Worker.
- Risco residual aceite (ver `docs/security-review-2026-07-29.md`, achado
  A2): sem um identificador estável por atacante, um adversário pode encher o
  orçamento diário de escritas do honeypot com pedidos triviais e enviesar o
  dashboard público. Mitigação futura possível (sub-cap por ASN) fica
  registada como *nice-to-have*, não implementada — o custo de a fazer bem
  (sem reintroduzir um proxy para IP) não se justificou ainda.
