# ADR 0003 — Rate limiting em KV (com falha fechada) como transição para uma regra nativa da Cloudflare

**Estado:** aceite, com uma migração pendente registada como manual.

## Contexto

O Worker implementa rate limiting por-cliente em `dynamic/worker/src/lib/ratelimit.js`:
hash salteado e diário do IP → chave KV `rl:<rota>:<hash>` → janela fixa
(contagem + início de janela). Existe também um **cap global** de escritas do
próprio rate limiter (`RATE_LIMIT_WRITE_CAP`, 300/dia) para não deixar um
único cliente dentro do limite por rota esgotar sozinho o teto de ~1.000
escritas/dia da conta inteira no plano Free.

KV é eventualmente consistente (~60s de propagação global). Isto é aceitável
para os contadores agregados do honeypot/CSP/vitals (não precisam de exatidão
ao pedido), mas é uma base estruturalmente errada para um rate limiter: pedidos
concorrentes em colos diferentes podem ler contagens desatualizadas.

**Achado de uma revisão de segurança (2026-07-29,
[docs/security-review-2026-07-29.md](../security-review-2026-07-29.md),
achado A1):** quando o cap global de escritas (300/dia) se esgotava,
`rateLimit()` continuava a devolver `allowed: true` — só deixava de persistir
o estado por-cliente. Isso congelava a janela desse cliente indefinidamente:
~300 pedidos triviais (10 minutos de tráfego num único IP em `/api/mirror` ou
`/api/vitals`, sem precisar de distribuir por origens) desligavam o rate
limit da rota inteira até à meia-noite UTC.

## Decisão

**Curto prazo (feito, 2026-07-29):** `rateLimit()` passa a falhar **fechado**
quando o cap global se esgota — a rota devolve 429 a todos os clientes até o
orçamento reabrir, sem gastar nenhuma escrita extra (o 429 continua "grátis",
como já acontecia para o rate limit por-cliente). Troca-se "toda a gente passa"
por "toda a gente espera", que é o lado seguro deste trade-off.

**Médio prazo (pendente, decisão manual do dono do repo):** substituir o rate
limiting por uma [regra nativa de Rate Limiting da
Cloudflare](https://developers.cloudflare.com/waf/rate-limiting-rules/) (WAF,
disponível no plano Free). Vantagens sobre a implementação atual:

- Aplica-se **antes** do Worker correr — zero CPU, zero escritas KV.
- Não depende de consistência eventual — o WAF impõe o limite corretamente.
- Elimina `ratelimit.js`, o espaço de chaves `rl:`/`rlcap:` e ~300
  escritas/dia do orçamento do KV, que passam a estar disponíveis para
  honeypot/CSP/vitals/firewall.

Não foi feito nesta ronda porque é uma alteração de configuração na dashboard
da Cloudflare (fora do que um PR de código consegue expressar) — ver
`docs/security-review-2026-07-29.md` §9 para o desenho da regra.

## Consequências

- Enquanto a migração para a regra nativa não acontece, a falha fechada é a
  rede de segurança: mesmo sob abuso deliberado do cap global, o pior cenário
  passa a ser "as rotas com input de visitante ficam indisponíveis até à meia-
  noite UTC", nunca "o rate limit desliga-se silenciosamente".
- As leituras públicas sem rate limit (`/api/honeypot`, `/api/map`,
  `/api/ticker`, `/api/ct`, `/api/cf-stats` sem `?refresh=1`) não são afetadas
  — continuam servidas da cache independentemente do estado deste cap.
- Teste de regressão em `dynamic/worker/test/logic.test.mjs` (`rate limit: cap
  global diário no teto falha fechado…`) fixa este comportamento; qualquer
  alteração futura que o reverta falha os testes.
