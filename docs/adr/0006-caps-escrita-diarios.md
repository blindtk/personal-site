# ADR 0006 — Caps de escrita do Worker: por dia e dimensionados ao orçamento, não à resistência a abuso

**Estado:** aceite e em produção.

## Contexto

`HONEYPOT_WRITE_CAP`, `CSP_WRITE_CAP` e `VITALS_WRITE_CAP` existiam desde o
início como travão anti-abuso — por hora, com valores "generosos para
tráfego legítimo de scanners" (500/h, 300/h, 5000/h respetivamente) — mas
desenhados sem qualquer relação com o teto real do plano Free: ~1.000
escritas/dia para a **conta inteira**, partilhado entre honeypot, CSP,
vitals, rate-limit e cron.

Ao ser questionado diretamente ("no futuro, quando ficar público, as APIs
estão bem protegidas? o honeypot não vai consumir tudo?"), a resposta
honesta era **não**: nos piores casos, honeypot 500×5=2.500 escritas numa
única hora (2,5× o orçamento diário inteiro); vitals 5.000×2=10.000/hora
(10×). Ou seja, mesmo sem qualquer ataque, tráfego orgânico normal do dia
de lançamento (RUM a disparar em cada page-load real) já podia esgotar a
quota do dia sozinho.

## Decisão

1. Os três caps passam de janela por **hora** para janela por **dia**
   (`windowMs: DAY_MS`), com as `capKey` recalculadas por dia (`wcap:d:…`,
   `cspcap:d:…`, `vitcap:d:…`).
2. Valores muito mais baixos, dimensionados ao orçamento da conta e não ao
   "quanto um scanner pode gerar": honeypot 60/dia, CSP 50/dia, vitals
   150/dia — juntos ~640/dia (contando múltiplas escritas por evento),
   deixando folga para o cron (~45/dia) e o rate-limit.
3. `recordHoneypot` deixa de reescrever a chave `meta` em todos os eventos —
   `deployTs`/`firstScanTs`, uma vez definidos, nunca voltam a mudar, por
   isso a escrita só acontece na primeira vez.

## Consequências

- **Trade-off consciente:** sob scanning pesado sustentado ou tráfego real
  elevado, eventos a mais no mesmo dia são descartados silenciosamente (o
  404/204 continua a sair, indistinguível) — perde-se granularidade no
  Threat Intel/RUM, nunca o core do site.
- Não resolve tudo: continua a não haver um orçamento partilhado entre as
  três chaves — é teoricamente possível esgotar o dia com
  honeypot+CSP+vitals em simultâneo, cada um dentro do seu próprio cap. Um
  "disjuntor" diário único e partilhado entre todas as escritas do Worker
  fica registado como ideia para depois, não implementado por falta de
  urgência comprovada — ver `dynamic/PLAN.md`.
- Teste de regressão em `dynamic/worker/test/logic.test.mjs` fixa a janela
  e as chaves por dia.
