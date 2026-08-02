# ADR 0005 — Relato de violações CSP: manual em vez de automático

**Estado:** aceite e em produção.

## Contexto

A CSP tinha `report-uri /api/csp-report` + `report-to csp-endpoint`
(cabeçalho `Reporting-Endpoints`): o browser mandava um POST a
`/api/csp-report` a cada violação de **qualquer** visitante, sem exceção —
o desenho standard para deteção automática de regressões.

Na prática, sem inline nenhum no site (ver [ADR 0001](0001-csp-sem-inline.md)),
uma violação de `script-src`/`style-src` só podia significar uma de duas
coisas: regressão da build ou injeção real. Mas a esmagadora maioria dos
relatórios era ruído de extensões de browser (ad-blockers, gestores de
password) a injetar conteúdo nas páginas de visitantes — e cada POST aceite
custa escritas no KV do Worker (rate-limit + bucket + cap, ~3 writes/POST),
partilhadas com honeypot/vitals/cron no mesmo teto diário apertado do plano
Free (~1.000 escritas/dia para a conta inteira). O volume de ruído
automático empurrou a conta para perto desse teto — motivado por um alerta
real da Cloudflare, "50% of your daily Workers KV operation limit reached".

## Decisão

Remover `report-uri`, `report-to` e o cabeçalho `Reporting-Endpoints`.
Substituir por captura 100% local: `static/public/js/csp-report.js` — o
primeiro recurso de `<head>`, sem `defer` de propósito, para ligar o
listener `securitypolicyviolation` antes de qualquer script/link que pudesse
violar a CSP e não perder o sinal de regressão da própria build — guarda em
`sessionStorage` (dedup por diretiva+origem, teto de 20). Nada sai daí sem
um clique: `CspViolations.astro` (página Provas) lê a fila e manda um botão
"Reportar" que envia tudo num único POST no formato batch
`application/reports+json`, já suportado por `parseReports()` — zero
mudança no recetor do Worker além dos comentários.

## Consequências

- Zero escritas no KV até alguém decidir mesmo reportar, em vez de uma
  escrita por violação de qualquer visitante.
- **Trade-off aceite conscientemente:** perde-se a deteção automática de
  regressões reais em produção — só se sabe se alguém (tipicamente o
  próprio dono, a testar após um deploy) visitar a página Provas e clicar.
- Revisitar se o teto do KV deixar de ser problema (upgrade de plano, ou
  amostragem em vez de corte total) — ver `dynamic/PLAN.md`.
