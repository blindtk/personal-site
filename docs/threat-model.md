# Modelo de ameaça

Documento vivo — rever a cada trimestre ou sempre que uma decisão de
arquitetura relevante for tomada (registar a data da revisão no fundo deste
ficheiro). Origem: análise inicial em
[`docs/security-review-2026-07-29.md`](security-review-2026-07-29.md) §8.

## Ativos

1. **A conta Cloudflare** — de longe o de maior valor; um comprometimento dá
   controlo de DNS, emissão de certificados e interceção de tráfego para o
   domínio.
2. **O repositório GitHub e os seus secrets de Actions.**
3. **Reputação/integridade do domínio e do conteúdo publicado.**
4. **Privacidade dos visitantes** — o site promete zero-PII explicitamente
   (ver [ADR 0004](adr/0004-zero-pii-honeypot.md)); é um ativo reputacional
   quebrável.
5. **Orçamento das quotas do plano Free** (escritas KV/dia, invocações do
   Worker) — invulgarmente, um *orçamento* é um ativo aqui: esgotá-lo
   degrada proteções reais (ver Ataque A1 abaixo).
6. **As próprias alegações de segurança do site** — um site que documenta os
   seus controlos sofre dano reputacional maior se um deles se provar falso.

## Fronteiras de confiança

Internet → borda Cloudflare (WAF/Access) → Worker → KV/APIs a montante.
Laptop do developer → GitHub → Cloudflare Workers Builds (deploy automático,
sem proveniência verificável nem gate de revisor — *lacuna real, ver H3*) →
produção (ver `docs/architecture.md`). Registo npm → lockfile → build →
artefacto deployado. Feeds a montante (NVD, CISA KEV, crt.sh, HIBP) → Worker →
DOM do browser. Browser → endpoints POST → KV.

## Superfícies de ataque

12 endpoints GET (a maioria sem input); 2 endpoints POST não-autenticados
(`/api/csp-report`, `/api/vitals`); 5 rotas-isco; o site estático; as
ferramentas client-side (todas locais exceto `pwned`, `self-scan`, `mirror`);
a cadeia de supply-chain do GitHub Actions; a árvore de dependências npm; as
credenciais da dashboard/API da Cloudflare.

## Ataques mais prováveis

### A1 — Desativação do rate limit por esgotamento do orçamento de escrita
**Estado: corrigido em 2026-07-29** (ver [ADR 0003](adr/0003-rate-limit-kv-vs-nativo.md)).
Achado original: com o cap global de escritas (300/dia) esgotado,
`rateLimit()` continuava a devolver `allowed: true` sem persistir estado —
~300 pedidos triviais desligavam o rate limit da rota inteira até à meia-noite
UTC. Corrigido para falhar fechado; migração para uma regra nativa de Rate
Limiting da Cloudflare continua pendente (decisão manual, dashboard).

### A2 — Envenenamento do dashboard do honeypot
**Estado: risco residual aceite.** O cap de 60 eventos/dia do honeypot
significa que um atacante consegue encher o orçamento do dia com pedidos
triviais a partir de um ASN escolhido, fazendo o dashboard de Threat
Intelligence mostrar dados escolhidos pelo atacante e escondendo scanning
genuíno. Impacto baixo (nenhum controlo de segurança depende deste dado);
mitigação possível (sub-cap por ASN) fica registada como *nice-to-have*.

### A3 — Envenenamento de métricas (Vitals/CSP)
**Estado: risco residual aceite por necessidade.** Ambos os endpoints POST
são não-autenticados por natureza (é o que os torna úteis). Um atacante pode
submeter valores de LCP/CLS fabricados ou violações CSP falsas dentro dos
caps. Impacto cosmético/reputacional — mitigação: ser explícito na página de
que são beacons first-party não-autenticados.

### A4 — Compromisso de dependências via npm
**Estado: mitigado em profundidade.** `minimumReleaseAge: 3 dias`,
OSV-Scanner, `npm audit`, `npm audit signatures` (verifica assinaturas de
registo), `npm ci --ignore-scripts` (nenhum postinstall arbitrário corre em
CI). Risco residual: um pacote comprometido só com scripts *necessários*
para funcionar (nenhum caso conhecido neste repo hoje).

## Ataques de maior impacto

### B1 — Comprometimento da conta Cloudflare
Catastrófico e sem mitigação técnica possível a partir deste repositório —
controlo de DNS implica emissão de certificados e interceção total de
tráfego. **Controlos a confirmar fora do código:** MFA por chave de hardware
na conta Cloudflare, tokens de API com escopo mínimo e rotação, revisão do
audit log da conta. É o risco de maior impacto e o menos discutido no
repositório — merece confirmação explícita, não assumida.

### B2 — Comprometimento da conta/Actions do GitHub
Bem mitigado para o *pipeline* (pins por SHA, `permissions: {}`,
`persist-credentials: false`, zizmor). Risco residual: MFA a nível de conta;
uma vez fechado o achado H3 (deploy via CI), o token de deploy passa a ser um
novo secret de alto valor que tem de viver num Environment protegido.

### B3 — Comprometimento do laptop do developer
O caminho normal para produção do Worker é automático (Workers Builds, no
push a `main` — ver `docs/architecture.md`), não o laptop. Mas continua a
existir um caminho manual secundário (`npx wrangler deploy` a partir do
laptop, usado para testar uma branch antes do merge, `CLAUDE.md`) que aponta
para o mesmo Worker de produção — um laptop comprometido continua a poder
publicar diretamente, sem passar pelo GitHub. Ver o achado H3 em
`docs/security-review-2026-07-29.md`: a lacuna real não é "deploy manual",
é a ausência de proveniência verificável e de um gate de revisor em
qualquer um dos dois caminhos.

## Casos de abuso

- **Esgotamento de quota** (A1) é o dominante.
- `/api/pwned-range` como proxy do HIBP: contido — `normalizePrefix` restringe
  a input a exatamente 5 hex, rate limit aplica-se, resultados em cache 24h.
- `/api/scan` apontado a terceiros: impossível — `SCAN_TARGET` é uma var fixa;
  `fetchSameOrigin` impede fuga de credenciais mesmo que isso mude.

## Riscos de supply-chain

Pacotes `p/*` do Semgrep não pináveis (documentado, mitigado por regras
locais + retry). Scripts de lifecycle do npm (mitigado: `--ignore-scripts` em
CI). **Sem proveniência entre CI e produção no Worker** — a maior lacuna
(achado H3).

## Riscos GitHub

Repositório privado: sem secret scanning/push protection nativos (gitleaks é
o único controlo de secrets); pressão de quota de Actions pode estar a
descartar execuções silenciosamente. Proteção de branch por confirmar.

## Riscos Cloudflare

Esgotamento de quota do plano Free como vetor de negação de serviço às
proteções (A1). Consistência eventual do KV a prejudicar lógica de segurança
(mitigado parcialmente pela falha fechada). Sem Logpush — reconstrução de
incidentes depende da janela de retenção da Observability.

## Riscos residuais aceites explicitamente

Envenenamento de dashboards públicos (A2/A3) — inevitável sem autenticação,
que custaria mais do que traria. Limites de fidelidade dos painéis de
firewall no plano Free. Disponibilidade do crt.sh como fonte única do vigia
CT. Zero-day no Astro ou no workerd. Cloudflare como ponto único de falha —
aceite deliberadamente, decisão correta para um site pessoal.

---

**Última revisão:** 2026-07-29 (criação deste documento, a partir da revisão
de segurança do mesmo dia). **2026-07-30:** corrigidas contagens de
superfície de ataque (12 endpoints GET, não 11; 5 rotas-isco, não 6) e a
descrição do deploy do Worker (é automático via Cloudflare Workers Builds,
não manual — o achado H3 continua aberto pela falta de proveniência/gate de
revisor, não pela falta de automação), no âmbito da preparação do
repositório para público.
