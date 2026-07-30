# Prompt — validar se o site está pronto para ir público (Fase 3 do lançamento)

Prompt de execução para dar a um agente. Objetivo: **validar**, não
executar — confirmar se está tudo pronto para desligar/ajustar a Cloudflare
Access e deixar `danielmala.co` acessível a qualquer visitante. A troca em
si (dashboard da Cloudflare) continua a ser só do dono, tal como no
[`prompt-repo-publico.md`](prompt-repo-publico.md).

**Porque isto importa mais do que parece:** o repositório já pode estar
público, mas o site **ainda não carrega para ninguém** — está atrás da
Cloudflare Access desde o início do desenvolvimento (`docs/cloudflare-deploy.md`
§3). Um repo público a apontar para um site inacessível é meio portefólio.
Ver `docs/public-repo-decision.md` §9: lançar o site vem primeiro.

Contexto de partida a ler antes de tocar em nada:
[`docs/cloudflare-deploy.md`](cloudflare-deploy.md) (especialmente §3 Access,
§5 WAF, §7 checklist), [`docs/dns-tls.md`](dns-tls.md),
[`docs/threat-model.md`](threat-model.md), [`dynamic/PLAN.md`](../dynamic/PLAN.md)
e o relatório mais recente de preparação para público,
[`relatorio-preparacao-repo-publico-2026-07-30.md`](relatorio-preparacao-repo-publico-2026-07-30.md)
(secção 5, checklist "só o dono pode fazer" — este prompt valida os itens
"No flip" e "Antes do flip" ligados ao lançamento, não à publicação do
repo).

Copia o bloco abaixo como pedido ao agente.

---

## Prompt

> **Tarefa:** validar se está tudo pronto para desligar/ajustar a
> Cloudflare Access e lançar `danielmala.co` a sério. **Não desligues nada,
> não mexas no dashboard da Cloudflare** — isso é só do dono. A tua entrega é
> um relatório com veredicto e lista exata de bloqueadores, se houver.
>
> ### Regras de trabalho
>
> 1. **Verifica antes de acreditar.** Os documentos em `docs/` podem estar
>    desatualizados — confirma cada afirmação no código/config antes de a
>    repetir no relatório.
> 2. **Não executes ações de dashboard/conta** (desligar Access, mudar
>    regras WAF, ativar DNSSEC, submeter HSTS preload, rodar segredos). Isso
>    fica na checklist final, para o dono executar.
> 3. **Não decidas sozinho** sobre nada que exija informação que só o dono
>    tem (ex.: se o diagnóstico de uma flag temporária já concluiu). Pergunta
>    ou regista como bloqueador.
> 4. Corre `cd static && npm run build` (sem erros nem warnings novos) e
>    `npm test` nos dois projetos (`static`, `dynamic/worker`) antes de
>    fechar o relatório.
>
> ---
>
> ### Fase 1 — Pressupostos de segurança que assumem a Access ligada
>
> Vários pontos do repositório foram aceites *porque* a Access ainda bloqueia
> produção. Desligar a Access invalida essas premissas — cada uma tem de ser
> reconfirmada, não só assumida como "já tratada":
>
> 1. **`DEBUG_EXPOSE_SELF_PATH`** (`dynamic/worker/src/lib/csp-report.js`,
>    ~linha 132). O risco aceite de a ligar (expõe o pathname nas violações
>    CSP `self/self`) assentava em "produção continua atrás de Cloudflare
>    Access" (`dynamic/PLAN.md`). Confirma o estado atual da flag e do
>    diagnóstico. **Se a flag ainda estiver `true` e o diagnóstico não tiver
>    concluído, isto é um bloqueador do lançamento** — pergunta ao dono se
>    quer lançar mesmo assim (risco muda de "mínimo" para "real") ou reverter
>    primeiro.
> 2. **`.github/expected-headers.json`** — `url` está em `SET-ME` de
>    propósito enquanto a Access bloqueia o cron `headers.yml`. Confirma que
>    o ficheiro e o `check-headers.mjs` estão prontos a "ligar" assim que o
>    dono preencher o `url` (não precisas de o preencher tu — é passo do
>    dono, depois da Access desligar). Testa a lógica de deteção do `SET-ME`
>    (`.github/scripts/check-headers.mjs`) para confirmar que continua a
>    degradar com aviso, não com falha silenciosa.
> 3. **`.github/scripts/check-invariants.mjs`** — mesmo padrão `SET-ME`. Confirma
>    que o workflow `invariants.yml` está pronto para passar a verificar
>    produção real assim que houver um `url` válido.
> 4. **Regras WAF (`docs/cloudflare-deploy.md` §5)** — a proteção real depois
>    da Access sair passa a ser: bots verificados (skip), CI headers-check
>    (skip), paths-isco → Managed Challenge, só PT → Managed Challenge, resto
>    do mundo → Block. Isto **não é verificável a partir do código** — é
>    configuração da zona Cloudflare. Regista como item a **confirmar no
>    dashboard pelo dono** antes do flip: que as 5 regras existem, por esta
>    ordem exata, e que nenhuma ficou desativada ou alterada desde
>    2026-07-29.
> 5. Procura no repositório por outras menções a "atrás da Access", "enquanto
>    a Access bloquear", "Access ainda ativa" ou equivalente
>    (`dynamic/PLAN.md`, `docs/*.md`) — qualquer risco aceite com essa
>    premissa como mitigação principal é um candidato a bloqueador. Lista-os
>    todos, não só os 3 acima.
>
> ### Fase 2 — Checklist de lançamento por fechar (`docs/cloudflare-deploy.md` §7, `docs/dns-tls.md`)
>
> Para cada item marcado `[ ]` nesses dois ficheiros: confirma se já foi
> feito (às vezes fica por marcar mesmo depois de resolvido — verifica no
> código/config, não só no texto) ou se continua genuinamente pendente.
> Classifica cada um como (a) trabalho de repositório ainda por fazer, ou (b)
> ação de dashboard/conta que só o dono confirma. Não tentes fazer nenhum
> item (b).
>
> ### Fase 3 — O que o agente consegue verificar de fora
>
> Se tiveres acesso à rede, tenta (sem autenticação, sem tentar contornar a
> Access):
>
> - `dig CAA danielmala.co` e compara com os registos documentados em
>   `docs/dns-tls.md`.
> - `dig DNSSEC`/`dig +dnssec danielmala.co` — confirma se já está assinado.
> - Um pedido HTTP simples a `https://danielmala.co/` — hoje deve devolver a
>   página de login da Access, não o site; confirma que é isso que acontece
>   (se devolver o site diretamente, a Access pode já não estar a bloquear, o
>   que muda tudo o resto deste relatório — sinaliza isso com destaque).
> - Se conseguires alcançar produção sem Access (pouco provável hoje),
>   verifica os headers de segurança contra `.github/expected-headers.json`.
>
> Se não tiveres rede ou os pedidos falharem, di-lo explicitamente — não
> presumas nenhum destes pontos.
>
> ### Fase 4 — Relatório
>
> Entrega:
> 1. Lista de bloqueadores reais (Fase 1), com `ficheiro:linha`.
> 2. Checklist reconciliada da Fase 2, dividida em "trabalho de repositório
>    por fazer" (nenhum esperado, mas confirma) vs. "só o dono, no
>    dashboard".
> 3. O que foi possível confirmar de fora (Fase 3) e o que não foi.
> 4. **Veredicto:** pronto para desligar/ajustar a Access? Sim ou não, com a
>    lista exata do que falta se for não.

---

## Depois do flip (opcional, prompt separado se quiseres)

Depois de a Access ser desligada, vale a pena um segundo prompt curto, só de
fumo: confirmar que `headers.yml` e `invariants.yml` passam a verificar
produção real (não só `SET-ME` no-op), que o self-scan (`/api/scan`) e o
ticker continuam a responder sob tráfego real, e que as regras WAF da
secção 5 de `docs/cloudflare-deploy.md` produzem o comportamento esperado
para um visitante fora de PT (deve ver `Block`, não o site). Isso já não é
"validar se está pronto" — é confirmar que o flip correu bem.
