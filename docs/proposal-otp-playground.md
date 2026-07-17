# Proposta: OTP Playground — TOTP/HOTP por dentro

> **Estado: proposta por aprovar** (decisão do dono do repo pendente — ver
> regra em `CLAUDE.md`/`dynamic/PLAN.md`). Sem código ainda; este documento
> é a fundamentação.

## 1. O que é

Uma ferramenta client-side em `/ferramentas/` que gera códigos **TOTP/HOTP**
(RFC 6238 / RFC 4226) e — este é o produto — **disseca cada passo do
algoritmo** numa vista de log de terminal:

1. segredo base32 → bytes da chave (RFC 4648);
2. contador temporal `T = floor(unix / período)` mostrado em hex big-endian,
   com o timestamp Unix usado à vista;
3. HMAC(chave, contador) completo, em hex;
4. truncamento dinâmico: o último nibble escolhe o offset, os 4 bytes
   selecionados ficam destacados no HMAC;
5. `mod 10^dígitos` → o código final.

À volta disso, o essencial de uma ferramenta útil a sério:

- código atual com barra de contagem decrescente até ao próximo período;
- códigos da janela anterior e seguinte (é assim que se explica visualmente
  a tolerância a desvio de relógio dos servidores);
- parâmetros configuráveis: dígitos (6/8), período (30/60 s), algoritmo
  (SHA-1/SHA-256/SHA-512);
- parse de URIs `otpauth://` (colar o URI de provisioning e ver tudo
  preenchido).

**Porque encaixa neste site:** 2FA por TOTP é omnipresente e completamente
opaco para quase toda a gente — "números mágicos que mudam de 30 em 30
segundos". O site ainda não toca em autenticação (as ferramentas atuais
cobrem hashing, encoding, redes, passwords, headers). E segue à letra a
filosofia já registada no `PLAN.md` a propósito do pwned-check: *a UI que
torna o protocolo visível é o produto, não o resultado*. Tem também uso
prático real: depurar enrolments de 2FA, confirmar que um segredo gera os
códigos esperados, diagnosticar dessincronização de relógio.

## 2. Onde vive

**`static/`, 100% client-side** — cumpre o contrato do índice
`/ferramentas/` sem exceções:

- HMAC via WebCrypto (`crypto.subtle.importKey` + `sign`), nativo no browser
  e em Node ≥ 20 (`globalThis.crypto`) — zero dependências, zero rede.
- Lógica pura em `static/src/scripts/otp.js`: decode base32, construção do
  contador, truncamento dinâmico, parse de `otpauth://`. Tudo testável com
  `node --test`.
- `static/src/components/tools/OtpTool.astro` faz só a ligação ao DOM,
  como as ferramentas existentes.
- Páginas finas PT/EN + par em `routes.ts` + strings em `ui.ts`, como manda
  o `CLAUDE.md`.

Não há razão nenhuma para envolver o Worker: seria pior (segredos a
atravessar a rede) e não acrescenta nada.

## 3. Riscos e coisas a validar

- **Utilizadores colarem segredos TOTP reais.** É o risco principal e é
  inerente à ferramenta. Mitigações:
  - tudo local, verificável: a página não faz um único `fetch`;
  - **nada persistido** — sem `localStorage`, e o segredo **nunca** entra em
    query strings (não aceitar `?secret=` — ficaria em históricos e logs de
    proxies), só input direto;
  - o estado inicial é um **segredo demo gerado localmente**, não um campo
    vazio a pedir o segredo real do utilizador;
  - aviso visível no estilo âmbar do Lab + `autocomplete="off"`.
- **Falsa confiança por implementação errada.** Um gerador TOTP errado é
  pior que nenhum. Mitigação: vetores oficiais nos testes — RFC 4226
  Apêndice D (HOTP) e RFC 6238 Apêndice B (TOTP com SHA-1/256/512) — na
  linha do que o repo já faz com MD5/RFC 1321. Validação final contra uma
  app autenticadora real.
- **Relógio local errado → códigos divergentes.** Sem rede não há correção
  possível (e não a queremos). Mitigar mostrando o timestamp Unix e o `T`
  usados, mais uma nota sobre dependência do relógio local — a transparência
  já é a ferramenta de diagnóstico.
- **Vetor de abuso do site:** nenhum. Sem backend, sem estado, sem rede —
  não há proxy, DoS nem fuga de dados possíveis a partir desta página.
- **Fase 2 (adiada de propósito):** gerar QR `otpauth://` localmente. É
  seguro (local), mas incentiva a manusear segredos reais na página; só com
  decisão explícita.

## 4. Esforço e passos

**Pequeno-médio** (~1–2 dias):

1. `static/src/scripts/otp.js` — base32, contador, HMAC (WebCrypto),
   truncamento; testes `node --test` com os vetores das RFCs.
2. Parse de `otpauth://` no mesmo módulo, também com testes.
3. `OtpTool.astro` — countdown, dissecação passo-a-passo, janelas ±1,
   estados de erro (base32 inválido, parâmetros fora de alcance).
4. Páginas PT/EN + `routes.ts` + `ui.ts` + entrada no índice de ferramentas.
5. `cd static && npm run build` limpo + validação manual contra um
   autenticador real.

## Alternativas consideradas (e porquê não)

- **Pipeline CSP / pwned-check:** eram os candidatos óbvios — já existem ou
  já estão aprovados no `PLAN.md`.
- **Inspetor de JWT:** útil mas comoditizado (jwt.io) e conceptualmente
  sobreposto ao encoder (base64url); pior perfil de risco — colar um token
  de produção é colar uma credencial bearer *viva*.
- **Monitor de Certificate Transparency do próprio domínio** (canário de
  certificados inesperados via crt.sh + cron do Worker): boa ideia
  defensiva, mas roça o item "verificação de certificados TLS" do roadmap e
  acrescenta dependência de um serviço externo instável. Fica como candidato
  futuro.
- **Dissecador de URLs de phishing** (punycode/homóglifos, truques de
  `user@host`): segunda escolha sólida, também client-side; perdeu porque o
  OTP tem vetores de teste oficiais e liga melhor à estética
  "protocolo visível".
