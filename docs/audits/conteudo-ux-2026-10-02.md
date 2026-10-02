# Auditoria de conteúdo e UX/UI — 2026-10-02

Executada com [`docs/prompts/prompt-conteudo-e-ux.md`](../prompts/prompt-conteudo-e-ux.md)
(fases 1 e 2). **Nada foi alterado no site** — isto é o relatório e o plano,
à espera de aprovação.

**Método.** `npm run build` (limpo, 0 warnings) + `astro preview`; 21
páginas PT/EN percorridas em Chromium a 390px e 1440px com capturas de
ecrã; `axe-core` (WCAG 2.2 AA + best-practice) em todas; Lighthouse mobile
na Home, Sobre e Este site; medição de contraste dos tokens de `:root`;
leitura de `content/`, `ui.ts` e `config.ts`.

**Limite.** Localmente não há Worker: os painéis ao vivo (Este site,
Honeypot, Cloudflare, Performance, Provas) aparecem no estado "sem dados".
Os achados sobre esses estados (U7) descrevem o que um visitante vê **quando
o Worker falha**, não o funcionamento normal em produção.

---

## Resumo executivo

O site está tecnicamente sólido — Lighthouse **100** em performance, SEO e
best-practices; páginas de 23–31 KiB; CLS 0. O que custa ao visitante não é
velocidade, é polimento e clareza:

1. **Títulos colados à nav em todas as páginas interiores** — bug de CSS:
   `.container` anula o padding vertical do `<main>` (U1).
2. **Telemóvel perde informação na Home**: as descrições dos projetos e
   ferramentas ficam reduzidas a ~15 caracteres + "…", e o percurso é um
   carrossel horizontal cortado (U4, U5).
3. **Contraste e links**: `--faint` (3,2:1) é usado como cor de texto em
   vários sítios; os links dentro de parágrafos só se distinguem pela cor
   (axe *serious* em 10 páginas) (U2, U3).
4. **A Home não tem chamada à ação** — quem chega (recrutador) não tem um
   "fala comigo" nem um caminho sugerido (C1).
5. **Meta description igual em 30 das 58 páginas** — ferramentas e projetos têm
   descrição própria; partilhas e resultados de pesquisa ficam todos iguais
   (C4).

---

## Achados — UX/UI

Impacto × esforço: **A**lto / **M**édio / **B**aixo.

| # | Onde | Problema | Correção proposta | Imp. | Esf. |
|---|---|---|---|---|---|
| U1 | `global.css:123` vs `:416` | `.container { padding: 0 1.1rem }` (especificidade 0,1,0) ganha a `main { padding: 2.2rem 0 4rem }`. O `h1` começa exatamente onde a nav acaba (medido: 55px/55px) e o conteúdo encosta ao rodapé. Afeta **todas** as páginas com `.page-head`. | Usar `padding-block` num seletor que não colida (ex.: `main.container { padding-block: 2.2rem 4rem }`). | A | B |
| U2 | `--faint #586475` | 3,24:1 sobre `--bg`, 2,84:1 sobre `--bg-raise-2` — abaixo de 4,5:1. axe falha em `.atk-hint` (ATT&CK, Home), `.chain-src` (Este site), eixos do heatmap (Honeypot), `.lab-hint` e relógio (Lab). | Regra: `--faint` só para decoração (`//`, bordas, setas); texto legível passa a `--muted` (6,2:1). Corrigir os 5 seletores sinalizados. | A | B |
| U3 | prosa em 10 páginas (Home, Sobre, projeto Este site, Este site, Honeypot, Provas, Contactos, Links…) | Links dentro de parágrafos só por cor (`a { text-decoration: none }`) — axe `link-in-text-block` *serious*. | Sublinhado subtil nos links de prosa (`p a`, `.note a`, `td a`, markdown): `text-decoration-color` com `--accent-dim` e `text-underline-offset`. Nav, cartões e listas ficam como estão. | A | B |
| U4 | Home 390px — `.mini-list .desc` (`global.css:551`) | `white-space: nowrap` + ellipsis: "Monorepo com site estático …", "Gera e verifica MD5, SHA-1, SH…". Em telemóvel a descrição não diz nada. | Abaixo de ~600px empilhar título e descrição e permitir 2 linhas (`-webkit-line-clamp: 2`). | A | B |
| U5 | Home — percurso `#journey-scroll` | Em 390px é um carrossel horizontal com texto cortado ("Redes em ferrovi…"), e axe *serious* `scrollable-region-focusable` (não é alcançável por teclado). | Mobile: timeline vertical (sem scroll horizontal). Desktop fica igual. Se ficar scroll em algum breakpoint, `tabindex="0"` + `aria-label`. | A | M |
| U6 | Sobre 390px | Overflow horizontal de 62px na página inteira (tabela "Referenciais aplicados", 3 colunas). | Envolver em `.table-scroll` (já existe) ou empilhar linhas em mobile. | M | B |
| U7 | Este site, Honeypot, Cloudflare, Performance | Com o Worker indisponível, os painéis mostram "—" e caixas vazias ("Países", "Redes (ASN)") sem explicação; o estado "Degradado/Indisponível" só aparece num cartão lá em baixo. | Estado vazio/erro explícito dentro de cada widget ("Sem dados — o Worker não respondeu; o resto do site não depende dele") com estilo único, partilhado via `Widget.astro`. | M | M |
| U8 | `/attack/` 390px | 14 táticas num scroll horizontal; só se vêem 1,5 colunas; "passa o rato (ou foca)" não serve em toque. | Mobile: táticas empilhadas em `<details>` (contagem no `summary`); copy de ajuda conforme o dispositivo. | M | M |
| U9 | Páginas curtas (Projetos, Ferramentas, Lab, 404 a 1440px) | O rodapé termina a meio do ecrã (Projetos: rodapé acaba a 742px num ecrã de 800px). | `body` em flex coluna, `main { flex: 1 }`. | B | B |
| U10 | Projetos (cartões) | Rodapés dos cartões inconsistentes: "como isto liga à segurança →", "[painel ao vivo]", ou nada. Descrições cortadas a meio da frase por `ProjectsPage.astro:22`. | Um padrão único de rodapé (tags + 1 link de ação). Descrições escritas para caber (ver C3) em vez de truncadas. | M | B |
| U11 | Calculadora de subnets 390px | O binário quebra a meio do octeto (`1010100 / 0.00000001`). | Quebrar só nos pontos (`<wbr>` após cada `.`, ou `overflow-wrap: anywhere` desligado). | B | B |
| U12 | Lab — relógio (`LabDesktop.astro:627`) | `toLocaleTimeString([])` usa a locale do browser: página PT mostra "12:48 AM". | Passar `lang` da página (`pt-PT` → 24h). | B | B |
| U13 | Títulos | axe `heading-order` em Projetos e Ferramentas (h1 → h3 nos cartões). | Cartões com `h2`, ou um `h2` visualmente escondido por secção. | B | B |

**Navegação e menu**: o menu móvel, o dropdown "Este Site", o estado ativo
e o seletor PT/EN funcionam bem e têm alvos de 44px — **não mexer**.

## Achados — conteúdo

| # | Onde | Problema | Correção proposta | Imp. | Esf. |
|---|---|---|---|---|---|
| C1 | Home (`HomePage.astro`, `ui.ts` home) | Nenhuma chamada à ação. O hero diz bem quem és, mas não há passo seguinte: contactar, ver o CV ou ver "como este site é defendido". | Dois botões no hero: primário "Falar comigo" → Contactos; secundário "Ver como este site é defendido" → Este site. **Pergunta:** queres um CV em PDF? | A | B |
| C2 | Home — "Stats do site" | Os 4 números da Home são todos sobre o **site** (camadas de CI, cabeçalhos, paths-isco). Para quem chega pela primeira vez, a pergunta é sobre **ti**; os dados pessoais fortes (9+ anos, 5 países, 11 certificações, 4 CTFs ganhos) estão em texto pequeno no hero. | Manter o painel, mas mostrar primeiro os números pessoais e passar os do site para o Este site (onde já fazem sentido). **Decisão tua** — é uma escolha de posicionamento. | A | B |
| C3 | `content/projects/*/este-site.md` (descrição) | "Monorepo com site estático em Astro, conteúdo em markdown e ferramentas client-side" descreve a implementação, não o resultado. É o projeto principal do portefólio e é o que tem a descrição mais fraca. | Reescrever com o resultado (ex.: "Um site pessoal tratado como sistema de produção: threat model, CSP sem inline, honeypot e provas verificáveis no build"). Rever também as outras 3 descrições para caberem em ~120 caracteres sem truncar (C3 ↔ U10). | A | B |
| C4 | `BaseLayout.astro` (meta description) | 30 das 58 páginas usam a descrição por omissão ("Site pessoal de Daniel Malaco — …"); só as ferramentas e os projetos têm a sua. | Uma `description` por página em `ui.ts` (PT/EN) passada ao layout; ≤155 caracteres. | M | M |
| C5 | Contactos — "Chave PGP: por publicar" | Caixa âmbar de aviso com algo por fazer — num site de segurança, lê-se como coisa inacabada. | Publicar a chave (`/pgp.asc` + fingerprint) **ou** retirar a caixa e deixar uma linha neutra. **Pergunta:** qual preferes? | M | B |
| C6 | `ui.ts:278` | "directamente" — grafia pré-AO90; o resto do site usa AO90 ("direto", "ação", "deteção"). | "diretamente". | B | B |
| C7 | Blog | Só existe o placeholder `reservado.md` (draft). A nav esconde bem o blog, por isso não há links partidos. | Nada a corrigir. Sugestão: o primeiro post pode sair do material que já existe (ex.: o incidente do limite de writes do KV no ADR 0003). **Decisão tua.** | M | A |
| C8 | Lab | O ambiente de trabalho tem 5 das 10 ferramentas (faltam CSP, passkeys, EXIF, pwned, espelho). | **Pergunta:** é intencional? Se não, acrescentar as que funcionam numa janela. | B | M |

**Sem problemas encontrados:** paridade PT/EN (todos os ficheiros de
conteúdo têm par com o mesmo nome; mesmas rotas nos dois idiomas), português
europeu (nenhum PT-BR no conteúdo editorial), `<title>` únicos dentro de cada idioma (os repetidos são pares PT/EN com o mesmo nome, ex.: "Hashes"), um `h1` por
página, `hreflang` e `og:image` por idioma.

---

## Plano — lotes (um PR cada, por ordem)

1. **Correções de layout e acessibilidade** — U1, U2, U3, U6, U9, U11,
   U12, U13, C6. Só CSS/pequenos ajustes; zero texto novo. Resolve todos
   os *serious* do axe exceto U5. *Esforço: baixo. Risco: baixo.*
2. **Home em telemóvel** — U4, U5. *Esforço: médio.*
3. **Home: proposta de valor e CTA** — C1, C2. **Precisa das tuas
   respostas** (CTA, CV, que números mostrar).
4. **Projetos: descrições e cartões** — C3, U10. Texto PT+EN.
5. **SEO: descrições por página** — C4.
6. **Estados vazios/erro dos painéis ao vivo** — U7 (validar contra o
   Worker em produção ou num deploy do branch).
7. **ATT&CK em telemóvel** — U8.
8. Itens com decisão pendente: C5 (PGP), C7 (blog), C8 (Lab).

## O que **não** recomendo mudar

- **A estética** (escura, mono, verde/âmbar) — é coerente e distintiva.
- **Fontes do sistema** — trazer web fonts custaria peso e uma alteração à
  CSP (`font-src 'self'`), sem ganho proporcional.
- **Performance** — 100/100 com 23–31 KiB por página. As fotos dos CTFs em
  `/awards/` (~790 KiB, até 1400×1867 mostradas a ~450px) são o único peso
  relevante; já têm `loading="lazy"` e dimensões. Redimensioná-las é um
  ganho opcional, não urgente.
- **Navegação** — já cumpre alvos de 44px, `aria-current` e seletor PT/EN.

## Perguntas para ti

1. CTA da Home: só "Falar comigo" (email/Contactos), ou também um CV em PDF?
2. Números da Home: pessoais primeiro (C2) ou mantém os do site?
3. Chave PGP: publicar ou retirar a caixa?
4. Lab com 5 ferramentas: intencional?
5. Que lotes aprovas?
