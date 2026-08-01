# Prompt — análise de consistência textual entre páginas

Prompt reutilizável para pedir a um agente que leia **todos os textos do site**
e verifique se fazem sentido entre si (coerência factual, de terminologia, de
tom e de paridade PT/EN). É uma tarefa de **análise**: por omissão produz um
relatório e **não altera conteúdo** — só corrige se lhe for pedido.

Copia o bloco abaixo como pedido a um agente.

---

## Prompt

> **Tarefa:** Lê todos os textos das páginas deste site e avalia se são
> coerentes entre si. O objetivo não é rever cada página isolada, mas verificar
> se, **em conjunto**, contam a mesma história sem contradições, sem termos
> baralhados e sem descompasso entre PT e EN.
>
> ### Onde vivem os textos (lê tudo isto)
>
> - `content/pages/` — `sobre.md` (PT) e `about.md` (EN).
> - `content/projects/pt/*.md` e `content/projects/en/*.md` — mesmo nome de
>   ficheiro nos dois lados liga as versões.
> - `content/blog/pt/*.md` e `content/blog/en/*.md`.
> - `content/*.json` — `awards`, `attack`, `certs`, `detections`, `catalog`,
>   `honeypot-attack`, `links`. Conteúdo estruturado, mas com texto visível.
> - `static/src/i18n/ui.ts` — **todas** as strings de interface, PT e EN na
>   mesma estrutura (títulos, intros, labels, blocos de cross-links como
>   `layers`). É aqui que vive a maior parte do texto "de página".
> - `static/src/config.ts` — dados pessoais (nome, handle, cargo, email,
>   domínio, redes, disponibilidade). **Fonte única** destes valores.
> - `static/src/components/pages/*.astro` **e** `static/src/components/tools/*.astro`
>   (+ `.js`/`.ts` associados) — as componentes de página e das ferramentas de
>   `/ferramentas/`. Não deviam ter strings hardcoded (as regras do projeto
>   proíbem-no); sinaliza qualquer texto visível que esteja aqui em vez de em
>   `ui.ts`. Nas de `tools/`, a lógica em si deve limitar-se a ligar ao DOM —
>   um achado de string hardcoded não é licença para mexer nessa lógica.
> - `static/src/i18n/routes.ts` — pares de rotas PT/EN, para confirmar que as
>   ligações cruzadas apontam para páginas que existem.
>
> ### O que verificar
>
> 1. **Paridade PT/EN.** Cada texto existe nos dois idiomas, com o **mesmo
>    nome de ficheiro** (`content/<coleção>/pt|en/…`) e a mesma estrutura em
>    `ui.ts`. Sinaliza: secções presentes num idioma e ausentes no outro,
>    traduções que mudaram de sentido (drift), chaves só num dos lados.
> 2. **Coerência factual entre páginas.** Nome, handle, cargo/role, email,
>    domínio, certificações e afirmações sobre a pessoa têm de bater certo em
>    todas as páginas — e com `config.ts`. Sinaliza qualquer página que
>    contradiga outra (ex.: um cargo na Home diferente do "Sobre", uma
>    certificação mencionada num sítio e ausente na página de Certificações).
> 3. **Terminologia consistente.** O mesmo conceito deve usar sempre o mesmo
>    termo (ex.: "Provas" ↔ "Evidence", "Perímetro" ↔ "Perimeter", "honeypot",
>    "self-scan", nomes das ferramentas, "camadas"). Presta atenção especial ao
>    bloco `layers` ("Este site, por camadas") em `ui.ts`: as descrições de
>    Segurança, Provas, Perímetro, Deteções e ATT&CK têm de descrever
>    fielmente o que cada uma dessas páginas realmente diz.
> 4. **Ligações cruzadas corretas.** Onde uma página remete para outra
>    (bloco de camadas, "Sobre" → Projetos, projeto "este-site" → Provas/
>    Perímetro), confirma que o destino existe em `routes.ts` e que a
>    descrição corresponde ao conteúdo do destino.
> 5. **Coerência narrativa.** Lê Home → Sobre → Projetos → páginas do
>    "sistema" (Segurança, Provas, Perímetro, Deteções, ATT&CK) como um todo.
>    Sinaliza repetição desnecessária, promessas feitas numa página e não
>    cumpridas noutra, e saltos de contexto que confundem o leitor.
> 6. **Tom, voz e idioma.** Estética escura, técnica, sóbria; acento
>    verde-terminal e âmbar para o Lab/avisos. **Português europeu**, nunca
>    brasileiro. Sinaliza deslizes PT-BR, mudanças de registo (tratamento por
>    tu/você/impessoal a variar entre páginas) e gralhas óbvias.
>
> ### Como reportar
>
> Produz um **relatório** agrupado por página/coleção. Para cada achado indica:
> `ficheiro:linha`, a que dimensão pertence (paridade / facto / terminologia /
> ligação / narrativa / tom), o problema em uma frase, e uma correção sugerida.
> Ordena por gravidade (contradições factuais e falhas de paridade primeiro;
> gralhas e afinações de tom por último). Se não encontrares problemas numa
> dimensão, di-lo explicitamente.
>
> **Não alteres conteúdo** a menos que to peça. Se te pedir para corrigir,
> respeita as regras do projeto (`CLAUDE.md`): strings de UI só em `ui.ts`,
> dados pessoais só em `config.ts`, criar/atualizar sempre os **dois** idiomas,
> e no fim correr `cd static && npm run build` sem erros nem warnings novos.
