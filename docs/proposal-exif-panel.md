# Proposta (aprovada): "O que a tua foto revela" — painel de metadados EXIF

> **Estado: aprovada pelo dono do repo e implementada nesta alteração.** Fica
> registada aqui a fundamentação, como nas outras ferramentas do Lab.

## 1. O que é

Uma ferramenta em `/ferramentas/` que extrai os metadados EXIF de uma imagem
JPEG — câmara, lente, definições de captura, data e, sobretudo, **coordenadas
GPS exatas quando existem** — e mostra exatamente o que essa foto revela
sobre quem a tirou. Inclui:

- resumo com miniatura, badges (câmara/modelo, data, presença de GPS);
- alerta dedicado quando há localização GPS, com as coordenadas decodificadas
  e um link para abrir o ponto exato no OpenStreetMap;
- tabela completa de metadados (fabricante, modelo, lente, software, data de
  captura, exposição, abertura, ISO, distância focal, dimensões, orientação);
- ação de **limpar metadados e descarregar** — redesenha a imagem num
  `<canvas>` (que nunca copia EXIF) e oferece o ficheiro resultante para
  download, sem exigir lógica de remoção própria.

Porque interessa num site pessoal de segurança: é um problema real e
recorrente (fotos partilhadas com GPS embutido já geraram incidentes de
doxing e casos judiciais conhecidos), é educativo por natureza — a maioria
das pessoas não sabe que a câmara grava isto —, e o botão de limpeza dá-lhe
uma componente prática imediata, não só demonstrativa.

## 2. Onde vive

`static/`, 100% client-side, seguindo o contrato do índice `/ferramentas/`:

- **`static/src/scripts/exif.js`** — lógica pura (parser EXIF: segmentos
  JPEG, IFD0, Exif SubIFD, GPS IFD, conversão DMS→decimal, formatação de
  exposição), sem DOM, testada com `node --test`
  (`static/test/exif.test.mjs`, com uma fixture JPEG mínima gerada com
  `piexif` e valores conhecidos — mesmo espírito dos vetores RFC usados no
  MD5/subnets).
- **`static/src/components/tools/ExifTool.astro`** — só liga ao DOM
  (dropzone, tabela, alerta GPS) e trata da remoção de metadados via
  `canvas` (é a única parte que precisa do browser, por isso não está em
  `exif.js`).
- Página fina PT/EN (`pages/ferramentas/exif.astro` + `pages/en/tools/exif.astro`),
  registada em `ToolPage.astro`/`ToolsIndexPage.astro`, strings em
  `i18n/ui.ts` (`tools.exif`, PT+EN) — sem novas entradas em `routes.ts`
  (os slugs de ferramentas não precisam disso, como as restantes).
- Imagem de demonstração sintética em `static/public/ferramentas/exif-demo.jpg`
  (paisagem gerada, sem pessoas nem dados reais, com EXIF fabricado —
  câmara fictícia + coordenadas de um marco público) para o botão "carregar
  exemplo", inspirado no `loadSample` do analisador de cabeçalhos de email.

Zero chamadas de rede a terceiros; o único `fetch` é ao próprio ficheiro
estático de demonstração, servido pelo mesmo domínio.

### Ajuste à CSP

O `img-src` global (fonte única em `astro.config.mjs`) passou de `'self'`
para `'self' blob:`. É necessário porque a pré-visualização e o redesenho no
`canvas` usam `URL.createObjectURL()` sobre o ficheiro carregado — sem isto,
a CSP (por padrão, correta) bloqueava o próprio `<img>` da ferramenta. O
`blob:` só permite URLs gerados pela própria página a partir de dados locais
(nunca um recurso remoto), por isso não abre a política a imagens de
terceiros nem enfraquece a proteção contra XSS que a CSP por hashes já dá.
Validado com `check-csp-consistency.mjs` (o mesmo teste que corre no CI).

## 3. Riscos e mitigações

- **Upload de fotos reais com dados sensíveis.** É o risco central e, tal
  como no verificador de passwords, é inerente à proposta de valor da
  ferramenta. Mitigado por: processamento 100% local (verificável — zero
  `fetch` fora do asset de demo), nada persistido (`localStorage` nunca
  usado, nenhuma cópia guardada), aviso âmbar explícito a desencorajar
  upload de fotos com pessoas/moradas reais, e um botão de exemplo que
  permite explorar a ferramenta sem arriscar nada.
- **Falso sentido de "limpeza completa".** Redesenhar num `canvas` remove
  *todos* os metadados (não seletivamente) porque o canvas só copia pixels —
  isto é uma garantia forte, não uma lista de exceções a manter.
- **Parser malformado como vetor de XSS local (self-XSS).** Campos ASCII do
  EXIF (fabricante, modelo, software) vêm de bytes não confiáveis — um
  ficheiro malicioso poderia tentar injetar HTML nesses campos. Mitigado
  por construção: todo o DOM é montado com `createElement` +
  `textContent`, nunca `innerHTML`, e a CSP do site já teria
  `require-trusted-types-for 'script'` como camada adicional.
- **Vetor de abuso do site:** nenhum novo — sem backend, sem estado, sem
  upload para servidor; o único recurso novo servido é uma imagem estática
  pública.

## 4. Esforço e passos (realizados)

**Pequeno** (~1 dia):

1. `exif.js` — parser de segmentos JPEG/TIFF/GPS IFD + `gpsToDecimal` +
   `formatExposure`; testes `node --test` com fixture gerada por `piexif`.
2. `ExifTool.astro` — dropzone (clique + drag&drop), resumo com badges,
   alerta de GPS com link para mapa, tabela de metadados, botão de limpeza
   via canvas.
3. Imagem de demonstração sintética + strings PT/EN em `ui.ts`.
4. Ligação ao `ToolPage`/`ToolsIndexPage`, páginas PT/EN.
5. Ajuste mínimo e documentado ao `img-src` da CSP (`blob:`), validado com
   `check-csp-consistency.mjs`.
6. `cd static && npm run build` limpo, `npm run test` (34 testes, todos a
   passar) e validação manual no browser (upload, exemplo, GPS, limpeza,
   mobile) via preview local.
