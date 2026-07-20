# design/ — direções de design exploradas

Sete mockups estáticos (HTML auto-contido + screenshot) foram criados durante
a fase de design do site para comparar direções lado a lado. **A direção
escolhida foi a nº 4 — Security Dashboard**, implementada em `static/`; os
ficheiros dos mockups foram removidos depois de a decisão estar tomada
(ficam registados aqui só como memória do processo).

| # | Nome | Ideia |
| --- | --- | --- |
| 1 | Terminal Elegante | Janela de terminal a correr `whoami`, verde sóbrio |
| 2 | Hacker Neon | Glitch, scanlines, neon verde/magenta/ciano |
| 3 | Minimal Moderno | Estilo linear/vercel: tipografia grande, muito espaço |
| **4** | **Security Dashboard** ✅ | **Painéis identidade + stats, chips de certificações** |
| 5 | Circuit/PCB | Inspirado no fundo do CV: pistas ciano, chip com pinos |
| 6 | Bento Grid | Mosaico de cartões (tendência 2025/26) |
| 7 | Aurora Glass | Gradientes suaves + cartões de vidro |

A estrutura do site (rotas, i18n, conteúdo) é independente do design — trocar
de "pele" mexe sobretudo em `static/src/styles/global.css` e no
`HomePage.astro`, não seria preciso recomeçar do zero.
