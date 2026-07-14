# design/ — direções de design exploradas

Sete mockups estáticos (HTML auto-contido + screenshot) criados durante a
fase de design do site. **A direção escolhida foi a nº 4 — Security
Dashboard**, que está implementada em `static/`.

| # | Nome | Ideia |
| --- | --- | --- |
| 1 | Terminal Elegante | Janela de terminal a correr `whoami`, verde sóbrio |
| 2 | Hacker Neon | Glitch, scanlines, neon verde/magenta/ciano |
| 3 | Minimal Moderno | Estilo linear/vercel: tipografia grande, muito espaço |
| **4** | **Security Dashboard** ✅ | **Painéis identidade + stats, chips de certificações** |
| 5 | Circuit/PCB | Inspirado no fundo do CV: pistas ciano, chip com pinos |
| 6 | Bento Grid | Mosaico de cartões (tendência 2025/26) |
| 7 | Aurora Glass | Gradientes suaves + cartões de vidro |

Cada `N-nome.html` abre diretamente no browser (sem build). Servem como
referência caso um dia se queira mudar a "pele" do site — a estrutura
(rotas, i18n, conteúdo) é independente do design, por isso a troca é barata:
mexe-se sobretudo em `static/src/styles/global.css` e no `HomePage.astro`.
