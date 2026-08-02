# Cabeçalhos de segurança — configuração portável

Este site serve os mesmos cabeçalhos de segurança em **Cloudflare Pages** e numa
**VPS** (nginx ou Caddy). Este documento é a fonte única para replicar essa
configuração em qualquer servidor, para que migrar de Pages para VPS seja
*copiar config*, não reconstruí-la.

## Como a segurança está dividida

Todos os cabeçalhos de segurança, incluindo a CSP, vivem numa única linha
estática em `static/public/_headers` (lido nativamente pelo Cloudflare
Pages) — sem geração no build, sem `<meta>` por página.

> **Porque não há duas camadas (hashes + header):** ver
> [ADR 0001](adr/0001-csp-sem-inline.md) — a decisão de eliminar todo o
> `<script>`/`<style>` inline em vez de catalogar hashes por bloco, e a
> única exceção (o JSON-LD de `BaseLayout.astro`, com um hash SHA-256
> fixo). Este documento mantém só os *valores* atuais do header e como
> mantê-los, replicáveis em qualquer servidor; a história e o raciocínio da
> decisão vivem só na ADR.
>
> **Recalcular o hash do JSON-LD**, se `role[pt]`/`role[en]` ou outro campo
> de `config.ts` usado no bloco alguma vez divergir entre PT e EN (hoje um
> único hash cobre as duas páginas):
> ```
> node -e "console.log('sha256-' + require('crypto').createHash('sha256').update(CONTEUDO_EXATO_DO_SCRIPT,'utf8').digest('base64'))"
> ```
> (usa o texto exato entre `<script type="application/ld+json">` e
> `</script>` do HTML gerado, ex.: `dist/index.html`) e acrescenta o segundo
> hash a par do primeiro em `script-src` — cresce por *variante de conteúdo*,
> não por página.
>
> **Reporting de violações — automático até 2026-07, agora manual.** A CSP
> teve `report-uri /api/csp-report` + `report-to csp-endpoint` (cabeçalho
> `Reporting-Endpoints`): o browser mandava um POST a cada violação de
> QUALQUER visitante, sem exceção. Sem inline nenhum, uma violação de
> `script-src`/`style-src` só pode significar uma coisa (regressão da build
> ou injeção real) — mas, na prática, a esmagadora maioria dos relatórios era
> ruído de extensões de browser (ad-blockers, gestores de password) a injetar
> conteúdo nas páginas de visitantes. Cada POST aceite custa escritas no KV
> do Worker (`dynamic/worker/`), e o plano Free da Cloudflare tem um teto
> diário apertado, partilhado com honeypot/vitals/cron — o volume de ruído
> automático empurrou a conta para perto do teto. Removidos os três
> cabeçalhos; substituídos por captura 100% local
> (`static/public/js/csp-report.js`, ouve `securitypolicyviolation` e guarda
> em `sessionStorage`) + envio manual num botão na página Provas
> (`CspViolations.astro`) — zero escritas até alguém decidir mesmo reportar.
> O recetor continua a ser o mesmo Worker (`POST /api/csp-report`), que
> agrega de forma anónima; só a forma como o pedido chega lá mudou. Ver
> `dynamic/PLAN.md`.
>
> A presença destes cabeçalhos em produção é verificada automaticamente pelo
> workflow `Headers` (`.github/workflows/headers.yml`) contra a lista
> versionada em `.github/expected-headers.json` — após cada deploy e num cron
> diário.

A fonte de verdade dos valores é sempre `static/public/_headers`. Se o alterares,
atualiza os blocos abaixo em espelho.

## Valores atuais (espelho de `_headers`)

```
Content-Security-Policy: default-src 'self'; script-src 'self' 'sha256-/RztAGp2rIIt3aqLYwLYPT9MWtDrHCcQxZQBSY9sugY='; style-src 'self'; img-src 'self' blob:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests; require-trusted-types-for 'script'; trusted-types 'none'
Strict-Transport-Security: max-age=63072000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), camera=(), microphone=(), payment=(), usb=()
Cross-Origin-Opener-Policy: same-origin
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Embedder-Policy: require-corp
```

> **COEP `require-corp`:** todo o site é same-origin (CSS/JS/fontes/imagens),
> por isso não quebra nada; a par do COOP ativa *cross-origin isolation*. As
> imagens OG são cross-origin mas só as buscam **outros** sites (previews),
> nunca as nossas páginas — daí o `CORP: cross-origin` específico delas.

Exceção das imagens Open Graph (`/og-image.png`, `/og-image-en.png`), que
precisam de ser carregáveis por outras origens (pré-visualizações de
LinkedIn/Slack/etc.):

```
! Cross-Origin-Resource-Policy
Cross-Origin-Resource-Policy: cross-origin
Cache-Control: public, max-age=31536000, immutable
```

> **Cuidado (Cloudflare Pages):** quando várias regras do `_headers` coincidem
> com o mesmo path, o Pages **não substitui** um header repetido — **concatena**
> os valores com vírgula (`same-origin, cross-origin`), que é inválido e faz o
> browser ignorar o header por inteiro. A linha `! Cross-Origin-Resource-Policy`
> remove primeiro o valor herdado do bloco `/*`; só depois se define o novo.
> (No nginx o problema é o inverso — ver o cuidado abaixo; no Caddy o override
> por matcher já substitui corretamente.)

Homepage (`/` e `/en/`), cabeçalho `Link` (RFC 8288) — mesmas relações já no
`<head>` (`rel="canonical"`/`rel="alternate" hreflang`, `BaseLayout.astro`),
para agentes que não chegam a fazer parsing de HTML:

```http
Link: <https://danielmala.co/>; rel="canonical", <https://danielmala.co/en/>; rel="alternate"; hreflang="en"
```
```http
Link: <https://danielmala.co/en/>; rel="canonical", <https://danielmala.co/>; rel="alternate"; hreflang="pt"
```

---

## nginx

Dentro do `server { … }` do site (assume TLS já terminado no nginx ou na
Cloudflare à frente). `always` garante que os cabeçalhos saem também em respostas
de erro (404, etc.).

```nginx
server {
    listen 443 ssl http2;
    server_name danielmala.co;
    root /var/www/site;          # destino do rsync do static/dist/
    index index.html;

    # --- Cabeçalhos de segurança (espelho de static/public/_headers) ---
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'sha256-/RztAGp2rIIt3aqLYwLYPT9MWtDrHCcQxZQBSY9sugY='; style-src 'self'; img-src 'self' blob:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests; require-trusted-types-for 'script'; trusted-types 'none'" always;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;
    add_header Cross-Origin-Embedder-Policy "require-corp" always;

    # security.txt e restante conteúdo estático servem-se tal-e-qual.
    location / {
        try_files $uri $uri/ =404;
    }

    # Imagens Open Graph: CORP relaxado + cache longa.
    location ~ ^/og-image(-en)?\.png$ {
        add_header Cross-Origin-Resource-Policy "cross-origin" always;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        # Reafirmar os restantes: um bloco add_header no location substitui
        # os herdados do server, por isso repetem-se os essenciais.
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
        add_header X-Content-Type-Options "nosniff" always;
    }
}
```

> **Cuidado (nginx):** `add_header` **não** é aditivo — declarar qualquer
> `add_header` dentro de um `location` faz esse bloco *ignorar* todos os
> `add_header` herdados do `server`. Por isso o `location` das imagens OG repete
> os cabeçalhos que ainda quer manter. Se preferires evitar a repetição, usa o
> módulo `headers-more` (`more_set_headers`), que é aditivo.

## Caddy

O Caddy termina TLS automaticamente (Let's Encrypt) e o HSTS não é obrigatório
declarar — mas mantém-se explícito para paridade com o `_headers`.

```caddy
danielmala.co {
    root * /var/www/site        # destino do rsync do static/dist/
    encode gzip zstd
    file_server

    header {
        Content-Security-Policy "default-src 'self'; script-src 'self' 'sha256-/RztAGp2rIIt3aqLYwLYPT9MWtDrHCcQxZQBSY9sugY='; style-src 'self'; img-src 'self' blob:; font-src 'self'; connect-src 'self'; object-src 'none'; frame-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests; require-trusted-types-for 'script'; trusted-types 'none'"
        Strict-Transport-Security "max-age=63072000; includeSubDomains"
        X-Content-Type-Options "nosniff"
        X-Frame-Options "DENY"
        Referrer-Policy "strict-origin-when-cross-origin"
        Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=()"
        Cross-Origin-Opener-Policy "same-origin"
        Cross-Origin-Resource-Policy "same-origin"
        Cross-Origin-Embedder-Policy "require-corp"
        -Server                 # remove o cabeçalho Server (menos fingerprinting)
    }

    # Imagens Open Graph: CORP relaxado + cache longa (sobrepõe o CORP acima).
    @og path /og-image.png /og-image-en.png
    header @og {
        Cross-Origin-Resource-Policy "cross-origin"
        Cache-Control "public, max-age=31536000, immutable"
    }
}
```

Ao contrário do nginx, o bloco `header @og` do Caddy é aditivo/sobreponível: só
altera os cabeçalhos que nomeia, mantendo os restantes do bloco global.

---

## HSTS preload (decisão futura, deliberadamente adiada)

O `max-age` é de 2 anos com `includeSubDomains`, mas **sem** a diretiva
`preload` — de propósito, para manter a configuração reversível até a família
de subdomínios estar decidida (ver `docs/dns-tls.md`). Submeter a `preload`
grava o domínio (e subdomínios) na lista *hard-coded* dos browsers e é
difícil de reverter.

Quando a família de subdomínios estiver fechada e quiseres o preload:

1. Acrescenta `; preload` ao valor (`max-age=63072000; includeSubDomains; preload`)
   em `static/public/_headers` **e** nos blocos nginx/Caddy acima.
2. Submete o domínio em <https://hstspreload.org>.

## Verificar depois do deploy

```bash
curl -sI https://danielmala.co | grep -iE 'content-security-policy|strict-transport|content-type-options|frame-options|referrer|permissions|cross-origin'
curl -s  https://danielmala.co/.well-known/security.txt
```

Scanners públicos (correr após o site estar publicado):

- <https://securityheaders.com/?q=danielmala.co&followRedirects=on>
- <https://developer.mozilla.org/en-US/observatory/analyze?host=danielmala.co>
