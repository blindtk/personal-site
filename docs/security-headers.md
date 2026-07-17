# Cabeçalhos de segurança — configuração portável

Este site serve os mesmos cabeçalhos de segurança em **Cloudflare Pages** e numa
**VPS** (nginx ou Caddy). Este documento é a fonte única para replicar essa
configuração em qualquer servidor, para que migrar de Pages para VPS seja
*copiar config*, não reconstruí-la.

## Como a segurança está dividida

| Camada | Onde vive | Portável? |
| --- | --- | --- |
| **CSP em `<meta>`** (por página) | `<meta http-equiv>` gerado pelo Astro em cada página (hashes SHA-256 por script/estilo) — ver `static/astro.config.mjs` | ✅ Automática — está dentro do HTML, independente do servidor. Nada a configurar na VPS. |
| **CSP em header** (site-wide) | Gerada no build por `static/scripts/csp-headers.mjs`: união dos hashes de todas as páginas + `frame-ancestors 'none'`, escrita em `dist/_headers` | ⚠️ Na VPS, copiar o valor gerado em `dist/_headers` para a config do servidor (regenera a cada build). |
| **Restantes cabeçalhos** (HSTS, nosniff, anti-clickjacking, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP) | `static/public/_headers` (lido nativamente pelo Cloudflare Pages) | ⚠️ Precisa de ser replicado na config do servidor na VPS — ver abaixo. |

> **Nota de design:** a CSP tem duas camadas deliberadas. A `<meta>` por página
> é a mais estrita (só os hashes daquela página) e viaja no HTML — imune a
> migrações. O header é a união de todas as páginas e acrescenta
> `frame-ancestors 'none'` (inválido em `<meta>`); é a única camada que
> scanners externos (securityheaders.com, Mozilla Observatory) conseguem
> avaliar. O browser aplica a **interseção** das duas, por isso a política
> efetiva por página continua a ser a estrita. O `X-Frame-Options: DENY`
> mantém-se para browsers antigos.
>
> A presença destes cabeçalhos em produção é verificada automaticamente pelo
> workflow `Headers` (`.github/workflows/headers.yml`) contra a lista
> versionada em `.github/expected-headers.json` — após cada deploy e num cron
> diário.

A fonte de verdade dos valores é sempre `static/public/_headers`. Se o alterares,
atualiza os blocos abaixo em espelho.

## Valores atuais (espelho de `_headers`)

```
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
`preload` — de propósito, para manter a configuração reversível enquanto o
domínio é provisório. Submeter a `preload` grava o domínio (e subdomínios) na
lista *hard-coded* dos browsers e é difícil de reverter.

Quando o domínio final estiver fixo e quiseres o preload:

1. Acrescenta `; preload` ao valor (`max-age=63072000; includeSubDomains; preload`)
   em `static/public/_headers` **e** nos blocos nginx/Caddy acima.
2. Submete o domínio em <https://hstspreload.org>.

## Opcional: promover o anti-clickjacking a `frame-ancestors`

`X-Frame-Options: DENY` cobre o essencial. Numa VPS, se quiseres a variante
moderna equivalente (que também restringe `<embed>`/`<object>`), acrescenta um
cabeçalho CSP mínimo *só* com a diretiva de frames — sem duplicar a CSP completa,
que continua a vir do `<meta>`:

- nginx: `add_header Content-Security-Policy "frame-ancestors 'none'" always;`
- Caddy: `Content-Security-Policy "frame-ancestors 'none'"`

Mantém o `X-Frame-Options: DENY` a par para browsers antigos.

## Verificar depois do deploy

```bash
curl -sI https://danielmala.co | grep -iE 'strict-transport|content-type-options|frame-options|referrer|permissions|cross-origin'
curl -s  https://danielmala.co/.well-known/security.txt
```

Scanners públicos (correr após o site estar publicado):

- <https://securityheaders.com/?q=danielmala.co&followRedirects=on>
- <https://developer.mozilla.org/en-US/observatory/analyze?host=danielmala.co>
