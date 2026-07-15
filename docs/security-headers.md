# Cabeçalhos de segurança — configuração portável

Este site serve os mesmos cabeçalhos de segurança em **Cloudflare Pages** e numa
**VPS** (nginx ou Caddy). Este documento é a fonte única para replicar essa
configuração em qualquer servidor, para que migrar de Pages para VPS seja
*copiar config*, não reconstruí-la.

## Como a segurança está dividida

| Camada | Onde vive | Portável? |
| --- | --- | --- |
| **Content-Security-Policy** | `<meta http-equiv>` gerado pelo Astro em cada página (hashes SHA-256 por script/estilo) — ver `static/astro.config.mjs` | ✅ Automática — está dentro do HTML, independente do servidor. Nada a configurar na VPS. |
| **Restantes cabeçalhos** (HSTS, nosniff, anti-clickjacking, Referrer-Policy, Permissions-Policy, COOP/CORP) | `static/public/_headers` (lido nativamente pelo Cloudflare Pages) | ⚠️ Precisa de ser replicado na config do servidor na VPS — ver abaixo. |

> **Nota de design:** entregar a CSP por `<meta>` em vez de por cabeçalho torna-a
> imune à migração — a política viaja no próprio HTML. O preço é não poder usar
> `frame-ancestors` (inválido em `<meta>`), pelo que o anti-clickjacking fica a
> cargo do `X-Frame-Options: DENY` na camada de cabeçalhos. Numa VPS podes, se
> quiseres, promover isto a um `frame-ancestors 'none'` num cabeçalho CSP real
> (ver nota no fim).

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
```

Exceção das imagens Open Graph (`/og-image.png`, `/og-image-en.png`), que
precisam de ser carregáveis por outras origens (pré-visualizações de
LinkedIn/Slack/etc.):

```
Cross-Origin-Resource-Policy: cross-origin
Cache-Control: public, max-age=31536000, immutable
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
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), camera=(), microphone=(), payment=(), usb=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;

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
