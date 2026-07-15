# DNS & TLS — checklist para quando o domínio estiver ativo

> **Estado:** o domínio (`danielmala.co` em `static/src/config.ts`) ainda não
> está ativo na Cloudflare. Este documento é a checklist a executar quando a
> zona existir; nada disto se aplica ao `*.pages.dev` provisório.

## 1. CAA — restringir quem pode emitir certificados

Registos CAA limitam as CAs autorizadas a emitir para o domínio. Sem CAA,
qualquer CA pública pode emitir. Com a zona na Cloudflare e **Universal SSL**
ativo, a Cloudflare emite através destas CAs — todas têm de estar autorizadas,
senão a emissão/renovação falha:

```
danielmala.co.  IN  CAA  0 issue "letsencrypt.org"
danielmala.co.  IN  CAA  0 issue "pki.goog; cansignhttpexchanges=yes"
danielmala.co.  IN  CAA  0 issue "ssl.com"
danielmala.co.  IN  CAA  0 issuewild "letsencrypt.org"
danielmala.co.  IN  CAA  0 issuewild "pki.goog; cansignhttpexchanges=yes"
danielmala.co.  IN  CAA  0 issuewild "ssl.com"
danielmala.co.  IN  CAA  0 iodef "mailto:daniel_malaco@hotmail.com"
```

- Criar no dashboard: **DNS → Records → Add record → CAA** (um por linha).
- O `iodef` recebe notificações de pedidos de emissão que violem a política.
- Nota: com Universal SSL, a própria Cloudflare acrescenta/gere registos CAA
  dinamicamente quando necessário; manter os registos explícitos acima
  documenta a intenção e cobre o caso de saíres da Cloudflare. Confirma a
  lista de CAs em uso na doc oficial antes de aplicar (pode mudar):
  <https://developers.cloudflare.com/ssl/reference/certificate-authorities/>
- Verificar depois: `dig CAA danielmala.co +short`

## 2. Redirect HTTP → HTTPS

- Cloudflare Pages já força HTTPS no `*.pages.dev` e nos custom domains.
- Na zona: **SSL/TLS → Edge Certificates → Always Use HTTPS: ON**.
- Se um dia servires da VPS: **SSL/TLS → Overview → Full (strict)** (nunca
  "Flexible"), com certificado válido na origem.
- Verificar: `curl -sI http://danielmala.co/ | grep -i location` → deve
  responder `301` para `https://…`.

## 3. HSTS com preload

O `_headers` já envia `max-age=63072000; includeSubDomains` (2 anos), **sem**
`preload` — deliberado enquanto o domínio é provisório. Quando for definitivo:

1. Confirmar os pré-requisitos da preload list:
   - redirect HTTP→HTTPS no próprio domínio (passo 2);
   - certificado válido; `max-age` ≥ 31536000 (temos 2× isso);
   - `includeSubDomains` + `preload` no header.
2. Acrescentar `; preload` ao `Strict-Transport-Security` em
   `static/public/_headers` (e no espelho em `docs/security-headers.md`).
3. Submeter em <https://hstspreload.org> e acompanhar o estado.

> ⚠️ **Antes de submeter:** `includeSubDomains` + preload obriga **todos** os
> subdomínios a HTTPS válido, para sempre (sair da lista demora meses e não é
> garantido). Se o homelab/`lab.` ou outro subdomínio alguma vez servir HTTP
> puro, parte. Só submeter quando a família de subdomínios estiver decidida.

## 4. Extra barato (recomendado)

- **DNSSEC**: um clique na Cloudflare (**DNS → Settings → Enable DNSSEC**) +
  registo DS no registrar (automático se o registrar for a própria
  Cloudflare). Protege a resolução do domínio contra spoofing.

## Relação com o resto do repo

- Os headers servidos (incluindo HSTS) são verificados em produção pelo
  workflow `Headers` (`.github/workflows/headers.yml`) contra
  `.github/expected-headers.json`. Quando ativares o `preload`, acrescenta
  `"preload"` à entrada `strict-transport-security` desse ficheiro para o
  check passar a exigi-lo.
