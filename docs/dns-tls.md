# DNS & TLS — checklist de reforço do domínio

> **Estado:** o domínio (`danielmala.co`, em `static/src/config.ts`) já está
> ativo na Cloudflare (nameservers trocados no Namecheap — ver
> `docs/cloudflare-deploy.md`). Os itens abaixo são endurecimentos
> adicionais, por executar/confirmar no dashboard — nenhum é automático só
> por a zona existir.

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
danielmala.co.  IN  CAA  0 iodef "mailto:me@danielmala.co"
```

- Criar no dashboard: **DNS → Records → Add record → CAA** (um por linha).
- O `iodef` recebe notificações de pedidos de emissão que violem a política.
- Nota: com Universal SSL, a própria Cloudflare acrescenta/gere registos CAA
  dinamicamente quando necessário; manter os registos explícitos acima
  documenta a intenção e cobre o caso de saíres da Cloudflare. Confirma a
  lista de CAs em uso na doc oficial antes de aplicar (pode mudar):
  <https://developers.cloudflare.com/ssl/reference/certificate-authorities/>
- Verificar depois: `dig CAA danielmala.co +short`

> **Confirmado em produção (2026-07-29, revisão de segurança):** a consulta
> `dig CAA danielmala.co` devolve **sem resposta** — os registos acima ainda
> não foram criados. Enquanto isto ficar por fazer, qualquer CA publicamente
> confiada pode emitir um certificado para o domínio, sem restrição.
> DMARC/SPF já confirmados corretos na mesma verificação (`p=reject` estrito,
> `-all`) — só falta mesmo o CAA desta lista.

## 2. Redirect HTTP → HTTPS

- Cloudflare Pages já força HTTPS no `*.pages.dev` e nos custom domains.
- Na zona: **SSL/TLS → Edge Certificates → Always Use HTTPS: ON**.
- Se um dia servires da VPS: **SSL/TLS → Overview → Full (strict)** (nunca
  "Flexible"), com certificado válido na origem.
- Verificar: `curl -sI http://danielmala.co/ | grep -i location` → deve
  responder `301` para `https://…`.

## 3. HSTS com preload

O `_headers` já envia `max-age=63072000; includeSubDomains` (2 anos), **sem**
`preload` — deliberado até a família de subdomínios estar decidida (ver aviso
abaixo). Quando estiver:

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

## 4. DNSSEC

- **Ativo.** Protege a resolução do domínio contra spoofing (**DNS →
  Settings → DNSSEC** na Cloudflare, `DS` registado no registrar).

> **Confirmado (2026-07-30, validação de lançamento):** `DNSKEY` devolvido
> por dois resolvedores validadores independentes (Cloudflare `1.1.1.1` e
> Google `8.8.8.8`, ambos com `AD: true`), com o `DS` correspondente já
> registado na zona pai `.co`. Verificar: `dig @1.1.1.1 danielmala.co
> DNSKEY +dnssec` (e o mesmo contra `@8.8.8.8`) devem incluir a flag `ad`.

## Relação com o resto do repo

- Os headers servidos (incluindo HSTS) são verificados em produção pelo
  workflow `Headers` (`.github/workflows/headers.yml`) contra
  `.github/expected-headers.json`. Quando ativares o `preload`, acrescenta
  `"preload"` à entrada `strict-transport-security` desse ficheiro para o
  check passar a exigi-lo.
