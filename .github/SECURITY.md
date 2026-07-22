# Política de segurança

Obrigado por ajudares a manter este projeto seguro. Este repositório contém
o site pessoal de Daniel Assis Malaco (Astro estático em `static/`) e o
Cloudflare Worker das features de segurança (`dynamic/worker/`).

## O que está coberto

- O site em produção (o *deploy* mais recente do `main`).
- O Worker em `dynamic/worker/` e os seus endpoints (`/api/*`).
- A própria cadeia de build (workflows em `.github/workflows/`).

Como é um site que se atualiza continuamente, **a única versão suportada é a
que está em produção** — não há *releases* antigos a manter.

## Como reportar uma vulnerabilidade

Reporta em **privado**, nunca numa Issue pública (uma Issue expõe a falha a
toda a gente antes de estar corrigida):

- Através da página de contactos: <https://danielmala.co/contactos/>

Ver também o `security.txt` do site
([`/.well-known/security.txt`](https://danielmala.co/.well-known/security.txt)),
no formato [RFC 9116](https://www.rfc-editor.org/rfc/rfc9116).

Inclui, se possível: o que encontraste, os passos para reproduzir, e o
impacto que lhe atribuis. Uma prova de conceito mínima ajuda muito.

## O que esperar

- Resposta normalmente em **24–48 h, em dias úteis**.
- Manténs-te ao corrente da correção e do *timing* de divulgação.
- Pedimos divulgação coordenada: dá tempo para corrigir antes de tornar
  público. Investigação de boa-fé é bem-vinda e nunca será penalizada.

## Fora de âmbito

Relatórios automáticos de *scanners* sem impacto demonstrável (ex.: ausência
de um header em endpoints que não servem conteúdo sensível, versões de
bibliotecas sem exploração prática) têm prioridade baixa.

## A postura de segurança deste repositório

O próprio *pipeline* é tratado como superfície de ataque: OSV-Scanner,
gitleaks, Semgrep e zizmor correm em cada PR, e as GitHub Actions estão
pinadas por *commit* SHA (mantidas pelo Renovate). Detalhes na secção
**"Segurança do pipeline"** do [README](../README.md).
