# CI/CD — pipeline de build e segurança

Fonte única dos detalhes de cada verificação que corre em push/PR ou contra
produção. O `README.md` mantém só um resumo com link para aqui — esta tabela
é a versão completa.

## Verificações em cada push/PR

| Verificação | Onde | O que garante |
| --- | --- | --- |
| **Build + `npm audit`** | `ci.yml` | O site builda sem erros, sem advisories high/critical nas dependências. |
| **Dependency Review** | `dependency-review.yml` | Bloqueia PRs que introduzam uma dependência nova com vulnerabilidade conhecida, restrito ao diff do PR (GitHub Dependency Graph) — o gate rápido, complementar à sweep completa do OSV-Scanner sobre o lockfile inteiro, abaixo. |
| **OSV-Scanner** | `security.yml` | `package-lock.json` sem vulnerabilidades conhecidas ([OSV.dev](https://osv.dev), inclui GHSA); falha a CI em qualquer advisory conhecida. |
| **gitleaks** | `security.yml` + hook local | Nenhum segredo (tokens Cloudflare, chaves) entra no histórico do git. Localmente: `pipx install pre-commit && pre-commit install`. |
| **CodeQL** | `codeql.yml` | SAST semântico para o JavaScript/TypeScript — classe de análise diferente do pattern-matching do Semgrep, corre à parte. |
| **Semgrep** | `security.yml` | SAST via `p/typescript`/`p/javascript` mais regras próprias para sinks de DOM-XSS em componentes `.astro` (`.semgrep/`) — os rulesets públicos não fazem parsing desse tipo de ficheiro. |
| **zizmor** | `security.yml` | Audita os próprios workflows: pins em falta, permissões excessivas, template injection, credenciais persistidas. |
| **Headers em produção** | `headers.yml` | Depois de cada deploy (e num cron diário), a produção é verificada contra `.github/expected-headers.json` — um header de segurança em falta ou regredido falha o workflow. |
| **`npm audit signatures` + SBOM** | `supply-chain.yml` (semanal + manual) | Verifica as assinaturas do registo npm (apanha um pacote servido sem a assinatura esperada) e gera um SBOM CycloneDX para os dois lockfiles, como artefacto. |
| **Invariantes de produção** | `invariants.yml` (diário + manual) | Verifica `/api/health` e as rotas de leitura do Worker; abre uma Issue se algo estiver genuinamente partido (fecha-se sozinha ao recuperar). Fecha o loop que os dashboards de honeypot/threat-intel deixam aberto por serem só-pull — nada avisava ninguém sem alguém a olhar. |
| **Scan de TLS/cifras/vulns em produção** | `tls-check.yml` (mensal + manual) | Corre [testssl.sh](https://testssl.sh) contra produção; achados classificados pela severidade do próprio testssl.sh — CRITICAL/HIGH (protocolos fracos, vulnerabilidades conhecidas tipo Heartbleed/POODLE, certificado inválido/expirado) falham o workflow, MEDIUM/LOW só avisam. |
| **Higiene de DNS em produção** | `dns-check.yml` (semanal + manual) | Verifica SPF, DMARC, CAA e a cadeia de confiança DNSSEC (flag `AD` de dois resolvers independentes) contra o que [`docs/dns-tls.md`](dns-tls.md) documenta como já correto — uma regressão falha o workflow; um registo CAA ainda em falta (lacuna conhecida e documentada) só avisa. |
| **Grade do Mozilla Observatory em produção** | `observatory-check.yml` (semanal + manual) | Chama a API gratuita do [Mozilla HTTP Observatory](https://github.com/mdn/mdn-http-observatory) — uma segunda rubrica de avaliação independente (cookies, cadeia de redirects, cross-origin isolation) por cima das verificações exatas de header do `headers.yml`. Grade D/F falha o workflow, B/C só avisa. |
| **Fuzzing** ([ClusterFuzzLite](https://google.github.io/clusterfuzzlite/) + Jazzer.js) | `fuzzing.yml` (só manual — ver nota abaixo) | Dois harnesses fazem fuzz às três funções do Worker que fazem parsing de input de rede não confiável — `parseReports()` (parsing de CSP-report) e os sanitizadores de output `sanitizeText()`/`escapeHtml()` — porque essas, ao contrário das ferramentas client-side, são uma fronteira de confiança real. |
| **Releases assinadas** | `release.yml` (em tag `v*` + manual) | Builda `static/dist` e um bundle dry-run do Worker, gera um SBOM CycloneDX para ambos, e assina a proveniência com Sigstore ([`actions/attest-build-provenance`](https://github.com/actions/attest-build-provenance)) antes de anexar tudo a um GitHub Release. Não toca no deploy real, que continua manual (`dynamic/PLAN.md`). |

## Práticas transversais

Toda a action **pinada a um commit SHA** ([Renovate](../renovate.json5)
mantém os digests atualizados e agrupa updates num PR semanal),
`permissions: {}` por omissão com least-privilege por job, `persist-credentials: false`
em todo o checkout, e `npm ci --ignore-scripts` em `ci.yml` (nenhuma
dependência corre um postinstall arbitrário em CI). A CSP é uma linha
estática em `static/public/_headers` — sem hashes, porque não há inline
`<script>`/`<style>` no site (ver [`docs/security-headers.md`](security-headers.md)
e [ADR 0001](adr/0001-csp-sem-inline.md)). O plano de DNS/TLS (CAA, HSTS
preload, DNSSEC) vive em [`docs/dns-tls.md`](dns-tls.md). O processo de
deploy na Cloudflare (domínio, Pages, Worker, Access, WAF) e os incidentes
reais ao longo do caminho estão em [`docs/cloudflare-deploy.md`](cloudflare-deploy.md).

## Cadência

**SBOM/verificação de assinaturas — semanal, não por PR.** Esta cadência é
anterior ao repositório ficar público, quando os minutos de Actions eram
contabilizados contra o tier gratuito de repo privado (2.000 min/mês).
Repos públicos têm minutos de Actions ilimitados, mas a cadência semanal
manteve-se — drift de SBOM e verificação de assinaturas não precisam de
granularidade por PR, e não havia razão para mudar um schedule que já
funcionava. Contexto completo em
[`docs/security-review-2026-07-29.md`](security-review-2026-07-29.md) §0.

**Fuzzing sem cron.** `fuzzing.yml` não tem cron por agora — `language:
javascript` + `sanitizer: coverage` (o único valor de `SANITIZER` aceite
tanto pelo compile script do OSS-Fuzz como pelo validador da própria action
do ClusterFuzzLite para JS) faz o `google/clusterfuzzlite/actions/build_fuzzers`
compilar binários wrapper de compilador honggfuzz/AFL sem relação com o
projeto a par dos targets JS reais, e o `run_fuzzers` trata-os como fuzz
targets, falhando de imediato. Confirmado independente do commit pinado —
esse e o `main` atual da action resolvem para a mesma imagem Docker
flutuante `gcr.io/oss-fuzz-base/clusterfuzzlite-build-fuzzers:v1`, logo o
bug vive lá, não neste repo. O workflow mantém-se `workflow_dispatch`-only
até a montante corrigir.

## Scans externos (manuais)

Além das verificações automatizadas acima, estes scanners de terceiros
correm manualmente contra produção, não estão ligados à CI — ou porque não
têm API, a API é redundante com uma verificação que este repo já corre, ou
o tier gratuito não encaixa num cron recorrente (raciocínio ferramenta a
ferramenta em [PR #155](https://github.com/blindtk/personal-site/pull/155)).
Cada link abaixo é um relatório ao vivo para `danielmala.co`, não um
snapshot estático:

| Scanner | O que verifica | Relatório |
| --- | --- | --- |
| Qualys SSL Labs | Grade de TLS/cifras/certificado | [ssllabs.com/ssltest](https://www.ssllabs.com/ssltest/analyze.html?d=danielmala.co) |
| Security Headers | Headers de segurança HTTP | [securityheaders.com](https://securityheaders.com/?q=danielmala.co&followRedirects=on) |
| Mozilla HTTP Observatory | Headers, cookies, redirects, cross-origin isolation — ver `observatory-check.yml` acima para a metade automatizada | [developer.mozilla.org/observatory](https://developer.mozilla.org/en-US/observatory/analyze?host=danielmala.co) |
| Hardenize | Monitorização de configuração DNS/TLS/email | [hardenize.com](https://www.hardenize.com/report/danielmala.co/1785606965) |
| DNSViz | Validação e visualização independente da cadeia DNSSEC | [dnsviz.net](https://dnsviz.net/d/danielmala.co/dnssec/) |
| ImmuniWeb | Score de segurança web/SSL | [immuniweb.com](https://www.immuniweb.com/cyberscore/danielmala.co/) |
| Cloudflare Agent Readiness | Descoberta/legibilidade por agentes de IA — ver o trabalho no header `Link` em [PR #154](https://github.com/blindtk/personal-site/pull/154) | [isitagentready.com](https://isitagentready.com/danielmala.co) |
| MXToolbox | Lookups DNS/email ad-hoc (blacklists, sintaxe SPF/DMARC) | [mxtoolbox.com](https://mxtoolbox.com/) |
