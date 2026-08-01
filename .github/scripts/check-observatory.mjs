// Consulta a API pública do Mozilla HTTP Observatory
// (observatory-api.mdn.mozilla.net) contra a produção — uma segunda
// grelha de avaliação, independente do check-headers.mjs: este último só
// confirma presença/valor exato de cada header já decidido; o Observatory
// testa também cookies, cadeia de redirects, isolamento cross-origin, etc.
// contra a rubrica pública dele, podendo apanhar algo que a nossa lista
// não cobre. API grátis, sem chave, feita de propósito para CI/CD (rate
// limit de 1 scan/host/minuto — devolve resultado em cache se excedido).
// Ver https://github.com/mdn/mdn-http-observatory.
//
// Alvo, mesmo padrão do check-headers.mjs:
//   1. TARGET_URL — input manual do workflow_dispatch
//   2. url        — valor versionado em .github/expected-headers.json
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const cfgPath = join(dirname(fileURLToPath(import.meta.url)), '..', 'expected-headers.json');
const cfg = JSON.parse(readFileSync(cfgPath, 'utf8'));
const target = process.env.TARGET_URL || cfg.url;

if (!target || target.startsWith('SET-ME')) {
  console.log('::warning::check-observatory: URL de produção por definir em .github/expected-headers.json — verificação IGNORADA (nada foi verificado nesta execução).');
  process.exit(0);
}

const host = new URL(target).host;
const API_URL = `https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${encodeURIComponent(host)}`;

// Timeout evita bloquear o job durante horas se a API ficar pendurada — sem
// isto, um hang ficava só limitado pelo timeout por omissão do GitHub
// Actions (360 min), não por nada que este script controle. Uma repetição
// cobre o 500 transitório já documentado do Observatory no primeiro scan de
// um host novo (achado do CodeRabbit no PR #155, confirmado) — como o alvo
// é sempre o mesmo host, isto só costuma importar na primeiríssima execução.
const REQUEST_TIMEOUT_MS = 30_000;

async function requestScan(attempt = 1) {
  let res;
  try {
    res = await fetch(API_URL, { method: 'POST', signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
  } catch (err) {
    if (attempt < 2) {
      console.log(`::warning::check-observatory: pedido falhou na tentativa ${attempt} (${err?.message ?? err}) — a repetir…`);
      return requestScan(attempt + 1);
    }
    console.error(`::error::check-observatory: pedido à API falhou — ${err?.message ?? err}`);
    process.exit(1);
  }
  if (!res.ok && attempt < 2) {
    console.log(`::warning::check-observatory: API respondeu HTTP ${res.status} na tentativa ${attempt} — a repetir…`);
    return requestScan(attempt + 1);
  }
  return res;
}

console.log(`A pedir scan do Mozilla HTTP Observatory para ${host}…`);
const res = await requestScan();
if (!res.ok) {
  console.error(`::error::check-observatory: API respondeu HTTP ${res.status} (${host})`);
  process.exit(1);
}

const result = await res.json();

if (result.error) {
  // O próprio Observatory não conseguiu avaliar o alvo (ex.: DNS, timeout)
  // — isto é uma falha real da verificação, não "grade baixa".
  console.error(`::error::check-observatory: o Observatory não conseguiu avaliar ${host} — ${result.error}`);
  process.exit(1);
}

const grade = String(result.grade ?? '?');
console.log(`Observatory: ${host} → grade ${grade} (score ${result.score}, ${result.tests_passed}/${result.tests_quantity} testes passados)`);
console.log(`Detalhe: ${result.details_url}`);

if (result.status_code && result.status_code !== 200) {
  console.log(`::warning::Observatory viu HTTP ${result.status_code} em vez de 200 ao pedir ${host} — pode ser um redirect inesperado ou o scanner a ser bloqueado.`);
}

// A produção já passa pelo check-headers.mjs (headers exatos) — um grade
// abaixo de A aqui sinaliza algo que essa lista não cobre; D/F é tratado
// como regressão séria (falha o job), B/C como aviso (vale a pena olhar,
// não é urgente).
const band = grade[0];
if (band === 'D' || band === 'F') {
  console.error(`::error::Observatory grade ${grade} para ${host} — ver ${result.details_url}.`);
  process.exit(1);
}
if (band === 'B' || band === 'C') {
  console.log(`::warning::Observatory grade ${grade} para ${host} (abaixo de A) — ver ${result.details_url}.`);
}

console.log('Verificação do Observatory concluída.');
