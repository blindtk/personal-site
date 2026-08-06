// Lógica pura (sem DOM, sem rede) da secção "Este Site" — formatação de
// números/bytes, tempo relativo, GROUP BY local e escala de barras. Vive aqui
// (e não dentro dos componentes) para poder ser testada em Node com vetores
// conhecidos, como o resto das ferramentas do site (ver CLAUDE.md). Os
// componentes/páginas importam estas funções e só fazem a ligação ao DOM.

/** Formata um inteiro com separadores de milhar no locale dado. */
export function formatNumber(n, locale = 'en-GB') {
  const v = Number(n);
  return Number.isFinite(v) ? v.toLocaleString(locale) : '—';
}

/** Bytes → string legível (B/KB/MB/GB/TB), base 1024, 1 casa decimal. */
export function formatBytes(bytes, locale = 'en-GB') {
  const v = Number(bytes);
  if (!Number.isFinite(v) || v <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(v) / Math.log(1024)));
  const scaled = v / 1024 ** i;
  const shown = i === 0 ? scaled : Number(scaled.toFixed(1));
  return `${shown.toLocaleString(locale)} ${units[i]}`;
}

/** Fração [0,1] → percentagem com `digits` casas (ex.: 0.1234 → "12.3%"). */
export function formatPercent(fraction, digits = 1) {
  const v = Number(fraction);
  if (!Number.isFinite(v)) return '—';
  return `${(v * 100).toFixed(digits)}%`;
}

/**
 * Tempo relativo compacto e determinístico entre dois instantes (ms epoch),
 * traduzido pelas unidades dadas. Sempre no passado ("há X" / "X ago").
 * Devolve { value, unit } para o chamador compor a string no seu idioma.
 */
export function relativeTime(fromMs, nowMs = Date.now()) {
  const secs = Math.max(0, Math.round((nowMs - Number(fromMs)) / 1000));
  const table = [
    ['year', 31536000],
    ['month', 2592000],
    ['day', 86400],
    ['hour', 3600],
    ['minute', 60],
    ['second', 1],
  ];
  for (const [unit, size] of table) {
    if (secs >= size || unit === 'second') {
      return { value: Math.floor(secs / size), unit };
    }
  }
  return { value: 0, unit: 'second' };
}

/**
 * GROUP BY local: agrega uma lista de objetos por `keyFn`, somando `valueFn`
 * (por omissão conta 1 por item). Devolve o top `limit` decrescente como
 * [{ key, value }]. É a peça que satisfaz "todos os GROUP BY feitos
 * localmente" — a API devolve linhas, a agregação acontece aqui.
 */
export function groupBy(rows, keyFn, valueFn = () => 1, limit = Infinity) {
  const acc = new Map();
  for (const row of Array.isArray(rows) ? rows : []) {
    const key = keyFn(row);
    if (key === null || key === undefined || key === '') continue;
    acc.set(key, (acc.get(key) ?? 0) + (Number(valueFn(row)) || 0));
  }
  return [...acc.entries()]
    .map(([key, value]) => ({ key, value }))
    .sort((a, b) => b.value - a.value)
    .slice(0, limit);
}

/**
 * Anexa a cada linha a largura de barra (0–100) relativa ao valor máximo da
 * lista, para desenhar barras horizontais sem depender de biblioteca de
 * gráficos (a CSP proíbe scripts externos). Máximo 0 → todas a 0.
 */
export function withBars(rows, valueKey = 'value') {
  const max = rows.reduce((m, r) => Math.max(m, Number(r?.[valueKey]) || 0), 0);
  return rows.map((r) => ({
    ...r,
    pct: max > 0 ? Math.round(((Number(r?.[valueKey]) || 0) / max) * 100) : 0,
  }));
}

/**
 * Caminhos SVG (linha + área) de um sparkline para uma série de valores, num
 * viewBox fixo (por omissão 100×30). Puro e determinístico — o desenho é só
 * SVG, sem biblioteca de gráficos (a CSP proíbe scripts externos). O chamador
 * usa a linha com vector-effect: non-scaling-stroke para o traço não distorcer
 * quando o viewBox estica na largura. Série vazia → caminhos vazios.
 */
export function sparkPath(values, { width = 100, height = 30, pad = 2 } = {}) {
  const arr = (Array.isArray(values) ? values : []).map((v) => Number(v) || 0);
  if (arr.length === 0) return { line: '', area: '', max: 0 };
  const max = Math.max(...arr, 1);
  const n = arr.length;
  const innerW = width - pad * 2;
  const innerH = height - pad * 2;
  const x = (i) => pad + (n === 1 ? innerW / 2 : (i / (n - 1)) * innerW);
  const y = (v) => pad + innerH - (v / max) * innerH;
  const pts = arr.map((v, i) => [x(i), y(v)]);
  const line = pts.map(([px, py], i) => `${i === 0 ? 'M' : 'L'}${px.toFixed(2)} ${py.toFixed(2)}`).join(' ');
  const base = height - pad;
  const area = `${line} L${x(n - 1).toFixed(2)} ${base.toFixed(2)} L${x(0).toFixed(2)} ${base.toFixed(2)} Z`;
  return { line, area, max };
}

/**
 * Taxa de ameaça: fração de pedidos classificados como ameaça. Defensiva a
 * zero/negativos/NaN — devolve sempre um número em [0,1].
 */
export function threatRate(threats, requests) {
  const t = Number(threats);
  const r = Number(requests);
  if (!Number.isFinite(t) || !Number.isFinite(r) || r <= 0) return 0;
  return Math.min(1, Math.max(0, t / r));
}

/**
 * Forma singular/plural pelas regras do idioma (Intl.PluralRules), não por
 * `n === 1` à mão. Os painéis mostram contagens reais e baixas — com 1 país
 * ou 1 toque, o texto lia-se "1 países de origem" / "1 toques".
 * `forms` é { one, other }; sem correspondência devolve `other`.
 */
export function plural(n, forms, locale = 'en-GB') {
  const rule = new Intl.PluralRules(locale).select(Number(n) || 0);
  return forms[rule] ?? forms.other ?? '';
}

/**
 * Classe de uma ação de firewall da Cloudflare, para o painel não pintar
 * tudo de âmbar como se fosse ameaça. Três classes:
 *   'blocked'   — o pedido não passou (block, drop);
 *   'challenged'— foi desafiado/atrasado (managed_challenge, js_challenge,
 *                 e o link_maze da AI Labyrinth);
 *   'allowed'   — passou (skip/allow, e os desafios que o cliente RESOLVEU:
 *                 *_bypassed, *_solved — são visitantes legítimos, não
 *                 ataques bloqueados).
 * A ordem importa: 'managed_challenge_bypassed' contém 'challenge', por isso
 * os sufixos de resolução testam-se primeiro. Puro e testável.
 */
export function firewallActionClass(action) {
  const a = String(action ?? '').toLowerCase();
  if (/(bypassed|solved|allow|^skip$|^log$)/.test(a)) return 'allowed';
  if (/(block|drop)/.test(a)) return 'blocked';
  if (/(challenge|maze)/.test(a)) return 'challenged';
  return 'allowed';
}

/** Tom de barra correspondente à classe (undefined = neutro). */
export function firewallActionTone(action) {
  const cls = firewallActionClass(action);
  if (cls === 'blocked') return 'down';
  if (cls === 'challenged') return 'warn';
  return undefined;
}

/** Soma as linhas {key,count} cuja classe (firewallActionClass) está em `classes`. */
export function sumByActionClass(rows, classes) {
  return (Array.isArray(rows) ? rows : []).reduce((sum, r) => {
    const n = Number(r?.count) || 0;
    return classes.includes(firewallActionClass(r?.key)) ? sum + n : sum;
  }, 0);
}

/**
 * Reparte a série diária crua da firewall (`firewall7d.daily`, do Worker —
 * `[{date, byAction}]`) em bloqueado/desafiado/passado por dia, pela mesma
 * classificação de `firewallActionClass`. Sem isto, dois dias de natureza
 * oposta (um de ataque a sério, outro de tráfego humano a resolver desafios)
 * ficavam indistinguíveis quando só se via o total da semana — ver dashboard
 * "Mitigação por dia".
 */
export function classifyDaily(daily) {
  return (Array.isArray(daily) ? daily : []).map(({ date, byAction }) => {
    let blocked = 0;
    let challenged = 0;
    let allowed = 0;
    for (const [action, count] of Object.entries(byAction ?? {})) {
      const n = Number(count) || 0;
      const cls = firewallActionClass(action);
      if (cls === 'blocked') blocked += n;
      else if (cls === 'challenged') challenged += n;
      else allowed += n;
    }
    return { date, blocked, challenged, allowed, total: blocked + challenged + allowed };
  });
}

/**
 * Posição X numa escala logarítmica de `min`..`max`, mapeada para
 * `rangeMin`..`rangeMax`. Valores fora do domínio (incl. ≤0) clampam ao
 * extremo — nunca devolve NaN/Infinity, mesmo com 1 pedido contra um domínio
 * que começa em 1. `min`/`max` iguais degrada para o centro do range.
 */
export function logScaleX(value, { min, max, rangeMin, rangeMax }) {
  if (!(min > 0) || !(max > min)) return (rangeMin + rangeMax) / 2;
  const v = Math.max(min, Math.min(max, Number(value) || min));
  const t = (Math.log10(v) - Math.log10(min)) / (Math.log10(max) - Math.log10(min));
  return rangeMin + t * (rangeMax - rangeMin);
}

/**
 * Raio de um círculo de ÁREA proporcional a `value` (escala em raiz
 * quadrada — a perceção de tamanho num scatter é pela área, não pelo raio),
 * com um mínimo para o ponto continuar clicável/visível mesmo a valor 0.
 */
export function areaRadius(value, { minR = 4, k = 1 } = {}) {
  return Math.max(minR, k * Math.sqrt(Math.max(0, Number(value) || 0)));
}

/**
 * Escolhe, entre os certificados devolvidos por /api/ct, o mais provável de
 * estar ATIVO agora: válido no instante `now` (notBefore ≤ now ≤ notAfter),
 * cobrindo o domínio exato (não só um wildcard/subdomínio) e de emissor
 * esperado. O CT não diz qual certificado a Cloudflare está de facto a
 * servir (podem coexistir vários válidos, ex. primário + backup) — o
 * desempate é pelo `notBefore` mais recente (o mais provável de ser o
 * "atual") e, ainda empatado, pelo `notAfter` mais distante. `null` se
 * nenhum bater — nesse caso, não há um certificado válido do próprio
 * domínio nem de emissor esperado nesta janela: um sinal em si mesmo, não
 * apenas dados em falta.
 */
export function currentCertificate(certs, { domain = '', now = Date.now() } = {}) {
  const candidates = (Array.isArray(certs) ? certs : []).filter(
    (c) => c && c.notBefore <= now && c.notAfter >= now
      && Array.isArray(c.names) && c.names.includes(domain) && c.expected,
  );
  if (candidates.length === 0) return null;
  candidates.sort((a, b) => b.notBefore - a.notBefore || b.notAfter - a.notAfter);
  return candidates[0];
}

/** Dias inteiros até `ms` (arredondado para cima; nunca negativo). */
export function daysUntil(ms, now = Date.now()) {
  return Math.max(0, Math.ceil((Number(ms) - now) / 86400_000));
}

/** Percentagem [0,100] já decorrida do intervalo [notBefore, notAfter]. */
export function certProgressPct(notBefore, notAfter, now = Date.now()) {
  const span = Number(notAfter) - Number(notBefore);
  if (!(span > 0)) return 0;
  return Math.min(100, Math.max(0, Math.round(((now - notBefore) / span) * 100)));
}
