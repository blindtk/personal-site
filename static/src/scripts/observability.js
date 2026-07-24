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
 * Taxa de ameaça: fração de pedidos classificados como ameaça. Defensiva a
 * zero/negativos/NaN — devolve sempre um número em [0,1].
 */
export function threatRate(threats, requests) {
  const t = Number(threats);
  const r = Number(requests);
  if (!Number.isFinite(t) || !Number.isFinite(r) || r <= 0) return 0;
  return Math.min(1, Math.max(0, t / r));
}
