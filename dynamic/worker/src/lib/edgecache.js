// Cache local do data center (Cache API, `caches.default`) — pura no sentido
// de não saber nada do router: recebe o objeto de cache por parâmetro, para
// os testes poderem passar um falso.
//
// Porquê (auditoria de segurança 2026-09-25, docs/security-audit-2026-09-25/):
// o KV do plano Free tem ~1.000 escritas/dia para a CONTA INTEIRA, e três
// coisas gastavam esse orçamento a partir de pedidos anónimos — o estado do
// rate limiter (2 puts por pedido aceite), a cache do relay HIBP (1 put por
// prefixo novo, escolhido pelo cliente) e as caches curtas de leitura. A
// Cache API não conta para nenhuma quota do KV: `match`/`put` são locais ao
// data center e grátis. O preço é a consistência — cada data center tem a
// sua cópia, e uma entrada pode ser despejada antes do max-age. Serve para
// dados que se podem recalcular (caches) e para contadores best-effort (rate
// limit por cliente, que no KV também não era consistente entre colos —
// propagação de ~60s, ver ADR 0003).
//
// As chaves vivem debaixo de /api/__cache/ na própria origem do pedido: é um
// path que só o Worker serve (rota danielmala.co/api/*) e que responde 404
// JSON a quem o pedir de fora — as entradas da Cache API nunca são servidas
// pela CDN a pedidos normais, mas assim nem por engano colidem com uma
// página do Pages.

/** Cache do data center, ou null fora do runtime da Cloudflare (Node, testes). */
export function edgeCache() {
  return globalThis.caches?.default ?? null;
}

/** URL-chave de uma entrada, na origem do pedido. */
export function edgeKey(requestUrl, key) {
  return new URL(`/api/__cache/${encodeURIComponent(key)}`, requestUrl).href;
}

/** Lê uma entrada JSON; null se não existe ou se o corpo não é JSON válido. */
export async function edgeGetJSON(cache, url) {
  const res = await cache.match(url);
  if (!res) return null;
  try {
    return await res.json();
  } catch {
    return null;
  }
}

/** Guarda `value` como JSON durante `ttlSec` segundos (mínimo 1). */
export async function edgePutJSON(cache, url, value, ttlSec) {
  const maxAge = Math.max(1, Math.ceil(ttlSec));
  await cache.put(url, new Response(JSON.stringify(value), {
    headers: { 'content-type': 'application/json', 'cache-control': `public, max-age=${maxAge}` },
  }));
}
