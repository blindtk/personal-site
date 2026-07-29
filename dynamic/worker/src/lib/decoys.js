// Paths-isco do honeypot: decisão de match, pura e testável. As rotas
// equivalentes (`routes = [...]`) vivem em wrangler.toml — é lá que a
// Cloudflare decide que pedidos chegam ao Worker; aqui decide-se quais
// desses pedidos contam como isco. As duas listas têm de bater certo (ver
// test/logic.test.mjs, "decoys: DECOYS cobre as routes do wrangler.toml") —
// já divergiram uma vez (revisão de segurança 2026-07, ronda 4, N5):
// `danielmala.co/phpmyadmin/*` é um glob no wrangler.toml (a Cloudflare
// manda `/phpmyadmin/index.php`, `/phpmyadmin/setup.php` — os paths que os
// scanners reais pedem — para o Worker), mas DECOYS tinha `/phpmyadmin/`
// como string exata: esses pedidos caíam no fim do router e recebiam o 404
// JSON da API (com `Vary: Origin` e os headers do Worker) em vez do 404
// HTML disfarçado — perdia-se o evento no honeypot E denunciava-se o Worker
// a quem estivesse a sondar.
//
// Convenção: uma entrada terminada em '/' cobre o próprio path e tudo por
// baixo dele (prefixo) — para os iscos declarados como glob no
// wrangler.toml. Uma entrada sem '/' final é match exato.
export const DECOYS = ['/wp-login.php', '/.env', '/admin', '/phpmyadmin/', '/.git/config'];

/** true se `path` corresponde a algum isco (exato ou por prefixo, ver acima). */
export function isDecoy(path) {
  for (const decoy of DECOYS) {
    if (decoy.endsWith('/') ? path.startsWith(decoy) : path === decoy) return true;
  }
  return false;
}
