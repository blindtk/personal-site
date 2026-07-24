// Beacon de Core Web Vitals — first-party, mede no browser e envia UMA vez,
// agregado, para POST /api/vitals (Worker). NÃO é um tracker: não há cookies,
// nem ID de sessão, nem envio de URL/UA/IP — só quatro números (LCP/CLS/INP/
// TTFB) desta visita, que o servidor conta num histograma e deita fora. É por
// isto que se usa código próprio e não o beacon de RUM da Cloudflare (script
// de terceiros, incompatível com a CSP e com o "sem trackers" do site).
//
// Ficheiro estático em public/js/ (não passa pelo bundler do Astro) — fica
// fora do bundle e nunca é inlinado, tal como o nav.js.
(function () {
  if (!('PerformanceObserver' in window)) return;

  var data = {};
  try {
    var nav = performance.getEntriesByType('navigation')[0];
    if (nav && nav.responseStart > 0) data.ttfb = Math.round(nav.responseStart);
  } catch (e) { /* sem navigation timing */ }

  var lcp = 0;
  var cls = 0;
  var inp = 0;

  function observe(type, cb, opts) {
    try {
      var po = new PerformanceObserver(function (list) {
        var entries = list.getEntries();
        for (var i = 0; i < entries.length; i++) cb(entries[i]);
      });
      var o = { type: type, buffered: true };
      if (opts) for (var k in opts) o[k] = opts[k];
      po.observe(o);
      return po;
    } catch (e) { return null; }
  }

  // LCP: fica o maior (o observer emite candidatos crescentes).
  observe('largest-contentful-paint', function (e) { lcp = e.startTime; });
  // CLS: soma os deslocamentos sem interação recente.
  observe('layout-shift', function (e) { if (!e.hadRecentInput) cls += e.value; });
  // INP (aproximação): maior duração de interação observada.
  observe('event', function (e) { if (e.duration > inp) inp = e.duration; }, { durationThreshold: 40 });
  observe('first-input', function (e) {
    var d = e.processingStart - e.startTime;
    if (d > inp) inp = d;
  });

  var sent = false;
  function send() {
    if (sent) return;
    sent = true;
    if (lcp > 0) data.lcp = Math.round(lcp);
    if (cls > 0) data.cls = Math.round(cls * 1000) / 1000;
    if (inp > 0) data.inp = Math.round(inp);
    if (Object.keys(data).length === 0) return;
    var body = JSON.stringify(data);
    try {
      if (navigator.sendBeacon) navigator.sendBeacon('/api/vitals', body);
      else fetch('/api/vitals', { method: 'POST', body: body, keepalive: true });
    } catch (e) { /* offline / bloqueado: perde-se esta amostra, sem efeito */ }
  }

  // Envia quando a página fica oculta (mais fiável que 'unload' em mobile).
  addEventListener('visibilitychange', function () {
    if (document.visibilityState === 'hidden') send();
  });
  addEventListener('pagehide', send);
})();
