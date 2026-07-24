// Captor de violações CSP — first-party, 100% local. A CSP já não tem
// report-uri/report-to (ver _headers): nada sai do browser sozinho. Este
// script só ouve o evento nativo securitypolicyviolation e guarda o mínimo
// em sessionStorage; o envio real só acontece se a pessoa clicar "Reportar"
// na página Provas (CspViolations.astro), que lê esta fila. Fora
// desse clique, zero pedidos de rede — é a poupança de escritas no KV do
// Worker (plano Free) que motivou a mudança.
(function () {
  if (!('addEventListener' in document)) return;

  var KEY = 'cspq';
  var MAX = 20;

  function load() {
    try {
      var raw = sessionStorage.getItem(KEY);
      var list = raw ? JSON.parse(raw) : [];
      return Array.isArray(list) ? list : [];
    } catch (e) {
      return [];
    }
  }

  function save(list) {
    try { sessionStorage.setItem(KEY, JSON.stringify(list)); } catch (e) { /* storage indisponível */ }
  }

  document.addEventListener('securitypolicyviolation', function (e) {
    var directive = e.effectiveDirective || e.violatedDirective || '';
    var blocked = e.blockedURI || '';
    var list = load();
    var key = directive + '|' + blocked;
    // Dedup: uma extensão barulhenta dispara o mesmo par diretiva/origem
    // repetidamente por página — só a 1.ª ocorrência interessa à fila.
    for (var i = 0; i < list.length; i++) {
      if ((list[i].d + '|' + list[i].b) === key) return;
    }
    list.push({ d: directive, b: blocked, u: location.href });
    save(list.slice(-MAX));
  });
})();
