// Correlação Honeypot ↔ ATT&CK ↔ ticker SOC (lookup local, sem rede).
// Puro e testável. Duas responsabilidades:
//   1) path-isco → técnica ATT&CK (mesmos IDs de content/attack.json);
//   2) texto de um CVE (KEV/NVD) → técnica(s) prováveis, por heurística de
//      palavras-chave, para cruzar com os paths tentados no honeypot.
//
// A fonte de verdade do mapa de paths é content/honeypot-attack.json; a cópia
// abaixo existe porque o Worker é um bundle independente (não importa content/).
// O teste `attack-map sincroniza com content/honeypot-attack.json` garante que
// as duas não divergem.

/** path tentado → ID de técnica ATT&CK. Sincronizado com content/. */
export const PATH_TECHNIQUE = {
  '/wp-login.php': 'T1110',
  '/.env': 'T1592',
  '/.git/config': 'T1592',
  '/admin': 'T1595',
  '/phpmyadmin/': 'T1190',
};

/** Técnica de um path-isco, ou null se o path não estiver mapeado. */
export function techniqueForPath(path) {
  return PATH_TECHNIQUE[path] ?? null;
}

// Heurística conservadora: só se atribui técnica a um CVE quando o texto
// (nome/descrição da vuln) casa claramente com um padrão. Sem match → sem
// técnica → o CVE não participa na correlação (degrada em silêncio, nunca
// inventa uma associação). A ordem é a de precedência de leitura, mas
// devolvem-se todas as técnicas que casam.
const KEV_KEYWORDS = [
  ['T1110', [/brute[\s-]?forc/, /credential stuffing/, /\bpassword\b/, /authentication bypass/, /auth bypass/, /weak (password|credential)/]],
  ['T1190', [/remote code execution/, /\brce\b/, /command (execution|injection)/, /code injection/, /sql injection/, /deserializ/, /arbitrary code/, /unauthenticated/, /server[\s-]?side request forgery/, /\bssrf\b/]],
  ['T1592', [/path traversal/, /directory traversal/, /information disclosure/, /arbitrary file (read|disclosure)/, /file read/, /exposure of sensitive/, /sensitive information/]],
  ['T1595', [/enumerat/, /\bscanning\b/]],
];

/**
 * Técnicas prováveis de um CVE a partir do seu texto descritivo.
 * Devolve um array de IDs (possivelmente vazio), sem repetições.
 */
export function techniquesForText(text) {
  if (typeof text !== 'string' || !text) return [];
  const lower = text.toLowerCase();
  const out = [];
  for (const [id, patterns] of KEV_KEYWORDS) {
    if (patterns.some((re) => re.test(lower)) && !out.includes(id)) out.push(id);
  }
  return out;
}
