// Alvo de fuzzing: sanitizeText(input, maxLen) e escapeHtml(str) —
// dynamic/worker/src/lib/sanitize.js. Alvo clássico de fuzzing (sanitizadores
// de output derivado de fontes externas). A única asserção que interessa é
// "não crasha / não lança exceção não tratada" — o comportamento funcional
// já está coberto por vetores conhecidos em
// dynamic/worker/test/sanitize.test.mjs (node --test).
import { sanitizeText, escapeHtml } from "../../dynamic/worker/src/lib/sanitize.js";

/**
 * @param { Buffer } data
 */
export function fuzz(data) {
	const text = data.toString("utf8");
	sanitizeText(text, data.length % 200);
	escapeHtml(text);
}
