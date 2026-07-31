// Alvo de fuzzing: parseReports(text, contentType) — dynamic/worker/src/lib/csp-report.js.
// É a função pura de maior valor real para fuzzing: processa o corpo bruto
// que qualquer browser de visitante pode enviar ao endpoint de relatórios
// CSP, ao contrário das ferramentas client-side de /ferramentas/ (essas não
// são fronteira de confiança real). A única asserção que interessa aqui é
// "não crasha / não lança exceção não tratada" — o comportamento funcional
// já está coberto por vetores conhecidos em
// dynamic/worker/test/csp-report.test.mjs (node --test).
import { parseReports, REPORT_CONTENT_TYPES } from "../../dynamic/worker/src/lib/csp-report.js";

const CONTENT_TYPES = [...REPORT_CONTENT_TYPES, "text/plain", ""];

/**
 * @param { Buffer } data
 */
export function fuzz(data) {
	if (data.length === 0) return;
	const contentType = CONTENT_TYPES[data[0] % CONTENT_TYPES.length];
	const text = data.subarray(1).toString("utf8");
	parseReports(text, contentType);
}
