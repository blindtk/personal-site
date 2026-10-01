// Alvo de fuzzing: as funções de dynamic/worker/src/lib/sanitize.js que
// recebem texto de fora sem confiança prévia (paths do honeypot, user-agents
// do firewall, feeds CISA/NVD, cabeçalhos cf-*). Não basta "não lança
// exceção" — estas funções são regex sobre strings e praticamente nunca
// lançam. Cada saída é verificada contra o contrato que a função promete;
// uma violação lança e o libFuzzer reporta-a como crash, com o input que a
// reproduz. Os vetores conhecidos continuam em
// dynamic/worker/test/logic.test.mjs (node --test); isto procura o que
// esses vetores não previram.
import {
	sanitizeText,
	escapeHtml,
	normalizeCountry,
	normalizeAsn,
	normalizeCveId,
} from "../../dynamic/worker/src/lib/sanitize.js";

function check(ok, what, input, output) {
	if (!ok) {
		throw new Error(
			`${what}: input=${JSON.stringify(input)} output=${JSON.stringify(output)}`,
		);
	}
}

function unescapeHtml(s) {
	return s
		.replaceAll("&#39;", "'")
		.replaceAll("&quot;", '"')
		.replaceAll("&gt;", ">")
		.replaceAll("&lt;", "<")
		.replaceAll("&amp;", "&");
}

/**
 * @param { Buffer } data
 */
export function fuzz(data) {
	if (data.length === 0) return;
	// 1.º byte → maxLen em [1, 256], independente do texto (antes era
	// data.length % 200, acoplado ao tamanho do input). Os chamadores usam
	// 24..160; 0 ou negativo não é uso válido e fica fora do contrato.
	const maxLen = data[0] + 1;
	const text = data.subarray(1).toString("utf8");

	// sanitizeText: texto plano, nunca markup, nunca maior que maxLen.
	const plain = sanitizeText(text, maxLen);
	check(!/[<>]/.test(plain), "sanitizeText deixou < ou >", text, plain);
	check(!/[\x00-\x1F\x7F]/.test(plain), "sanitizeText deixou controlo C0/DEL", text, plain);
	check(plain.length <= maxLen, `sanitizeText passou maxLen=${maxLen}`, text, plain);
	check(!/\s\s/.test(plain), "sanitizeText deixou espaços seguidos", text, plain);
	check(plain === plain.trimStart(), "sanitizeText deixou espaço inicial", text, plain);

	// escapeHtml: nenhum dos cinco caracteres fica cru, cada & abre uma das
	// cinco entidades, e o escape é reversível (sem duplo-escape nem perda).
	const escaped = escapeHtml(text);
	check(!/[<>"']/.test(escaped), "escapeHtml deixou caractere cru", text, escaped);
	check(!/&(?!amp;|lt;|gt;|quot;|#39;)/.test(escaped), "escapeHtml deixou & solto", text, escaped);
	check(unescapeHtml(escaped) === text, "escapeHtml não é reversível", text, escaped);

	// Normalizadores: ou o valor canónico, ou o valor de rejeição — nunca
	// outra coisa (é isto que entra nos buckets do KV).
	const country = normalizeCountry(text);
	check(country === "XX" || /^[A-Z]{2}$/.test(country), "normalizeCountry", text, country);

	const asn = normalizeAsn(text);
	check(
		asn === null || (Number.isInteger(asn) && asn >= 1 && asn <= 4_294_967_294),
		"normalizeAsn",
		text,
		asn,
	);

	const cve = normalizeCveId(text);
	check(cve === "" || /^CVE-\d{4}-\d{4,7}$/.test(cve), "normalizeCveId", text, cve);
}
