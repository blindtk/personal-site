/**
 * Resumo agregado do honeypot externo, mostrado na página do projeto
 * Threat Intel.
 *
 * Tal como o catálogo de estrelas (lib/catalog.ts), o ficheiro é gerado fora
 * deste repo e chega por pull request como content/intel-summary.json — ver
 * docs/intel-sync.md. Não há fetch no build nem no browser.
 *
 * Ao contrário do catálogo, o ficheiro é OPCIONAL: enquanto o repo do
 * honeypot não o entregar, `intelSummary` é `null` e a secção não aparece.
 * Nunca há dados de exemplo no lugar dele. Se o ficheiro existir e o schema
 * não bater (ou trouxer algo com forma de IP), o build falha.
 */
import { parseIntelSummary } from '../scripts/intel-summary.js';

export interface IntelSummary {
  generatedAt: string;
  windowDays: number;
  totals: { events: number; sources: number; sessions: number };
  techniques: { id: string; name: string; count: number }[];
  usernames: { name: string; count: number }[];
  stale: boolean;
}

// import.meta.glob e não um import estático: um ficheiro ausente dá um
// objeto vazio em vez de falhar a resolução do módulo.
const found = import.meta.glob<{ default: unknown }>('../../../content/intel-summary.json', { eager: true });
const raw = Object.values(found)[0]?.default;

const parsed: IntelSummary | null = raw === undefined ? null : parseIntelSummary(raw);

/** `null` sem ficheiro ou com um resumo demasiado antigo para se chamar "recente". */
export const intelSummary: IntelSummary | null = parsed && !parsed.stale ? parsed : null;
