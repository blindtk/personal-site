// Durable Object dos Core Web Vitals: um único objeto global ("global") que é
// dono dos histogramas diários e do teto de amostras por dia.
//
// Porquê: no KV, `recordVitals` era ler → somar → escrever, e duas amostras
// concorrentes liam o mesmo histograma e uma desaparecia; o teto diário
// (`underCap`) tinha o mesmo defeito e deixava passar um pouco do limite
// (ver lib/kvcap.js). Um Durable Object é single-threaded e as suas
// operações de storage não se intercalam (input gates da plataforma), por
// isso ler-somar-escrever aqui é atómico: cada amostra aceite conta
// exatamente uma vez e o teto é exato.
//
// Efeito lateral bom: as escritas deixam de gastar o orçamento do KV (plano
// Free: ~1.000 escritas/dia para a conta) — o storage do DO tem quota própria.
//
// Classe "clássica" (fetch + constructor(state)), sem `extends
// DurableObject` de `cloudflare:workers`, para o `node --test` a poder
// importar. Só é alcançável pelo binding VITALS do Worker: não tem rota
// pública. Lógica de histograma em lib/vitals.js (pura).

import { emptyVitalsBucket, addVitals } from './vitals.js';

const DAY_MS = 86400_000;

/** Máximo de amostras aceites por dia UTC (o resto é descartado). */
export const VITALS_MAX_SAMPLES_PER_DAY = 1000;
/** Histogramas com mais dias do que isto são apagados (a janela lida é 7). */
export const VITALS_RETENTION_DAYS = 9;
export const VITALS_READ_DAYS = 7;

export const vitalsDayKey = (ms) => `vit:${new Date(ms).toISOString().slice(0, 10)}`; // vit:2026-07-24

export class VitalsCounter {
  constructor(state) {
    this.storage = state.storage;
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === 'POST' && url.pathname === '/record') {
      const { sample, now } = await request.json();
      return Response.json({ accepted: await this.record(sample, Number(now)) });
    }
    if (request.method === 'GET' && url.pathname === '/read') {
      return Response.json({ buckets: await this.read(Number(url.searchParams.get('now'))) });
    }
    return new Response(null, { status: 404 });
  }

  /** Conta a amostra no dia de `now`. false = teto do dia atingido (descartada). */
  async record(sample, now) {
    if (!Number.isFinite(now)) throw new Error('vitals_bad_now');
    const key = vitalsDayKey(now);
    const bucket = (await this.storage.get(key)) ?? emptyVitalsBucket();
    if (bucket.count >= VITALS_MAX_SAMPLES_PER_DAY) return false;
    addVitals(bucket, sample);
    await this.storage.put(key, bucket);
    // Só no 1.º registo do dia: o resto do dia não paga a listagem.
    if (bucket.count === 1) await this.prune(now);
    return true;
  }

  /** Os histogramas dos últimos 7 dias, hoje primeiro (null = dia sem dados). */
  async read(now) {
    if (!Number.isFinite(now)) throw new Error('vitals_bad_now');
    const keys = Array.from({ length: VITALS_READ_DAYS }, (_, i) => vitalsDayKey(now - i * DAY_MS));
    const found = await this.storage.get(keys);
    return keys.map((k) => found.get(k) ?? null);
  }

  async prune(now) {
    const oldest = vitalsDayKey(now - (VITALS_RETENTION_DAYS - 1) * DAY_MS);
    const all = await this.storage.list({ prefix: 'vit:' });
    const stale = [...all.keys()].filter((k) => k < oldest); // ISO → ordem lexical = cronológica
    if (stale.length) await this.storage.delete(stale);
  }
}
