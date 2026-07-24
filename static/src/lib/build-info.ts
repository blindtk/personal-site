/**
 * Metadados de build/deploy — resolvidos UMA vez no build (SSG), a partir do
 * git e do package.json. Alimenta o painel "Estado" da Visão Geral (versão,
 * commit, branch, quando foi feito o deploy). Tudo degrada para valores
 * seguros: se o git não existir no ambiente de build (ex.: tarball sem .git),
 * cai para 'unknown' em vez de rebentar o build.
 *
 * Só corre no servidor/build — NUNCA é enviado lógica de git para o cliente;
 * o resultado é um objeto estático embebido no HTML.
 */
import { execSync } from 'node:child_process';
// Vite resolve o import de JSON no build (mesmo padrão dos imports de
// content/*.json noutras páginas) — robusto ao contexto de bundling, ao
// contrário de ler o ficheiro por import.meta.url.
import pkg from '../../package.json';

function git(args: string, fallback = 'unknown'): string {
  try {
    return execSync(`git ${args}`, { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString()
      .trim() || fallback;
  } catch {
    return fallback;
  }
}

export interface BuildInfo {
  version: string;
  commit: string;
  branch: string;
  /** ISO 8601 do último commit (proxy da fonte do deploy). */
  commitDate: string;
  /** ISO 8601 do momento do build (proxy do deploy). */
  builtAt: string;
}

export const BUILD_INFO: BuildInfo = {
  version: (pkg as { version?: string }).version ?? '0.0.0',
  commit: git('rev-parse --short HEAD'),
  branch: git('rev-parse --abbrev-ref HEAD'),
  commitDate: git('log -1 --format=%cI', ''),
  builtAt: new Date().toISOString(),
};
