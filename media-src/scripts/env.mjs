// Ambiente comum a todas as chamadas à CLI do HyperFrames.
// - Telemetria desligada sempre: a CLI envia contadores de uso por omissão.
// - Sem conta HeyGen: nada aqui usa render na cloud, partilha ou modelos.
// - Browser: o Chrome do sistema (HF_BROWSER ou /usr/bin/google-chrome),
//   em vez de descarregar um.
import { existsSync } from 'node:fs';

export const FILMS = ['honeypot-pipeline', 'ci-pipeline'];

export function hfEnv() {
  const env = { ...process.env, HYPERFRAMES_NO_TELEMETRY: '1', DO_NOT_TRACK: '1' };
  const browser = process.env.HF_BROWSER ?? '/usr/bin/google-chrome';
  if (existsSync(browser)) env.HYPERFRAMES_BROWSER_PATH = browser;
  return env;
}
