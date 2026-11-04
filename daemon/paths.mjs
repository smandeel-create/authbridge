import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

export function abHome() {
  return process.env.AUTHBRIDGE_HOME || path.join(os.homedir(), '.authbridge');
}
export function sockPath(home = abHome()) {
  return path.join(home, 'run', 'daemon.sock');
}
export function seBin() {
  return process.env.AUTHBRIDGE_SE_BIN || path.join(REPO, 'se', 'bin', 'authbridge-se');
}
