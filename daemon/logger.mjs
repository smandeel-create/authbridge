// Logger with a redaction guard: any field whose name contains a forbidden word as a token is replaced.
import fs from 'node:fs';
import path from 'node:path';

const FORBIDDEN = new Set([
  'password', 'passwd', 'share', 'code', 'secret', 'key', 'plaintext', 'token',
  's1', 'k', 'p', 'sealed', 'ct', 'nonce', 'epk', 'priv', 'private', 'pass',
]);

function tokens(name) {
  return String(name)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

export function isForbiddenName(name) {
  return tokens(name).some((t) => FORBIDDEN.has(t));
}

export function redact(value, depth = 0) {
  if (depth > 6) return '[deep]';
  if (value === null || value === undefined) return value;
  if (Buffer.isBuffer(value) || value instanceof Uint8Array) return '[binary]';
  if (value instanceof Error) return { error: String(value.message).slice(0, 200) };
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => redact(v, depth + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = isForbiddenName(k) ? '[REDACTED]' : redact(v, depth + 1);
    }
    return out;
  }
  if (typeof value === 'string') return value.length > 300 ? value.slice(0, 300) + '...' : value;
  return value;
}

export function createLogger({ file = null, sink = null } = {}) {
  if (file) fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  function write(level, msg, fields) {
    const line = JSON.stringify({ t: new Date().toISOString(), level, msg: String(msg), ...(fields ? { f: redact(fields) } : {}) });
    if (sink) sink.push(line);
    if (file) {
      try { fs.appendFileSync(file, line + '\n', { mode: 0o600 }); } catch { /* ignore */ }
    }
  }
  return {
    info: (m, f) => write('info', m, f),
    warn: (m, f) => write('warn', m, f),
    error: (m, f) => write('error', m, f),
  };
}
