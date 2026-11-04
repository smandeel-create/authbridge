import crypto from 'node:crypto';

export class PairCodes {
  constructor({ ttlMs = 600000, maxAttempts = 5, now = () => Date.now() } = {}) {
    this.ttlMs = ttlMs; this.maxAttempts = maxAttempts; this.now = now; this.cur = null;
  }
  create() {
    const code = String(crypto.randomInt(0, 100000000)).padStart(8, '0');
    this.cur = { code, expires: this.now() + this.ttlMs, attempts: 0 };
    return { code, expires_at: this.cur.expires };
  }
  // true only for the right code; one-time; wrong guesses count and invalidate after maxAttempts
  verify(candidate) {
    const c = this.cur;
    if (!c) return false;
    if (this.now() > c.expires) { this.cur = null; return false; }
    const a = Buffer.from(String(candidate ?? '').padEnd(8, ' ').slice(0, 8));
    const b = Buffer.from(c.code);
    const ok = String(candidate) === c.code && crypto.timingSafeEqual(a, b);
    if (ok) { this.cur = null; return true; }
    c.attempts++;
    if (c.attempts >= this.maxAttempts) this.cur = null;
    return false;
  }
  active() { return !!this.cur && this.now() <= this.cur.expires; }
}
