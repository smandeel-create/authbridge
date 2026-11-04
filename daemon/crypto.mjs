import crypto from 'node:crypto';
import { execFile } from 'node:child_process';

export const b64 = (b) => Buffer.from(b).toString('base64');
export const unb64 = (s) => Buffer.from(String(s), 'base64');
const u8 = (s) => Buffer.from(s, 'utf8');

export function hkdf(ikm, salt, info, len = 32) {
  return Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, len));
}

// ---- Secure Enclave helper -------------------------------------------------
export function makeSE({ bin, home }) {
  const run = (args) => new Promise((resolve, reject) => {
    execFile(bin, args, { env: { ...process.env, AUTHBRIDGE_HOME: home }, maxBuffer: 1 << 16 }, (err, stdout) => {
      if (err) reject(new Error('se_helper_failed'));
      else resolve(stdout.trim());
    });
  });
  let pubCache = null;
  return {
    init: async () => { pubCache = await run(['init']); return pubCache; },
    pubkey: async () => (pubCache ??= await run(['pubkey'])),
    derive: (peerB64) => run(['derive', peerB64]),
  };
}

// ---- X25519 helpers + sealed box ------------------------------------------
const bu = (b) => Buffer.from(b).toString('base64url');
const xPub = (raw) => crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: bu(raw) }, format: 'jwk' });
const xPriv = (d, x) => crypto.createPrivateKey({ key: { kty: 'OKP', crv: 'X25519', d: bu(d), x: bu(x) }, format: 'jwk' });

export function x25519Generate() {
  const { privateKey } = crypto.generateKeyPairSync('x25519');
  const j = privateKey.export({ format: 'jwk' });
  return { priv: Buffer.from(j.d, 'base64url'), pub: Buffer.from(j.x, 'base64url') };
}

function sealKey(ss, epk, recipientPub) {
  return hkdf(ss, Buffer.concat([epk, recipientPub]), u8('authbridge-seal-v1'), 32);
}

export function seal(recipientPub, plaintext, aad) {
  const eph = x25519Generate();
  const ss = crypto.diffieHellman({ privateKey: xPriv(eph.priv, eph.pub), publicKey: xPub(recipientPub) });
  const key = sealKey(ss, eph.pub, recipientPub);
  const nonce = crypto.randomBytes(12);
  const pt = Buffer.from(plaintext);
  const c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
  c.setAAD(u8(aad), { plaintextLength: pt.length });
  const ct = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]);
  key.fill(0); ss.fill(0);
  return { epk: b64(eph.pub), nonce: b64(nonce), ct: b64(ct) };
}

// returns Buffer; throws on any failure
export function open(recipientPriv, recipientPub, sealed, aad) {
  const epk = unb64(sealed?.epk), nonce = unb64(sealed?.nonce), ctt = unb64(sealed?.ct);
  if (epk.length !== 32 || nonce.length !== 12 || ctt.length < 16) throw new Error('bad_sealed');
  const ss = crypto.diffieHellman({ privateKey: xPriv(recipientPriv, recipientPub), publicKey: xPub(epk) });
  const key = sealKey(ss, epk, recipientPub);
  try {
    const d = crypto.createDecipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 });
    const ct = ctt.subarray(0, ctt.length - 16);
    d.setAAD(u8(aad), { plaintextLength: ct.length });
    d.setAuthTag(ctt.subarray(ctt.length - 16));
    return Buffer.concat([d.update(ct), d.final()]);
  } catch {
    throw new Error('open_failed');
  } finally { key.fill(0); ss.fill(0); }
}

// ---- Credential storage (split key) ----------------------------------------
export function deriveK(S1, P, recordId, domain) {
  const ikm = Buffer.concat([S1, P]);
  const K = hkdf(ikm, u8(recordId), u8('authbridge-v1|' + domain), 32);
  ikm.fill(0);
  return K;
}

function ecdhToSE(sePubB64) {
  const e = crypto.createECDH('prime256v1');
  e.generateKeys();
  return { S1: e.computeSecret(unb64(sePubB64)), epub: e.getPublicKey() };
}

function gcmEncrypt(K, plaintext, aad) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', K, nonce);
  c.setAAD(u8(aad));
  const ct = Buffer.concat([c.update(plaintext), c.final(), c.getAuthTag()]);
  return { nonce: b64(nonce), ct: b64(ct) };
}
function gcmDecrypt(K, nonceB64, ctB64, aad) {
  const all = unb64(ctB64);
  if (all.length < 16) throw new Error('decrypt');
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', K, unb64(nonceB64));
    d.setAAD(u8(aad));
    d.setAuthTag(all.subarray(all.length - 16));
    return Buffer.concat([d.update(all.subarray(0, all.length - 16)), d.final()]);
  } catch { throw new Error('decrypt'); }
}

export async function encryptCredential(se, { record_id, domain, username, password, email }, P) {
  const { S1, epub } = ecdhToSE(await se.pubkey());
  const K = deriveK(S1, P, record_id, domain);
  const pt = Buffer.from(JSON.stringify({ username, password, ...(email ? { email } : {}) }), 'utf8');
  const out = gcmEncrypt(K, pt, record_id + '|' + domain);
  pt.fill(0); K.fill(0); S1.fill(0);
  return { epub: b64(epub), ...out };
}

// returns plaintext Buffer (JSON). Throws Error('decrypt').
export async function decryptCredential(se, rec, P) {
  let S1;
  try { S1 = unb64(await se.derive(rec.epub)); } catch { throw new Error('decrypt'); }
  const K = deriveK(S1, P, rec.record_id, rec.domain);
  try { return gcmDecrypt(K, rec.nonce, rec.ct, rec.record_id + '|' + rec.domain); }
  finally { K.fill(0); S1.fill(0); }
}

// Decrypts rec with P, applies edit(creds) -> creds, re-encrypts under the same K with a fresh nonce.
// Returns {nonce, ct}. Throws Error('decrypt') on any GCM/SE failure. Wipes all plaintext buffers.
export async function updateCredential(se, rec, P, edit) {
  let S1;
  try { S1 = unb64(await se.derive(rec.epub)); } catch { throw new Error('decrypt'); }
  const K = deriveK(S1, P, rec.record_id, rec.domain);
  const aad = rec.record_id + '|' + rec.domain;
  let plain = null, pt = null;
  try {
    plain = gcmDecrypt(K, rec.nonce, rec.ct, aad);
    let creds;
    try { creds = JSON.parse(plain.toString('utf8')); } catch { throw new Error('decrypt'); }
    creds = edit(creds);
    pt = Buffer.from(JSON.stringify(creds), 'utf8');
    return gcmEncrypt(K, pt, aad);
  } finally { plain?.fill(0); pt?.fill(0); K.fill(0); S1.fill(0); }
}

// Generic SE-wrapped blob (used for the Mac's X25519 private key at rest)
export async function wrapBlob(se, plaintext, label) {
  const { S1, epub } = ecdhToSE(await se.pubkey());
  const K = hkdf(S1, Buffer.alloc(0), u8('authbridge-wrap-v1|' + label), 32);
  const out = gcmEncrypt(K, plaintext, label);
  K.fill(0); S1.fill(0);
  return { epub: b64(epub), ...out };
}
export async function unwrapBlob(se, w, label) {
  const S1 = unb64(await se.derive(w.epub));
  const K = hkdf(S1, Buffer.alloc(0), u8('authbridge-wrap-v1|' + label), 32);
  try { return gcmDecrypt(K, w.nonce, w.ct, label); } finally { K.fill(0); S1.fill(0); }
}

// ---- Request signing -------------------------------------------------------
export function signingString(method, path, ts, nonce, body) {
  const h = crypto.createHash('sha256').update(body ?? Buffer.alloc(0)).digest('hex');
  return u8([method, path, ts, nonce, h].join('\n'));
}

export class ReplayCache {
  constructor(ttlMs = 120000) { this.ttl = ttlMs; this.seen = new Map(); }
  check(nonce, now = Date.now()) {
    for (const [n, t] of this.seen) if (now - t > this.ttl) this.seen.delete(n);
    if (this.seen.has(nonce)) return false;
    this.seen.set(nonce, now);
    return true;
  }
}

export function verifyRequest({ method, path, headers, body }, signPubSpkiB64, replay, now = Date.now()) {
  const ts = headers['x-ab-ts'], nonce = headers['x-ab-nonce'], sig = headers['x-ab-sig'];
  if (!ts || !nonce || !sig) return { ok: false, reason: 'missing_headers' };
  if (!/^\d{10,16}$/.test(ts) || Math.abs(now - Number(ts)) > 60000) return { ok: false, reason: 'stale_ts' };
  let ok = false;
  try {
    const pub = crypto.createPublicKey({ key: unb64(signPubSpkiB64), format: 'der', type: 'spki' });
    ok = crypto.verify('sha256', signingString(method, path, ts, nonce, body), pub, unb64(sig));
  } catch { ok = false; }
  if (!ok) return { ok: false, reason: 'bad_sig' };
  if (!replay.check(nonce, now)) return { ok: false, reason: 'replay' };
  return { ok: true };
}
