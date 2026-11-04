import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { ImapFlow } from 'imapflow';
import { abHome } from './paths.mjs';
import { senderMatches, registrableDomain } from './domain.mjs';

// ---- code extraction --------------------------------------------------------
const KEYWORDS = /(verification|vérification|verification code|passcode|one[- ]time|otp|code de|security code|login code|sign[- ]?in code|\bcode\b|confirmation)/i;

export function extractCode(text) {
  if (!text) return null;
  const t = String(text);
  const re = /(?<![\d.])(\d{3}[ -]\d{3}|\d{4,8})(?![\d])/g;
  let m;
  while ((m = re.exec(t))) {
    const raw = m[1];
    const digits = raw.replace(/[ -]/g, '');
    if (digits.length < 4 || digits.length > 8) continue;
    const before = t.slice(Math.max(0, m.index - 80), m.index);
    const after = t.slice(m.index + raw.length, m.index + raw.length + 40);
    if (KEYWORDS.test(before) || KEYWORDS.test(after)) return digits;
  }
  // Alphanumeric codes (booking.com sends e.g. "1ABCDE is your verification code"): 4-8 chars with
  // at least one digit and one letter, next to a keyword. Case is preserved.
  const alnum = /(?<![A-Za-z0-9])([A-Za-z0-9]{4,8})(?![A-Za-z0-9])/g;
  while ((m = alnum.exec(t))) {
    const tok = m[1];
    if (!/\d/.test(tok) || !/[A-Za-z]/.test(tok) || /^\d+(st|nd|rd|th|am|pm|px|gb|mb|kb)$/i.test(tok)) continue;
    const before = t.slice(Math.max(0, m.index - 40), m.index);
    const after = t.slice(m.index + tok.length, m.index + tok.length + 40);
    if (KEYWORDS.test(before) || KEYWORDS.test(after)) return tok;
  }
  return null;
}

export function pickCode({ subject, body }) {
  return extractCode(subject) || extractCode(body);
}

// ---- minimal MIME text extraction -------------------------------------------
function splitMessage(buf) {
  const s = buf.toString('latin1');
  const i = s.search(/\r?\n\r?\n/);
  if (i < 0) return { head: s, body: '' };
  const sep = s.slice(i).match(/^\r?\n\r?\n/)[0].length;
  return { head: s.slice(0, i), body: s.slice(i + sep) };
}
function parseHeaders(head) {
  const h = {};
  for (const line of head.replace(/\r?\n[ \t]+/g, ' ').split(/\r?\n/)) {
    const k = line.indexOf(':');
    if (k > 0) h[line.slice(0, k).toLowerCase()] = line.slice(k + 1).trim();
  }
  return h;
}
function decodeBody(bodyLatin1, enc, charset) {
  let buf;
  enc = (enc || '').toLowerCase();
  if (enc === 'base64') buf = Buffer.from(bodyLatin1.replace(/\s+/g, ''), 'base64');
  else if (enc === 'quoted-printable') {
    const s = bodyLatin1.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
    buf = Buffer.from(s, 'latin1');
  } else buf = Buffer.from(bodyLatin1, 'latin1');
  try { return new TextDecoder((charset || 'utf-8').toLowerCase()).decode(buf); }
  catch { return buf.toString('utf8'); }
}
const stripHtml = (h) => h.replace(/<(style|script)[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]+>/g, ' ').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/\s+/g, ' ');

function collect(buf, out, depth = 0) {
  if (depth > 6) return;
  const { head, body } = splitMessage(buf);
  const h = parseHeaders(head);
  const ct = h['content-type'] || 'text/plain';
  const type = ct.split(';')[0].trim().toLowerCase();
  if (type.startsWith('multipart/')) {
    const bm = ct.match(/boundary="?([^";]+)"?/i);
    if (!bm) return;
    for (const part of body.split('--' + bm[1])) {
      if (!part.trim() || part.startsWith('--')) continue;
      collect(Buffer.from(part.replace(/^\r?\n/, ''), 'latin1'), out, depth + 1);
    }
  } else if (type === 'text/plain' || type === 'text/html') {
    const cs = (ct.match(/charset="?([^";]+)"?/i) || [])[1];
    const txt = decodeBody(body, h['content-transfer-encoding'], cs);
    (type === 'text/plain' ? out.plain : out.html).push(type === 'text/html' ? stripHtml(txt) : txt);
  }
}
export function mimeText(sourceBuf) {
  const out = { plain: [], html: [] };
  collect(Buffer.from(sourceBuf), out);
  return (out.plain.length ? out.plain : out.html).join('\n');
}

// ---- IMAP -------------------------------------------------------------------
function keychainPassword(service, account) {
  return new Promise((resolve, reject) => {
    execFile('/usr/bin/security', ['find-generic-password', '-s', service, '-a', account, '-w'], (err, stdout) => {
      if (err) reject(new Error('keychain_unavailable'));
      else resolve(stdout.replace(/\r?\n$/, ''));
    });
  });
}

// Accounts file: cfg.accounts_path or ~/.authbridge/mail.json, { "<name>": { email, imap: {host, port, secure},
// keychainService?, keychainAccount? } }. cfg.accounts (array of names) optionally filters. A missing or
// unreadable file means "no accounts" (email codes are skipped and the phone is asked); never throws.
export function loadAccounts(cfg = {}) {
  const p = (cfg.accounts_path || path.join(abHome(), 'mail.json')).replace(/^~(?=\/)/, os.homedir());
  let all;
  try { all = JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return []; }
  if (!all || typeof all !== 'object') return [];
  const names = Array.isArray(cfg.accounts) ? cfg.accounts : Object.keys(all);
  return names.filter((n) => all[n] && all[n].imap && all[n].email).map((n) => ({ name: n, ...all[n] }));
}

async function openClient(acct) {
  const pass = await keychainPassword(acct.keychainService || 'authbridge-mail', acct.keychainAccount || acct.name);
  const client = new ImapFlow({
    host: acct.imap.host, port: acct.imap.port, secure: acct.imap.secure,
    auth: { user: acct.email, pass }, logger: false, socketTimeout: 30000,
  });
  client.on('error', () => {});
  await client.connect();
  return client;
}

// Read-only connectivity check: login + select INBOX + logout. Prints nothing sensitive.
export async function connectivityCheck(cfg = {}) {
  const res = {};
  for (const acct of loadAccounts(cfg)) {
    try {
      const c = await openClient(acct);
      const lock = await c.getMailboxLock('INBOX', { readOnly: true });
      lock.release();
      await c.logout();
      res[acct.name] = 'ok';
    } catch (e) { res[acct.name] = 'error:' + String(e.message).slice(0, 60); }
  }
  return res;
}

// Finds the junk folder of an account: IMAP SPECIAL-USE \Junk, else "Bulk" (Yahoo) / "[Gmail]/Spam".
export function pickJunkFolder(boxes) {
  const list = boxes || [];
  const su = list.find((b) => String(b.specialUse || '').toLowerCase() === '\\junk');
  if (su) return su.path;
  const named = list.find((b) => ['bulk', '[gmail]/spam'].includes(String(b.path || '').toLowerCase()));
  return named ? named.path : null;
}

// Creates a fetcher:
//   findCode({sinceMs, startMs, domain, codeSenders, preferredMail, allowFallback})
//     -> {code, account, folder: 'inbox'|'junk', path: 'sender'|'learned'|'fallback', senderDomain?}
//      | {ambiguous: true} | null
// One call = one polling pass across accounts and folders; an error on one account or folder never stops
// the others. Primary: sender matches (sinceMs may carry slack). Fallback (allowFallback only): emails
// received at/after startMs from any sender with a code AND the site's brand word; exactly one such
// candidate across all accounts/folders wins, two or more -> ambiguous.
// `openClient` / `accounts` are injectable for tests.
export function createMailFetcher(cfg = {}, { log, openClient: openFn = openClient, accounts: injected } = {}) {
  const getAccounts = () => injected || loadAccounts(cfg); // re-read each call so mail-add needs no restart
  const clients = new Map();
  const junkFolders = new Map();
  // Yahoo is slow to tell an already-open connection about new mail (Apple Mail needs "Get All New
  // Mail" too), so connections are recycled every 30 s and each scan re-SELECTs the folder.
  const MAX_CLIENT_AGE_MS = cfg.max_client_age_ms ?? 30000;
  async function client(acct) {
    let c = clients.get(acct.name);
    if (c && c.usable && Date.now() - (c._abOpenedAt || 0) < MAX_CLIENT_AGE_MS) return c;
    if (c) { clients.delete(acct.name); try { await c.logout(); } catch { /* ignore */ } }
    c = await openFn(acct);
    c._abOpenedAt = Date.now();
    clients.set(acct.name, c);
    return c;
  }
  async function junkFolder(acct, c) {
    if (junkFolders.has(acct.name)) return junkFolders.get(acct.name);
    const f = pickJunkFolder(await c.list());
    if (f) junkFolders.set(acct.name, f);
    return f;
  }
  const textOf = async (c, uid, subject) => {
    const full = await c.fetchOne(String(uid), { source: true }, { uid: true });
    return full?.source ? mimeText(full.source) : '';
  };
  // -> {hit} | {cands: [{code, senderDomain}]}
  async function scanFolder(c, mailbox, { sinceMs, startMs, domain, codeSenders, allowFallback, brand }) {
    const cands = [];
    // Close any selected mailbox so the lock below issues a fresh SELECT (a fresh view of new mail).
    try { if (c.mailbox && typeof c.mailboxClose === 'function') await c.mailboxClose(); } catch { /* ignore */ }
    const lock = await c.getMailboxLock(mailbox, { readOnly: true });
    try {
      await c.noop();
      const uids = await c.search({ since: new Date(Math.min(sinceMs, startMs) - 86400000) }, { uid: true });
      if (!uids || !uids.length) return { cands };
      for (const uid of uids.slice(-15).reverse()) {
        const msg = await c.fetchOne(String(uid), { envelope: true, internalDate: true }, { uid: true });
        if (!msg) continue;
        const received = new Date(msg.internalDate || msg.envelope?.date || 0).getTime();
        const f = msg.envelope?.from?.[0];
        const from = f?.address;
        const subject = msg.envelope?.subject;
        if (received >= sinceMs && senderMatches(from, domain, codeSenders)) {
          let code = extractCode(subject);
          if (!code) code = extractCode(await textOf(c, uid));
          if (code) return { hit: { code, path: senderMatches(from, domain, []) ? 'sender' : 'learned' } };
          continue;
        }
        if (!allowFallback || received < startMs || !brand) continue;
        const body = await textOf(c, uid);
        const code = extractCode(subject) || extractCode(body);
        if (!code) continue;
        const hay = `${from || ''} ${f?.name || ''} ${subject || ''} ${body}`.toLowerCase();
        if (!hay.includes(brand)) continue;
        const at = String(from || '').lastIndexOf('@');
        cands.push({ code, senderDomain: at >= 0 ? registrableDomain(String(from).slice(at + 1).toLowerCase()) : null });
      }
      return { cands };
    } finally { lock.release(); }
  }
  async function scan(acct, q) {
    const out = { hit: null, cands: [] };
    let c;
    try { c = await client(acct); } catch (e) { clients.delete(acct.name); log?.warn('imap_error', { account: acct.name, error: e }); return out; }
    let junk = null;
    try { junk = await junkFolder(acct, c); } catch (e) { log?.warn('imap_error', { account: acct.name, error: e }); }
    for (const [kind, mailbox] of [['inbox', 'INBOX'], ['junk', junk]]) {
      if (!mailbox) continue;
      try {
        const r = await scanFolder(c, mailbox, q);
        if (r.hit) { out.hit = { ...r.hit, account: acct.name, folder: kind }; return out; }
        for (const cd of r.cands) out.cands.push({ ...cd, account: acct.name, folder: kind });
      } catch (e) {
        if (kind === 'inbox') clients.delete(acct.name);
        log?.warn('imap_error', { account: acct.name, folder: kind, error: e });
      }
    }
    return out;
  }
  return {
    accountNames() { return getAccounts().map((a) => a.name); },
    async findCode({ sinceMs, startMs, domain, codeSenders = [], preferredMail, allowFallback = false }) {
      const accounts = getAccounts();
      const brand = String(registrableDomain(domain) || '').split('.')[0].toLowerCase();
      const q = { sinceMs, startMs: startMs ?? sinceMs, domain, codeSenders, allowFallback, brand };
      const order = [...accounts].sort((a, b) => (b.name === preferredMail) - (a.name === preferredMail));
      const results = await Promise.all(order.map((acct) => scan(acct, q)));
      const hit = results.find((r) => r.hit);
      if (hit) return hit.hit;
      const cands = results.flatMap((r) => r.cands);
      if (cands.length === 1) { const [c] = cands; return { code: c.code, account: c.account, folder: c.folder, path: 'fallback', senderDomain: c.senderDomain }; }
      if (cands.length > 1) return { ambiguous: true };
      return null;
    },
    async close() {
      for (const c of clients.values()) { try { await c.logout(); } catch { /* ignore */ } }
      clients.clear();
    },
  };
}
