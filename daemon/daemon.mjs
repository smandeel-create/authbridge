#!/opt/homebrew/bin/node
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { abHome, sockPath as defaultSock, seBin } from './paths.mjs';
import { createLogger } from './logger.mjs';
import { makeSE, seal, open, x25519Generate, encryptCredential, decryptCredential, updateCredential, wrapBlob, unwrapBlob, ReplayCache, verifyRequest, b64, unb64 } from './crypto.mjs';
import { Store, PairingFile } from './store.mjs';
import { PairCodes } from './pairing.mjs';
import { normalizeDomain, checkUrl } from './domain.mjs';
import { createNotifier } from './notifier.mjs';
import { createApnsNotifier } from './apns.mjs';
import { createMailFetcher } from './mail.mjs';

const DEFAULTS = {
  host: '0.0.0.0',
  port: 47900,
  insecure_test_hosts: [],
  notifier: {},
  fallback_notifier: {},
  mail: {},
  timing: { probe_interval_ms: 1000, probe_timeout_ms: 20000, mail_interval_ms: 5000, mail_fast_interval_ms: 2000, mail_fast_window_ms: 30000, mail_timeout_ms: 180000, cmd_timeout_ms: 15000, code_request_after_ms: 20000, prompt_min_ms: 45000, prompt_max_ms: 150000, prompt_default_ms: 75000, code_request_ttl_ms: 180000, max_code_steps: 3 },
};

class HttpErr extends Error { constructor(status, code) { super(code); this.status = status; this.code = code; } }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const hasLoginForm = (p) => !!(p.has_password || p.has_username_only || p.has_otp);
const wipeBuf = (b) => { try { b?.fill(0); } catch { /* ignore */ } };

export async function createDaemon(opts = {}) {
  const home = opts.home ?? abHome();
  fs.mkdirSync(path.join(home, 'run'), { recursive: true, mode: 0o700 });
  fs.chmodSync(home, 0o700);
  let fileCfg = {};
  try { fileCfg = JSON.parse(fs.readFileSync(path.join(home, 'config.json'), 'utf8')); } catch { /* none */ }
  const cfg = { ...DEFAULTS, ...fileCfg, ...(opts.config || {}) };
  cfg.timing = { ...DEFAULTS.timing, ...(fileCfg.timing || {}), ...(opts.config?.timing || {}) };
  const insecure = Array.isArray(cfg.insecure_test_hosts) ? cfg.insecure_test_hosts : [];

  const log = opts.log ?? createLogger({ file: path.join(home, 'daemon.log') });
  const se = opts.se ?? makeSE({ bin: seBin(), home });
  await se.init();
  const store = new Store(path.join(home, 'store.json'));
  const pairing = new PairingFile(path.join(home, 'pairing.json'));
  const codes = new PairCodes(opts.pairCodes);
  const replay = new ReplayCache();
  const mail = opts.mail ?? createMailFetcher(cfg.mail, { log });
  const notifier = opts.notifier ?? createNotifier(cfg.fallback_notifier, { log });
  const apns = opts.apns ?? createApnsNotifier(cfg.notifier, { log });
  const sockFile = opts.sockPath ?? defaultSock(home);

  // Mac X25519 key: private half wrapped by the Secure Enclave at rest, plaintext only in memory.
  let macPriv, macPub;
  async function ensureMacKey() {
    if (!pairing.mac) {
      const k = x25519Generate();
      const wrap = await wrapBlob(se, k.priv, 'mac-agree');
      pairing.setMac({ agree_pub: b64(k.pub), wrap });
      wipeBuf(k.priv);
    }
    macPub = unb64(pairing.mac.agree_pub);
    macPriv = await unwrapBlob(se, pairing.mac.wrap, 'mac-agree');
  }
  await ensureMacKey();

  // ---------------- pending approvals ----------------
  const pending = new Map();
  const finished = new Map(); // code request id -> {state, resolved_by?, at}
  function createPending({ domain, task, record_id, needs_enroll = false, timeoutMs, kind = 'login', parent_id }) {
    const id = crypto.randomUUID();
    const now = Date.now();
    const p = { id, kind, domain, task, record_id, needs_enroll, requested_at: now, expires_at: now + timeoutMs, decided: false, ...(parent_id ? { parent_id } : {}) };
    p.promise = new Promise((resolve) => {
      p.resolve = (v) => {
        if (p.decided) return;
        p.decided = true; clearTimeout(p.timer); pending.delete(id);
        if (kind === 'code') {
          finished.set(id, v.decision === 'timeout' ? { state: 'expired', at: Date.now() } : { state: 'resolved', ...(v.resolved_by ? { resolved_by: v.resolved_by } : {}), at: Date.now() });
          for (const [k, f] of finished) if (Date.now() - f.at > 3600000) finished.delete(k);
        }
        resolve(v);
      };
      p.timer = setTimeout(() => p.resolve({ decision: 'timeout' }), timeoutMs);
    });
    pending.set(id, p);
    return p;
  }

  // APNs when configured and the device has a token; otherwise the optional webhook fallback. Never throws.
  async function notifyPhone(req, task) {
    try {
      const tok = pairing.device?.push_token?.token;
      if (apns.configured && tok) {
        const r = await apns.send({ deviceToken: tok, title: 'Login approval needed', body: req.needs_enroll ? `${req.domain} — first login, pick it from Passwords` : req.domain, request_id: req.id, expires_at: req.expires_at });
        if (r.gone) { pairing.clearPushToken(); log.info('push_token_cleared', { status: r.status }); }
        return;
      }
      await notifier.notify({ domain: req.domain, task, ...(req.needs_enroll ? { first_login: true } : {}) });
    } catch { /* never break login */ }
  }

  // A code request asks the phone for a verification code (SMS / app) the Mac cannot read itself.
  function createCodeRequest({ domain, parent_id, reason = 'follow_up' }) {
    const req = createPending({ domain, task: 'enter the verification code', record_id: null, timeoutMs: cfg.timing.code_request_ttl_ms, kind: 'code', parent_id });
    req.reason = reason;
    if (reason === 'email_not_found') {
      let names = [];
      try { names = mail.accountNames?.() ?? []; } catch { /* ignore */ }
      req.searched = names.map((n) => n.charAt(0).toUpperCase() + n.slice(1));
    }
    log.info('code_request_created', { domain, reason });
    (async () => {
      try {
        const tok = pairing.device?.push_token?.token;
        if (apns.configured && tok) {
          const r = await apns.send({ deviceToken: tok, title: 'Verification code needed', body: `${domain} — enter the verification code`, request_id: req.id, kind: 'code', expires_at: req.expires_at });
          if (r.gone) { pairing.clearPushToken(); log.info('push_token_cleared', { status: r.status }); }
          return;
        }
        await notifier.notify({ domain, task: 'enter the verification code' });
      } catch { /* never break login */ }
    })();
    return req;
  }

  // ---------------- extension channel ----------------
  let ext = null;
  const extPending = new Map();
  function sendCmd(cmd, params = {}, timeout = cfg.timing.cmd_timeout_ms) {
    if (!ext) return Promise.reject(new Error('extension_unavailable'));
    const cmd_id = crypto.randomUUID();
    const conn = ext;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { extPending.delete(cmd_id); reject(new Error('cmd_timeout')); }, timeout);
      extPending.set(cmd_id, { resolve, reject, conn, timer });
      conn.sock.write(JSON.stringify({ cmd_id, cmd, ...params }) + '\n');
    });
  }

  // ---------------- login algorithm ----------------
  const locks = new Map();
  function withDomainLock(domain, fn) {
    const prev = locks.get(domain) || Promise.resolve(null);
    const mine = prev.then((prevStatus) => fn(prevStatus)).catch((e) => { log.error('login_internal_error', { error: e }); return { status: 'failed', detail: 'internal' }; });
    const tail = mine.then((r) => r.status);
    locks.set(domain, tail);
    tail.then(() => { if (locks.get(domain) === tail) locks.delete(domain); });
    return mine;
  }

  const probe = (tab_id) => sendCmd('probe', { tab_id });
  const urlOk = (url, domain) => checkUrl(url, domain, insecure);

  async function afterSubmit(tab_id, domain, { stale }) {
    const t = cfg.timing;
    const deadline = Date.now() + t.probe_timeout_ms;
    let last = null, leftDomain = false, formFreeSince = 0;
    // Sites often show nothing in between steps (Airbnb after "Log in", before the code box), so a
    // login form must stay gone for settle_ms before we call it signed in.
    const settleMs = t.done_settle_ms ?? 2500;
    for (;;) {
      let p = null;
      try { p = await probe(tab_id); } catch (e) { if (e.message === 'extension_unavailable' || e.message === 'extension_disconnected') return { status: 'extension_unavailable' }; }
      if (p) {
        last = p;
        if (!urlOk(p.url, domain).ok) leftDomain = true;
        else {
          leftDomain = false;
          if (p.has_otp) return { phase: 'otp' };
          if (p.captcha) return { status: 'needs_more', detail: 'captcha' };
          if (p.passkey_prompt && !p.has_password) return { status: 'needs_more', detail: 'passkey' };
          if (!hasLoginForm(p) && !p.continue_button) {
            if (!formFreeSince) formFreeSince = Date.now();
            if (Date.now() - formFreeSince >= settleMs) return { phase: 'done' };
          } else formFreeSince = 0;
        }
      }
      if (Date.now() >= deadline) break;
      await sleep(t.probe_interval_ms);
    }
    if (leftDomain) return { status: 'failed', detail: 'left_domain' };
    // Still on an identifier-only step: the site rejected the username, not the password.
    if (last?.has_username_only) return { status: 'failed', detail: 'username_rejected' };
    if (last?.has_password) { stale(); return { status: 'out_of_date' }; }
    return { status: 'needs_more', detail: 'unsupported_form' };
  }

  async function pollMail(rec, sinceMs, startMs, shouldStop = () => false, timeoutMs = cfg.timing.mail_timeout_ms) {
    const t = cfg.timing;
    const began = Date.now();
    const deadline = began + timeoutMs;
    const fallbackAfter = t.fallback_after_ms ?? t.code_request_after_ms;
    for (;;) {
      if (shouldStop()) return null;
      try {
        const cur = store.byId(rec.record_id) || rec;
        const r = await mail.findCode({ sinceMs, startMs, domain: rec.domain, codeSenders: cur.code_senders || [], preferredMail: rec.preferred_mail, allowFallback: Date.now() - began >= fallbackAfter });
        if (r?.ambiguous) { log.info('email_code_ambiguous', { domain: rec.domain }); return r; }
        if (r) {
          log.info('code_found', { path: r.path || 'sender', folder: r.folder || 'inbox', account: r.account });
          if (r.path === 'fallback' && r.senderDomain) {
            const have = cur.code_senders || [];
            if (!have.includes(r.senderDomain)) store.patch(rec.record_id, { code_senders: [...have, r.senderDomain] });
          }
          return r;
        }
      } catch (e) { log.warn('mail_poll_error', { error: e }); }
      if (Date.now() >= deadline) return null;
      // Check every 2 s for the first 30 s (most codes arrive quickly), then every 5 s.
      const fast = Date.now() - began < (t.mail_fast_window_ms ?? 0);
      await sleep(fast ? Math.min(t.mail_fast_interval_ms ?? t.mail_interval_ms, t.mail_interval_ms) : t.mail_interval_ms);
    }
  }

  // First code step: poll email; if nothing turns up within code_request_after_ms also ask the phone.
  // First source to yield a code wins. Returns {found}|{code}|{cancel}|{timeout}|{none}.
  function promptDelayMs(rec) {
    const t = cfg.timing;
    const d = store.byId(rec.record_id)?.email_delay_ms;
    if (!(d > 0)) return t.prompt_default_ms;
    return Math.max(t.prompt_min_ms, Math.min(t.prompt_max_ms, 1.5 * d));
  }

  async function obtainOtp(rec, sinceMs, startMs, { domain, parent_id }) {
    const t = cfg.timing;
    const promptMs = promptDelayMs(rec);
    const stepStart = Date.now();
    let stopped = false, mailDone = false, mailRes = null, ambiguous = false, codeReq = null, codeRes = null, wake = null;
    const kick = () => { const w = wake; wake = null; w?.(); };
    const askPhone = () => {
      codeReq = createCodeRequest({ domain, parent_id, reason: 'email_not_found' });
      codeReq.promise.then((r) => { codeRes = r; kick(); });
    };
    // No mail accounts configured: skip email and ask the phone straight away.
    let noMail = false;
    try { const n = mail.accountNames?.(); noMail = Array.isArray(n) && n.length === 0; } catch { /* ignore */ }
    if (noMail) { mailDone = true; askPhone(); }
    else pollMail(rec, sinceMs, startMs, () => stopped, promptMs + t.code_request_ttl_ms).then((r) => {
      if (r?.ambiguous) { ambiguous = true; if (!stopped && !codeReq) askPhone(); } else mailRes = r;
      mailDone = true; kick();
    }, () => { mailDone = true; kick(); });
    const timer = setTimeout(() => {
      if (stopped || mailDone || mailRes) return;
      askPhone();
    }, promptMs);
    try {
      for (;;) {
        if (mailRes) return { found: mailRes, delay_ms: Date.now() - stepStart };
        if (codeRes?.decision === 'submit') return { code: codeRes.code };
        if (codeRes?.decision === 'cancel') return { cancel: true, ambiguous };
        if (mailDone && !codeReq) return { none: true };
        if (mailDone && codeRes) return { timeout: true, ambiguous };
        await new Promise((r) => { wake = r; });
      }
    } finally {
      stopped = true; clearTimeout(timer);
      if (codeReq && !codeReq.decided) codeReq.resolve({ decision: 'superseded', ...(mailRes ? { resolved_by: 'email' } : {}) });
    }
  }

  // Follow-up code step: ask the phone straight away. Returns {code}|{cancel}|{timeout}.
  async function requestCodeFromPhone({ domain, parent_id }) {
    const r = await createCodeRequest({ domain, parent_id }).promise;
    if (r.decision === 'submit') return { code: r.code };
    return r.decision === 'cancel' ? { cancel: true } : { timeout: true };
  }

  async function runLogin({ domain: rawDomain, tab_id, task, timeout_s }) {
    const startMs = Date.now();
    const domain = normalizeDomain(rawDomain);
    if (!domain || tab_id === undefined || tab_id === null) return { status: 'failed', detail: 'bad_request' };
    if (!ext) return { status: 'extension_unavailable' };
    let info;
    try { info = await sendCmd('tab_info', { tab_id }); } catch (e) { return { status: 'extension_unavailable', detail: e.message === 'extension_unavailable' ? undefined : 'tab_info_failed' }; }
    if (!urlOk(info?.url, domain).ok) return { status: 'domain_mismatch' };
    let p;
    try { p = await probe(tab_id); } catch { return { status: 'failed', detail: 'probe_failed' }; }
    if (!urlOk(p.url, domain).ok) return { status: 'domain_mismatch' };
    // A remembered-account screen (fields-free, one "Log in" button) is a login page too.
    const continueOnly = !hasLoginForm(p) && !!p.continue_button;
    log.info('start_probe', { pw: !!p.has_password, user: !!p.has_username_only, otp: !!p.has_otp, cont: p.continue_button === undefined ? 'missing' : !!p.continue_button });
    if (!hasLoginForm(p) && !continueOnly) return { status: 'already_signed_in' };
    if (!pairing.device) return { status: 'not_paired' };

    const timeoutMs = Math.max(100, Math.round((Number(timeout_s) || 300) * 1000));
    return withDomainLock(domain, async (prevStatus) => {
      if (prevStatus === 'signed_in' || prevStatus === 'already_signed_in') {
        try {
          await sendCmd('reload', { tab_id }, cfg.timing.cmd_timeout_ms * 2);
          const q = await probe(tab_id);
          if (urlOk(q.url, domain).ok && !hasLoginForm(q)) return { status: 'already_signed_in' };
        } catch { /* fall through to a normal login */ }
      }
      const existing = store.byDomain(domain);
      const req = createPending({ domain, task: String(task ?? '').slice(0, 200), record_id: existing ? existing.record_id : null, needs_enroll: !existing, timeoutMs });
      log.info('pending_created', { domain, needs_enroll: !existing });
      notifyPhone(req, task);
      const decision = await req.promise;
      if (decision.decision === 'timeout') return { status: 'timed_out' };
      if (decision.decision === 'no_credential') return { status: 'no_credential' };
      if (decision.decision !== 'approve') return { status: 'denied' };
      // For a first login the phone enrolled just before approving: use the record it named.
      const rec = decision.record_id ? store.byId(decision.record_id) : existing;
      if (!rec || rec.domain !== domain) { wipeBuf(decision.share); return { status: 'failed', detail: 'decrypt' }; }

      // decrypt -> fill -> wipe
      const share = decision.share;
      let plain = null, creds = null, allowInsecure = false;
      try {
        try { plain = await decryptCredential(se, rec, share); creds = JSON.parse(plain.toString('utf8')); }
        catch { return { status: 'failed', detail: 'decrypt' }; }
        try {
          const cur = await sendCmd('tab_info', { tab_id });
          if (!urlOk(cur?.url, domain).ok) return { status: 'domain_mismatch' };
          allowInsecure = new URL(cur.url).protocol === 'http:';
          if (continueOnly) {
            // Nothing to type: pressing the button makes the site send a code (handled below).
            await sendCmd('press_continue', { tab_id, expected_domain: domain, allow_insecure: allowInsecure });
          } else {
            await sendCmd('fill_credentials', { tab_id, expected_domain: domain, allow_insecure: allowInsecure, username: creds.username, password: creds.password, email: creds.email || (String(creds.username || '').includes('@') ? creds.username : '') }, cfg.timing.cmd_timeout_ms * 2);
          }
        } catch (e) {
          if (e.message === 'domain_mismatch') return { status: 'domain_mismatch' };
          if (e.message === 'extension_unavailable' || e.message === 'extension_disconnected') return { status: 'extension_unavailable' };
          if (e.message === 'email_required') return { status: 'failed', detail: 'email_required' };
          if (e.message === 'no_login_form' || e.message === 'no_continue_button') return { status: 'needs_more', detail: 'unsupported_form' };
          // Error codes from the extension are short identifiers; log only if it looks like one.
          log.info('fill_error', { err: /^[a-z_]{1,40}$/.test(e.message) ? e.message : 'other' });
          return { status: 'failed', detail: 'fill' };
        }
      } finally { wipeBuf(plain); wipeBuf(share); creds = null; }

      const markStale = () => store.patch(rec.record_id, { stale: true });
      let out = await afterSubmit(tab_id, domain, { stale: markStale });
      let codeSteps = 0;
      while (out.phase === 'otp') {
        if (codeSteps >= cfg.timing.max_code_steps) return { status: 'needs_more', detail: 'sms_or_app_code' };
        let r;
        if (codeSteps === 0) {
          r = await obtainOtp(rec, startMs - 30000, startMs, { domain, parent_id: req.id });
          if (r.none) return { status: 'needs_more', detail: 'email_code_not_found' };
        } else r = await requestCodeFromPhone({ domain, parent_id: req.id });
        if (r.cancel || r.timeout) return { status: 'needs_more', detail: r.ambiguous ? 'email_code_ambiguous' : 'sms_or_app_code' };
        const code = r.found ? r.found.code : r.code;
        if (r.found && codeSteps === 0) {
          const old = store.byId(rec.record_id)?.email_delay_ms;
          const nu = r.delay_ms;
          store.patch(rec.record_id, { email_delay_ms: Math.round(old > 0 ? Math.max(nu, 0.7 * old + 0.3 * nu) : nu) });
        }
        codeSteps++;
        let codeUrl = null;
        try { codeUrl = (await sendCmd('tab_info', { tab_id }))?.url || null; } catch { /* best effort */ }
        try {
          await sendCmd('fill_code', { tab_id, expected_domain: domain, allow_insecure: allowInsecure, code });
        } catch (e) {
          if (e.message === 'domain_mismatch') return { status: 'domain_mismatch' };
          return { status: 'failed', detail: 'fill_code' };
        }
        if (r.found?.account && r.found.account !== rec.preferred_mail) store.patch(rec.record_id, { preferred_mail: r.found.account });
        out = await afterSubmit(tab_id, domain, { stale: markStale });
        if (out.phase === 'otp') {
          // A code field on a different page means the code was accepted and the site wants another
          // factor (booking.com follows up with SMS); same page means the code was refused.
          // The site may still be navigating (booking.com takes a few seconds), so give the URL
          // time to change before calling the code refused.
          const settleUntil = Date.now() + (cfg.timing.code_settle_ms ?? 8000);
          let samePage = true;
          for (;;) {
            let nowUrl = null;
            try { nowUrl = (await sendCmd('tab_info', { tab_id }))?.url || null; } catch { /* best effort */ }
            samePage = !!(codeUrl && nowUrl && new URL(codeUrl).pathname === new URL(nowUrl).pathname);
            if (!samePage || Date.now() >= settleUntil) break;
            await sleep(cfg.timing.probe_interval_ms);
          }
          if (samePage) return { status: 'failed', detail: 'code_rejected' };
          out = await afterSubmit(tab_id, domain, { stale: markStale });
        }
      }
      if (out.phase === 'done') {
        if (rec.stale) store.patch(rec.record_id, { stale: false });
        return { status: 'signed_in' };
      }
      return out;
    });
  }

  // ---------------- phone HTTP API ----------------
  function pairDevice(body) {
    if (!codes.verify(body?.code)) throw new HttpErr(403, 'bad_code');
    let pubOk = false;
    try {
      const k = crypto.createPublicKey({ key: unb64(body.sign_pub), format: 'der', type: 'spki' });
      pubOk = k.asymmetricKeyType === 'ec' && k.asymmetricKeyDetails?.namedCurve === 'prime256v1';
    } catch { /* invalid */ }
    if (!pubOk || unb64(body.agree_pub).length !== 32) throw new HttpErr(400, 'bad_keys');
    const device_id = crypto.randomBytes(16).toString('hex');
    pairing.setDevice({ device_id, device_name: String(body.device_name || 'iPhone').slice(0, 80), sign_pub: body.sign_pub, agree_pub: body.agree_pub, paired_at: Date.now() });
    log.info('paired', { device: pairing.device.device_name });
    return { device_id, mac_agree_pub: pairing.mac.agree_pub, mac_name: os.hostname() };
  }

  function pushToken(body) {
    const t = body?.token;
    if (typeof t !== 'string' || !/^[0-9a-fA-F]{64,200}$/.test(t)) throw new HttpErr(400, 'bad_token');
    const env = body.env === 'production' ? 'production' : 'development';
    pairing.setPushToken({ token: t.toLowerCase(), env });
    log.info('push_token_set', { env });
    return { ok: true };
  }

  async function enroll(body) {
    let plain;
    try { plain = open(macPriv, macPub, body?.sealed, 'enroll'); } catch { throw new HttpErr(400, 'bad_sealed'); }
    let d;
    try { d = JSON.parse(plain.toString('utf8')); } catch { throw new HttpErr(400, 'bad_payload'); } finally { wipeBuf(plain); }
    const domain = normalizeDomain(d?.domain);
    const P = unb64(d?.share);
    if (!domain || typeof d.record_id !== 'string' || !d.record_id || typeof d.username !== 'string' || typeof d.password !== 'string' || (d.email != null && typeof d.email !== 'string') || P.length !== 32) throw new HttpErr(400, 'bad_payload');
    const enc = await encryptCredential(se, { record_id: d.record_id, domain, username: d.username, password: d.password, email: d.email }, P);
    wipeBuf(P);
    const old = store.byDomain(domain);
    store.upsertForDomain({ record_id: d.record_id, domain, ...enc, stale: false, created_at: Date.now(), code_senders: old?.code_senders || [], preferred_mail: old?.preferred_mail, ...(old?.email_delay_ms ? { email_delay_ms: old.email_delay_ms } : {}) });
    log.info('enrolled', { domain });
    return { record_id: d.record_id, domain };
  }

  // Edit username/email of a stored login without the password. Needs the record's share (Face ID on the phone).
  async function updateRecord(recordId, body) {
    const rec = store.byId(recordId);
    if (!rec) throw new HttpErr(404, 'unknown_record');
    let plain;
    try { plain = open(macPriv, macPub, body?.sealed, 'update|' + recordId); } catch { throw new HttpErr(400, 'bad_sealed'); }
    let d;
    try { d = JSON.parse(plain.toString('utf8')); } catch { throw new HttpErr(400, 'bad_payload'); } finally { wipeBuf(plain); }
    const P = unb64(d?.share);
    const bad = !d || typeof d !== 'object' || P.length !== 32
      || (d.username !== undefined && (typeof d.username !== 'string' || !d.username))
      || (d.email !== undefined && typeof d.email !== 'string');
    if (bad) { wipeBuf(P); throw new HttpErr(400, 'bad_payload'); }
    let enc;
    try {
      enc = await updateCredential(se, rec, P, (c) => {
        if (d.username !== undefined) c.username = d.username;
        if (d.email !== undefined) { if (d.email) c.email = d.email; else delete c.email; }
        return c;
      });
    } catch { throw new HttpErr(400, 'decrypt'); } finally { wipeBuf(P); }
    store.patch(recordId, { nonce: enc.nonce, ct: enc.ct, stale: false });
    log.info('record_updated', { domain: rec.domain });
    return { ok: true };
  }

  function requestState(id) {
    const p = pending.get(id);
    if (p && !p.decided) return p.expires_at > Date.now() ? { state: 'pending' } : { state: 'expired' };
    const f = finished.get(id);
    if (!f) throw new HttpErr(404, 'unknown_request');
    return { state: f.state, ...(f.resolved_by ? { resolved_by: f.resolved_by } : {}) };
  }

  const routes = {
    'GET /v1/pending': () => ({
      requests: [...pending.values()].filter((p) => !p.decided && p.expires_at > Date.now())
        .map((p) => p.kind === 'code'
          ? { id: p.id, kind: 'code', domain: p.domain, task: p.task, requested_at: p.requested_at, expires_at: p.expires_at, parent_id: p.parent_id, reason: p.reason, ...(p.searched ? { searched: p.searched } : {}) }
          : ({ id: p.id, kind: 'login', domain: p.domain, task: p.task, record_id: p.needs_enroll ? null : p.record_id, needs_enroll: !!p.needs_enroll, requested_at: p.requested_at, expires_at: p.expires_at })),
    }),
    'POST /v1/approve': (body) => {
      const p = typeof body?.request_id === 'string' ? pending.get(body.request_id) : null;
      if (!p || p.decided || p.kind === 'code') throw new HttpErr(404, 'unknown_request');
      if (body.decision === 'deny') { p.resolve({ decision: 'deny' }); return { ok: true }; }
      if (body.decision === 'no_credential') { p.resolve({ decision: 'no_credential' }); return { ok: true }; }
      if (body.decision !== 'approve') throw new HttpErr(400, 'bad_decision');
      if (p.needs_enroll) {
        const r = typeof body.record_id === 'string' ? store.byId(body.record_id) : null;
        if (!r || r.domain !== p.domain) throw new HttpErr(400, 'record_mismatch');
      } else if (body.record_id !== p.record_id) throw new HttpErr(400, 'record_mismatch');
      let share;
      try { share = open(macPriv, macPub, body.sealed_share, p.id); } catch { throw new HttpErr(400, 'bad_sealed'); }
      if (share.length !== 32) { wipeBuf(share); throw new HttpErr(400, 'bad_share'); }
      p.resolve({ decision: 'approve', share, record_id: body.record_id });
      return { ok: true };
    },
    'POST /v1/code': (body) => {
      const p = typeof body?.request_id === 'string' ? pending.get(body.request_id) : null;
      if (!p || p.decided || p.kind !== 'code') throw new HttpErr(404, 'unknown_request');
      if (body.decision === 'cancel') { p.resolve({ decision: 'cancel' }); return { ok: true }; }
      if (body.decision !== 'submit') throw new HttpErr(400, 'bad_decision');
      let plain;
      try { plain = open(macPriv, macPub, body.sealed, 'code|' + p.id); } catch { throw new HttpErr(400, 'bad_sealed'); }
      let d;
      try { d = JSON.parse(plain.toString('utf8')); } catch { throw new HttpErr(400, 'bad_payload'); } finally { wipeBuf(plain); }
      const code = typeof d?.code === 'string' ? d.code.replace(/[\s-]/g, '') : '';
      if (!/^[A-Za-z0-9]{4,10}$/.test(code)) throw new HttpErr(400, 'bad_code');
      p.resolve({ decision: 'submit', code });
      return { ok: true };
    },
    'POST /v1/push-token': (body) => pushToken(body),
    'POST /v1/enroll': (body) => enroll(body),
    'GET /v1/records': () => ({ records: store.list().map((r) => ({ record_id: r.record_id, domain: r.domain, stale: !!r.stale, created_at: r.created_at })) }),
    'POST /v1/wipe': () => { store.wipe(); log.info('wiped_by_phone'); return { ok: true }; },
  };

  function readBody(req, max = 262144) {
    return new Promise((resolve, reject) => {
      const chunks = []; let n = 0;
      req.on('data', (c) => { n += c.length; if (n > max) { reject(new HttpErr(413, 'too_large')); req.destroy(); } else chunks.push(c); });
      req.on('end', () => resolve(Buffer.concat(chunks)));
      req.on('error', reject);
    });
  }

  async function handleHttp(req, res) {
    let status = 200, out;
    try {
      const url = new URL(req.url, 'http://x');
      const raw = await readBody(req);
      let body = {};
      if (raw.length) { try { body = JSON.parse(raw.toString('utf8')); } catch { throw new HttpErr(400, 'bad_json'); } }
      const key = `${req.method} ${url.pathname}`;
      if (key === 'POST /v1/pair') out = pairDevice(body);
      else {
        const dev = pairing.device;
        if (!dev || req.headers['x-ab-device'] !== dev.device_id) throw new HttpErr(401, 'unauthorized');
        const v = verifyRequest({ method: req.method, path: req.url, headers: req.headers, body: raw }, dev.sign_pub, replay);
        if (!v.ok) { log.warn('auth_rejected', { reason: v.reason }); throw new HttpErr(401, 'unauthorized'); }
        const m = url.pathname.match(/^\/v1\/records\/([^/]+)$/);
        const mq = url.pathname.match(/^\/v1\/requests\/([^/]+)$/);
        const mu = url.pathname.match(/^\/v1\/records\/([^/]+)\/update$/);
        if (req.method === 'GET' && mq) out = requestState(decodeURIComponent(mq[1]));
        else if (req.method === 'POST' && mu) out = await updateRecord(decodeURIComponent(mu[1]), body);
        else if (req.method === 'DELETE' && m) {
          if (!store.remove(decodeURIComponent(m[1]))) throw new HttpErr(404, 'unknown_record');
          out = { ok: true };
        } else {
          const h = routes[key];
          if (!h) throw new HttpErr(404, 'not_found');
          out = await h(body);
        }
      }
    } catch (e) {
      if (e instanceof HttpErr) { status = e.status; out = { error: e.code }; }
      else { log.error('http_error', { error: e }); status = 500; out = { error: 'internal' }; }
    }
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(out));
  }

  // ---------------- unix socket ----------------
  const sockets = new Set();
  function handleSocket(sock) {
    const conn = { sock, role: 'client' };
    sockets.add(sock);
    let buf = '';
    const reply = (obj) => { if (!sock.destroyed) sock.write(JSON.stringify(obj) + '\n'); };
    sock.on('data', (d) => {
      buf += d.toString('utf8');
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        if (line.trim()) onMessage(line);
      }
    });
    sock.on('error', () => {});
    sock.on('close', () => {
      sockets.delete(sock);
      if (ext === conn) ext = null;
      for (const [id, c] of extPending) if (c.conn === conn) { clearTimeout(c.timer); extPending.delete(id); c.reject(new Error('extension_disconnected')); }
    });
    async function onMessage(line) {
      let msg;
      try { msg = JSON.parse(line); } catch { return; }
      const id = msg.id;
      if (msg.cmd_id && !msg.op) {
        if (conn.role !== 'extension') return;
        const c = extPending.get(msg.cmd_id);
        if (!c) return;
        clearTimeout(c.timer); extPending.delete(msg.cmd_id);
        if (msg.ok) c.resolve(msg.result ?? {}); else c.reject(new Error(String(msg.error || 'error').slice(0, 60)));
        return;
      }
      if (msg.op === 'extension_hello') { conn.role = 'extension'; ext = conn; log.info('extension_connected'); return reply({ id, ok: true }); }
      if (conn.role === 'extension') return reply({ id, error: 'forbidden' });
      try {
        switch (msg.op) {
          case 'request_login': {
            const r = await runLogin(msg);
            return reply({ id, status: r.status, ...(r.detail ? { detail: String(r.detail).slice(0, 40) } : {}) });
          }
          case 'status':
            return reply({ id, paired: !!pairing.device, domains: store.list().map((r) => r.domain), extension_connected: !!ext });
          case 'reload_extension': {
            try { await sendCmd('reload_extension', {}); return reply({ id, ok: true }); }
            catch (e) { return reply({ id, ok: false, error: String(e.message).slice(0, 40) }); }
          }
          case 'create_pair_code': {
            const c = codes.create();
            return reply({ id, code: c.code, expires_at: c.expires_at });
          }
          case 'test_push': {
            const tok = pairing.device?.push_token?.token;
            if (!apns.configured) return reply({ id, ok: false, reason: 'apns_not_configured' });
            if (!tok) return reply({ id, ok: false, reason: 'no_push_token' });
            const r = await apns.send({ deviceToken: tok, title: 'AuthBridge test', body: 'Push notifications work' });
            if (r.gone) pairing.clearPushToken();
            return reply({ id, ok: !!r.ok, ...(r.ok ? {} : { reason: r.reason || 'unknown' }) });
          }
          case 'wipe':
            return reply({ id, ok: true, removed: store.wipe() });
          default:
            return reply({ id, error: 'unknown_op' });
        }
      } catch (e) {
        log.error('socket_op_error', { error: e });
        reply({ id, status: 'failed', detail: 'internal' });
      }
    }
  }

  const httpServer = http.createServer((req, res) => { handleHttp(req, res); });
  const sockServer = net.createServer(handleSocket);

  const d = {
    home, sockFile, store, pairing, codes,
    httpPort: null,
    async start() {
      try { fs.unlinkSync(sockFile); } catch { /* none */ }
      await new Promise((r, j) => { sockServer.once('error', j); sockServer.listen(sockFile, r); });
      fs.chmodSync(sockFile, 0o600);
      await new Promise((r, j) => { httpServer.once('error', j); httpServer.listen(cfg.port, cfg.host, r); });
      d.httpPort = httpServer.address().port;
      log.info('daemon_started', { port: d.httpPort });
      return d;
    },
    async stop() {
      for (const p of pending.values()) p.resolve({ decision: 'timeout' });
      for (const s of sockets) s.destroy();
      await new Promise((r) => httpServer.close(r));
      httpServer.closeAllConnections?.();
      await new Promise((r) => sockServer.close(r));
      try { fs.unlinkSync(sockFile); } catch { /* ignore */ }
      await mail.close?.();
      wipeBuf(macPriv);
    },
  };
  return d;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const d = await createDaemon();
  await d.start();
  const stop = async () => { await d.stop(); process.exit(0); };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}
