import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import crypto from 'node:crypto';
import { createDaemon } from '../daemon/daemon.mjs';
import { createLogger } from '../daemon/logger.mjs';
import { seal, open, x25519Generate, signingString, b64, unb64 } from '../daemon/crypto.mjs';
import { seBin } from '../daemon/paths.mjs';
import { makeSE } from '../daemon/crypto.mjs';

export function tmpHome() {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ab-test-'));
  fs.chmodSync(d, 0o700);
  return d;
}
export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function realSE(home) { return makeSE({ bin: seBin(), home }); }

export async function startDaemon({ mail, notifier, apns, config = {} } = {}) {
  const home = tmpHome();
  const logLines = [];
  const notes = [];
  const daemon = await createDaemon({
    home,
    log: createLogger({ sink: logLines }),
    mail: mail ?? { findCode: async () => null, close: async () => {} },
    apns: apns ?? { configured: false },
    notifier: notifier ?? { notify: async (n) => { notes.push(n); return true; } },
    config: { host: '127.0.0.1', port: 0, insecure_test_hosts: [], timing: { probe_interval_ms: 20, probe_timeout_ms: 400, mail_interval_ms: 20, mail_timeout_ms: 300, prompt_min_ms: 50, prompt_max_ms: 50, prompt_default_ms: 50, code_request_ttl_ms: 300, cmd_timeout_ms: 2000, code_settle_ms: 100, done_settle_ms: 40 }, ...config },
  });
  await daemon.start();
  return { daemon, home, logLines, notes, stop: async () => { await daemon.stop(); fs.rmSync(home, { recursive: true, force: true }); } };
}

// ---- socket client (MCP-like) ----
export function rpc(sockFile, msg, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(sockFile);
    let buf = '';
    const t = setTimeout(() => { s.destroy(); reject(new Error('rpc timeout')); }, timeoutMs);
    s.on('connect', () => s.write(JSON.stringify({ id: 1, ...msg }) + '\n'));
    s.on('data', (d) => { buf += d; if (buf.includes('\n')) { clearTimeout(t); s.end(); resolve(JSON.parse(buf.split('\n')[0])); } });
    s.on('error', (e) => { clearTimeout(t); reject(e); });
  });
}

// ---- mock extension on the socket ----
export async function mockExtension(sockFile, handlers) {
  const s = net.createConnection(sockFile);
  await new Promise((r) => s.once('connect', r));
  const calls = [];
  let buf = '';
  s.on('data', async (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i); buf = buf.slice(i + 1);
      const m = JSON.parse(line);
      if (!m.cmd) continue;
      calls.push(m);
      try {
        const h = handlers[m.cmd];
        if (!h) throw new Error('unsupported');
        const result = await h(m);
        s.write(JSON.stringify({ cmd_id: m.cmd_id, ok: true, result: result ?? {} }) + '\n');
      } catch (e) {
        s.write(JSON.stringify({ cmd_id: m.cmd_id, ok: false, error: e.message }) + '\n');
      }
    }
  });
  s.write(JSON.stringify({ op: 'extension_hello' }) + '\n');
  await sleep(50);
  return { calls, close: () => s.destroy() };
}

// ---- fake phone (software keys) ----
export class FakePhone {
  constructor(port) {
    this.port = port;
    const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    this.signKey = kp.privateKey;
    this.signPubB64 = kp.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    this.agree = x25519Generate();
    this.shares = new Map();
  }
  async raw(method, p, bodyBuf, headers) {
    const res = await fetch(`http://127.0.0.1:${this.port}${p}`, { method, body: bodyBuf && bodyBuf.length ? bodyBuf : undefined, headers: { 'content-type': 'application/json', ...headers } });
    return { status: res.status, json: await res.json().catch(() => null) };
  }
  signedHeaders(method, p, bodyBuf, { ts = Date.now(), nonce = crypto.randomBytes(16).toString('base64') } = {}) {
    const sig = crypto.sign('sha256', signingString(method, p, String(ts), nonce, bodyBuf), this.signKey);
    return { 'x-ab-device': this.deviceId, 'x-ab-ts': String(ts), 'x-ab-nonce': nonce, 'x-ab-sig': sig.toString('base64') };
  }
  async req(method, p, body, opts) {
    const buf = body === undefined ? Buffer.alloc(0) : Buffer.from(JSON.stringify(body));
    return this.raw(method, p, buf, this.signedHeaders(method, p, buf, opts));
  }
  async pair(code) {
    const r = await this.raw('POST', '/v1/pair', Buffer.from(JSON.stringify({ code, device_name: 'Fake iPhone', sign_pub: this.signPubB64, agree_pub: b64(this.agree.pub) })));
    if (r.status === 200) { this.deviceId = r.json.device_id; this.macPub = unb64(r.json.mac_agree_pub); }
    return r;
  }
  async enroll({ domain, username, password, email }) {
    const record_id = crypto.randomUUID();
    const P = crypto.randomBytes(32);
    this.shares.set(record_id, P);
    const sealed = seal(this.macPub, Buffer.from(JSON.stringify({ record_id, domain, username, password, ...(email !== undefined ? { email } : {}), share: b64(P) })), 'enroll');
    const r = await this.req('POST', '/v1/enroll', { sealed });
    return { ...r, record_id };
  }
  async pending() { return (await this.req('GET', '/v1/pending')).json.requests; }
  async approve(request) {
    const sealed_share = seal(this.macPub, this.shares.get(request.record_id), request.id);
    return this.req('POST', '/v1/approve', { request_id: request.id, decision: 'approve', record_id: request.record_id, sealed_share });
  }
  async deny(request) { return this.req('POST', '/v1/approve', { request_id: request.id, decision: 'deny', record_id: request.record_id }); }
  async submitCode(request, code, { raw } = {}) {
    const sealed = seal(this.macPub, Buffer.from(JSON.stringify({ code })), 'code|' + request.id);
    return this.req('POST', '/v1/code', { request_id: request.id, decision: 'submit', sealed: raw ?? sealed });
  }
  async cancelCode(request) { return this.req('POST', '/v1/code', { request_id: request.id, decision: 'cancel' }); }
  async waitPending(n = 1, ms = 3000) {
    const end = Date.now() + ms;
    for (;;) { const p = await this.pending(); if (p.length >= n) return p; if (Date.now() > end) throw new Error('no pending'); await sleep(20); }
  }
}

export async function pairedPhone(d) {
  const phone = new FakePhone(d.daemon.httpPort);
  const code = (await rpc(d.daemon.sockFile, { op: 'create_pair_code' })).code;
  const r = await phone.pair(code);
  if (r.status !== 200) throw new Error('pair failed ' + r.status);
  return phone;
}
export { seal, open, b64, unb64 };
