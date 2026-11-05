import test from 'node:test';
import assert from 'node:assert/strict';
import http2 from 'node:http2';
import crypto from 'node:crypto';
import { createApnsNotifier } from '../daemon/apns.mjs';
import { startDaemon, pairedPhone, rpc, sleep } from './helpers.mjs';

const pem = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const PEM = pem.privateKey.export({ type: 'pkcs8', format: 'pem' });
const CFG = { type: 'apns', key_id: 'KEY123', team_id: 'ABCDE12345', topic: 'com.example.authbridge', env: 'development' };
const TOKEN = 'ab'.repeat(32);

async function mockApns(respond = () => ({ status: 200 })) {
  const calls = [];
  const srv = http2.createServer();
  srv.on('stream', (stream, headers) => {
    let body = '';
    stream.on('data', (c) => { body += c; });
    stream.on('end', () => {
      calls.push({ headers, body: JSON.parse(body) });
      const r = respond();
      stream.respond({ ':status': r.status, 'content-type': 'application/json' });
      stream.end(r.reason ? JSON.stringify({ reason: r.reason }) : '');
    });
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { calls, authority: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((r) => { srv.close(r); srv.closeAllSessions?.(); }) };
}

test('apns: JWT shape, headers, payload without task text', async () => {
  const m = await mockApns();
  let keyReads = 0, t = 1_700_000_000_000;
  const n = createApnsNotifier(CFG, { authority: m.authority, getKey: () => { keyReads++; return PEM; }, now: () => t });
  const r = await n.send({ deviceToken: TOKEN, title: 'Login approval needed', body: 'example.com', request_id: 'rid-1', expires_at: t + 300000 });
  assert.equal(r.ok, true);
  const c = m.calls[0];
  assert.equal(c.headers[':path'], `/3/device/${TOKEN}`);
  assert.equal(c.headers['apns-push-type'], 'alert');
  assert.equal(c.headers['apns-priority'], '10');
  assert.equal(c.headers['apns-topic'], CFG.topic);
  assert.equal(c.headers['apns-expiration'], String(Math.floor((t + 300000) / 1000)));
  const [h, cl, sig] = c.headers.authorization.replace('bearer ', '').split('.');
  assert.deepEqual(JSON.parse(Buffer.from(h, 'base64url')), { alg: 'ES256', kid: 'KEY123' });
  assert.deepEqual(JSON.parse(Buffer.from(cl, 'base64url')), { iss: 'ABCDE12345', iat: 1_700_000_000 });
  assert.ok(crypto.verify('sha256', Buffer.from(`${h}.${cl}`), { key: pem.publicKey, dsaEncoding: 'ieee-p1363' }, Buffer.from(sig, 'base64url')));
  assert.deepEqual(c.body, { aps: { alert: { title: 'Login approval needed', body: 'example.com' }, sound: 'default', 'thread-id': 'authbridge' }, request_id: 'rid-1' });
  // cached within 40 min, refreshed after
  await n.send({ deviceToken: TOKEN, title: 'x', body: 'y' });
  assert.equal(m.calls[1].headers.authorization, c.headers.authorization);
  t += 41 * 60 * 1000;
  await n.send({ deviceToken: TOKEN, title: 'x', body: 'y' });
  assert.notEqual(m.calls[2].headers.authorization, c.headers.authorization);
  await m.close();
});

test('apns: not configured and failures never throw', async () => {
  assert.equal(createApnsNotifier({}).configured, false);
  assert.equal((await createApnsNotifier({}).send({ deviceToken: TOKEN })).reason, 'apns_not_configured');
  const n = createApnsNotifier(CFG, { getKey: () => { throw new Error('no key'); } });
  assert.equal((await n.send({ deviceToken: TOKEN, title: 't', body: 'b' })).ok, false);
});

test('push-token endpoint: signature + validation + stored with device, re-pair clears', async () => {
  const d = await startDaemon();
  try {
    const phone = await pairedPhone(d);
    const unsigned = await phone.raw('POST', '/v1/push-token', Buffer.from(JSON.stringify({ token: TOKEN, env: 'development' })));
    assert.equal(unsigned.status, 401);
    assert.equal((await phone.req('POST', '/v1/push-token', { token: 'zz'.repeat(40) })).status, 400);
    assert.equal((await phone.req('POST', '/v1/push-token', { token: 'ab'.repeat(10) })).status, 400);
    assert.equal((await phone.req('POST', '/v1/push-token', { token: 'ab'.repeat(101) })).status, 400);
    assert.equal((await phone.req('POST', '/v1/push-token', {})).status, 400);
    assert.equal((await phone.req('POST', '/v1/push-token', { token: TOKEN, env: 'development' })).status, 200);
    assert.equal(d.daemon.pairing.device.push_token.token, TOKEN);
    await pairedPhone(d);
    assert.equal(d.daemon.pairing.device.push_token, undefined);
  } finally { await d.stop(); }
});

async function loginWith(d, phone) {
  const { mockExtension } = await import('./helpers.mjs');
  const ext = await mockExtension(d.daemon.sockFile, {
    tab_info: () => ({ url: 'https://example.com/login' }),
    probe: () => ({ url: 'https://example.com/login', has_password: true }),
  });
  await phone.enroll({ domain: 'example.com', username: 'u', password: 'p' });
  const p = rpc(d.daemon.sockFile, { op: 'request_login', domain: 'example.com', tab_id: 1, task: 'SECRET TASK TEXT', timeout_s: 1 });
  return { ext, p };
}

test('daemon: pending request sends APNs push (domain only), no fallback notifier', async () => {
  const sent = [];
  const apns = { configured: true, send: async (x) => { sent.push(x); return { ok: true }; } };
  const notes = [];
  const d = await startDaemon({ apns, notifier: { notify: async (n) => { notes.push(n); return true; } } });
  try {
    const phone = await pairedPhone(d);
    await phone.req('POST', '/v1/push-token', { token: TOKEN, env: 'development' });
    const { ext, p } = await loginWith(d, phone);
    await phone.waitPending();
    assert.equal(sent.length, 1);
    assert.equal(sent[0].deviceToken, TOKEN);
    assert.equal(sent[0].body, 'example.com');
    assert.ok(sent[0].request_id);
    assert.ok(!JSON.stringify(sent[0]).includes('SECRET TASK'));
    assert.equal(notes.length, 0);
    await p; ext.close();
  } finally { await d.stop(); }
});

test('daemon: 410 clears stored token', async () => {
  const apns = { configured: true, send: async () => ({ ok: false, status: 410, reason: 'Unregistered', gone: true }) };
  const d = await startDaemon({ apns });
  try {
    const phone = await pairedPhone(d);
    await phone.req('POST', '/v1/push-token', { token: TOKEN });
    const { ext, p } = await loginWith(d, phone);
    await phone.waitPending(); await sleep(50);
    assert.equal(d.daemon.pairing.device.push_token, undefined);
    await p; ext.close();
  } finally { await d.stop(); }
});

test('daemon: falls back to the fallback notifier when APNs not configured or no token', async () => {
  for (const [configured, withToken] of [[false, true], [true, false]]) {
    const apns = { configured, send: async () => { throw new Error('should not send'); } };
    const d = await startDaemon({ apns });
    try {
      const phone = await pairedPhone(d);
      if (withToken) await phone.req('POST', '/v1/push-token', { token: TOKEN });
      const { ext, p } = await loginWith(d, phone);
      await phone.waitPending(); await sleep(50);
      assert.equal(d.notes.length, 1);
      assert.equal(d.notes[0].domain, 'example.com');
      await p; ext.close();
    } finally { await d.stop(); }
  }
});

test('test_push op reports reasons', async () => {
  let d = await startDaemon({ apns: { configured: false } });
  assert.equal((await rpc(d.daemon.sockFile, { op: 'test_push' })).reason, 'apns_not_configured');
  await d.stop();
  const sent = [];
  d = await startDaemon({ apns: { configured: true, send: async (x) => { sent.push(x); return { ok: false, reason: 'BadDeviceToken', gone: false }; } } });
  try {
    assert.equal((await rpc(d.daemon.sockFile, { op: 'test_push' })).reason, 'no_push_token');
    const phone = await pairedPhone(d);
    await phone.req('POST', '/v1/push-token', { token: TOKEN });
    const r = await rpc(d.daemon.sockFile, { op: 'test_push' });
    assert.deepEqual([r.ok, r.reason], [false, 'BadDeviceToken']);
    assert.equal(sent[0].title, 'AuthBridge test');
  } finally { await d.stop(); }
});

test('fallback notifier: disabled without url; posts text, domain and static body with bearer token', async () => {
  const { createNotifier } = await import('../daemon/notifier.mjs');
  assert.equal(await createNotifier({}).notify({ domain: 'example.com' }), false);
  assert.equal(await createNotifier(undefined).notify({ domain: 'example.com' }), false);
  const os = await import('node:os'), fs = await import('node:fs'), path = await import('node:path');
  const tp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'abn-')), 'token');
  fs.writeFileSync(tp, 'tok123\n');
  const calls = [];
  const fetchImpl = async (url, init) => { calls.push({ url, init }); return { ok: true }; };
  const n = createNotifier({ url: 'https://hooks.example.test/send', token_path: tp, body: { chat: 'chat-1' } }, { fetchImpl });
  assert.equal(await n.notify({ domain: 'example.com', task: 'log in' }), true);
  assert.equal(calls[0].url, 'https://hooks.example.test/send');
  assert.equal(calls[0].init.headers.authorization, 'Bearer tok123');
  const body = JSON.parse(calls[0].init.body);
  assert.equal(body.chat, 'chat-1');
  assert.equal(body.domain, 'example.com');
  assert.match(body.text, /example\.com/);
  const n2 = createNotifier({ url: 'https://hooks.example.test/send' }, { fetchImpl });
  await n2.notify({ domain: 'example.com' });
  assert.equal(calls[1].init.headers.authorization, undefined);
});

test('daemon: one reminder push if the phone has not opened the request', async () => {
  const sent = [];
  const apns = { configured: true, send: async (x) => { sent.push(x); return { ok: true }; } };
  const d = await startDaemon({ apns, config: { timing: { reminder_ms: 100 } } });
  try {
    const phone = await pairedPhone(d);
    await phone.req('POST', '/v1/push-token', { token: TOKEN });
    const { ext, p } = await loginWith(d, phone);
    await sleep(400);
    assert.equal(sent.length, 2);
    assert.equal(sent[1].title, 'Still waiting: login approval');
    assert.equal(sent[1].body, 'example.com');
    await sleep(300);
    assert.equal(sent.length, 2);
    await p; ext.close();
  } finally { await d.stop(); }
});

test('daemon: no reminder once the phone has seen the request', async () => {
  const sent = [];
  const apns = { configured: true, send: async (x) => { sent.push(x); return { ok: true }; } };
  const d = await startDaemon({ apns, config: { timing: { reminder_ms: 200 } } });
  try {
    const phone = await pairedPhone(d);
    await phone.req('POST', '/v1/push-token', { token: TOKEN });
    const { ext, p } = await loginWith(d, phone);
    await phone.waitPending();
    await sleep(400);
    assert.equal(sent.length, 1);
    await p; ext.close();
  } finally { await d.stop(); }
});
