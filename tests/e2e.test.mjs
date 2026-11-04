import test from 'node:test';
import fs from 'node:fs';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startDaemon, rpc, mockExtension, pairedPhone, FakePhone, sleep, seal, b64 } from './helpers.mjs';
import { startTestSite, TEST_USER, TEST_PASS, TEST_CODE, TEST_CODE2 } from '../testsite/server.mjs';

// A "browser" with no JS: just enough to drive the test site through form posts and cookies.
function mockBrowser(base) {
  const st = { url: base + '/login', cookie: '', fills: 0 };
  async function get(url) {
    for (let i = 0; i < 5; i++) {
      const r = await fetch(url, { redirect: 'manual', headers: { cookie: st.cookie } });
      const sc = r.headers.get('set-cookie'); if (sc) st.cookie = sc.split(';')[0];
      if (r.status >= 300 && r.status < 400) { url = new URL(r.headers.get('location'), url).href; continue; }
      st.url = url; return r.text();
    }
  }
  async function post(action, fields) {
    const r = await fetch(new URL(action, st.url), { method: 'POST', redirect: 'manual', headers: { cookie: st.cookie, 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(fields) });
    const sc = r.headers.get('set-cookie'); if (sc) st.cookie = sc.split(';')[0];
    if (r.status >= 300 && r.status < 400) return get(new URL(r.headers.get('location'), st.url).href);
    return r.text();
  }
  const html = async () => get(st.url);
  const info = (h) => ({
    url: st.url,
    has_password: /type="password"/.test(h) && /<form/.test(h),
    has_username_only: /<form/.test(h) && !/type="password"/.test(h) && /name="(email|username)"/.test(h),
    has_otp: /one-time-code|name="d1"/.test(h),
    captcha: false, passkey_prompt: false,
  });
  return {
    st,
    handlers: {
      tab_info: async () => ({ url: st.url }),
      probe: async () => info(await html()),
      reload: async () => { await get(st.url); return {}; },
      fill_credentials: async (m) => {
        st.fills++;
        let h = await html();
        if (!/type="password"/.test(h)) { h = await post(h.match(/action="([^"]+)"/)[1], { email: m.username }); }
        const hidden = h.match(/name="email" value="([^"]*)"/);
        const f = /name="username"/.test(h) ? { username: m.username, password: m.password } : { ...(hidden ? { email: hidden[1] } : {}), password: m.password };
        await post(h.match(/action="([^"]+)"/)[1], f);
        return { submitted: true };
      },
      fill_code: async (m) => {
        const h = await html();
        const action = h.match(/action="([^"]+)"/)[1];
        await post(action, /name="d1"/.test(h) ? Object.fromEntries([...m.code].map((c, i) => ['d' + (i + 1), c])) : { otp: m.code });
        return { submitted: true };
      },
    },
  };
}

async function setup(extra = {}) {
  const site = await startTestSite();
  const base = `http://localhost:${site.port}`;
  const d = await startDaemon({ config: { insecure_test_hosts: ['localhost', '127.0.0.1'] }, ...extra });
  const phone = await pairedPhone(d);
  const browser = mockBrowser(base);
  const ext = await mockExtension(d.daemon.sockFile, browser.handlers);
  return { site, base, d, phone, browser, ext, stop: async () => { ext.close(); await d.stop(); await site.close(); } };
}

// Approve every pending request that appears, counting approvals.
function autoApprove(phone, counter) {
  let on = true;
  (async () => {
    while (on) {
      try { for (const r of await phone.pending()) { await phone.approve(r); counter.n++; } } catch { /* ignore */ }
      await sleep(15);
    }
  })();
  return () => { on = false; };
}

test('e2e: one-step login with a fake phone and mock extension; no secrets leak', async () => {
  const t = await setup();
  try {
    const enr = await t.phone.enroll({ domain: 'localhost', username: TEST_USER, password: TEST_PASS });
    assert.equal(enr.status, 200); assert.equal(enr.json.domain, 'localhost');
    const recs = await t.phone.req('GET', '/v1/records');
    assert.equal(recs.json.records.length, 1);
    assert.ok(!JSON.stringify(recs.json).includes(TEST_USER));

    const st = await rpc(t.d.daemon.sockFile, { op: 'status' });
    assert.deepEqual(st, { id: 1, paired: true, domains: ['localhost'], extension_connected: true });

    const login = rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 7, task: 'check billing' });
    const [req] = await t.phone.waitPending();
    assert.equal(req.domain, 'localhost'); assert.equal(req.task, 'check billing'); assert.equal(req.record_id, enr.record_id);
    assert.equal(t.d.notes.length, 1); assert.equal(t.d.notes[0].domain, 'localhost');
    assert.equal((await t.phone.approve(req)).status, 200);
    const res = await login;
    assert.deepEqual(res, { id: 1, status: 'signed_in' });
    assert.ok(t.browser.st.cookie.includes('sid=ok'));
    assert.deepEqual((await t.phone.pending()), []);

    // logs and the store file never contain the credentials
    const fs = await import('node:fs');
    const all = t.d.logLines.join('\n') + fs.readFileSync(t.d.home + '/store.json', 'utf8') + fs.readFileSync(t.d.home + '/pairing.json', 'utf8');
    assert.ok(!all.includes(TEST_PASS) && !all.includes(TEST_USER));
    assert.ok(!JSON.stringify(res).includes(TEST_PASS));

    // already signed in now
    assert.deepEqual(await rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 7, task: 'again' }), { id: 1, status: 'already_signed_in' });
  } finally { await t.stop(); }
});

test('e2e: two-step (email then password) login', async () => {
  const t = await setup();
  try {
    await t.phone.enroll({ domain: 'localhost', username: TEST_USER, password: TEST_PASS });
    t.browser.st.url = t.base + '/login-2step';
    const login = rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 1, task: 't' });
    await t.phone.approve((await t.phone.waitPending())[0]);
    assert.equal((await login).status, 'signed_in');
  } finally { await t.stop(); }
});

test('e2e: email-code step uses the mail fetcher and remembers the account', async () => {
  const seen = [];
  const mail = { findCode: async (q) => { seen.push(q); return { code: TEST_CODE, account: 'gmail' }; }, close: async () => {} };
  const t = await setup({ mail });
  try {
    const enr = await t.phone.enroll({ domain: 'localhost', username: TEST_USER, password: TEST_PASS });
    t.browser.st.url = t.base + '/login-code';
    const before = Date.now();
    const login = rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 1, task: 't' });
    await t.phone.approve((await t.phone.waitPending())[0]);
    assert.equal((await login).status, 'signed_in');
    assert.equal(seen[0].domain, 'localhost');
    assert.ok(seen[0].sinceMs <= before - 29000 && seen[0].sinceMs >= before - 31000);
    assert.equal(t.d.daemon.store.byId(enr.record_id).preferred_mail, 'gmail');
  } finally { await t.stop(); }
});

test('e2e: no code found anywhere -> needs_more sms_or_app_code (phone asked, never answered)', async () => {
  const t = await setup();
  try {
    await t.phone.enroll({ domain: 'localhost', username: TEST_USER, password: TEST_PASS });
    t.browser.st.url = t.base + '/login-code';
    const login = rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 1, task: 't' });
    await t.phone.approve((await t.phone.waitPending())[0]);
    assert.deepEqual(await login, { id: 1, status: 'needs_more', detail: 'sms_or_app_code' });
  } finally { await t.stop(); }
});

test('e2e: wrong stored password -> out_of_date and record marked stale', async () => {
  const t = await setup();
  try {
    const enr = await t.phone.enroll({ domain: 'localhost', username: TEST_USER, password: 'old-password' });
    const login = rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 1, task: 't' });
    await t.phone.approve((await t.phone.waitPending())[0]);
    assert.equal((await login).status, 'out_of_date');
    const recs = await t.phone.req('GET', '/v1/records');
    assert.equal(recs.json.records[0].stale, true);
    assert.equal(enr.status, 200);
  } finally { await t.stop(); }
});

test('e2e: deny, timeout, no_credential, domain_mismatch, extension_unavailable, not_paired', async () => {
  const t = await setup();
  try {
    await t.phone.enroll({ domain: 'localhost', username: TEST_USER, password: TEST_PASS });
    let login = rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 1, task: 't' });
    await t.phone.deny((await t.phone.waitPending())[0]);
    assert.equal((await login).status, 'denied');
    assert.equal((await rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 1, task: 't', timeout_s: 0.2 })).status, 'timed_out');
    assert.equal((await rpc(t.d.daemon.sockFile, { op: 'request_login', domain: '127.0.0.1', tab_id: 1, task: 't' })).status, 'domain_mismatch');
    t.browser.st.url = 'https://localhost.evil.net/login';
    assert.equal((await rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 1, task: 't' })).status, 'domain_mismatch');
    t.browser.st.url = t.base + '/login';
    t.browser.handlers.tab_info = async () => ({ url: t.base + '/login' });
    // no record for this domain
    assert.equal((await rpc(t.d.daemon.sockFile, { op: 'request_login', domain: '127.0.0.1', tab_id: 1, task: 't' })).status, 'domain_mismatch');
    t.ext.close(); await sleep(50);
    assert.equal((await rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 1, task: 't' })).status, 'extension_unavailable');
  } finally { await t.stop(); }
});

test('http on a non-test host is rejected as domain_mismatch (insecure_test_hosts off by default)', async () => {
  const d = await startDaemon();
  try {
    const ext = await mockExtension(d.daemon.sockFile, { tab_info: async () => ({ url: 'http://localhost:1/login' }) });
    assert.equal((await rpc(d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 1, task: 't' })).status, 'domain_mismatch');
    ext.close();
  } finally { await d.stop(); }
});

test('not_paired, and not_paired again after enrolling', async () => {
  const d = await startDaemon();
  try {
    const login = { has_password: true, captcha: false };
    const ext = await mockExtension(d.daemon.sockFile, { tab_info: async () => ({ url: 'https://example.com/login' }), probe: async () => ({ url: 'https://example.com/login', ...login }) });
    assert.equal((await rpc(d.daemon.sockFile, { op: 'request_login', domain: 'example.com', tab_id: 1, task: 't' })).status, 'not_paired');
    const phone = await pairedPhone(d);
    await phone.enroll({ domain: 'example.com', username: 'u', password: 'p' });
    d.daemon.pairing.data.device = null; // simulate unpaired
    assert.equal((await rpc(d.daemon.sockFile, { op: 'request_login', domain: 'example.com', tab_id: 1, task: 't' })).status, 'not_paired');
    ext.close();
  } finally { await d.stop(); }
});

test('per-domain lock: same-domain requests share one approval; different domains do not block', async () => {
  const d = await startDaemon();
  try {
    const phone = await pairedPhone(d);
    // a fake browser state per domain: signed in once the credential is filled
    const signed = new Set();
    const hostOf = (tab) => (tab === 1 || tab === 2 ? 'a.example.com' : 'b.example.org');
    const ext = await mockExtension(d.daemon.sockFile, {
      tab_info: async (m) => ({ url: `https://${hostOf(m.tab_id)}/login` }),
      probe: async (m) => ({ url: `https://${hostOf(m.tab_id)}/`, has_password: !signed.has(hostOf(m.tab_id)), captcha: false }),
      fill_credentials: async (m) => { signed.add(m.expected_domain === 'example.com' ? 'a.example.com' : 'b.example.org'); return { submitted: true }; },
      reload: async () => ({}),
    });
    await phone.enroll({ domain: 'example.com', username: 'u', password: 'p' });
    await phone.enroll({ domain: 'example.org', username: 'u', password: 'p' });
    const reqA1 = rpc(d.daemon.sockFile, { op: 'request_login', domain: 'example.com', tab_id: 1, task: 'a1' });
    await sleep(30);
    const reqA2 = rpc(d.daemon.sockFile, { op: 'request_login', domain: 'example.com', tab_id: 2, task: 'a2' });
    const reqB = rpc(d.daemon.sockFile, { op: 'request_login', domain: 'example.org', tab_id: 3, task: 'b' });
    const pend = await phone.waitPending(2);
    assert.equal(pend.length, 2); // one for A (a2 waits behind it), one for B
    assert.deepEqual(pend.map((p) => p.domain).sort(), ['example.com', 'example.org']);
    // approve B only: B finishes while A is still waiting
    await phone.approve(pend.find((p) => p.domain === 'example.org'));
    assert.equal((await reqB).status, 'signed_in');
    const stillWaiting = await Promise.race([reqA1.then(() => 'done'), sleep(80).then(() => 'waiting')]);
    assert.equal(stillWaiting, 'waiting');
    await phone.approve(pend.find((p) => p.domain === 'example.com'));
    assert.equal((await reqA1).status, 'signed_in');
    assert.equal((await reqA2).status, 'already_signed_in');
    assert.deepEqual(await phone.pending(), []); // A2 never created its own approval
    ext.close();
  } finally { await d.stop(); }
});

test('phone API security: unsigned, wrong device, replay, bad pairing code, wipe, delete', async () => {
  const d = await startDaemon();
  try {
    const stranger = new FakePhone(d.daemon.httpPort);
    assert.equal((await stranger.raw('GET', '/v1/pending', undefined, {})).status, 401); // not paired yet
    const phone = await pairedPhone(d);
    assert.equal((await stranger.pair('00000000')).status, 403); // no code issued / wrong
    assert.equal((await phone.raw('GET', '/v1/pending', undefined, {})).status, 401); // unsigned
    stranger.deviceId = phone.deviceId; // impersonation with another key
    assert.equal((await stranger.req('GET', '/v1/pending')).status, 401);
    // replay of an identical signed request
    const buf = Buffer.alloc(0);
    const h = phone.signedHeaders('GET', '/v1/records', buf);
    assert.equal((await phone.raw('GET', '/v1/records', buf, h)).status, 200);
    assert.equal((await phone.raw('GET', '/v1/records', buf, h)).status, 401);
    // stale timestamp
    assert.equal((await phone.req('GET', '/v1/records', undefined, { ts: Date.now() - 120000 })).status, 401);
    // enroll garbage
    assert.equal((await phone.req('POST', '/v1/enroll', { sealed: { epk: 'AA==', nonce: 'AA==', ct: 'AA==' } })).status, 400);
    // delete + wipe
    const a = await phone.enroll({ domain: 'a.com', username: 'u', password: 'p' });
    await phone.enroll({ domain: 'b.com', username: 'u', password: 'p' });
    assert.equal((await phone.req('DELETE', '/v1/records/' + a.record_id)).status, 200);
    assert.equal((await phone.req('GET', '/v1/records')).json.records.length, 1);
    assert.equal((await phone.req('POST', '/v1/wipe', {})).status, 200);
    assert.equal((await phone.req('GET', '/v1/records')).json.records.length, 0);
    // enrolling the same domain replaces the record
    await phone.enroll({ domain: 'A.com', username: 'u', password: 'p' });
    const second = await phone.enroll({ domain: 'a.com', username: 'u2', password: 'p2' });
    const recs = (await phone.req('GET', '/v1/records')).json.records;
    assert.equal(recs.length, 1); assert.equal(recs[0].record_id, second.record_id);
    // 5 wrong pairing guesses invalidate the code, even the right one
    const code = (await rpc(d.daemon.sockFile, { op: 'create_pair_code' })).code;
    for (let i = 0; i < 5; i++) await stranger.pair(code === '12345678' ? '87654321' : '12345678');
    assert.equal((await stranger.pair(code)).status, 403);
  } finally { await d.stop(); }
});

test('create_pair_code is refused for an extension connection and not exposed over HTTP', async () => {
  const d = await startDaemon();
  try {
    const net = await import('node:net');
    const s = net.createConnection(d.daemon.sockFile);
    await new Promise((r) => s.once('connect', r));
    let out = '';
    s.on('data', (x) => { out += x; });
    s.write(JSON.stringify({ op: 'extension_hello' }) + '\n');
    await sleep(40);
    s.write(JSON.stringify({ id: 9, op: 'create_pair_code' }) + '\n');
    await sleep(60);
    assert.ok(out.includes('forbidden') && !/"code"/.test(out));
    s.destroy();
    const r = await fetch(`http://127.0.0.1:${d.daemon.httpPort}/v1/create_pair_code`, { method: 'POST' });
    assert.ok(r.status === 401 || r.status === 404);
  } finally { await d.stop(); }
});

test('first login: needs_enroll pending shape, notification, enroll then approve signs in', async () => {
  const t = await setup();
  try {
    const login = rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 7, task: 'first time' });
    const [req] = await t.phone.waitPending();
    assert.equal(req.needs_enroll, true); assert.equal(req.record_id, null); assert.equal(req.domain, 'localhost');
    assert.equal(t.d.notes.length, 1); assert.equal(t.d.notes[0].domain, 'localhost');
    const enr = await t.phone.enroll({ domain: 'localhost', username: TEST_USER, password: TEST_PASS });
    assert.equal(enr.status, 200);
    assert.equal((await t.phone.approve({ id: req.id, record_id: enr.record_id })).status, 200);
    assert.deepEqual(await login, { id: 1, status: 'signed_in' });
    assert.ok(t.browser.st.cookie.includes('sid=ok'));
    const all = t.d.logLines.join('\n');
    assert.ok(!all.includes(TEST_PASS) && !all.includes(TEST_USER));
  } finally { await t.stop(); }
});

test('first login: record for a different domain is rejected, then deny works', async () => {
  const t = await setup();
  try {
    const login = rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 7, task: 't' });
    const [req] = await t.phone.waitPending();
    const other = await t.phone.enroll({ domain: 'example.org', username: 'u', password: 'p' });
    const bad = await t.phone.approve({ id: req.id, record_id: other.record_id });
    assert.equal(bad.status, 400); assert.equal(bad.json.error, 'record_mismatch');
    const missing = await t.phone.req('POST', '/v1/approve', { request_id: req.id, decision: 'approve', record_id: null });
    assert.equal(missing.status, 400);
    assert.equal((await t.phone.pending()).length, 1);
    await t.phone.deny(req);
    assert.equal((await login).status, 'denied');
  } finally { await t.stop(); }
});

test('first login: explicit no_credential decision, and timeout', async () => {
  const t = await setup();
  try {
    const login = rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 7, task: 't' });
    const [req] = await t.phone.waitPending();
    assert.equal((await t.phone.req('POST', '/v1/approve', { request_id: req.id, decision: 'no_credential' })).status, 200);
    assert.equal((await login).status, 'no_credential');
    assert.equal((await rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 7, task: 't', timeout_s: 0.2 })).status, 'timed_out');
  } finally { await t.stop(); }
});

test('e2e: fill_credentials carries email (explicit, and username-with-@ fallback); never logged', async () => {
  const seen = [];
  const site = await startTestSite();
  const d = await startDaemon({ config: { insecure_test_hosts: ['localhost', '127.0.0.1'] } });
  const phone = await pairedPhone(d);
  const browser = mockBrowser(`http://localhost:${site.port}`);
  const ext = await mockExtension(d.daemon.sockFile, { ...browser.handlers, fill_credentials: async (m) => { seen.push({ username: m.username, email: m.email }); return browser.handlers.fill_credentials(m); } });
  try {
    for (const [username, email, want] of [[TEST_USER, 'me@mail.example', 'me@mail.example'], [TEST_USER, undefined, TEST_USER], ['plainuser', undefined, '']]) {
      browser.st.cookie = ''; browser.st.url = `http://localhost:${site.port}/login`;
      await phone.enroll({ domain: 'localhost', username, password: TEST_PASS, email });
      const login = rpc(d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 7, task: 't' });
      const [req] = await phone.waitPending();
      await phone.approve(req);
      await login;
      assert.equal(seen.at(-1).email, want);
    }
    assert.equal(seen.length, 3);
    const log = d.logLines.join('\n');
    assert.ok(!log.includes('mail.example') && !log.includes('plainuser'));
  } finally { ext.close(); await d.stop(); await site.close(); }
});

test('e2e: extension email_required maps to failed/email_required', async () => {
  const site = await startTestSite();
  const d = await startDaemon({ config: { insecure_test_hosts: ['localhost', '127.0.0.1'] } });
  const phone = await pairedPhone(d);
  const browser = mockBrowser(`http://localhost:${site.port}`);
  const ext = await mockExtension(d.daemon.sockFile, { ...browser.handlers, fill_credentials: async () => { throw new Error('email_required'); } });
  try {
    await phone.enroll({ domain: 'localhost', username: 'plainuser', password: TEST_PASS });
    const login = rpc(d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 7, task: 't' });
    const [req] = await phone.waitPending();
    await phone.approve(req);
    assert.deepEqual(await login, { id: 1, status: 'failed', detail: 'email_required' });
  } finally { ext.close(); await d.stop(); await site.close(); }
});

test('update: edit email via signed endpoint, password kept; bad share / aad / unsigned rejected', async () => {
  const t = await setup();
  try {
    const { record_id } = await t.phone.enroll({ domain: 'localhost', username: TEST_USER, password: TEST_PASS });
    const P = t.phone.shares.get(record_id);
    const path = `/v1/records/${record_id}/update`;
    const mk = (payload, aad = 'update|' + record_id) => ({ sealed: seal(t.phone.macPub, Buffer.from(JSON.stringify(payload)), aad) });
    const snap = () => JSON.stringify(t.d.daemon.store.byId(record_id));
    const before = snap();

    // wrong share -> 400 decrypt, record unchanged
    let r = await t.phone.req('POST', path, mk({ share: b64(crypto.randomBytes(32)), email: 'x@y.z' }));
    assert.equal(r.status, 400); assert.equal(r.json.error, 'decrypt'); assert.equal(snap(), before);
    // wrong aad
    r = await t.phone.req('POST', path, mk({ share: b64(P), email: 'x@y.z' }, 'update|other'));
    assert.equal(r.status, 400); assert.equal(snap(), before);
    // empty username rejected
    r = await t.phone.req('POST', path, mk({ share: b64(P), username: '' }));
    assert.equal(r.status, 400); assert.equal(snap(), before);
    // unsigned
    r = await t.phone.raw('POST', path, Buffer.from(JSON.stringify(mk({ share: b64(P), email: 'x@y.z' }))), {});
    assert.equal(r.status, 401); assert.equal(snap(), before);

    // happy path
    t.d.daemon.store.patch(record_id, { stale: true });
    r = await t.phone.req('POST', path, mk({ share: b64(P), email: 'new@example.com' }));
    assert.equal(r.status, 200); assert.deepEqual(r.json, { ok: true });
    const rec = t.d.daemon.store.byId(record_id);
    assert.equal(rec.stale, false);
    assert.notEqual(snap(), before);
    assert.ok(!JSON.stringify(t.d.logLines).includes('new@example.com'));

    // login now receives the new email and the original password
    const stop = autoApprove(t.phone, { n: 0 });
    const res = await rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 1, task: 't', timeout_s: 5 });
    stop();
    const fill = t.ext.calls.find((c) => c.cmd === 'fill_credentials');
    assert.ok(fill, 'fill_credentials called');
    assert.equal(fill.email, 'new@example.com');
    assert.equal(fill.password, TEST_PASS);
    assert.equal(fill.username, TEST_USER);
    void res;

    // remove email with empty string
    r = await t.phone.req('POST', path, mk({ share: b64(P), email: '' }));
    assert.equal(r.status, 200);
  } finally { await t.stop(); }
});

// ---------------- code requests (phone supplies a code) ----------------
const codeTiming = { probe_interval_ms: 20, probe_timeout_ms: 400, mail_interval_ms: 20, mail_timeout_ms: 600, cmd_timeout_ms: 2000, code_request_after_ms: 100, prompt_min_ms: 100, prompt_max_ms: 100, prompt_default_ms: 100, code_request_ttl_ms: 800, done_settle_ms: 40 };
async function codeSetup(page, extra = {}) {
  const t = await setup({ config: { insecure_test_hosts: ['localhost', '127.0.0.1'], timing: codeTiming, ...(extra.config || {}) }, ...(extra.mail ? { mail: extra.mail } : {}) });
  await t.phone.enroll({ domain: 'localhost', username: TEST_USER, password: TEST_PASS });
  t.browser.st.url = t.base + page;
  const codes = [];
  const orig = t.browser.handlers.fill_code;
  t.browser.handlers.fill_code = async (m) => { codes.push(m.code); return orig(m); };
  const login = rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 1, task: 'dashboard' });
  await t.phone.approve((await t.phone.waitPending())[0]);
  const waitCode = async () => { const end = Date.now() + 3000; for (;;) { const c = (await t.phone.pending()).find((r) => r.kind === 'code'); if (c) return c; if (Date.now() > end) throw new Error('no code request'); await sleep(15); } };
  return { t, codes, login, waitCode };
}

test('e2e: email code not found -> code request -> phone submits -> signed_in', async () => {
  const pushes = [];
  const apns = { configured: true, send: async (m) => { pushes.push(m); return { ok: true }; } };
  const { t, codes, login, waitCode } = await codeSetup('/login-code', { apns });
  try {
    const c = await waitCode();
    assert.equal(c.kind, 'code'); assert.equal(c.domain, 'localhost'); assert.ok(c.parent_id);
    assert.equal(c.reason, 'email_not_found'); assert.deepEqual(c.searched, []);
    assert.ok(c.expires_at - c.requested_at <= 800 + 50);
    assert.equal(t.d.notes.length, 2); // login + code via the fallback notifier
    // spaces/dashes are stripped
    assert.equal((await t.phone.submitCode(c, TEST_CODE.slice(0, 3) + ' - ' + TEST_CODE.slice(3))).status, 200);
    assert.deepEqual(await login, { id: 1, status: 'signed_in' });
    assert.deepEqual(codes, [TEST_CODE]);
    assert.deepEqual(await t.phone.pending(), []);
    assert.ok(!t.d.logLines.join('\n').includes(TEST_CODE));
    // a late answer is ignored
    assert.equal((await t.phone.submitCode(c, TEST_CODE)).status, 404);
  } finally { await t.stop(); }
});

test('e2e: push for a code request carries request_id and kind', async () => {
  const pushes = [];
  const apns = { configured: true, send: async (m) => { pushes.push(m); return { ok: true }; } };
  const t = await setup({ apns, config: { insecure_test_hosts: ['localhost'], timing: codeTiming } });
  try {
    await t.phone.enroll({ domain: 'localhost', username: TEST_USER, password: TEST_PASS });
    await t.phone.req('POST', '/v1/push-token', { token: 'ab'.repeat(32) });
    t.browser.st.url = t.base + '/login-code';
    const login = rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 1, task: 't' });
    await t.phone.approve((await t.phone.waitPending())[0]);
    let c; for (;;) { c = (await t.phone.pending()).find((r) => r.kind === 'code'); if (c) break; await sleep(15); }
    const push = pushes.find((p) => p.kind === 'code');
    assert.equal(push.request_id, c.id); assert.equal(push.body, 'localhost — enter the verification code');
    await t.phone.cancelCode(c);
    await login;
  } finally { await t.stop(); }
});

test('e2e: email code found first -> code request removed', async () => {
  let calls = 0;
  const mail = { findCode: async () => (++calls > 8 ? { code: TEST_CODE, account: 'gmail' } : null), close: async () => {} };
  const { t, codes, login, waitCode } = await codeSetup('/login-code', { mail, config: { insecure_test_hosts: ['localhost'], timing: { ...codeTiming, mail_interval_ms: 30 } } });
  try {
    const c = await waitCode();
    assert.deepEqual(await login, { id: 1, status: 'signed_in' });
    assert.deepEqual(codes, [TEST_CODE]);
    assert.equal((await t.phone.pending()).find((r) => r.id === c.id), undefined);
    assert.equal((await t.phone.submitCode(c, '999999')).status, 404);
  } finally { await t.stop(); }
});

test('e2e: follow-up code step creates a code request straight away (no mail polling)', async () => {
  let mailCalls = 0;
  const mail = { findCode: async () => { mailCalls++; return { code: TEST_CODE, account: 'yahoo' }; }, close: async () => {} };
  const { t, codes, login, waitCode } = await codeSetup('/login-code2', { mail });
  try {
    const c = await waitCode();
    assert.equal(mailCalls >= 1, true);
    const before = mailCalls;
    assert.equal((await t.phone.submitCode(c, TEST_CODE2)).status, 200);
    assert.deepEqual(await login, { id: 1, status: 'signed_in' });
    assert.deepEqual(codes, [TEST_CODE, TEST_CODE2]);
    assert.equal(mailCalls, before);
  } finally { await t.stop(); }
});

test('e2e: cancel and timeout of a code request -> needs_more sms_or_app_code', async () => {
  let x = await codeSetup('/login-code');
  try {
    const c = await x.waitCode();
    assert.equal((await x.t.phone.cancelCode(c)).status, 200);
    assert.deepEqual(await x.login, { id: 1, status: 'needs_more', detail: 'sms_or_app_code' });
  } finally { await x.t.stop(); }
  x = await codeSetup('/login-code');
  try {
    await x.waitCode();
    assert.deepEqual(await x.login, { id: 1, status: 'needs_more', detail: 'sms_or_app_code' });
    assert.deepEqual(await x.t.phone.pending(), []);
  } finally { await x.t.stop(); }
});

test('e2e: invalid or unsigned code submissions are rejected', async () => {
  const { t, login, waitCode } = await codeSetup('/login-code');
  try {
    const c = await waitCode();
    for (const bad of ['12', '123 456 789 01', 'ab$cd', '']) assert.equal((await t.phone.submitCode(c, bad)).status, 400, bad);
    assert.equal((await t.phone.submitCode(c, 'abcdef', { raw: { epk: 'x', nonce: 'y', ct: 'z' } })).status, 400);
    // sealed for the wrong request id
    const wrong = seal(t.phone.macPub, Buffer.from(JSON.stringify({ code: TEST_CODE })), 'code|other');
    assert.equal((await t.phone.req('POST', '/v1/code', { request_id: c.id, decision: 'submit', sealed: wrong })).status, 400);
    // unsigned
    const body = Buffer.from(JSON.stringify({ request_id: c.id, decision: 'cancel' }));
    assert.equal((await t.phone.raw('POST', '/v1/code', body, {})).status, 401);
    assert.equal((await t.phone.pending()).filter((r) => r.kind === 'code').length, 1); // still open
    // login requests cannot be answered via /v1/code, nor code requests via /v1/approve
    assert.equal((await t.phone.deny({ id: c.id, record_id: null })).status, 404);
    await t.phone.cancelCode(c);
    await login;
  } finally { await t.stop(); }
});

test('e2e: remembered-account page (one "Log in" button, no fields) -> press_continue -> phone code -> signed_in', async () => {
  const t = await setup({ config: { insecure_test_hosts: ['localhost', '127.0.0.1'], timing: codeTiming } });
  try {
    await t.phone.enroll({ domain: 'localhost', username: TEST_USER, password: TEST_PASS });
    let page = 'remembered'; const calls = [];
    const url = () => t.base + '/' + page;
    const h = t.browser.handlers;
    h.tab_info = async () => ({ url: url() });
    h.probe = async () => ({ url: url(), has_password: false, has_username_only: false, has_otp: page === 'otp', captcha: false, passkey_prompt: false, continue_button: page === 'remembered' });
    h.fill_credentials = async () => { calls.push('fill_credentials'); return { submitted: true }; };
    h.press_continue = async (m) => { calls.push('press_continue:' + m.expected_domain); page = 'otp'; return { pressed: true }; };
    h.fill_code = async (m) => { calls.push('fill_code'); page = m.code === TEST_CODE ? 'home' : 'otp'; return { submitted: true }; };
    const login = rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 1, task: 'airbnb-like' });
    await t.phone.approve((await t.phone.waitPending())[0]);
    const end = Date.now() + 3000; let c;
    while (!(c = (await t.phone.pending()).find((r) => r.kind === 'code'))) { if (Date.now() > end) throw new Error('no code request'); await sleep(15); }
    await t.phone.submitCode(c, TEST_CODE);
    assert.deepEqual(await login, { id: 1, status: 'signed_in' });
    assert.deepEqual(calls, ['press_continue:localhost', 'fill_code']);
  } finally { await t.stop(); }
});

test('e2e: fallback success learns the sender into code_senders and logs the path', async () => {
  const mail = { accountNames: () => ['yahoo', 'gmail'], findCode: async (q) => (q.allowFallback ? { code: TEST_CODE, account: 'yahoo', folder: 'junk', path: 'fallback', senderDomain: 'otp-provider.net' } : null), close: async () => {} };
  const { t, login, waitCode } = await codeSetup('/login-code', { mail, config: { insecure_test_hosts: ['localhost'], timing: { ...codeTiming, mail_interval_ms: 30, code_request_after_ms: 60, prompt_min_ms: 60, prompt_max_ms: 60, prompt_default_ms: 60 } } });
  try {
    await login;
    const rec = t.d.daemon.store.byDomain('localhost');
    assert.deepEqual(rec.code_senders, ['otp-provider.net']);
    const log = t.d.logLines.join('\n');
    assert.ok(log.includes('code_found') && log.includes('fallback') && log.includes('junk'));
    assert.ok(!log.includes(TEST_CODE));
  } finally { await t.stop(); }
});

test('e2e: ambiguous email candidates -> phone request, unanswered -> needs_more email_code_ambiguous', async () => {
  const mail = { accountNames: () => ['yahoo', 'gmail'], findCode: async () => ({ ambiguous: true }), close: async () => {} };
  const { t, login, waitCode } = await codeSetup('/login-code', { mail, config: { insecure_test_hosts: ['localhost'], timing: { ...codeTiming, code_request_ttl_ms: 300 } } });
  try {
    const c = await waitCode();
    assert.equal(c.reason, 'email_not_found'); assert.deepEqual(c.searched, ['Yahoo', 'Gmail']);
    assert.deepEqual(await login, { id: 1, status: 'needs_more', detail: 'email_code_ambiguous' });
  } finally { await t.stop(); }
});

// ---------------- learned email delay / late prompt ----------------
const lateTiming = { ...codeTiming, mail_interval_ms: 20, mail_timeout_ms: 5000, prompt_min_ms: 150, prompt_max_ms: 400, prompt_default_ms: 250, code_request_ttl_ms: 800 };

test('e2e: email delay is learned, smoothed, never stores the code', async () => {
  const mail = { findCode: async () => ({ code: TEST_CODE, account: 'gmail' }), close: async () => {} };
  const { t, login } = await codeSetup('/login-code', { mail, config: { insecure_test_hosts: ['localhost'], timing: lateTiming } });
  try {
    assert.equal((await login).status, 'signed_in');
    const rec = t.d.daemon.store.byDomain('localhost');
    assert.ok(rec.email_delay_ms >= 0 && rec.email_delay_ms < 150);
    assert.ok(!JSON.stringify(rec).includes(TEST_CODE));
    // smoothing: a big old value decays slowly (0.7*old + 0.3*new)
    t.d.daemon.store.patch(rec.record_id, { email_delay_ms: 10000 });
    t.browser.st.url = t.base + '/login-code';
    const l2 = rpc(t.d.daemon.sockFile, { op: 'request_login', domain: 'localhost', tab_id: 1, task: 't' });
    await t.phone.approve((await t.phone.waitPending())[0]);
    assert.equal((await l2).status, 'signed_in');
    const v = t.d.daemon.store.byDomain('localhost').email_delay_ms;
    assert.ok(v >= 7000 && v < 7200, String(v));
  } finally { await t.stop(); }
});

test('e2e: email found before the computed delay -> no code request, no second notification', async () => {
  let t0 = 0;
  const mail = { findCode: async () => { t0 ||= Date.now(); return Date.now() - t0 > 100 ? { code: TEST_CODE, account: 'gmail' } : null; }, close: async () => {} };
  const { t, login } = await codeSetup('/login-code', { mail, config: { insecure_test_hosts: ['localhost'], timing: lateTiming } });
  try {
    assert.equal((await login).status, 'signed_in');
    assert.equal(t.d.notes.length, 1);
    assert.deepEqual(await t.phone.pending(), []);
  } finally { await t.stop(); }
});

test('e2e: code request waits for the learned delay (1.5x, clamped), then email wins -> resolved_by email', async () => {
  let t0 = 0, go = false;
  const mail = { findCode: async () => { t0 ||= Date.now(); return go ? { code: TEST_CODE, account: 'gmail' } : null; }, close: async () => {} };
  const { t, login, waitCode } = await codeSetup('/login-code', { mail, config: { insecure_test_hosts: ['localhost'], timing: lateTiming } });
  try {
    t.d.daemon.store.patch(t.d.daemon.store.byDomain('localhost').record_id, { email_delay_ms: 200 }); // 1.5x = 300 ms
    const started = Date.now();
    const c = await waitCode();
    const waited = Date.now() - started;
    assert.ok(waited < 800);
    assert.equal(t.d.notes.length, 2);
    assert.deepEqual(await t.phone.req('GET', '/v1/requests/' + c.id).then((r) => r.json), { state: 'pending' });
    go = true;
    assert.equal((await login).status, 'signed_in');
    assert.deepEqual((await t.phone.req('GET', '/v1/requests/' + c.id)).json, { state: 'resolved', resolved_by: 'email' });
    assert.deepEqual(await t.phone.pending(), []);
    assert.equal((await t.phone.req('GET', '/v1/requests/nope')).status, 404);
    assert.ok(!t.d.logLines.join('\n').includes(TEST_CODE));
  } finally { await t.stop(); }
});

test('e2e: no code request before the delay; expired request reports expired', async () => {
  const { t, login } = await codeSetup('/login-code', { config: { insecure_test_hosts: ['localhost'], timing: { ...lateTiming, prompt_default_ms: 300, prompt_min_ms: 300, prompt_max_ms: 300, code_request_ttl_ms: 200 } } });
  try {
    const t0 = Date.now();
    await sleep(150);
    assert.equal((await t.phone.pending()).filter((r) => r.kind === 'code').length, 0);
    assert.equal(t.d.notes.length, 1);
    const c = await (async () => { for (;;) { const x = (await t.phone.pending()).find((r) => r.kind === 'code'); if (x) return x; await sleep(15); } })();
    assert.ok(Date.now() - t0 >= 280);
    assert.equal((await login).status, 'needs_more');
    assert.deepEqual((await t.phone.req('GET', '/v1/requests/' + c.id)).json, { state: 'expired' });
  } finally { await t.stop(); }
});

test('e2e: zero mail accounts -> email skipped, phone asked for the code at once', async () => {
  let polls = 0;
  const mail = { accountNames: () => [], findCode: async () => { polls++; return null; }, close: async () => {} };
  const { t, codes, login, waitCode } = await codeSetup('/login-code', { mail, config: { insecure_test_hosts: ['localhost'], timing: { ...codeTiming, prompt_min_ms: 60000, prompt_max_ms: 60000, prompt_default_ms: 60000 } } });
  try {
    const c = await waitCode();
    assert.equal(c.reason, 'email_not_found');
    assert.equal(polls, 0);
    assert.equal((await t.phone.submitCode(c, TEST_CODE)).status, 200);
    assert.deepEqual(await login, { id: 1, status: 'signed_in' });
    assert.deepEqual(codes, [TEST_CODE]);
  } finally { await t.stop(); }
});
