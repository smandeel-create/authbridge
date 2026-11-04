import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { seal, open, x25519Generate, encryptCredential, decryptCredential, verifyRequest, ReplayCache, signingString, b64, unb64 } from '../daemon/crypto.mjs';
import { PairCodes } from '../daemon/pairing.mjs';
import { normalizeDomain, checkUrl, registrableDomain, senderMatches, hostMatchesDomain } from '../daemon/domain.mjs';
import { createLogger, redact, isForbiddenName } from '../daemon/logger.mjs';
import { extractCode, pickCode, mimeText } from '../daemon/mail.mjs';
import { verifyVectors } from '../daemon/tools/verify-vectors.mjs';
import vm from 'node:vm';
import { tmpHome, realSE } from './helpers.mjs';

test('crypto: store encrypt/decrypt via Secure Enclave; wrong share fails', async () => {
  const home = tmpHome();
  const se = realSE(home);
  await se.init();
  const P = crypto.randomBytes(32);
  const enc = await encryptCredential(se, { record_id: 'rec-1', domain: 'example.com', username: 'u', password: 'p@ss' }, P);
  assert.equal(unb64(enc.epub).length, 65);
  const rec = { record_id: 'rec-1', domain: 'example.com', ...enc };
  const pt = await decryptCredential(se, rec, P);
  assert.deepEqual(JSON.parse(pt.toString()), { username: 'u', password: 'p@ss' });
  await assert.rejects(decryptCredential(se, rec, crypto.randomBytes(32)), /decrypt/);
  await assert.rejects(decryptCredential(se, { ...rec, domain: 'evil.com' }, P), /decrypt/);
  await assert.rejects(decryptCredential(se, { ...rec, record_id: 'rec-2' }, P), /decrypt/);
  // another device's SE key cannot decrypt
  const se2 = realSE(tmpHome()); await se2.init();
  await assert.rejects(decryptCredential(se2, rec, P), /decrypt/);
  assert.ok((fs.statSync(path.join(home, 'se-key.blob')).mode & 0o777) === 0o600);
});

test('sealed box: roundtrip, wrong aad, wrong key, tamper', () => {
  const r = x25519Generate();
  const s = seal(r.pub, Buffer.from('hello'), 'aad-1');
  assert.equal(open(r.priv, r.pub, s, 'aad-1').toString(), 'hello');
  assert.throws(() => open(r.priv, r.pub, s, 'aad-2'));
  const o = x25519Generate();
  assert.throws(() => open(o.priv, o.pub, s, 'aad-1'));
  const ct = unb64(s.ct); ct[0] ^= 1;
  assert.throws(() => open(r.priv, r.pub, { ...s, ct: b64(ct) }, 'aad-1'));
});

test('verify-vectors tool accepts a valid vector file and rejects a bad one', () => {
  const r = x25519Generate();
  const sealed = seal(r.pub, Buffer.from('plain'), 'rid');
  const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const msg = Buffer.from('msg');
  const v = {
    recipient_priv_raw_b64: b64(r.priv), recipient_pub_b64: b64(r.pub), aad: 'rid', plaintext_b64: b64(Buffer.from('plain')), sealed,
    sign: { pub_spki_b64: kp.publicKey.export({ format: 'der', type: 'spki' }).toString('base64'), message_b64: b64(msg), sig_der_b64: crypto.sign('sha256', msg, kp.privateKey).toString('base64') },
  };
  assert.deepEqual(verifyVectors(v), { sealed_open: true, signature: true });
  const f = path.join(tmpHome(), 'v.json');
  fs.writeFileSync(f, JSON.stringify(v));
  const out = execFileSync(process.execPath, [path.resolve('daemon/tools/verify-vectors.mjs'), f]).toString();
  assert.match(out, /sealed box open: PASS[\s\S]*signature verify: PASS/);
  assert.equal(verifyVectors({ ...v, aad: 'x' }).sealed_open, false);
});

test('signature verification, stale timestamp and replay rejection', () => {
  const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const pubB64 = kp.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  const body = Buffer.from('{"a":1}');
  const mk = (ts, nonce, method = 'POST', p = '/v1/x?y=1') => ({
    method, path: p, body,
    headers: { 'x-ab-ts': String(ts), 'x-ab-nonce': nonce, 'x-ab-sig': crypto.sign('sha256', signingString('POST', '/v1/x?y=1', String(ts), nonce, body), kp.privateKey).toString('base64') },
  });
  const replay = new ReplayCache();
  const now = Date.now();
  assert.equal(verifyRequest(mk(now, 'n1'), pubB64, replay, now).ok, true);
  assert.equal(verifyRequest(mk(now, 'n1'), pubB64, replay, now).reason, 'replay');
  assert.equal(verifyRequest(mk(now - 61000, 'n2'), pubB64, replay, now).reason, 'stale_ts');
  assert.equal(verifyRequest(mk(now + 61000, 'n3'), pubB64, replay, now).reason, 'stale_ts');
  assert.equal(verifyRequest(mk(now, 'n4', 'POST', '/v1/other'), pubB64, replay, now).reason, 'bad_sig');
  assert.equal(verifyRequest({ ...mk(now, 'n5'), body: Buffer.from('tampered') }, pubB64, replay, now).reason, 'bad_sig');
  const other = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'der', type: 'spki' }).toString('base64');
  assert.equal(verifyRequest(mk(now, 'n6'), other, replay, now).reason, 'bad_sig');
  // nonce is forgotten after 120 s
  assert.equal(verifyRequest(mk(now + 130000, 'n1'), pubB64, replay, now + 130000).ok, true);
});

test('pairing code rules: 8 digits, one-time, 10 min expiry, 5 wrong attempts invalidates', () => {
  let t = 1000;
  const pc = new PairCodes({ now: () => t });
  const { code } = pc.create();
  assert.match(code, /^\d{8}$/);
  assert.equal(pc.verify(code), true);
  assert.equal(pc.verify(code), false); // one-time
  const c2 = pc.create().code;
  t += 600001;
  assert.equal(pc.verify(c2), false); // expired
  const c3 = pc.create().code;
  const wrong = c3 === '00000000' ? '11111111' : '00000000';
  for (let i = 0; i < 5; i++) assert.equal(pc.verify(wrong), false);
  assert.equal(pc.verify(c3), false); // invalidated after 5 wrong
  const c4 = pc.create().code;
  for (let i = 0; i < 4; i++) pc.verify(wrong);
  assert.equal(pc.verify(c4), true); // 4 wrong attempts do not invalidate
});

test('domain matching: subdomains ok; lookalikes, http and bad URLs rejected', () => {
  const ok = (u, d = 'example.com', ins = []) => checkUrl(u, d, ins).ok;
  assert.equal(ok('https://example.com/login'), true);
  assert.equal(ok('https://login.example.com/x'), true);
  assert.equal(ok('https://evil-example.com/'), false);
  assert.equal(ok('https://example.com.evil.net/'), false);
  assert.equal(ok('https://evilexample.com/'), false);
  assert.equal(ok('https://example.com@evil.net/'), false);
  assert.equal(ok('http://example.com/login'), false);
  assert.equal(ok('javascript:alert(1)'), false);
  assert.equal(ok('not a url'), false);
  assert.equal(ok('http://localhost:3000/', 'localhost', ['localhost']), true);
  assert.equal(ok('http://localhost:3000/', 'localhost', []), false);
  assert.equal(ok('http://sub.localhost/', 'localhost', ['localhost']), false); // exact host only
  assert.equal(ok('http://example.com/', 'example.com', ['localhost']), false);
  assert.equal(hostMatchesDomain('EXAMPLE.com.', 'example.com'), true);
  assert.equal(normalizeDomain('  Example.COM '), 'example.com');
  assert.equal(normalizeDomain('https://Login.Example.com/path'), 'login.example.com');
  assert.equal(normalizeDomain('bücher.de'), 'xn--bcher-kva.de');
  assert.equal(normalizeDomain('exa mple.com'), null);
  assert.equal(normalizeDomain('a.com/evil'), null);
});

test('redaction guard: forbidden field names are redacted, nested and case-insensitive', () => {
  for (const n of ['password', 'Password', 'userPassword', 'share', 'code', 'secret', 'key', 'plaintext', 'api_key', 'sealed_share']) assert.equal(isForbiddenName(n), true, n);
  for (const n of ['domain', 'status', 'task', 'username']) assert.equal(isForbiddenName(n), false, n);
  const sink = [];
  const log = createLogger({ sink });
  log.info('x', { domain: 'a.com', password: 'hunter2', nested: { Share: 'abc', ok: 1, list: [{ code: '123456' }] }, buf: Buffer.from('s3cr3t'), err: new Error('boom') });
  const line = sink.join('');
  assert.ok(!line.includes('hunter2') && !line.includes('abc') && !line.includes('123456') && !line.includes('s3cr3t'));
  assert.ok(line.includes('a.com') && line.includes('[REDACTED]') && line.includes('[binary]'));
  assert.equal(redact({ a: { key: 'k' } }).a.key, '[REDACTED]');
});

test('email code extraction and sender-domain filter', () => {
  assert.equal(extractCode('Your verification code is 482913'), '482913');
  assert.equal(extractCode('482913 is your code'), '482913');
  assert.equal(extractCode('Booking.com – 7QXKRT is your verification code'), '7QXKRT');
  assert.equal(extractCode('Your sign-in code: a1b2c3'), 'a1b2c3');
  assert.equal(extractCode('Meet at 10am, see code of conduct'), null);
  assert.equal(extractCode('Votre code de vérification : 1234'), '1234');
  assert.equal(extractCode('Your one-time passcode: 123-456'), '123456');
  assert.equal(extractCode('Order 12345678 shipped'), null); // no keyword nearby
  assert.equal(extractCode('Code: 123456789'), null); // too long
  assert.equal(extractCode('Your code is 123'), null); // too short
  assert.equal(pickCode({ subject: 'Your code is 111111', body: 'verification 222222' }), '111111'); // subject first
  assert.equal(pickCode({ subject: 'Welcome', body: 'Your verification code: 222222' }), '222222');
  const mime = ['Content-Type: multipart/alternative; boundary="b1"', '', '--b1', 'Content-Type: text/plain; charset=utf-8', 'Content-Transfer-Encoding: quoted-printable', '', 'Your verification code is =\r\n654321', '--b1--', ''].join('\r\n');
  assert.equal(pickCode({ subject: '', body: mimeText(Buffer.from(mime)) }), '654321');
  const html = ['Content-Type: text/html', 'Content-Transfer-Encoding: base64', '', Buffer.from('<p>Your <b>code</b>: 777888</p>').toString('base64')].join('\r\n');
  assert.equal(extractCode(mimeText(Buffer.from(html))), '777888');

  assert.equal(senderMatches('no-reply@accounts.example.com', 'example.com'), true);
  assert.equal(senderMatches('x@example.com', 'login.example.com'), true);
  assert.equal(senderMatches('x@evil-example.com', 'example.com'), false);
  assert.equal(senderMatches('x@example.com.evil.net', 'example.com'), false);
  assert.equal(senderMatches('x@example.co.uk', 'example.com'), false);
  assert.equal(senderMatches('x@mailer.thirdparty.io', 'example.com', ['thirdparty.io']), true);
  assert.equal(senderMatches('a@thirdparty.io', 'example.com', ['b@thirdparty.io']), false);
  // same-brand sibling domain (free.fr codes come from free-mobile.fr), whole token only
  assert.equal(senderMatches('freemobile@free-mobile.fr', 'free.fr'), true);
  assert.equal(senderMatches('x@freedom-mobile.fr', 'free.fr'), false);
  assert.equal(senderMatches('x@notfree.com', 'free.fr'), false);
  assert.equal(senderMatches('x@bo-mail.com', 'bo.com'), false); // brand under 4 chars never fuzzy-matches
  assert.equal(registrableDomain('a.b.example.co.uk'), 'example.co.uk');
});

test('crypto: stored credential JSON carries optional email only when set', async () => {
  const se = await realSE();
  const P = crypto.randomBytes(32);
  const enc = await encryptCredential(se, { record_id: 'rec-e', domain: 'example.com', username: 'u', password: 'p', email: 'a@b.co' }, P);
  const pt = await decryptCredential(se, { record_id: 'rec-e', domain: 'example.com', ...enc }, P);
  assert.deepEqual(JSON.parse(pt.toString()), { username: 'u', password: 'p', email: 'a@b.co' });
});

const ab = (() => {
  const sandbox = {}; sandbox.globalThis = sandbox;
  vm.runInNewContext(fs.readFileSync(new URL('../extension/identifier.js', import.meta.url), 'utf8'), sandbox);
  return sandbox.__abIdentifier;
})();

test('identifier: wantsEmail detection', () => {
  const w = ab.wantsEmail;
  assert.equal(w({ type: 'email' }), true);
  assert.equal(w({ type: 'text', autocomplete: 'username email' }), true);
  assert.equal(w({ name: 'user_email' }), true);
  assert.equal(w({ id: 'E-Mail' }), true);
  assert.equal(w({ ariaLabel: 'Your email address' }), true);
  assert.equal(w({ placeholder: 'e-mail' }), true);
  assert.equal(w({ labelText: 'Email or phone' }), true);
  assert.equal(w({ type: 'text', name: 'username', id: 'login', placeholder: 'Username' }), false);
  assert.equal(w({}), false);
  assert.equal(w(), false);
});

test('identifier: chooseIdentifier decisions', () => {
  const c = ab.chooseIdentifier;
  assert.deepEqual({ ...c({ username: 'bob', email: 'b@x.io', wantsEmail: true }) }, { value: 'b@x.io' });
  assert.deepEqual({ ...c({ username: 'b@x.io', email: '', wantsEmail: true }) }, { value: 'b@x.io' });
  assert.deepEqual({ ...c({ username: 'bob', email: '', wantsEmail: true }) }, { error: 'email_required' });
  assert.deepEqual({ ...c({ username: 'bob', email: 'b@x.io', wantsEmail: false }) }, { value: 'bob' });
  assert.deepEqual({ ...c({ username: '', email: 'b@x.io', wantsEmail: false }) }, { value: 'b@x.io' });
});
