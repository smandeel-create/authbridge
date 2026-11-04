import test from 'node:test';
import assert from 'node:assert/strict';
import { createMailFetcher, pickJunkFolder } from '../daemon/mail.mjs';

const START = Date.now();
const raw = (body) => Buffer.from(`Content-Type: text/plain\r\n\r\n${body}`);

// folders: { 'INBOX': [msg], 'Bulk': [msg] }; msg = {from, name, subject, body, at}
function mockClient(folders, { list, failOn } = {}) {
  let cur = null;
  return {
    usable: true,
    list: async () => list || [{ path: 'INBOX' }, ...Object.keys(folders).filter((f) => f !== 'INBOX').map((path) => ({ path, specialUse: path === 'Junk' ? '\\Junk' : undefined }))],
    getMailboxLock: async (name) => { if (name === failOn) throw new Error('boom'); cur = folders[name] || []; return { release() {} }; },
    noop: async () => {},
    search: async () => cur.map((_, i) => i + 1),
    fetchOne: async (uid, q) => {
      const m = cur[Number(uid) - 1];
      if (q.source) return { source: raw(m.body || '') };
      return { internalDate: new Date(m.at ?? START + 1000), envelope: { subject: m.subject || '', from: [{ address: m.from, name: m.name || '' }] } };
    },
    logout: async () => {},
  };
}
function fetcher(folders, opts) {
  return createMailFetcher({}, { accounts: [{ name: 'yahoo' }], openClient: async () => mockClient(folders, opts) });
}
const q = (extra = {}) => ({ sinceMs: START - 30000, startMs: START, domain: 'free.fr', codeSenders: [], ...extra });

test('mail: Free code from sibling domain found by the primary rule', async () => {
  const f = fetcher({ INBOX: [{ from: 'freemobile@free-mobile.fr', subject: 'Votre code de vérification : 123456' }] });
  const r = await f.findCode(q());
  assert.deepEqual([r.code, r.path, r.folder], ['123456', 'sender', 'inbox']);
});

test('mail: fallback with exactly one branded candidate succeeds and reports sender domain', async () => {
  const folders = { INBOX: [{ from: 'noreply@otp-provider.net', subject: 'Your code', body: 'Free login verification code 482913' }] };
  const f = fetcher(folders);
  assert.equal(await f.findCode(q()), null); // not before the fallback window
  const r = await f.findCode(q({ allowFallback: true }));
  assert.deepEqual([r.code, r.path, r.senderDomain], ['482913', 'fallback', 'otp-provider.net']);
});

test('mail: two fallback candidates -> ambiguous', async () => {
  const f = fetcher({
    INBOX: [{ from: 'a@x-one.net', body: 'free verification code 111111' }, { from: 'b@y-two.net', body: 'free verification code 222222' }],
  });
  assert.deepEqual(await f.findCode(q({ allowFallback: true })), { ambiguous: true });
});

test('mail: candidates across inbox and junk count together', async () => {
  const f = fetcher({ INBOX: [{ from: 'a@x-one.net', body: 'free verification code 111111' }], Junk: [{ from: 'b@y-two.net', body: 'free verification code 222222' }] });
  assert.deepEqual(await f.findCode(q({ allowFallback: true })), { ambiguous: true });
});

test('mail: code email older than request start is ignored by fallback', async () => {
  const f = fetcher({ INBOX: [{ from: 'a@x-one.net', body: 'free verification code 111111', at: START - 5000 }] });
  assert.equal(await f.findCode(q({ allowFallback: true })), null);
});

test('mail: Yahoo Bulk folder found by name; sender match works there', async () => {
  const f = fetcher({ INBOX: [], Bulk: [{ from: 'x@free.fr', subject: 'Your code is 654321' }] });
  const r = await f.findCode(q());
  assert.deepEqual([r.code, r.folder, r.path], ['654321', 'junk', 'sender']);
});

test('mail: junk candidate without the brand word is ignored', async () => {
  const f = fetcher({ INBOX: [], Junk: [{ from: 'a@x-one.net', body: 'verification code 333333' }] });
  assert.equal(await f.findCode(q({ allowFallback: true })), null);
});

test('mail: an error on one folder does not stop the others', async () => {
  const f = fetcher({ INBOX: [], Junk: [{ from: 'x@free.fr', subject: 'Your code is 654321' }] }, { failOn: 'INBOX' });
  assert.equal((await f.findCode(q())).code, '654321');
});

test('mail: junk folder discovery', () => {
  assert.equal(pickJunkFolder([{ path: 'INBOX' }, { path: 'Spam!', specialUse: '\\Junk' }, { path: 'Bulk' }]), 'Spam!');
  assert.equal(pickJunkFolder([{ path: 'INBOX' }, { path: 'Bulk' }]), 'Bulk');
  assert.equal(pickJunkFolder([{ path: 'INBOX' }, { path: '[Gmail]/Spam' }]), '[Gmail]/Spam');
  assert.equal(pickJunkFolder([{ path: 'INBOX' }]), null);
});

test('loadAccounts: missing file means no accounts; defaults to all entries; accounts filter', async () => {
  const { loadAccounts } = await import('../daemon/mail.mjs');
  const fs = await import('node:fs'), os = await import('node:os'), path = await import('node:path');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'abm-'));
  assert.deepEqual(loadAccounts({ accounts_path: path.join(dir, 'nope.json') }), []);
  const p = path.join(dir, 'mail.json');
  const imap = { host: 'imap.example.test', port: 993, secure: true };
  fs.writeFileSync(p, JSON.stringify({ a: { email: 'a@example.test', imap }, b: { email: 'b@example.test', imap } }));
  assert.deepEqual(loadAccounts({ accounts_path: p }).map((x) => x.name), ['a', 'b']);
  assert.deepEqual(loadAccounts({ accounts_path: p, accounts: ['b'] }).map((x) => x.name), ['b']);
  assert.deepEqual(createMailFetcher({ accounts_path: path.join(dir, 'nope.json') }).accountNames(), []);
});
