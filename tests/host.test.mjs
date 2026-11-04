import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { encodeFrame, FrameDecoder } from '../host/frame.mjs';
import { startDaemon, rpc, pairedPhone, sleep } from './helpers.mjs';

test('native messaging framing: 4-byte LE length, split and coalesced chunks', () => {
  const got = [];
  const dec = new FrameDecoder((m) => got.push(m));
  const a = encodeFrame({ a: 1 }), b = encodeFrame({ b: 'é' });
  assert.equal(a.readUInt32LE(0), a.length - 4);
  const all = Buffer.concat([a, b]);
  dec.push(all.subarray(0, 3)); dec.push(all.subarray(3, 9)); dec.push(all.subarray(9));
  assert.deepEqual(got, [{ a: 1 }, { b: 'é' }]);
});

test('nmh host bridges Chrome stdio frames to the daemon socket and back', async () => {
  const d = await startDaemon();
  const child = spawn(process.execPath, [path.resolve('host/nmh.mjs')], { env: { ...process.env, AUTHBRIDGE_HOME: d.home }, stdio: ['pipe', 'pipe', 'inherit'] });
  const got = [];
  const dec = new FrameDecoder((m) => got.push(m));
  child.stdout.on('data', (c) => dec.push(c));
  try {
    await sleep(300);
    assert.equal((await rpc(d.daemon.sockFile, { op: 'status' })).extension_connected, true);
    // daemon -> extension: a login attempt sends tab_info; answer it through the host
    await pairedPhone(d);
    const login = rpc(d.daemon.sockFile, { op: 'request_login', domain: 'example.com', tab_id: 5, task: 't' });
    for (let i = 0; i < 100 && !got.length; i++) await sleep(20);
    assert.equal(got[0].cmd, 'tab_info'); assert.equal(got[0].tab_id, 5);
    child.stdin.write(encodeFrame({ cmd_id: got[0].cmd_id, ok: true, result: { url: 'https://other.net/' } }));
    assert.equal((await login).status, 'domain_mismatch');
  } finally { child.kill(); await d.stop(); }
});
