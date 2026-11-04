import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import path from 'node:path';
import { startDaemon, mockExtension } from './helpers.mjs';
import { sanitizeResult } from '../mcp/server.mjs';

test('mcp: sanitizeResult passes only status + short enum detail', () => {
  assert.deepEqual(sanitizeResult({ status: 'signed_in', password: 'x' }), { status: 'signed_in' });
  assert.deepEqual(sanitizeResult({ status: 'needs_more', detail: 'captcha' }), { status: 'needs_more', detail: 'captcha' });
  assert.deepEqual(sanitizeResult({ status: 'hax' }), { status: 'failed' });
  assert.equal(sanitizeResult({ status: 'failed', detail: 'a b!c' + 'x'.repeat(100) }).detail.length <= 40, true);
});

test('mcp: stdio server lists tools and relays status from the daemon', async () => {
  const d = await startDaemon();
  const ext = await mockExtension(d.daemon.sockFile, {});
  const child = spawn(process.execPath, [path.resolve('mcp/server.mjs')], { env: { ...process.env, AUTHBRIDGE_HOME: d.home }, stdio: ['pipe', 'pipe', 'inherit'] });
  const lines = [];
  let buf = '';
  child.stdout.on('data', (c) => { buf += c; let i; while ((i = buf.indexOf('\n')) >= 0) { lines.push(JSON.parse(buf.slice(0, i))); buf = buf.slice(i + 1); } });
  const send = (o) => child.stdin.write(JSON.stringify(o) + '\n');
  const waitFor = async (id) => { for (let i = 0; i < 200; i++) { const m = lines.find((l) => l.id === id); if (m) return m; await new Promise((r) => setTimeout(r, 25)); } throw new Error('no reply ' + id); };
  try {
    send({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 't', version: '1' } } });
    await waitFor(1);
    send({ jsonrpc: '2.0', method: 'notifications/initialized' });
    send({ jsonrpc: '2.0', id: 2, method: 'tools/list' });
    const tools = (await waitFor(2)).result.tools.map((t) => t.name).sort();
    assert.deepEqual(tools, ['authbridge_status', 'request_login']);
    send({ jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'authbridge_status', arguments: {} } });
    const st = JSON.parse((await waitFor(3)).result.content[0].text);
    assert.deepEqual(st, { paired: false, domains: [], extension_connected: true });
    send({ jsonrpc: '2.0', id: 4, method: 'tools/call', params: { name: 'request_login', arguments: { domain: 'example.com', tab_id: 1, task: 't' } } });
    const rl = JSON.parse((await waitFor(4)).result.content[0].text);
    assert.ok(rl.status && Object.keys(rl).every((k) => ['status', 'detail'].includes(k)));
  } finally { child.kill(); ext.close(); await d.stop(); }
});
