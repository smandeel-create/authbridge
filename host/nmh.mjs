#!/usr/bin/env node
// Native messaging host: Chrome (stdio, length-framed) <-> daemon (unix socket, newline JSON).
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { sockPath } from '../daemon/paths.mjs';
import { encodeFrame, FrameDecoder } from './frame.mjs';

export function run({ stdin = process.stdin, stdout = process.stdout, sock = sockPath(), retries = 20 } = {}) {
  let attempt = 0;
  let conn = null;
  const queue = [];
  const toDaemon = (obj) => {
    const line = JSON.stringify(obj) + '\n';
    if (conn && !conn.destroyed && conn.ready) conn.write(line); else queue.push(line);
  };
  const dec = new FrameDecoder((msg) => toDaemon(msg));
  stdin.on('data', (c) => { try { dec.push(c); } catch { process.exit(1); } });
  stdin.on('end', () => { conn?.destroy(); process.exit(0); });

  function connect() {
    const s = net.createConnection(sock);
    let buf = '';
    s.on('connect', () => {
      conn = s; s.ready = true; attempt = 0;
      s.write(JSON.stringify({ op: 'extension_hello' }) + '\n');
      while (queue.length) s.write(queue.shift());
    });
    s.on('data', (d) => {
      buf += d;
      let i;
      while ((i = buf.indexOf('\n')) >= 0) {
        const line = buf.slice(0, i); buf = buf.slice(i + 1);
        if (!line.trim()) continue;
        try { const m = JSON.parse(line); if (m.cmd_id) stdout.write(encodeFrame(m)); } catch { /* ignore */ }
      }
    });
    s.on('error', () => {});
    s.on('close', () => {
      if (s.ready) process.exit(0); // daemon went away: let Chrome respawn us via connectNative
      if (++attempt > retries) process.exit(1);
      setTimeout(connect, Math.min(250 * attempt, 2000));
    });
  }
  connect();
}

if (process.argv[1] === fileURLToPath(import.meta.url)) run();
