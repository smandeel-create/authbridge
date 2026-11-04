#!/usr/bin/env node
// AuthBridge MCP server (stdio). The agent never receives credentials: results are {status, detail} only.
import net from 'node:net';
import { fileURLToPath } from 'node:url';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { sockPath } from '../daemon/paths.mjs';

const STATUSES = new Set(['signed_in', 'already_signed_in', 'failed', 'needs_more', 'out_of_date', 'no_credential', 'denied', 'timed_out', 'domain_mismatch', 'extension_unavailable', 'not_paired']);

export function daemonCall(msg, { sock = sockPath(), timeoutMs = 330000 } = {}) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(sock);
    let buf = '';
    const t = setTimeout(() => { s.destroy(); reject(new Error('timeout')); }, timeoutMs);
    s.on('connect', () => s.write(JSON.stringify({ id: 1, ...msg }) + '\n'));
    s.on('data', (d) => { buf += d; if (buf.includes('\n')) { clearTimeout(t); s.end(); try { resolve(JSON.parse(buf.split('\n')[0])); } catch (e) { reject(e); } } });
    s.on('error', (e) => { clearTimeout(t); reject(e); });
  });
}

// Only a status and a short enum-ish detail ever reach the agent.
export function sanitizeResult(r) {
  const status = STATUSES.has(r?.status) ? r.status : 'failed';
  const detail = typeof r?.detail === 'string' ? r.detail.replace(/[^a-z0-9_]/gi, '').slice(0, 40) : '';
  return { status, ...(detail ? { detail } : {}) };
}

const text = (obj) => ({ content: [{ type: 'text', text: JSON.stringify(obj) }] });

export function buildServer(call = daemonCall) {
  const server = new McpServer({ name: 'authbridge', version: '0.1.0' });

  server.registerTool('request_login', {
    description:
      'Call request_login when a Chrome tab shows a login page for a site the user asked you to work on. ' +
      'The user approves on their iPhone with Face ID; the login form is then filled in the browser. ' +
      'You never receive credentials, passwords or email codes. ' +
      'domain is the site the login belongs to (e.g. "example.com"). tab_id is the Chrome tab id from the Claude in Chrome tools. ' +
      'task is a short description of what you are doing (shown on the phone). ' +
      'The result is a status: signed_in, already_signed_in, needs_more (with a detail such as captcha, passkey, email_code_not_found), ' +
      'out_of_date, no_credential, denied, timed_out, domain_mismatch, extension_unavailable, not_paired, or failed. ' +
      'After signed_in or already_signed_in, continue your task in the tab.',
    inputSchema: {
      domain: z.string().describe('Site domain, e.g. example.com'),
      tab_id: z.number().int().describe('Chrome tab id from the Claude in Chrome tools'),
      task: z.string().describe('Short description of what you are doing on the site'),
    },
  }, async ({ domain, tab_id, task }) => {
    try {
      const r = await call({ op: 'request_login', domain, tab_id, task, timeout_s: 300 });
      return text(sanitizeResult(r));
    } catch {
      return text({ status: 'failed', detail: 'daemon_unavailable' });
    }
  });

  server.registerTool('authbridge_status', {
    description: 'Report whether AuthBridge is paired with an iPhone, which domains have a stored login, and whether the Chrome extension is connected. Returns no credentials.',
    inputSchema: {},
  }, async () => {
    try {
      const r = await call({ op: 'status' }, { timeoutMs: 10000 });
      return text({ paired: !!r.paired, domains: Array.isArray(r.domains) ? r.domains.map(String) : [], extension_connected: !!r.extension_connected });
    } catch {
      return text({ paired: false, domains: [], extension_connected: false, daemon: 'not_running' });
    }
  });
  return server;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await buildServer().connect(new StdioServerTransport());
}
