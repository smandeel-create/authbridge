#!/usr/bin/env node
// Fallback for Claude sessions that have lost the authbridge MCP tools (e.g. install.sh was re-run
// mid-session). Talks to the daemon directly and prints the same sanitised result as the MCP tool.
//   authbridge-login status
//   authbridge-login <domain> <chrome-tab-id> "<task shown on the phone>"
import { daemonCall, sanitizeResult } from './server.mjs';

const [first, tab, task] = process.argv.slice(2);

if (!first || first === '-h' || first === '--help') {
  console.error('usage: authbridge-login status | authbridge-login <domain> <tab_id> "<task>"');
  process.exit(2);
}

try {
  if (first === 'status') {
    const r = await daemonCall({ op: 'status' }, { timeoutMs: 10000 });
    console.log(JSON.stringify({ paired: !!r.paired, domains: Array.isArray(r.domains) ? r.domains.map(String) : [], extension_connected: !!r.extension_connected }));
  } else {
    const tab_id = Number(tab);
    if (!Number.isInteger(tab_id) || !task) {
      console.error('usage: authbridge-login <domain> <tab_id> "<task>"');
      process.exit(2);
    }
    const r = await daemonCall({ op: 'request_login', domain: first, tab_id, task, timeout_s: 300 });
    console.log(JSON.stringify(sanitizeResult(r)));
  }
} catch {
  console.log(JSON.stringify({ status: 'failed', detail: 'daemon_not_running' }));
  process.exit(1);
}
process.exit(0);
