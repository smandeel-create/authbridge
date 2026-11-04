import fs from 'node:fs';
import os from 'node:os';

const expand = (p) => p.replace(/^~(?=\/|$)/, os.homedir());

// Optional webhook fallback (config key `fallback_notifier` = {url, token_path?, body?}). Disabled unless `url`
// is set. POSTs JSON {text, domain, ...body} with `Authorization: Bearer <token>` if token_path is set.
// Notifications carry only the domain and task text (spec rule 5). Failure-tolerant.
export function createNotifier(cfg = {}, { fetchImpl = globalThis.fetch, log } = {}) {
  const c = cfg || {};
  return {
    async notify({ domain, task }) {
      if (!c.url) return false;
      try {
        const headers = { 'content-type': 'application/json' };
        if (c.token_path) headers.authorization = 'Bearer ' + fs.readFileSync(expand(c.token_path), 'utf8').trim();
        const cleanTask = String(task ?? '').replace(/\s+/g, ' ').slice(0, 200);
        const text = `AuthBridge: approve login to ${domain} on your iPhone.` + (cleanTask ? `\nTask: ${cleanTask}` : '');
        const res = await fetchImpl(c.url, {
          method: 'POST',
          headers,
          body: JSON.stringify({ ...(c.body && typeof c.body === 'object' ? c.body : {}), text, domain }),
          signal: AbortSignal.timeout(5000),
        });
        if (!res.ok) { log?.warn('notify_http_error', { status: res.status }); return false; }
        return true;
      } catch (e) {
        log?.warn('notify_failed', { error: e });
        return false;
      }
    },
  };
}
