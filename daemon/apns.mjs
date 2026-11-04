import http2 from 'node:http2';
import crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';

const JWT_TTL_MS = 40 * 60 * 1000;
const b64u = (b) => Buffer.from(b).toString('base64url');

export function keychainKey(keyId) {
  const out = execFileSync('security', ['find-generic-password', '-s', 'authbridge-apns', '-a', keyId, '-w'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  // `security -w` prints multi-line values (a PEM) as hex.
  return /^[0-9a-f]+$/i.test(out) ? Buffer.from(out, 'hex').toString('utf8') : out;
}

// APNs token-auth notifier. Key PEM is read from the keychain on demand and held only in memory.
// Payload carries the domain only (spec rule 5: never task text or secrets).
export function createApnsNotifier(cfg = {}, { log, getKey = keychainKey, now = () => Date.now(), authority } = {}) {
  const configured = cfg.type === 'apns' && !!cfg.key_id && !!cfg.team_id && !!cfg.topic;
  const env = cfg.env === 'production' ? 'production' : 'development';
  const auth = authority ?? (env === 'production' ? 'https://api.push.apple.com' : 'https://api.sandbox.push.apple.com');
  let jwt = null, jwtAt = 0, keyObj = null;

  function token() {
    if (jwt && now() - jwtAt < JWT_TTL_MS) return jwt;
    if (!keyObj) keyObj = crypto.createPrivateKey(getKey(cfg.key_id));
    const iat = Math.floor(now() / 1000);
    const head = b64u(JSON.stringify({ alg: 'ES256', kid: cfg.key_id }));
    const claims = b64u(JSON.stringify({ iss: cfg.team_id, iat }));
    const sig = crypto.sign('sha256', Buffer.from(`${head}.${claims}`), { key: keyObj, dsaEncoding: 'ieee-p1363' });
    jwt = `${head}.${claims}.${b64u(sig)}`; jwtAt = now();
    return jwt;
  }

  function post(deviceToken, headers, body) {
    return new Promise((resolve) => {
      let done = false;
      const finish = (r) => { if (done) return; done = true; try { client.close(); } catch { /* ignore */ } resolve(r); };
      const client = http2.connect(auth);
      client.on('error', () => finish({ ok: false, reason: 'connect_error' }));
      const timer = setTimeout(() => finish({ ok: false, reason: 'timeout' }), 10000);
      timer.unref?.();
      const req = client.request({ ':method': 'POST', ':path': `/3/device/${deviceToken}`, ...headers });
      let status = 0, buf = '';
      req.on('response', (h) => { status = h[':status']; });
      req.on('data', (c) => { buf += c; });
      req.on('error', () => finish({ ok: false, reason: 'request_error' }));
      req.on('end', () => {
        clearTimeout(timer);
        let reason;
        try { reason = JSON.parse(buf).reason; } catch { /* none */ }
        const gone = status === 410 || reason === 'BadDeviceToken' || reason === 'Unregistered';
        finish({ ok: status === 200, status, reason: status === 200 ? undefined : String(reason || 'unknown').slice(0, 60), gone });
      });
      req.end(body);
    });
  }

  return {
    configured,
    // Never throws. Returns {ok, status?, reason?, gone?}.
    async send({ deviceToken, title, body, request_id, kind, expires_at }) {
      if (!configured) return { ok: false, reason: 'apns_not_configured' };
      try {
        const payload = { aps: { alert: { title, body }, sound: 'default', 'thread-id': 'authbridge' } };
        if (request_id) payload.request_id = request_id;
        if (kind) payload.kind = kind;
        const headers = {
          authorization: `bearer ${token()}`,
          'apns-topic': cfg.topic,
          'apns-push-type': 'alert',
          'apns-priority': '10',
          'content-type': 'application/json',
        };
        if (expires_at) headers['apns-expiration'] = String(Math.floor(expires_at / 1000));
        const r = await post(deviceToken, headers, JSON.stringify(payload));
        if (!r.ok) log?.warn('apns_failed', { status: r.status, reason: r.reason });
        return r;
      } catch {
        log?.warn('apns_failed', { reason: 'internal' });
        return { ok: false, reason: 'internal' };
      }
    },
  };
}
