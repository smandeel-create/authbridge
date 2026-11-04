#!/opt/homebrew/bin/node
// Tiny local login site for AuthBridge tests. TEST CREDENTIALS ONLY.
import http from 'node:http';
import { fileURLToPath } from 'node:url';

export const TEST_USER = 'tester@example.test';
export const TEST_PASS = 'test-password-123';
export const TEST_CODE = '482913';
export const TEST_CODE2 = '7305Q9';

const page = (title, body) => `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title></head><body><h1>${title}</h1>${body}</body></html>`;
const form = (action, inner, btn = 'Sign in') => `<form method="POST" action="${action}">${inner}<button type="submit">${btn}</button></form>`;
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

function parseCookies(h) {
  const o = {};
  for (const p of String(h || '').split(/;\s*/)) { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i)] = p.slice(i + 1); }
  return o;
}
async function readForm(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString('utf8')));
}

// Decoy-field styles: each is an identifier-first flow whose step 1 also carries a decoy password input.
const IDENT = '<label for="em">Email</label><input id="em" name="email" type="email" autocomplete="username">';
const DECOYS = {
  offscreen: '<input name="decoy_password" type="password" style="position:absolute;left:-9999px;top:0;width:200px;height:30px">',
  clip1px: '<input name="decoy_password" type="password" style="position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);clip-path:inset(50%)">',
  ariahidden: '<div aria-hidden="true"><input id="hidden-password" name="decoy_password" type="password" tabindex="-1" style="width:200px;height:30px"></div>',
  overlaid: '<div style="position:relative;width:200px;height:30px"><input name="decoy_password" type="password" style="width:200px;height:30px"><div style="position:absolute;inset:0;background:#fff;z-index:5"></div></div>',
  collapsed: '<div style="height:0;overflow:hidden"><input name="decoy_password" type="password" style="width:200px;height:30px"></div>',
};

export function startTestSite({ port = 0, host = '127.0.0.1' } = {}) {
  const decoyValues = []; // every decoy_password value any POST carried (should all be '')
  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const cookies = parseCookies(req.headers.cookie);
    const send = (status, html, headers = {}) => { res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', ...headers }); res.end(html); };
    const redirect = (to, headers = {}) => { res.writeHead(302, { location: to, ...headers }); res.end(); };
    const signedIn = { 'set-cookie': 'sid=ok; Path=/' };
    const p = url.pathname;
    try {
      if (req.method === 'GET') {
        const dm = p.match(/^\/decoy-([a-z0-9]+)(\/password)?$/);
        if (dm && DECOYS[dm[1]]) {
          const base = '/decoy-' + dm[1];
          if (!dm[2]) return send(200, page('Decoy step 1 ' + dm[1], form(base, IDENT + DECOYS[dm[1]], 'Next')));
          return send(200, page('Decoy step 2 ' + dm[1], form(base + '/password', `<input type="hidden" name="email" value="${esc(url.searchParams.get('email') || '')}"><input name="password" type="password" autocomplete="current-password">`)));
        }
        if (p === '/home') return cookies.sid === 'ok' ? send(200, page('Home', '<p id="who">Signed in</p>')) : redirect('/login');
        if (p === '/logout') return redirect('/login', { 'set-cookie': 'sid=; Path=/; Max-Age=0' });
        if (p === '/login') return send(200, page('Login', form('/login', '<input name="username" type="text" autocomplete="username"><input name="password" type="password" autocomplete="current-password">')));
        if (p === '/login-2step') return send(200, page('Login step 1', form('/login-2step', '<input name="email" type="email" autocomplete="username">', 'Next')));
        if (p === '/login-2step/password') return send(200, page('Login step 2', form('/login-2step/password', `<input type="hidden" name="email" value="${esc(url.searchParams.get('email') || '')}"><input name="password" type="password" autocomplete="current-password">`)));
        if (p === '/login-code') return send(200, page('Login (with code)', form('/login-code', '<input name="username" type="text"><input name="password" type="password">')));
        if (p === '/login-code2') return send(200, page('Login (with two codes)', form('/login-code2', '<input name="username" type="text"><input name="password" type="password">')));
        if (p === '/verify-a' || p === '/verify-b') return send(200, page('Verification code ' + p.slice(-1), form(p, '<input name="otp" type="text" autocomplete="one-time-code">', 'Verify')));
        if (p === '/verify') return send(200, page('Verification code', form('/verify', '<input name="otp" type="text" inputmode="numeric" autocomplete="one-time-code">', 'Verify')));
        if (p === '/verify-split') return send(200, page('Verification code', form('/verify-split', [1, 2, 3, 4, 5, 6].map((i) => `<input name="d${i}" maxlength="1" inputmode="numeric">`).join(''), 'Verify')));
        return send(404, page('Not found', ''));
      }
      if (req.method === 'POST') {
        const f = await readForm(req);
        const dm = p.match(/^\/decoy-([a-z0-9]+)(\/password)?$/);
        if (dm && DECOYS[dm[1]]) {
          decoyValues.push({ style: dm[1], value: f.decoy_password ?? '' });
          if (!dm[2]) return f.email === TEST_USER ? redirect('/decoy-' + dm[1] + '/password?email=' + encodeURIComponent(f.email)) : send(200, page('Decoy step 1', '<p class="error">Unknown account</p>'));
          return f.email === TEST_USER && f.password === TEST_PASS ? redirect('/home', signedIn) : send(200, page('Decoy step 2', '<p class="error">Wrong password</p>'));
        }
        if (p === '/login') return f.username === TEST_USER && f.password === TEST_PASS ? redirect('/home', signedIn) : send(200, page('Login', '<p class="error">Wrong credentials</p>' + form('/login', '<input name="username"><input name="password" type="password">')));
        if (p === '/login-2step') return f.email === TEST_USER ? redirect('/login-2step/password?email=' + encodeURIComponent(f.email)) : send(200, page('Login step 1', '<p class="error">Unknown account</p>'));
        if (p === '/login-2step/password') return f.email === TEST_USER && f.password === TEST_PASS ? redirect('/home', signedIn) : send(200, page('Login step 2', '<p class="error">Wrong password</p>' + form('/login-2step/password', '<input name="password" type="password">')));
        if (p === '/login-code') return f.username === TEST_USER && f.password === TEST_PASS ? redirect('/verify') : send(200, page('Login (with code)', '<p class="error">Wrong credentials</p>'));
        if (p === '/login-code2') return f.username === TEST_USER && f.password === TEST_PASS ? redirect('/verify-a') : send(200, page('Login (with two codes)', '<p class="error">Wrong credentials</p>'));
        if (p === '/verify-a') return f.otp === TEST_CODE ? redirect('/verify-b') : send(200, page('Verification code a', '<p class="error">Wrong code</p>'));
        if (p === '/verify-b') return f.otp === TEST_CODE2 ? redirect('/home', signedIn) : send(200, page('Verification code b', '<p class="error">Wrong code</p>'));
        if (p === '/verify') return f.otp === TEST_CODE ? redirect('/home', signedIn) : send(200, page('Verification code', '<p class="error">Wrong code</p>'));
        if (p === '/verify-split') return [1, 2, 3, 4, 5, 6].map((i) => f['d' + i] || '').join('') === TEST_CODE ? redirect('/home', signedIn) : send(200, page('Verification code', '<p class="error">Wrong code</p>'));
      }
      send(404, page('Not found', ''));
    } catch { send(500, 'error'); }
  });
  return new Promise((resolve) => server.listen(port, host, () => resolve({ server, decoyValues, decoyStyles: Object.keys(DECOYS), port: server.address().port, close: () => new Promise((r) => { server.close(r); server.closeAllConnections?.(); }) })));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const s = await startTestSite({ port: Number(process.env.PORT) || 47950 });
  console.log(`test site on http://127.0.0.1:${s.port}  (user ${TEST_USER} / pass ${TEST_PASS} / code ${TEST_CODE})`);
}
