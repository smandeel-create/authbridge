// AuthBridge background service worker. Never logs values (credentials, codes).
const HOST = 'com.authbridge.host';
let port = null;
let backoff = 1000;

function connect() {
  if (port) return;
  try {
    port = chrome.runtime.connectNative(HOST);
  } catch (e) {
    port = null;
    schedule();
    return;
  }
  port.onMessage.addListener(onMessage);
  port.onDisconnect.addListener(() => {
    void chrome.runtime.lastError; // consume
    port = null;
    schedule();
  });
  port.postMessage({ op: 'extension_hello' });
  backoff = 1000;
}

function schedule() {
  setTimeout(connect, backoff);
  backoff = Math.min(backoff * 2, 30000);
}

chrome.runtime.onStartup.addListener(connect);
chrome.runtime.onInstalled.addListener(connect);
connect();

async function onMessage(msg) {
  if (!msg || !msg.cmd_id || !msg.cmd) return;
  const reply = (o) => { try { port && port.postMessage({ cmd_id: msg.cmd_id, ...o }); } catch { /* port gone */ } };
  try {
    const handler = COMMANDS[msg.cmd];
    if (!handler) throw new Error('unsupported_cmd');
    reply({ ok: true, result: await handler(msg) });
  } catch (e) {
    reply({ ok: false, error: String((e && e.message) || 'error').slice(0, 60) });
  }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---- helpers --------------------------------------------------------------
async function waitComplete(tabId, ms = 10000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const t = await chrome.tabs.get(tabId);
    if (t.status === 'complete') return;
    await sleep(150);
  }
}

// Runs abPage(op, args) in the TOP frame only. Retries across navigations.
async function runInTab(tabId, op, args, { retries = 3 } = {}) {
  let lastErr;
  for (let i = 0; i < retries; i++) {
    try {
      // identifier.js defines globalThis.__abIdentifier in this (isolated) world; abPage stays self-contained.
      await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, files: ['identifier.js'] });
      const [res] = await chrome.scripting.executeScript({ target: { tabId, frameIds: [0] }, func: abPage, args: [op, args || {}] });
      if (!res || res.result === undefined) throw new Error('no_result');
      return res.result;
    } catch (e) {
      lastErr = e;
      await sleep(300);
    }
  }
  throw new Error(lastErr && lastErr.message === 'no_result' ? 'no_result' : 'inject_failed');
}

const COMMANDS = {
  // Re-reads the unpacked extension from disk after an update; the host reconnects on restart.
  async reload_extension() {
    setTimeout(() => chrome.runtime.reload(), 200);
    return {};
  },
  async tab_info({ tab_id }) {
    const t = await chrome.tabs.get(tab_id);
    return { url: t.url || '' };
  },

  async probe({ tab_id }) {
    return runInTab(tab_id, 'probe', {});
  },

  async press_continue({ tab_id, expected_domain, allow_insecure }) {
    const r = await runInTab(tab_id, 'press_continue', { expected_domain, allow_insecure: !!allow_insecure });
    if (r.error) throw new Error(r.error);
    return { pressed: true };
  },

  async reload({ tab_id }) {
    await chrome.tabs.reload(tab_id);
    await sleep(200);
    await waitComplete(tab_id);
    return {};
  },

  async fill_credentials({ tab_id, expected_domain, allow_insecure, username, password, email }) {
    const base = { expected_domain, allow_insecure: !!allow_insecure };
    // Step 1: whatever form is on the page right now.
    let r = await runInTab(tab_id, 'fill_login', { ...base, username, password, email });
    if (r.error) throw new Error(r.error);
    if (r.action === 'username_submitted') {
      // Two-step flow: wait up to 10 s for the password field, then fill it.
      const end = Date.now() + 10000;
      let ready = false;
      while (Date.now() < end) {
        await sleep(300);
        try {
          const p = await runInTab(tab_id, 'probe', {}, { retries: 1 });
          if (p.has_password) { ready = true; break; }
          // Passwordless / code-first step (e.g. booking.com emails a code): let the daemon's probe take over.
          if (p.has_otp || p.captcha) return { submitted: true, next: p.has_otp ? 'otp' : 'captcha' };
        } catch { /* mid-navigation */ }
      }
      if (!ready) throw new Error('password_field_timeout');
      r = await runInTab(tab_id, 'fill_login', { ...base, username, password, email, passwordStepOnly: true });
      if (r.error) throw new Error(r.error);
    }
    return { submitted: true };
  },

  async fill_code({ tab_id, expected_domain, allow_insecure, code }) {
    const r = await runInTab(tab_id, 'fill_code', { expected_domain, allow_insecure: !!allow_insecure, code });
    if (r.error) throw new Error(r.error);
    return { submitted: true };
  },
};

// ---------------------------------------------------------------------------
// Injected into the page (self-contained: no references to outer scope).
// ---------------------------------------------------------------------------
function abPage(op, args) {
  'use strict';
  // ---- rule 3, re-checked right before touching any field ----
  function domainOk() {
    if (window.top !== window) return false;
    const host = location.hostname.toLowerCase();
    const d = String(args.expected_domain || '').toLowerCase();
    if (!d) return false;
    if (!(host === d || host.endsWith('.' + d))) return false;
    if (location.protocol === 'https:') return true;
    return location.protocol === 'http:' && args.allow_insecure === true && (host === 'localhost' || host === '127.0.0.1') && host === d;
  }

  const visible = (el) => {
    if (!el || !el.isConnected) return false;
    const r = el.getBoundingClientRect();
    if (r.width <= 0 || r.height <= 0) return false;
    const cs = getComputedStyle(el);
    if (cs.display === 'none' || cs.visibility === 'hidden' || cs.opacity === '0') return false;
    // Decoy fields for password managers (e.g. booking.com's #hidden-password) are aria-hidden / untabbable.
    if (el.closest('[aria-hidden="true"]') || el.tabIndex < 0) return false;
    return true;
  };
  // ---- real-field check: never treat decoys (hidden / off-screen / clipped / overlaid) as fields ----
  const MIN = 4;
  const px = (tok, ref) => (/%$/.test(tok) ? (parseFloat(tok) / 100) * ref : parseFloat(tok) || 0);
  // Visible box left after this element's own clip / clip-path (null = fully clipped).
  function clipBox(el, r) {
    const cs = getComputedStyle(el);
    let box = { l: r.left, t: r.top, r: r.right, b: r.bottom };
    if (cs.clip && cs.clip !== 'auto' && (cs.position === 'absolute' || cs.position === 'fixed')) {
      const m = cs.clip.match(/rect\(([^)]*)\)/);
      if (m) {
        const v = m[1].split(/[\s,]+/).filter(Boolean).map((x) => (x === 'auto' ? null : parseFloat(x)));
        if (v.length === 4) {
          const [ct, cr, cb, cl] = v;
          box = { l: cl === null ? box.l : r.left + cl, t: ct === null ? box.t : r.top + ct, r: cr === null ? box.r : r.left + cr, b: cb === null ? box.b : r.top + cb };
        }
      }
    }
    const cp = cs.clipPath || '';
    const im = cp.match(/^inset\(([^)]*)\)/);
    if (im) {
      const toks = im[1].split(/\s+round\s+/)[0].trim().split(/\s+/);
      const [a, b2 = a, c = a, d = b2] = toks;
      box = { l: Math.max(box.l, r.left + px(d, r.width)), t: Math.max(box.t, r.top + px(a, r.height)), r: Math.min(box.r, r.right - px(b2, r.width)), b: Math.min(box.b, r.bottom - px(c, r.height)) };
    } else if (/^(circle|ellipse|polygon|path)\(/.test(cp)) {
      const zero = /^(circle|ellipse)\(\s*0(px|%)?[\s)]/.test(cp) || /^polygon\(\s*0(px)?\s+0(px)?\s*(,\s*0(px)?\s+0(px)?\s*)*\)/.test(cp);
      if (zero) return null;
    }
    return box.r - box.l >= 0 && box.b - box.t >= 0 ? box : null;
  }
  function realField(el) {
    if (!el || !el.isConnected) return false;
    if (el.closest('[aria-hidden="true"]') || el.tabIndex < 0) return false;
    for (let n = el; n && n.nodeType === 1; n = n.parentElement) {
      const cs = getComputedStyle(n);
      if (cs.display === 'none' || cs.opacity === '0' || (n === el && cs.visibility === 'hidden')) return false;
    }
    try { el.scrollIntoView({ block: 'center', inline: 'center', behavior: 'instant' }); } catch { /* ignore */ }
    const r = el.getBoundingClientRect();
    if (r.width <= MIN || r.height <= MIN) return false;
    let box = clipBox(el, r);
    if (!box) return false;
    for (let n = el.parentElement; n; n = n.parentElement) {
      const cs = getComputedStyle(n);
      if (n !== document.body && n !== document.documentElement && (/(hidden|clip)/.test(cs.overflowX) || /(hidden|clip)/.test(cs.overflowY))) {
        const pr = n.getBoundingClientRect();
        if (/(hidden|clip)/.test(cs.overflowX)) { box.l = Math.max(box.l, pr.left); box.r = Math.min(box.r, pr.right); }
        if (/(hidden|clip)/.test(cs.overflowY)) { box.t = Math.max(box.t, pr.top); box.b = Math.min(box.b, pr.bottom); }
      }
      // Only an explicit clip / clip-path crops descendants; a parent's own box does not (Airbnb wraps
      // its login button in zero-size, overflow-visible divs).
      if ((cs.clip && cs.clip !== 'auto') || (cs.clipPath && cs.clipPath !== 'none')) {
        const cb = clipBox(n, n.getBoundingClientRect());
        if (!cb) return false;
        box = { l: Math.max(box.l, cb.l), t: Math.max(box.t, cb.t), r: Math.min(box.r, cb.r), b: Math.min(box.b, cb.b) };
      }
    }
    // intersect with the viewport
    box = { l: Math.max(box.l, 0), t: Math.max(box.t, 0), r: Math.min(box.r, window.innerWidth), b: Math.min(box.b, window.innerHeight) };
    if (box.r - box.l <= MIN || box.b - box.t <= MIN) return false;
    // topmost element at the visible centre must be the field (or its label / a descendant)
    const hit = document.elementFromPoint((box.l + box.r) / 2, (box.t + box.b) / 2);
    if (!hit) return false;
    if (hit === el || el.contains(hit)) return true;
    try { return Array.from(el.labels || []).some((l) => l === hit || l.contains(hit)); } catch { return false; }
  }
  const inputs = () => Array.from(document.querySelectorAll('input')).filter(realField);
  const txt = (el) => [el.name, el.id, el.getAttribute('autocomplete'), el.getAttribute('aria-label'), el.placeholder].filter(Boolean).join(' ').toLowerCase();

  const OTP_RE = /one-time-code|otp|verification|verif|passcode|(^|[^a-z])code([^a-z]|$)|(^|[^a-z])pin([^a-z]|$)/;
  const NOT_OTP_RE = /zip|postal|post-?code|promo|coupon|discount|voucher|gift|referral|invite|captcha|country|area/;
  const TEXTLIKE = new Set(['text', 'tel', 'number', 'email', 'search', '']);

  function splitBoxes() {
    // 4-8 visible single-char inputs sharing a close ancestor
    // Single-char by maxlength, or box-shaped without one (Free Mobile: six 48x48 type=number boxes).
    const boxy = (i) => {
      const t = (i.type || '').toLowerCase();
      if (!(TEXTLIKE.has(t) || t === 'number')) return false;
      if (i.maxLength === 1) return true;
      const r = i.getBoundingClientRect();
      return r.width > 0 && r.width <= 64 && r.height <= 80 && Math.abs(r.width - r.height) <= 24;
    };
    const singles = inputs().filter(boxy);
    if (singles.length < 4) return null;
    const groups = new Map();
    for (const i of singles) {
      let p = i.parentElement;
      for (let k = 0; k < 2 && p && p.parentElement; k++) p = p.parentElement;
      if (!groups.has(p)) groups.set(p, []);
      groups.get(p).push(i);
    }
    for (const g of groups.values()) if (g.length >= 4 && g.length <= 8) return g;
    if (singles.length >= 4 && singles.length <= 8) return singles;
    return null;
  }
  function otpField() {
    for (const i of inputs()) {
      const t = (i.type || '').toLowerCase();
      if (!TEXTLIKE.has(t) || t === 'email') continue;
      const s = txt(i);
      if ((i.getAttribute('autocomplete') || '').toLowerCase().includes('one-time-code')) return i;
      if (OTP_RE.test(s) && !NOT_OTP_RE.test(s)) return i;
    }
    return null;
  }
  const passwordField = () => inputs().find((i) => (i.type || '').toLowerCase() === 'password') || null;
  function usernameField(pw) {
    const scope = (pw && pw.form) || document;
    const cands = Array.from(scope.querySelectorAll('input')).filter((i) => realField(i) && ['text', 'email', 'tel', ''].includes((i.type || '').toLowerCase()) && !i.readOnly && !i.disabled);
    const good = cands.filter((i) => /user|email|login|ident|account|name/.test(txt(i)) && !/search/.test(txt(i)));
    if (pw) {
      // prefer the last candidate that precedes the password field in DOM order
      const before = (good.length ? good : cands).filter((i) => i.compareDocumentPosition(pw) & Node.DOCUMENT_POSITION_FOLLOWING);
      if (before.length) return before[before.length - 1];
    }
    return good[0] || (pw ? null : cands[0]) || null;
  }

  // Decide what goes into an identifier field: email vs username (logic lives in identifier.js).
  function labelText(el) {
    try { return Array.from(el.labels || []).map((l) => l.textContent || '').join(' '); } catch { return ''; }
  }
  function identifierFor(el) {
    const ab = globalThis.__abIdentifier;
    if (!ab) return { error: 'no_login_form' };
    const wants = ab.wantsEmail({ type: el.type, autocomplete: el.getAttribute('autocomplete'), name: el.name, id: el.id, ariaLabel: el.getAttribute('aria-label'), placeholder: el.placeholder, labelText: labelText(el) });
    return ab.chooseIdentifier({ username: args.username, email: args.email, wantsEmail: wants });
  }

  function setValue(el, v) {
    el.focus();
    const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(el, v);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  }

  // Remembered-account screens (e.g. Airbnb "Welcome back" + a single "Log in" button) have no fields:
  // the one real button that starts the login, excluding social sign-in and sign-up.
  function continueButton() {
    const LABEL = /^(log ?in|sign ?in|continue|next|send code|email me a code|text me a code)$/i;
    const SKIP = /google|apple|facebook|microsoft|passkey|sign ?up|create/i;
    const btns = Array.from(document.querySelectorAll('button, input[type=submit], [role=button]')).filter((b) => {
      const label = (b.innerText || b.value || b.getAttribute('aria-label') || '').trim().replace(/\s+/g, ' ');
      return LABEL.test(label) && !SKIP.test(label) && !b.disabled && realField(b);
    });
    return btns.length === 1 ? btns[0] : null;
  }

  function submitButton(form, scopeEl) {
    const root = form || scopeEl || document;
    const btns = Array.from(root.querySelectorAll('button, input[type=submit], input[type=button], [role=button]')).filter(visible);
    const typed = btns.find((b) => (b.type || '').toLowerCase() === 'submit' || (b.tagName === 'BUTTON' && !b.getAttribute('type')));
    if (typed) return typed;
    return btns.find((b) => /sign ?in|log ?in|continue|next|submit|verify|confirm|connexion|suivant|continuer|valider|se connecter/i.test(b.innerText || b.value || b.getAttribute('aria-label') || '')) || null;
  }
  function submit(anchorEl) {
    const form = anchorEl.form || anchorEl.closest('form');
    const btn = submitButton(form, anchorEl.parentElement && anchorEl.parentElement.parentElement);
    if (form) {
      try {
        if (btn && btn.form === form && ((btn.type || '').toLowerCase() === 'submit')) form.requestSubmit(btn); else form.requestSubmit();
        return true;
      } catch { /* fall through to click */ }
    }
    if (btn) { btn.click(); return true; }
    return false;
  }

  // ---- ops ----
  if (op === 'probe') {
    const pw = passwordField();
    const otp = otpField();
    const boxes = splitBoxes();
    const has_otp = !!(otp || boxes);
    let has_username_only = false;
    if (!pw && !has_otp) {
      const u = usernameField(null);
      has_username_only = !!u && /user|email|login|ident|account|phone/.test(txt(u));
    }
    const captcha = Array.from(document.querySelectorAll('iframe')).some((f) => {
      const src = (f.src || '').toLowerCase();
      if (!/recaptcha|hcaptcha|turnstile|challenges\.cloudflare\.com/.test(src)) return false;
      if (/size=invisible/.test(src)) return false;
      const r = f.getBoundingClientRect();
      return visible(f) && r.width > 40 && r.height > 40;
    });
    let passkey_prompt = false;
    if (!pw && !has_otp) {
      const dlg = document.querySelector('dialog[open], [role=dialog], [aria-modal=true]');
      const hay = ((dlg && dlg.innerText) || '').toLowerCase();
      passkey_prompt = /passkey|security key|touch id|face id|windows hello/.test(hay) && !!dlg && visible(dlg);
      if (!passkey_prompt && !dlg) {
        const h = Array.from(document.querySelectorAll('h1,h2,h3')).map((e) => e.innerText || '').join(' ').toLowerCase();
        passkey_prompt = /passkey/.test(h);
      }
    }
    const continue_button = !pw && !has_otp && !has_username_only && !!continueButton();
    return { url: location.href, has_password: !!pw, has_username_only, has_otp, captcha, passkey_prompt, continue_button };
  }

  if (op === 'press_continue') {
    if (!domainOk()) return { error: 'domain_mismatch' };
    const btn = continueButton();
    if (!btn) return { error: 'no_continue_button' };
    btn.click();
    return { action: 'continue_pressed' };
  }

  if (op === 'fill_login') {
    if (!domainOk()) return { error: 'domain_mismatch' };
    const pw = passwordField();
    if (pw) {
      if (!args.passwordStepOnly) {
        const u = usernameField(pw);
        if (u && !u.readOnly && !u.disabled) {
          const id = identifierFor(u);
          if (id.error) return { error: id.error };
          if (u.value !== id.value) setValue(u, id.value);
        }
      }
      setValue(pw, args.password);
      return submit(pw) ? { action: 'password_submitted' } : { error: 'no_submit' };
    }
    if (args.passwordStepOnly) return { error: 'no_login_form' };
    const u = usernameField(null);
    if (!u) return { error: 'no_login_form' };
    const id = identifierFor(u);
    if (id.error) return { error: id.error };
    setValue(u, id.value);
    return submit(u) ? { action: 'username_submitted' } : { error: 'no_submit' };
  }

  if (op === 'fill_code') {
    if (!domainOk()) return { error: 'domain_mismatch' };
    const code = String(args.code || '');
    const boxes = splitBoxes();
    if (boxes) {
      const chars = Array.from(code.replace(/[^A-Za-z0-9]/g, '')); // codes may be alphanumeric (booking.com)
      boxes.forEach((b, i) => { if (chars[i] !== undefined) setValue(b, chars[i]); });
      const last = boxes[boxes.length - 1];
      submit(last); // many split-box UIs auto-submit; a missing button is fine
      return { action: 'code_submitted' };
    }
    const f = otpField();
    if (!f) return { error: 'no_code_field' };
    setValue(f, code);
    submit(f);
    return { action: 'code_submitted' };
  }
  return { error: 'unknown_op' };
}
