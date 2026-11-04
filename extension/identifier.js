// Pure identifier-choice logic. Injected into the page's isolated world (via executeScript `files`)
// before abPage runs, and unit-tested in tests/identifier.test.mjs by evaluating this file in a vm.
// No DOM access, no references outside this file.
(function (root) {
  'use strict';
  const EMAIL_RE = /e-?mail/i;

  // desc: { type, autocomplete, name, id, ariaLabel, placeholder, labelText } (all optional strings)
  function wantsEmail(desc) {
    const d = desc || {};
    if (String(d.type || '').toLowerCase() === 'email') return true;
    if (String(d.autocomplete || '').toLowerCase().includes('email')) return true;
    return [d.name, d.id, d.ariaLabel, d.placeholder, d.labelText].some((s) => EMAIL_RE.test(String(s || '')));
  }

  // -> { value } or { error: 'email_required' }
  function chooseIdentifier({ username, email, wantsEmail: wants }) {
    const u = String(username || ''), e = String(email || '');
    if (wants) {
      if (e) return { value: e };
      if (u.includes('@')) return { value: u };
      return { error: 'email_required' };
    }
    return { value: u || e };
  }

  root.__abIdentifier = { wantsEmail, chooseIdentifier };
})(globalThis);
