# AuthBridge — spec (v1)

Lets Claude Code get a Chrome tab logged in without ever seeing credentials. Each login is approved
on the user's iPhone with Face ID / passcode; the approval releases a key share without which the stored
credential cannot be decrypted.

## Components

```
Claude Code ──stdio──> mcp/server.mjs ──unix sock──> daemon/ (Node, launchd)
                                                     │  ├─ authbridge-se (Swift CLI, Secure Enclave ECDH)
                                                     │  ├─ IMAP (configured mail accounts, read-only) for email codes
                                                     │  ├─ notifier (optional webhook fallback)
                                                     │  └─ HTTP :47900 <──── iPhone app (ios/)
Chrome extension (extension/) ──native messaging──> host/nmh.mjs ──unix sock──> daemon
```

Runtime dir `~/.authbridge/` (0700): `se-key.blob`, `store.json`, `pairing.json`, `config.json`,
`daemon.log`, `run/daemon.sock` (0600).

## Hard security rules (apply to every component)

1. No password, key share, email code, S1, K or decrypted JSON is ever logged, printed, written to
   disk, put in a URL, returned over the unix socket to the MCP, or included in an MCP tool result.
   The logger must reject/redact any field named password, share, code, secret, key, plaintext.
2. The MCP only ever receives `{status, detail}` where detail is a short enum-ish string.
3. Credentials are only filled into the top frame of an `https:` page whose `location.hostname`
   equals the record domain or ends with `"." + domain`. Checked in the daemon (tab URL) AND again in
   the injected script immediately before setting values. Mismatch → abort, `domain_mismatch`.
4. Plaintext exists only in process memory for the duration of one fill; use Buffers and
   `fill(0)` where possible.
5. Notifications contain the domain and task text only.

## Crypto

Encoding: all binary values in JSON are standard base64 (with padding).

### Credential storage (split key)
- Mac Secure Enclave P-256 key-agreement key; blob at `~/.authbridge/se-key.blob` (device-bound).
- Enroll: daemon makes an ephemeral P-256 key E, `S1 = ECDH(E_priv, SE_pub)` (Node crypto), stores
  `E_pub` (x963 uncompressed, 65 bytes), discards `E_priv`. Later `S1 = ECDH(SE_priv, E_pub)` via
  `authbridge-se derive <E_pub_b64>`.
- Phone generates `P` (32 random bytes) per record; it lives only in the iPhone keychain
  (`kSecAttrAccessControl` = `.userPresence`, `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`,
  service `authbridge.share`, account = record_id).
- `K = HKDF-SHA256(ikm = S1 || P, salt = utf8(record_id), info = utf8("authbridge-v1|" + domain), L=32)`
- Ciphertext: AES-256-GCM, 12-byte random nonce, AAD = utf8(record_id + "|" + domain), plaintext =
  JSON `{"username": "...", "password": "...", "email": "..."}` (`email` optional, omitted when empty). Store `nonce`, `ct` (ciphertext||16-byte tag).

### Sealed box (phone → Mac)  `seal(recipient_x25519_pub, plaintext, aad)`
- `epk` = fresh X25519 key; `ss = X25519(eph_priv, recipient_pub)`
- `key = HKDF-SHA256(ikm = ss, salt = epk_pub_raw || recipient_pub_raw, info = utf8("authbridge-seal-v1"), L=32)`
- ChaCha20-Poly1305, 12-byte random nonce, AAD = utf8(aad).
- JSON: `{"epk": b64(32 raw), "nonce": b64(12), "ct": b64(ciphertext || 16-byte tag)}`

### Request signing (phone → Mac, all endpoints except /v1/pair)
Phone has a Secure Enclave P-256 signing key. Headers:
`X-AB-Device: <device_id>`, `X-AB-Ts: <unix ms>`, `X-AB-Nonce: <b64 16 random bytes>`,
`X-AB-Sig: b64(DER ECDSA-SHA256 signature over utf8(METHOD + "\n" + PATH + "\n" + TS + "\n" + NONCE + "\n" + hex(sha256(body bytes))))`
(empty body → sha256 of empty string; PATH excludes host, includes query). Daemon rejects |now-ts| > 60 s
and nonces seen in the last 120 s.

## Phone HTTP API (daemon, port 47900, JSON)

- `POST /v1/pair` `{code, device_name, sign_pub: b64(SPKI DER P-256), agree_pub: b64(32 raw X25519)}`
  → `{device_id, mac_agree_pub: b64(32 raw), mac_name}`. Code is a one-time 8-digit code from
  `authbridge pair` (valid 10 min, 5 wrong attempts invalidates it). Single paired device in v1
  (re-pair replaces).
- `GET /v1/pending` → `{requests: [...]}`. Each has `kind`: `"login"` `{id, kind, domain, task, record_id, needs_enroll, requested_at, expires_at}`
  or `"code"` `{id, kind, domain, task, requested_at, expires_at, parent_id}` (see code requests below).
- `POST /v1/approve` `{request_id, decision: "approve"|"deny"|"no_credential", record_id, sealed_share?}`;
  `sealed_share = seal(mac_agree_pub, P, aad = request_id)`. → `{ok:true}`.
  `no_credential` means the user has no login for that site (only status that yields `no_credential`).
  For a `needs_enroll` request, `approve` must carry the `record_id` of a record that now exists on the Mac
  and whose domain equals the request's domain (else 400 `record_mismatch`): the phone first calls
  `POST /v1/enroll`, then approves with the new record_id and its sealed share.
- `POST /v1/code` `{request_id, decision: "submit"|"cancel", sealed?}` (signed; answers a `kind:"code"` request only,
  else 404 `unknown_request`; login requests likewise cannot be answered via `/v1/approve`). For `submit`,
  `sealed = seal(mac_agree_pub, JSON{code}, aad = "code|" + request_id)`. The daemon strips spaces/dashes and requires
  4-10 chars of `[A-Za-z0-9]` (else 400 `bad_code`, request stays open); bad envelope → 400 `bad_sealed`/`bad_payload`.
  No Face ID: the request is device-signed. The code is never logged. A late answer (request already resolved or
  removed) gets 404 and is ignored. → `{ok:true}`.
- `POST /v1/enroll` `{sealed}` where `sealed = seal(mac_agree_pub, JSON{record_id, domain, username, password, email?, share: b64(P)}, aad="enroll")`
  → `{record_id, domain}` (domain normalised: lowercase, punycode; replaces any existing record for that domain).
- `POST /v1/records/<record_id>/update` `{sealed}` where `sealed = seal(mac_agree_pub, JSON{share: b64(P), username?, email?}, aad="update|"+record_id)`
  → `{ok:true}`. Edits a stored login without re-entering the password: the daemon recomputes S1 via the SE helper,
  derives K with the share exactly as for login, decrypts (GCM failure → 400 `decrypt`, record untouched), replaces
  `username` and/or `email` when present (`username` must be non-empty; empty-string `email` removes it), keeps the
  password, re-encrypts under the same K with a fresh nonce, clears `stale`, saves. Unknown record → 404
  `unknown_record`; bad aad/envelope → 400 `bad_sealed`; malformed payload → 400 `bad_payload`. Values are never logged.
- `GET /v1/records` → `{records: [{record_id, domain, stale, created_at}]}` (no usernames)
- `DELETE /v1/records/<record_id>` → `{ok:true}`
- `POST /v1/wipe` → deletes all records `{ok:true}`

- `GET /v1/requests/<id>` (signed) → `{state: "pending"|"resolved"|"expired", resolved_by?: "email"}` for a code request
  (404 `unknown_request` if never seen / forgotten after 1 h). `resolved_by: "email"` means the Mac found the code in
  email after the request was created; the request is then gone from `GET /v1/pending`. The phone polls this every 2 s
  while the code screen is open.

Code requests: `{kind:"code", id, domain, task:"enter the verification code", requested_at, expires_at (3 min),
parent_id, reason, searched?}` where `reason` is `"email_not_found"` (the Mac searched email and found nothing yet; `searched` = configured account names, e.g. `["Gmail"]`) or `"follow_up"` (another code step after one was accepted). The iOS code screen says "Enter the code from the email or text message" plus "Not found yet in Gmail (inbox and junk)" for `email_not_found`, and "Enter the code the site just sent (text message or app)" for `follow_up`; never "SMS" specifically. `parent_id` is the login request's id. The push body is `<domain> — enter the verification code` and
the APNs payload carries `request_id` and `kind:"code"` (optional webhook fallback when no push token). Timings
(`prompt_min_ms` 45000, `prompt_max_ms` 150000, `prompt_default_ms` 75000, `code_request_ttl_ms` 180000,
`max_code_steps` 3, `code_request_after_ms` 20000 = default email-fallback threshold) are injectable via `config.timing`.

Pending request objects include `record_id` so the phone knows which share to read. When the domain has no
stored record, the request is created with `needs_enroll: true` and `record_id: null` (enroll at first login);
the push body is then e.g. `booking.com — first login, pick it from Passwords` (still domain only).

## Unix socket protocol (`~/.authbridge/run/daemon.sock`, newline-delimited JSON)

Client sends `{id, op, ...}`, daemon replies `{id, ...}`.

MCP ops:
- `request_login {domain, tab_id, task, timeout_s?=300}` → `{status, detail?}` (long-running)
- `status` → `{paired, domains:[...], extension_connected}`

Statuses: `signed_in`, `already_signed_in`, `failed`, `needs_more` (detail: `email_code_not_found`,
`email_code_ambiguous`, `sms_or_app_code`, `passkey`, `captcha`, `unsupported_form`, `unknown`), `out_of_date`,
`no_credential`, `denied`, `timed_out`, `domain_mismatch`, `extension_unavailable`, `not_paired`.

Extension (via host/nmh.mjs): host sends `{op:"extension_hello"}` first. Then the daemon sends
commands `{cmd_id, cmd, ...}` and the extension answers `{cmd_id, ok, result|error}`:
- `tab_info {tab_id}` → `{url}`
- `probe {tab_id}` → `{url, has_password, has_username_only, has_otp, captcha, passkey_prompt}`
- `fill_credentials {tab_id, expected_domain, username, password, email}` → `{submitted: true}` (handles
  username→Next→password two-step flows, waits ≤10 s for the password field). `email` may be empty; the
  daemon sets it to the username when email is empty and the username contains "@". The extension decides
  per identifier field (`extension/identifier.js`): the field "wants an email" if type=email, autocomplete
  contains "email", or name/id/aria-label/placeholder/label text matches /e-?mail/i. Wants email → use
  `email`, else the username if it contains "@", else abort with error `email_required` (nothing
  submitted). Otherwise use the username (falling back to `email` if the username is empty). Same in
  the two-step path. Error `email_required` → daemon status `failed` detail `email_required`.
- `fill_code {tab_id, expected_domain, code}` → `{submitted: true}`
- `reload {tab_id}` → `{}`

## Login algorithm (daemon)

1. Normalise domain; `tab_info` → host must match (rule 3) → else `domain_mismatch`.
2. `probe`: no password/username/otp field → `already_signed_in`.
3. Not paired → `not_paired`. (No record is not an error: see step 5.)
4. Per-domain lock. A second request for the same domain waits for the first; if the first ended
   `signed_in`, `reload` this tab, `probe`, and return `already_signed_in` if no login form remains.
   Different domains never wait on each other.
5. Create pending request (expires after timeout_s), notify phone, wait for approve/deny/timeout. If the phone has not fetched the request after `reminder_ms` (120000), send one reminder push. If the domain
   has no record the request has `needs_enroll: true`; the phone enrolls then approves with the new record_id.
   Phone answers `no_credential` → `no_credential`; deny → `denied`; timeout → `timed_out`.
6. Decrypt (S1 via helper, P from sealed share). GCM failure → `failed` detail `decrypt`.
7. `fill_credentials`. Then poll `probe` every 1 s for ≤20 s:
   - otp field → email-code step; captcha → `needs_more captcha`; passkey → `needs_more passkey`
   - no login form → `signed_in`
   - password field still there after 20 s → mark record stale → `out_of_date`
8. Email-code step: poll the configured mail accounts (IMAP config in `~/.authbridge/mail.json`, passwords in
   keychain service `authbridge-mail` with the entry name as account; add with `cli.mjs mail-add`; with no accounts
   this step is skipped and the phone is asked for the code at once) every 5 s for ≤120 s. Accept only
   messages received ≥ (login start − 30 s) whose From address's registrable domain equals the
   record's registrable domain (or is in that record's `code_senders`). Extract the first 4–8 digit
   code near a keyword (code, verification, passcode, OTP, one-time, vérification, code de) — subject
   first, then text body. `fill_code`, then probe as in 7. Nothing found → `needs_more email_code_not_found`.
   Remember which account worked per record (`preferred_mail`). An IMAP error on one account must not
   stop the other.
9. Code requests (phone-supplied codes). Email polling runs for the whole code step. The daemon records per login
   record `email_delay_ms` = time from the code step starting to the email code being found, smoothed as
   `max(new, 0.7*old + 0.3*new)` (never the code itself). The phone is asked ("email_not_found" code request, one
   extra notification) only at `max(prompt_min_ms 45 s, min(prompt_max_ms 150 s, 1.5 * email_delay_ms))`, or
   `prompt_default_ms` (75 s) when nothing is learned yet; an email found earlier means no code request and no second
   notification. The mail window is that prompt delay + `code_request_ttl_ms` (180 s). If email wins after the request
   exists it is resolved with `resolved_by: "email"` (see `GET /v1/requests/<id>`). First source to yield a code wins;
   an unanswered code request is removed, so a late answer is ignored. The step ends without a code when the mail
   window and the code request have both expired: cancelled or timed out -> `needs_more sms_or_app_code`
   (`email_code_not_found` only if mail polling ends before any request was created).
   A code field on a different page after a code was accepted (e.g. SMS after the email code) creates a code request
   immediately, with no email polling, then fills the answer and probes again. At most 3 code steps per login; a
   further code field -> `needs_more sms_or_app_code`. A code field on the same page after filling -> `failed code_rejected`.
10. Mail scanning covers INBOX and each account's junk folder (IMAP SPECIAL-USE `\Junk`, else a folder named `Bulk`
    or `[Gmail]/Spam`; cached per account; an error on one folder/account never stops the others). Primary match =
    sender rule as in 8 (registrable domain, same-brand sibling, `code_senders`), allowed in any folder. Fallback,
    considered only after `fallback_after_ms` (default `code_request_after_ms`, 20 s) of polling without a primary
    match: emails received at or after the login request start (no slack), any sender, with a keyword-adjacent code
    AND the site's brand word (registrable-domain label, e.g. `free`) in sender, subject or body. Exactly one
    candidate across all accounts and folders -> used, and its sender's registrable domain is appended to the record's
    `code_senders`; two or more -> no guess: the code request to the phone is created immediately (if not already) and, if it is
    unanswered/cancelled, the login ends `needs_more email_code_ambiguous`. `code_found` is logged with
    `{path: "sender"|"learned"|"fallback", folder: "inbox"|"junk", account}`; the code and message content never are.
