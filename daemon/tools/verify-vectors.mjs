#!/opt/homebrew/bin/node
// Usage: verify-vectors.mjs <vectors.json>
// {recipient_priv_raw_b64, recipient_pub_b64, aad, plaintext_b64, sealed:{epk,nonce,ct}, sign:{pub_spki_b64, message_b64, sig_der_b64}}
import fs from 'node:fs';
import crypto from 'node:crypto';
import { open, unb64 } from '../crypto.mjs';

export function verifyVectors(v) {
  const results = {};
  try {
    const pt = open(unb64(v.recipient_priv_raw_b64), unb64(v.recipient_pub_b64), v.sealed, v.aad);
    results.sealed_open = pt.equals(unb64(v.plaintext_b64));
  } catch { results.sealed_open = false; }
  try {
    const pub = crypto.createPublicKey({ key: unb64(v.sign.pub_spki_b64), format: 'der', type: 'spki' });
    results.signature = crypto.verify('sha256', unb64(v.sign.message_b64), pub, unb64(v.sign.sig_der_b64));
  } catch { results.signature = false; }
  return results;
}

import { fileURLToPath } from 'node:url';
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const file = process.argv[2];
  if (!file) { console.error('usage: verify-vectors.mjs <vectors.json>'); process.exit(2); }
  const r = verifyVectors(JSON.parse(fs.readFileSync(file, 'utf8')));
  console.log(`sealed box open: ${r.sealed_open ? 'PASS' : 'FAIL'}`);
  console.log(`signature verify: ${r.signature ? 'PASS' : 'FAIL'}`);
  process.exit(r.sealed_open && r.signature ? 0 : 1);
}
