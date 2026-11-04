import { domainToASCII } from 'node:url';
import tldts from 'tldts';

export function normalizeDomain(input) {
  if (typeof input !== 'string') return null;
  let s = input.trim().toLowerCase();
  if (!s) return null;
  if (s.includes('://')) {
    try { s = new URL(s).hostname; } catch { return null; }
  }
  s = s.replace(/\.$/, '');
  if (/[\s/\\@?#:]/.test(s)) return null;
  const ascii = domainToASCII(s);
  if (!ascii || !/^[a-z0-9.-]+$/.test(ascii) || ascii.startsWith('.') || ascii.includes('..')) return null;
  return ascii;
}

export function hostMatchesDomain(hostname, domain) {
  if (!hostname || !domain) return false;
  const h = hostname.toLowerCase().replace(/\.$/, '');
  return h === domain || h.endsWith('.' + domain);
}

// Rule 3: https only (except exact insecure test hosts), hostname equals or is a subdomain of domain.
export function checkUrl(urlStr, domain, insecureHosts = []) {
  let u;
  try { u = new URL(urlStr); } catch { return { ok: false, reason: 'bad_url' }; }
  const host = u.hostname;
  if (u.protocol !== 'https:') {
    const allowHttp = u.protocol === 'http:' && insecureHosts.includes(host);
    if (!allowHttp) return { ok: false, reason: 'not_https' };
  }
  if (!hostMatchesDomain(host, domain)) return { ok: false, reason: 'host_mismatch' };
  return { ok: true, host, insecure: u.protocol === 'http:' };
}

export function registrableDomain(host) {
  if (!host) return null;
  const h = host.toLowerCase();
  return tldts.getDomain(h) || h;
}

export function senderMatches(fromAddress, recordDomain, codeSenders = []) {
  const at = String(fromAddress || '').toLowerCase().lastIndexOf('@');
  if (at < 0) return false;
  const sdom = fromAddress.toLowerCase().slice(at + 1).trim();
  if (!sdom) return false;
  if (registrableDomain(sdom) === registrableDomain(recordDomain)) return true;
  // Same brand on a sibling domain (free.fr's codes come from free-mobile.fr): the record's name
  // label (>= 4 chars) must be the first hyphen token of the sender's registrable name, so
  // evil-example.com never counts for example.com.
  const brand = String(registrableDomain(recordDomain) || '').split('.')[0];
  const sname = String(registrableDomain(sdom) || '').split('.')[0];
  if (brand.length >= 4 && sname.split('-')[0] === brand && sname !== brand) return true;
  for (const cs of codeSenders) {
    const c = String(cs).toLowerCase().trim();
    if (c.includes('@')) { if (c === fromAddress.toLowerCase()) return true; }
    else if (registrableDomain(c) === registrableDomain(sdom)) return true;
  }
  return false;
}
