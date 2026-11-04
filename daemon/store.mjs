import fs from 'node:fs';
import path from 'node:path';

function readJson(file, dflt) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return dflt; }
}
function writeJson(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 });
  const tmp = file + '.tmp-' + process.pid;
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 1), { mode: 0o600 });
  fs.chmodSync(tmp, 0o600);
  fs.renameSync(tmp, file);
}

export class Store {
  constructor(file) { this.file = file; this.data = readJson(file, { records: [] }); this.data.records ??= []; }
  save() { writeJson(this.file, this.data); }
  list() { return this.data.records; }
  byDomain(domain) { return this.data.records.find((r) => r.domain === domain) || null; }
  byId(id) { return this.data.records.find((r) => r.record_id === id) || null; }
  upsertForDomain(rec) {
    this.data.records = this.data.records.filter((r) => r.domain !== rec.domain && r.record_id !== rec.record_id);
    this.data.records.push(rec);
    this.save();
  }
  remove(id) {
    const n = this.data.records.length;
    this.data.records = this.data.records.filter((r) => r.record_id !== id);
    this.save();
    return this.data.records.length !== n;
  }
  wipe() { const n = this.data.records.length; this.data.records = []; this.save(); return n; }
  patch(id, fields) { const r = this.byId(id); if (r) { Object.assign(r, fields); this.save(); } }
}

export class PairingFile {
  constructor(file) { this.file = file; this.data = readJson(file, {}); }
  save() { writeJson(this.file, this.data); }
  get device() { return this.data.device || null; }
  get mac() { return this.data.mac || null; }
  setMac(mac) { this.data.mac = mac; this.save(); }
  setDevice(d) { this.data.device = d; this.save(); }
  setPushToken(t) { if (this.data.device) { this.data.device.push_token = t; this.save(); } }
  clearPushToken() { if (this.data.device?.push_token) { delete this.data.device.push_token; this.save(); } }
}
