#!/usr/bin/env node
import net from 'node:net';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { sockPath, abHome } from './paths.mjs';
import { connectivityCheck } from './mail.mjs';

const PROVIDERS = {
  yahoo: 'imap.mail.yahoo.com',
  gmail: 'imap.gmail.com',
  icloud: 'imap.mail.me.com',
  outlook: 'outlook.office365.com',
  fastmail: 'imap.fastmail.com',
};
const SECURITY = '/usr/bin/security';
const MAIL_SERVICE = 'authbridge-mail';
const RESTART_HINT = 'launchctl kickstart -k gui/$UID/com.authbridge.daemon';

function parseArgs(argv) {
  const pos = [], flags = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      const k = argv[i].slice(2);
      if (i + 1 < argv.length && !argv[i + 1].startsWith('--')) flags[k] = argv[++i]; else flags[k] = true;
    } else pos.push(argv[i]);
  }
  return { pos, flags };
}
function readJson(p) { try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return {}; } }
function writeJson600(p, obj) {
  fs.mkdirSync(path.dirname(p), { recursive: true, mode: 0o700 });
  fs.chmodSync(path.dirname(p), 0o700);
  fs.writeFileSync(p, JSON.stringify(obj, null, 2) + '\n', { mode: 0o600 });
  fs.chmodSync(p, 0o600);
}
const mailPath = () => path.join(abHome(), 'mail.json');
const die = (msg, code = 2) => { console.error(msg); process.exit(code); };

function rpc(msg) {
  return new Promise((resolve, reject) => {
    const s = net.createConnection(sockPath());
    let buf = '';
    s.on('connect', () => s.write(JSON.stringify({ id: 1, ...msg }) + '\n'));
    s.on('data', (d) => { buf += d; if (buf.includes('\n')) { s.end(); try { resolve(JSON.parse(buf.split('\n')[0])); } catch (e) { reject(e); } } });
    s.on('error', () => reject(new Error('daemon not running (no socket at ' + sockPath() + ')')));
  });
}

const cmd = process.argv[2];
try {
  if (cmd === 'pair') {
    const r = await rpc({ op: 'create_pair_code' });
    console.log(`Pairing code: ${r.code}  (valid 10 minutes, 5 attempts)`);
    console.log('Enter it in the AuthBridge app on your iPhone.');
  } else if (cmd === 'status') {
    const r = await rpc({ op: 'status' });
    console.log(`paired: ${r.paired}\nextension connected: ${r.extension_connected}\ndomains: ${r.domains.join(', ') || '(none)'}`);
  } else if (cmd === 'test-push') {
    const r = await rpc({ op: 'test_push' });
    console.log(r.ok ? 'ok' : (r.reason || 'failed'));
    if (!r.ok) process.exit(1);
  } else if (cmd === 'reload-extension') {
    const r = await rpc({ op: 'reload_extension' });
    console.log(r.ok ? 'ok' : (r.error || 'failed'));
    if (!r.ok) process.exit(1);
  } else if (cmd === 'wipe') {
    const r = await rpc({ op: 'wipe' });
    console.log(`wiped ${r.removed} record(s)`);
  } else if (cmd === 'mail-add') {
    const { pos, flags } = parseArgs(process.argv.slice(3));
    const [name, email] = pos;
    if (!name || !email) die('usage: cli.mjs mail-add <name> <email> [--provider yahoo|gmail|icloud|outlook|fastmail] | [--host H --port 993]');
    let host = flags.host, port = Number(flags.port || 993);
    if (flags.provider) {
      host = PROVIDERS[flags.provider];
      if (!host) die('unknown provider "' + flags.provider + '" (known: ' + Object.keys(PROVIDERS).join(', ') + ')');
    }
    if (!host || typeof host !== 'string') die('give --provider ' + Object.keys(PROVIDERS).join('|') + ' or --host H [--port 993]');
    if (!Number.isInteger(port) || port <= 0) die('bad --port');
    const accounts = readJson(mailPath());
    accounts[name] = { email, imap: { host, port, secure: port !== 143 } };
    writeJson600(mailPath(), accounts);
    console.log(`Saved ${name} (${email}, ${host}:${port}) to ${mailPath()}`);
    console.log('Enter the app password when prompted (use an app-specific password, not your main one).');
    // `-w` last with no value makes `security` prompt interactively: the password never appears in argv.
    const r = spawnSync(SECURITY, ['add-generic-password', '-U', '-s', MAIL_SERVICE, '-a', name, '-w'], { stdio: 'inherit' });
    if (r.status !== 0) die('could not store the password in the keychain', 1);
    const res = await connectivityCheck({ accounts: [name] });
    const st = res[name] || 'failed';
    console.log(st === 'ok' ? `connectivity check: ok` : `connectivity check: failed (${st})`);
    console.log('The daemon re-reads mail.json on every code lookup; no restart needed. If it was running before the first account existed and misbehaves, run: ' + RESTART_HINT);
    if (st !== 'ok') process.exit(1);
  } else if (cmd === 'mail-list') {
    const accounts = readJson(mailPath());
    const names = Object.keys(accounts);
    if (!names.length) console.log('(no mail accounts; use mail-add)');
    for (const n of names) console.log(`${n}\t${accounts[n].email}\t${accounts[n].imap?.host ?? '?'}`);
  } else if (cmd === 'mail-remove') {
    const name = process.argv[3];
    if (!name) die('usage: cli.mjs mail-remove <name>');
    const accounts = readJson(mailPath());
    const had = name in accounts;
    delete accounts[name];
    if (had) writeJson600(mailPath(), accounts);
    spawnSync(SECURITY, ['delete-generic-password', '-s', MAIL_SERVICE, '-a', name], { stdio: 'ignore' });
    console.log(had ? `removed ${name}` : `no account named ${name} in ${mailPath()} (keychain entry deleted if present)`);
  } else if (cmd === 'push-setup') {
    const { flags } = parseArgs(process.argv.slice(3));
    const keyId = flags['key-id'], teamId = flags['team-id'], bundleId = flags['bundle-id'], p8 = flags.p8;
    if (![keyId, teamId, bundleId, p8].every((v) => typeof v === 'string')) die('usage: cli.mjs push-setup --key-id K --team-id T --bundle-id B --p8 /path/AuthKey_K.p8 [--production]');
    let pem;
    try { pem = fs.readFileSync(p8, 'utf8').trim(); } catch (e) { die('cannot read ' + p8 + ': ' + e.message, 1); }
    // Note: the PEM is passed on argv here. Acceptable for a one-off local command run by the machine's owner
    // (the .p8 is an APNs signing key for this app only); `security` has no stdin mode for -w with a value.
    const r = spawnSync(SECURITY, ['add-generic-password', '-U', '-s', 'authbridge-apns', '-a', keyId, '-w', pem], { stdio: ['ignore', 'ignore', 'inherit'] });
    if (r.status !== 0) die('could not store the key in the keychain', 1);
    const cfgFile = path.join(abHome(), 'config.json');
    const cfg = readJson(cfgFile);
    cfg.notifier = { type: 'apns', key_id: keyId, team_id: teamId, topic: bundleId, env: flags.production ? 'production' : 'development' };
    writeJson600(cfgFile, cfg);
    console.log(`APNs key ${keyId} stored in the keychain; notifier written to ${cfgFile} (${cfg.notifier.env}).`);
    console.log(`Restart the daemon (${RESTART_HINT}) then run: node daemon/cli.mjs test-push`);
  } else {
    console.error('usage: cli.mjs pair|status|test-push|reload-extension|wipe|mail-add|mail-list|mail-remove|push-setup');
    process.exit(2);
  }
} catch (e) {
  console.error(e.message);
  process.exit(1);
}
