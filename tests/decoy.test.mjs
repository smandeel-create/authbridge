// Browser test: runs the extension's real injected logic (abPage + identifier.js) in headless Chrome
// against decoy-password login pages. Uses a throwaway profile (playwright launches a temp user-data-dir).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { chromium } from 'playwright-core';
import { startTestSite, TEST_USER, TEST_PASS } from '../testsite/server.mjs';

const bg = fs.readFileSync(new URL('../extension/background.js', import.meta.url), 'utf8');
const abPageSrc = bg.slice(bg.indexOf('function abPage('));
const identifierSrc = fs.readFileSync(new URL('../extension/identifier.js', import.meta.url), 'utf8');

const chromePath = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
const haveChrome = fs.existsSync(chromePath);

async function run(page, op, args) {
  await page.evaluate(identifierSrc);
  return page.evaluate(`(${abPageSrc.replace(/;\s*$/, '')})(${JSON.stringify(op)}, ${JSON.stringify(args)})`);
}

test('decoy password fields are never filled', { skip: !haveChrome && 'Google Chrome not installed' }, async (t) => {
  const site = await startTestSite();
  const browser = await chromium.launch({ channel: 'chrome', headless: true });
  const base = { expected_domain: '127.0.0.1', allow_insecure: true, username: TEST_USER, password: TEST_PASS, email: TEST_USER };
  try {
    for (const style of site.decoyStyles) {
      await t.test(style, async () => {
        const page = await browser.newPage({ viewport: { width: 1000, height: 700 } });
        site.decoyValues.length = 0;
        await page.goto(`http://127.0.0.1:${site.port}/decoy-${style}`);
        const p1 = await run(page, 'probe', {});
        assert.equal(p1.has_password, false, 'probe must not see the decoy');
        assert.equal(p1.has_username_only, true);
        const nav = page.waitForURL(/\/password/);
        const r1 = await run(page, 'fill_login', base);
        assert.equal(r1.action, 'username_submitted');
        await nav;
        const p2 = await run(page, 'probe', {});
        assert.equal(p2.has_password, true);
        const home = page.waitForURL(/\/home/);
        const r2 = await run(page, 'fill_login', { ...base, passwordStepOnly: true });
        assert.equal(r2.action, 'password_submitted');
        await home;
        assert.ok(site.decoyValues.length >= 2);
        assert.ok(site.decoyValues.every((d) => d.value === ''), 'decoy received a value: ' + JSON.stringify(site.decoyValues));
        await page.close();
      });
    }
  } finally {
    await browser.close();
    await site.close();
  }
});
