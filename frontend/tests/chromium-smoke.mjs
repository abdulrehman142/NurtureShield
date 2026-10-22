// Native MV3 load/popup smoke test. Real model transport is tested separately.
import { chromium } from 'playwright';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
const extensionPath=fileURLToPath(new URL('../',import.meta.url));
const profile=await mkdtemp(join(tmpdir(),'nurtureshield-chromium-'));
let browser;
try {
 browser=await chromium.launchPersistentContext(profile,{channel:'chromium',headless:true,args:[`--disable-extensions-except=${extensionPath}`,`--load-extension=${extensionPath}`]});
 const worker=browser.serviceWorkers()[0]||await browser.waitForEvent('serviceworker');
 const id=new URL(worker.url()).host;
 const page=await browser.newPage();
 await page.goto(`chrome-extension://${id}/popup.html`);
 assert.equal(await page.locator('h1').textContent(),'NurtureShield');
 await page.getByRole('button',{name:'Check Link',exact:true}).click();
 await page.getByRole('alert').waitFor({state:'visible'});
 assert.match(await page.getByRole('alert').textContent(),/Paste a link/);
 console.log('Native Chromium MV3 load and popup validation passed.');
} finally {
 if(browser)await browser.close();
 await rm(profile,{recursive:true,force:true});
}
