const fs = require('fs');
const {chromium} = require('playwright');
(async () => {
  const browser = await chromium.launch({channel:'chrome',headless:true});
  const page = await browser.newPage({viewport:{width:1200,height:700}});
  const pages = JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
  const errors = []; let documents = 0;
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    window.streams=[];
    window.EventSource=class {constructor(){this.closed=false;window.streams.push(this)}addEventListener(){}close(){this.closed=true}};
  });
  await page.route('**/*', route => {
    const url = new URL(route.request().url());
    if(route.request().resourceType()==='document') documents++;
    if(url.pathname.startsWith('/static/')) {
      const file='apps/web'+url.pathname;
      if(fs.existsSync(file)) return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'image/svg+xml'});
    }
    const html=pages[url.pathname+url.search];
    return route.fulfill(html?{body:html,contentType:'text/html'}:{status:404,body:'Not found'});
  });
  await page.goto('http://testserver/settings/connectors');
  await page.waitForFunction(()=>window.PodPilotPage);
  await page.evaluate(()=>{window.savedSidebar=document.querySelector('.sidebar');window.savedNav=document.querySelector('.nav-list');savedNav.scrollTop=90;});
  await page.locator('.connector-discovery-findings > summary').first().click();
  await page.locator('[data-discovery-open-id$="-apps"] > summary').click();
  await page.evaluate(()=>window.savedScroll=scrollY);
  await page.locator('.sidebar a[href="/memory"]').scrollIntoViewIfNeeded();
  await page.evaluate(()=>window.savedNavScroll=savedNav.scrollTop);
  await page.locator('.sidebar a[href="/memory"]').click();
  await page.waitForURL('**/memory');
  if(!await page.evaluate(()=>savedSidebar===document.querySelector('.sidebar')&&savedNav===document.querySelector('.nav-list')))throw Error('Shell replaced');
  if(!await page.evaluate(()=>Math.abs(savedNav.scrollTop-savedNavScroll)<2))throw Error('Sidebar scroll lost');
  await page.goBack();
  await page.waitForFunction(()=>location.pathname==='/settings/connectors'&&document.querySelector('[data-discovery-open-id$="-apps"]')?.open);
  if(!await page.evaluate(()=>Math.abs(scrollY-savedScroll)<2))throw Error('Page scroll lost');
  await page.locator('.sidebar a[href="/settings/model"]').click();
  await page.waitForURL('**/settings/model');
  await page.locator('[data-theme-option="orange"]').click();
  if(await page.locator('html').getAttribute('data-theme')!=='orange')throw Error('Theme controls lost');
  await page.locator('.sidebar a[href="/incidents"]').click();
  await page.waitForURL('**/incidents');
  if(!await page.evaluate(()=>window.streams.length))throw Error('Incident initialization missing');
  await page.locator('.sidebar a[href="/settings/connectors"]').click();
  await page.waitForURL('**/settings/connectors');
  if(!await page.evaluate(()=>window.streams.every(source=>source.closed)))throw Error('Old stream leaked');
  await page.locator('.sidebar a[href="/ask?new=1"]').last().click();
  await page.waitForURL('**/ask?new=1');
  if(documents!==1)throw Error('Full document navigation occurred: '+documents);
  if(errors.length)throw Error(errors.join('\n'));
  console.log('PASS: persistent sidebar; history, scroll and disclosures restored; destination controls initialized; streams cleaned up; one document load across five routes.');
  await browser.close();
})().catch(error=>{console.error(error);process.exit(1)});
