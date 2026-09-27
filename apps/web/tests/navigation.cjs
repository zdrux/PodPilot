const fs = require('fs');
const {chromium} = require('playwright');
(async () => {
  const browser = await chromium.launch({channel:'chrome',headless:true});
  const page = await browser.newPage({viewport:{width:1200,height:700}});
  const pages = JSON.parse(fs.readFileSync(process.argv[2],'utf8'));
  const errors = []; let documents = 0;
  let releaseApp;
  const appGate = new Promise(resolve => { releaseApp = resolve; });
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(() => {
    localStorage.setItem('podpilot-color-theme', 'orange');
    window.streams=[];
    window.EventSource=class {constructor(){this.closed=false;window.streams.push(this)}addEventListener(){}close(){this.closed=true}};
  });
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    if(route.request().resourceType()==='document') documents++;
    if(url.pathname === '/static/app.js') await appGate;
    if(url.pathname.startsWith('/static/')) {
      const file='apps/web'+url.pathname;
      if(fs.existsSync(file)) return route.fulfill({body:fs.readFileSync(file),contentType:file.endsWith('.js')?'text/javascript':file.endsWith('.css')?'text/css':'image/svg+xml'});
    }
    const html=pages[url.pathname+url.search];
    return route.fulfill(html?{body:html,contentType:'text/html'}:{status:404,body:'Not found'});
  });
  await page.goto('http://testserver/settings/connectors', {waitUntil:'commit'});
  await page.locator('.sidebar').waitFor({state:'visible'});
  if(await page.locator('html').getAttribute('data-theme') !== 'orange') throw Error('Saved theme missing before deferred app initialization');
  releaseApp();
  await page.waitForLoadState('load');
  await page.waitForFunction(()=>window.PodPilotPage);
  // Theme switches must not alter typography or layout at any breakpoint.
  for (const width of [1200, 800, 600]) {
    await page.setViewportSize({width, height:900});
    let reference;
    for (const theme of ['grafana-compact','classic','dark','light','medium-light','cibc-red','orange']) {
      await page.evaluate(theme=>document.documentElement.dataset.theme=theme, theme);
      const geometry = await page.evaluate(()=>{
        const props=['fontFamily','fontSize','fontWeight','lineHeight','letterSpacing','display','padding','margin','gap','width','height','minHeight','borderWidth','borderRadius','gridTemplateColumns'];
        return [...document.querySelectorAll('.sidebar, .sidebar *, .page-header, .panel-header, .button, .connector-setup-row')].map(el=>{
          const css=getComputedStyle(el);
          return {element:el.tagName+'.'+el.className, values:props.map(prop=>css[prop])};
        });
      });
      if (!reference) reference=geometry;
      else if(JSON.stringify(geometry)!==JSON.stringify(reference)) {
        const index=geometry.findIndex((value,i)=>JSON.stringify(value)!==JSON.stringify(reference[i]));
        throw Error(`Theme geometry differs: ${theme} at ${width}px: ${JSON.stringify(geometry[index])} expected ${JSON.stringify(reference[index])}`);
      }
    }
  }
  await page.setViewportSize({width:1200,height:700});
  await page.evaluate(()=>document.documentElement.dataset.theme='orange');
  const connectorToggle = page.locator('.connector-admin-menu > summary');
  await connectorToggle.click();
  await page.locator('.connector-admin-panel').waitFor({state:'visible'});
  if(!await page.evaluate(()=>{const panel=document.querySelector('.connector-admin-panel').getBoundingClientRect();const toggle=document.querySelector('.connector-admin-menu > summary').getBoundingClientRect();return panel.bottom<=toggle.top&&panel.top>=0;}))throw Error('Connector panel does not open upward within viewport');
  await page.keyboard.press('Escape');
  if(await page.locator('.connector-admin-menu').getAttribute('open')!==null)throw Error('Escape did not close connectors');
  await connectorToggle.press('Enter');
  await page.locator('.connector-admin-panel').waitFor({state:'visible'});
  await page.locator('.main').click({position:{x:5,y:5}});
  if(await page.locator('.connector-admin-menu').getAttribute('open')!==null)throw Error('Outside click did not close connectors');

  const grip = page.locator('.sidebar-resizer');
  const initialWidth = await page.locator('.sidebar').evaluate(el=>el.getBoundingClientRect().width);
  await grip.focus(); await grip.press('ArrowRight');
  if(Math.abs(await page.locator('.sidebar').evaluate(el=>el.getBoundingClientRect().width)-initialWidth-10)>2)throw Error('Sidebar keyboard resize failed');
  await page.reload();
  if(Math.abs(await page.locator('.sidebar').evaluate(el=>el.getBoundingClientRect().width)-initialWidth-10)>2)throw Error('Sidebar width not persisted');
  const bounds=await grip.boundingBox();
  await page.mouse.move(bounds.x+4,bounds.y+100);await page.mouse.down();await page.mouse.move(350,bounds.y+100);await page.mouse.up();
  if(Math.abs(await page.locator('.sidebar').evaluate(el=>el.getBoundingClientRect().width)-350)>2)throw Error('Sidebar pointer resize failed');
  await page.setViewportSize({width:600,height:700});
  if(await grip.isVisible())throw Error('Resize grip visible on mobile');
  await page.setViewportSize({width:1200,height:700});
  await grip.focus(); await grip.press('Home');

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
  await page.locator('.connector-admin-menu > summary').click();
  await page.locator('.sidebar a[href="/settings/connectors"]').click();
  await page.waitForURL('**/settings/connectors');
  if(!await page.evaluate(()=>window.streams.every(source=>source.closed)))throw Error('Old stream leaked');
  await page.locator('.sidebar a[href="/ask?new=1"]').last().click();
  await page.waitForURL('**/ask?new=1');
  if(documents!==2)throw Error('Full document navigation occurred: '+documents);
  if(errors.length)throw Error(errors.join('\n'));
  console.log('PASS: persistent sidebar; history, scroll and disclosures restored; destination controls initialized; streams cleaned up; one document load across five routes.');
  await browser.close();
})().catch(error=>{console.error(error);process.exit(1)});
