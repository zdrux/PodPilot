const fs=require('fs'),assert=require('assert'); const {chromium}=require('playwright');
(async()=>{const browser=await chromium.launch({channel:'chrome',headless:true});try{
const p=await browser.newPage({viewport:{width:1440,height:960}}); const errors=[];p.on('pageerror',e=>errors.push(e.message));
const html=fs.readFileSync(process.argv[2],'utf8');await p.addInitScript(()=>window.EventSource=class{addEventListener(){}close(){}});
await p.route('**/*',r=>{const path=new URL(r.request().url()).pathname;if(path.startsWith('/static/'))return r.fulfill({body:fs.readFileSync('apps/web'+path),contentType:path.endsWith('.css')?'text/css':path.endsWith('.svg')?'image/svg+xml':'text/javascript'});if(path.startsWith('/api/'))return r.fulfill({json:{status:'running',events:[],operations:[],approvals:[]}});return r.fulfill({contentType:'text/html',body:html});});
await p.goto('http://podpilot.test/ask/conversation');
await p.getByRole('button',{name:'Use Grafana Compact theme',exact:true}).click();
assert.equal(await p.locator('html').getAttribute('data-theme'),'grafana-compact');
assert.equal(await p.locator('.sidebar').evaluate(e=>Math.round(e.getBoundingClientRect().width)),240);
assert.equal(await p.locator('.nav-link').first().evaluate(e=>Math.round(e.getBoundingClientRect().height)),30);
await p.reload();assert.equal(await p.locator('html').getAttribute('data-theme'),'grafana-compact');
await p.screenshot({path:process.argv[3]});
await p.getByRole('button',{name:'Use Classic theme',exact:true}).click();assert.equal(await p.locator('.sidebar').evaluate(e=>Math.round(e.getBoundingClientRect().width)),260);
await p.getByRole('button',{name:'Use Grafana Compact theme',exact:true}).click();await p.setViewportSize({width:390,height:844});
assert(await p.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
assert.deepEqual(errors,[]);console.log('Compact theme: switch, persistence, 240px rail/30px rows, Classic isolation and mobile width passed.');
}finally{await browser.close();}})().catch(e=>{console.error(e);process.exitCode=1});
