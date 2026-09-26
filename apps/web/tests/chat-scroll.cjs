const fs = require('fs');
const assert = require('assert');
const {chromium} = require('playwright');
(async () => {
  const browser = await chromium.launch({channel:'chrome',headless:true});
  try {
    const page = await browser.newPage({viewport:{width:1280,height:900}});
    const html = fs.readFileSync(process.argv[2],'utf8').replace('<div class="chat-thread ask-thread" data-scroll-latest>', '<div class="chat-thread ask-thread" data-scroll-latest><div style="height:2000px;flex-shrink:0">Earlier conversation</div>');
    let operations = [];
    const errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.addInitScript(() => {
      window.EventSource = class {
        constructor(){this.handlers={};window.stream=this;}
        addEventListener(name, callback){this.handlers[name]=callback;}
        close(){}
        emit(name,value){this.handlers[name]?.({data:JSON.stringify(value)});}
      };
    });
    await page.route('**/*', route => {
      const path = new URL(route.request().url()).pathname;
      if(path.startsWith('/static/')) return route.fulfill({body:fs.readFileSync('apps/web'+path), contentType:path.endsWith('.css')?'text/css':'text/javascript'});
      if(path.startsWith('/api/')) return route.fulfill({json:{status:'running',events:[],operations,approvals:[]}});
      return route.fulfill({contentType:'text/html',body:html});
    });
    await page.goto('http://podpilot.test/ask/conversation');
    await page.waitForFunction(()=>window.stream && document.querySelector('.ask-thread').scrollTop>0);
    const thread = page.locator('.ask-thread');
    await thread.evaluate(e=>e.scrollTop=150);
    await page.evaluate(()=>window.stream.emit('progress',{seq:1,phase:'agent_thinking',message:'New thinking update'}));
    assert.equal(await thread.evaluate(e=>e.scrollTop),150);
    operations = Array.from({length:16},(_,i)=>({tool_call_id:'op-'+i,tool:'execute_shell',title:'Read pods '+i,command:'oc get pods',status:'running',operation_kind:'read'}));
    await page.evaluate(ops=>window.stream.emit('operations',ops),operations);
    const panel = page.locator('.activity-timeline-panel');
    assert(await panel.evaluate(e=>e.scrollHeight>e.clientHeight && e.scrollHeight-e.clientHeight-e.scrollTop<2));
    assert.equal(await thread.evaluate(e=>e.scrollTop),150);
    await panel.evaluate(e=>e.scrollTop=0);
    operations[0].status='completed';
    await page.evaluate(ops=>window.stream.emit('operations',ops),operations);
    assert.equal(await panel.evaluate(e=>e.scrollTop),0);
    operations.push({...operations[0],tool_call_id:'op-new'});
    await page.evaluate(ops=>window.stream.emit('operations',ops),operations);
    assert(await panel.evaluate(e=>e.scrollHeight-e.clientHeight-e.scrollTop<2));
    await thread.evaluate(e=>e.scrollTop=e.scrollHeight);
    await page.evaluate(()=>window.stream.emit('progress',{seq:2,phase:'agent_command',message:'Command update'}));
    assert(await thread.evaluate(e=>e.scrollHeight-e.clientHeight-e.scrollTop<2));
    await thread.evaluate(e=>e.scrollTop=200);
    await Promise.all([page.waitForEvent('load'),page.evaluate(()=>window.stream.emit('complete',{location:'/ask/conversation'}))]);
    await page.waitForFunction(()=>document.querySelector('.ask-thread').scrollTop===200);
    assert.deepEqual(errors,[]);
    console.log('Chat reading position, resume following, completion reload, evidence append and status-only updates passed.');
  } finally {await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
