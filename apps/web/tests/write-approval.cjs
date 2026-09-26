const fs = require("fs");
const assert = require("assert");
const {chromium} = require("playwright");
(async () => {
  const browser = await chromium.launch({channel:"chrome", headless:true});
  try {
    const page = await browser.newPage({viewport:{width:1280,height:900}});
    const html = fs.readFileSync(process.argv[2], "utf8");
    const errors = [], decisions = [];
    let pending = true, failDecision = false;
    const proposal = {id:"approval-fixture", cluster:"SNO lab", api_url:"https://api.sno.example:6443",
      requester:"requester", cluster_identity:"cluster-requester", method:"POST", path:"/api/v1/namespaces",
      command:"oc create namespace mike", query:"fieldManager=kubectl-create", content_type:"application/json",
      body:JSON.stringify({apiVersion:"v1",kind:"Namespace",metadata:{name:"mike"}}, null, 2),
      request_hash:"1234567890abcdef", expires_at:new Date(Date.now()+120000).toISOString(),
      notice:"Approve only this API request. Other writes need separate approval. Kubernetes RBAC and admission still apply.",
      risk:"This request creates an empty namespace. Review the exact request."};
    page.on("pageerror", error => errors.push(error.message));
    await page.addInitScript(() => {
      window.EventSource = class {addEventListener(){}close(){}};
    });
    await page.route("**/*", async route => {
      const path = new URL(route.request().url()).pathname;
      if(path.startsWith("/static/")) return route.fulfill({body:fs.readFileSync("apps/web"+path),contentType:path.endsWith(".css")?"text/css":"text/javascript"});
      if(path.startsWith("/api/v1/write-approvals/")) {
        assert(route.request().headers()["x-podpilot-csrf"]);
        decisions.push(path);
        if(failDecision) return route.fulfill({status:409,json:{detail:"This request has expired."}});
        pending=false;
        return route.fulfill({json:{status:path.endsWith("/approve")?"approved":"rejected"}});
      }
      if(path === "/api/v1/adhoc-runs/run") return route.fulfill({json:{id:"run",status:"running",events:[],operations:[],approvals:pending?[proposal]:[]}});
      return route.fulfill({contentType:"text/html",body:html});
    });
    await page.goto("http://podpilot.test/ask/conversation");
    const dialog = page.locator("dialog.write-approval-dialog[open]");
    await dialog.waitFor();
    assert(await page.getByRole("button",{name:"Reject change"}).evaluate(el=>el===document.activeElement));
    assert(await dialog.innerText().then(text=>text.includes('"name": "mike"')));
    assert.equal(decisions.length,0);
    if(process.argv[3]) await page.screenshot({path:process.argv[3]});
    await page.getByRole("button",{name:"Approve and execute once"}).click();
    await dialog.waitFor({state:"hidden"});
    assert.equal(decisions.length,1); assert(decisions[0].endsWith("/approve"));
    pending=true;
    await page.reload();
    await dialog.waitFor();
    await page.setViewportSize({width:390,height:844});
    assert(await dialog.evaluate(el=>el.getBoundingClientRect().width<=innerWidth));
    failDecision=true;
    await page.getByRole("button",{name:"Approve and execute once"}).click();
    await page.getByRole("alert").filter({hasText:"This request has expired."}).waitFor();
    assert(await page.getByRole("button",{name:"Reject change"}).isEnabled());
    failDecision=false;
    await page.keyboard.press("Escape");
    await dialog.waitFor({state:"hidden"});
    assert(decisions.at(-1).endsWith("/reject"));
    assert.deepEqual(errors,[]);
    console.log("Approval modal: exact body, initial rejection focus, one-click approval, refresh, mobile width, error recovery and Escape rejection passed.");
  } finally { await browser.close(); }
})().catch(error=>{console.error(error);process.exitCode=1});
