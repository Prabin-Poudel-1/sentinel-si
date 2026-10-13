const {chromium}=require('playwright');
const fs=require('node:fs');
let stage='start';
(async()=>{
  const config=JSON.parse(fs.readFileSync(0,'utf8'));
  const browser=await chromium.launch({headless:true,...(process.env.BROWSER_CHANNEL?{channel:process.env.BROWSER_CHANNEL}:{})});
  const checks=[];
  try {
    const context=await browser.newContext({viewport:{width:1440,height:1000}});
    const page=await context.newPage();
    const errors=[];page.on('pageerror',e=>errors.push(e.message));
    stage='public pages';
    for(const name of ['index','features','downloads','docs','research']) {
      const response=await page.goto(config.origin+'/'+name+'.html');
      if(response.status()!==200)throw Error('Public page failed');
      if(!response.headers()['content-security-policy'])throw Error('Missing CSP');
      await page.locator('h1').waitFor();
    }
    checks.push('five_public_pages_and_security_headers');
    await page.goto(config.origin+'/');
    await page.screenshot({path:config.reportDir+'/public-homepage.png'});
    stage='alice login';
    await page.goto(config.origin+'/dashboard.html');
    await page.locator('#dev-login summary').click();
    await page.locator('#dev-key').fill(config.key);
    await page.locator('#dev-identity').selectOption('alice');
    await page.locator('#login-form button').click();
    await page.waitForFunction(()=>document.getElementById('metric-total').textContent==='4');
    if(!(await page.locator('#account-label').innerText()).includes('alice'))throw Error('Wrong identity');
    stage='alice device';
    checks.push('alice_real_cloud_summary_four_events');
    await page.locator('[data-view="devices"]').click();
    await page.getByRole('heading',{name:'Synthetic E2E device'}).waitFor();
    checks.push('real_paired_device_display');
    await page.locator('[data-view="overview"]').click();
    await page.screenshot({path:config.reportDir+'/public-dashboard-desktop.png',fullPage:true});
    stage='mobile layout';
    await page.setViewportSize({width:390,height:844});
    if(await page.evaluate(()=>document.documentElement.scrollWidth>innerWidth+1))throw Error('Mobile horizontal overflow');
    await page.screenshot({path:config.reportDir+'/public-dashboard-mobile.png',fullPage:false});
    checks.push('mobile_dashboard_no_horizontal_overflow');
    stage='bob login';
    await page.locator('#logout').click();
    await page.locator('#dev-key').fill(config.key);
    await page.locator('#dev-identity').selectOption('bob');
    await page.locator('#login-form button').click();
    await page.waitForFunction(()=>document.getElementById('metric-total').textContent==='0' && document.getElementById('account-label').textContent.includes('bob'));
    checks.push('bob_sees_zero_alice_events');
    await page.locator('[data-view="devices"]').click();
    if((await page.locator('#device-list').innerText()).includes('Synthetic E2E device'))throw Error('Cross-account device visible');
    checks.push('bob_cannot_view_alice_device');
    // Separate rendering fixture: hostile text from a compromised cloud never becomes HTML.
    stage='hostile rendering';
    await page.route('**/api/devices',r=>r.fulfill({json:{devices:[{id:'synthetic',name:'<img src=x onerror=alert(1)>',created_at:1,revoked_at:1}]}}));
    await page.locator('#refresh').click();
    await page.getByRole('heading',{name:'<img src=x onerror=alert(1)>'}).waitFor();
    if(await page.locator('#device-list img').count())throw Error('Unsafe HTML rendering');
    checks.push('hostile_text_rendered_inert_separate_mock_fixture');
    if(errors.length)throw Error('Browser JavaScript errors');
    fs.writeFileSync(config.reportDir+'/public-browser.json',JSON.stringify({status:'passed',checks,engine:'Chromium/Chrome headless',scope:'Actual local Worker+D1 records except explicitly labeled hostile rendering fixture'},null,2)+'\n');
    console.log(JSON.stringify({browser:'passed',checks:checks.length}));
  } finally {await browser.close();}
})().catch(e=>{console.error('Browser smoke failed at '+stage+'; '+e.name+'; '+e.message.split('\n')[0]);process.exitCode=1;});
