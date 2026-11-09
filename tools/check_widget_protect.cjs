// Run against an isolated widget preview only: this check saves application policy.
// Usage: node tools/check_widget_protect.cjs [preview-directory]
const path=require('path');const root=path.resolve(__dirname,'..');const preview=path.resolve(process.argv[2]||path.join(root,'.runtime/protect-preview'));
const {chromium}=require(path.join(root,'.runtime/dashboard-preview/node_modules/playwright'));const fs=require('fs');
(async()=>{
 let html=fs.readFileSync(path.join(root,'native-edge/dashboard/widget.html'),'utf8');for(const part of ['settings','scanner','journal','protect'])html=html.replace('__'+part.toUpperCase()+'_SCRIPT__',fs.readFileSync(path.join(root,'native-edge/dashboard/widget_'+part+'.js'),'utf8'));new Function(html.match(/<script>([\s\S]*?)<\/script>/)[1]);
 const browser=await chromium.launch({channel:'msedge',headless:true});try{
 const page=await browser.newPage({viewport:{width:1320,height:820}}),errors=[];page.on('pageerror',e=>errors.push(e.message));
 const at=Date.now()/1000;let phase=0,controls=0;await page.route('**/api/control',route=>{controls++;return route.fulfill({status:500,json:{error:'Unexpected connection control during UI check'}})});
 const row={path:'c:\\apps\\browser.exe',name:'Browser',version:'1.2.3',pids:[101,102],active_connections:3,destinations:['example.test:443','second.test:443'],downloaded_bytes:10000,uploaded_bytes:1000,down_Bps:1000,up_Bps:500,history:[{observed_at:at-3,down_Bps:200,up_Bps:100},{observed_at:at-2,down_Bps:800,up_Bps:300},{observed_at:at-1,down_Bps:1000,up_Bps:500}]};
 await page.route('**/api/status',route=>route.fulfill({json:{state:phase===2?'stopped':'running',pid:1,created:100,updated_at:at+phase,peer:['195.154.119.136',4433],app_attribution:{available:true},transport:{paths:[{slot:0,healthy:true}]},protect_activity:{available:phase!==2,observed_at:at+phase,applications:phase===2?[]:[{...row,down_Bps:phase===1?2000:1000}]}}}));
 const url=fs.readFileSync(path.join(preview,'url.txt'),'utf8').trim().replace('/?t=','/widget?t=');await page.goto(url);await page.locator('nav button[data-tab=protect]').click();
 await page.getByRole('cell',{name:'Browser',exact:true}).waitFor();
 await page.evaluate(()=>{window.previousOutbound=protectRows.querySelector('select');window.previousSpark=protectRows.querySelector('canvas')});
 const app=page.locator('#protect tbody tr[data-path]');await app.first().click();phase=1;
 await page.waitForFunction(()=>protectRows.querySelector('td:nth-child(6)').textContent==='2.0 KB/s');
 if(!await page.evaluate(()=>previousOutbound===protectRows.querySelector('select')&&previousSpark===protectRows.querySelector('canvas')&&protectRows.querySelector('tr').classList.contains('selected')))throw Error('Controls/selection were rebuilt');
 const painted=await page.evaluate(()=>[...previousSpark.getContext('2d').getImageData(0,0,previousSpark.width,previousSpark.height).data].some((v,i)=>i%4===3&&v>0));if(!painted)throw Error('Sparkline not painted');
 await page.getByLabel('Outbound for Browser',{exact:true}).selectOption('block');
 await page.waitForFunction(()=>!protectBusy&&protectPolicy.app_rules['c:\\apps\\browser.exe']?.outbound==='block');
 await page.getByLabel('Selected application or default traffic profile',{exact:true}).selectOption('gaming');
 await page.waitForFunction(()=>!protectBusy&&protectPolicy.app_rules['c:\\apps\\browser.exe']?.profile==='gaming');
 await page.getByLabel('Tunnel protection',{exact:true}).uncheck();await page.waitForFunction(()=>!protectBusy&&protectPolicy.protection_enabled===false);
 const config=JSON.parse(fs.readFileSync(path.join(preview,'client.json'),'utf8'));if(config.protection_enabled!==false||config.app_rules['c:\\apps\\browser.exe'].profile!=='gaming')throw Error('Policy not persisted');
 await page.screenshot({path:path.join(preview,'protect.png')});
 await page.getByLabel('Search applications',{exact:true}).fill('does-not-exist');if(await page.locator('#protect tbody tr[data-path]').count())throw Error('Search failed');
 await page.getByLabel('Search applications',{exact:true}).fill('second.test');await page.getByRole('cell',{name:'Browser',exact:true}).waitFor();
 await page.locator('nav button[data-tab=traffic]').click();phase=2;await page.waitForFunction(()=>current.state==='stopped');await page.locator('nav button[data-tab=protect]').click();
 await page.getByLabel('Search applications',{exact:true}).fill('');
 await page.waitForFunction(()=>protectRows.querySelector('tr[data-path] td:nth-child(6)').textContent==='—');
 if(await page.locator('#protect tr[data-path]').count()!==1)throw Error('Configured rule missing after disconnect');
 if(!await page.locator('#protect tr[data-path] td').first().getAttribute('title').then(t=>t.includes('no verified')))throw Error('Disconnected activity retained');
 await page.evaluate(()=>{window.reloadCalls=[];window.gamebondWindow=action=>{reloadCalls.push(action);return Promise.resolve()}});await page.locator('#settings').click();await page.getByRole('button',{name:'Reload interface (keep tunnel)',exact:true}).click();if(!await page.evaluate(()=>reloadCalls.length===1&&reloadCalls[0]==='reload'))throw Error('Native reload dispatch failed');await page.evaluate(()=>delete window.gamebondWindow);await page.locator('#settings').click();await Promise.all([page.waitForNavigation(),page.getByRole('button',{name:'Reload interface (keep tunnel)',exact:true}).click()]);await page.waitForFunction(()=>current.state==='stopped'&&protectPolicy.app_rules['c:\\apps\\browser.exe']?.profile==='gaming');if(controls!==0)throw Error('Reload sent connection control');if(errors.length)throw Error(errors.join('\n'));
 console.log(JSON.stringify({reload_without_control:true,sampling:'mocked status; sampler separately unit-tested',row_reuse:true,selection:true,sparkline:true,outbound_and_profile_saved:true,protection_enabled:false,search:true,disconnect_retains_only_rule:true,page_errors:errors}));
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
