// Protect presents authenticated routed applications independently of the saved
// rule list. Activity is sampled by Go even while this panel is hidden.
const protectPanel = document.querySelector('#protect .panel');
const protectEditor = element('details'), protectSummary = element('summary', 'Edit configured application rules');
protectEditor.append(protectSummary);
for (const child of Array.from(protectPanel.children)) if (child.tagName !== 'H1' && child.tagName !== 'P') protectEditor.append(child);
protectEditor.append($('policymsg'));
protectPanel.replaceChildren();
const protectToolbar = element('div', null, {class:'protect-toolbar'});
const protectEnable = input('checkbox', '', 'Tunnel protection');
const protectProfile = select(profiles,'automatic','Selected application or default traffic profile');
const protectMode = select(['Click to block','Show configured rules'],'Click to block','Protection mode');
const protectSearch = input('search','','Search applications',{placeholder:'Search'});
function protectSection(title,control) { const section = element('label',title,{class:'protect-section'});section.append(control);protectToolbar.append(section); }
protectSection('Tunnel protection',protectEnable);protectSection('Traffic profile',protectProfile);protectSection('Protection mode',protectMode);protectSection('Search',protectSearch);
protectToolbar.append(action('Add app…',()=>{protectEditor.open=true;addRule();$('rules').lastElementChild.querySelector('input').focus();}));
const protectTable = element('table',null,{'aria-label':'Application tunnel activity'});
protectTable.innerHTML='<thead><tr><th>Apps</th><th>In Connections</th><th>Out Connections</th><th>Version</th><th>Hosts</th><th>↓</th><th>↑</th><th>Traffic</th></tr></thead>';
const protectRows = element('tbody');protectTable.append(protectRows);
const protectFeedback = element('p','Loading application policy…',{class:'help',role:'status'});
protectPanel.append(protectToolbar,protectTable,protectFeedback,protectEditor);
const protectStyle=element('style');protectStyle.textContent='.protect-toolbar{display:flex;align-items:end;gap:22px;flex-wrap:wrap;padding:8px 14px 22px;border-bottom:1px solid #d7d9dd}.protect-section{display:flex;flex-direction:column;gap:10px;color:#737d89}.protect-section input[type=checkbox]{appearance:none;width:64px;height:25px;border:0;border-radius:20px;background:#8fa4c1;cursor:pointer;position:relative}.protect-section input[type=checkbox]:checked{background:#6ad68c}.protect-section input[type=checkbox]:after{content:"OFF";position:absolute;left:1px;top:1px;background:white;color:#8fa4c1;border-radius:20px;width:32px;height:23px;text-align:center;line-height:23px;font-size:9px}.protect-section input[type=checkbox]:checked:after{content:"ON";left:31px;color:#58a76c}#protect .selected{background:#edf4fb}#protect td{height:48px}#protect .app-name{max-width:230px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}#protect canvas{width:150px;height:34px;display:block}#protect td:nth-child(6),#protect td:nth-child(7){white-space:nowrap;text-align:right}#protect details{margin-top:20px}#protect select.allowed{color:#58a76c;background:#e4f2e7}#protect select.blocked{color:#cf6d65;background:#f9e6e4}';document.head.append(protectStyle);
let protectPolicy={protection_enabled:true,default_app_profile:'automatic',app_rules:{}}, protectSelected=null, protectBusy=false;
const protectCache=new Map();
function activityApps() { return current.protect_activity?.available ? current.protect_activity.applications || [] : []; }
function ruleFor(path) {return protectPolicy.app_rules[path]||{outbound:'allow',profile:protectPolicy.default_app_profile};}
function syncProtectToolbar() {
  protectEnable.checked=protectPolicy.protection_enabled;
  protectProfile.value=protectSelected ? ruleFor(protectSelected).profile : protectPolicy.default_app_profile;
  protectProfile.title=protectSelected ? 'Profile for '+protectSelected : 'Default profile for applications without an explicit rule';
  protectEnable.disabled=protectProfile.disabled=protectBusy;
}
function drawAppSpark(canvas,samples) {
  const ratio=devicePixelRatio||1,width=150,height=34;canvas.width=width*ratio;canvas.height=height*ratio;
  const context=canvas.getContext('2d');context.scale(ratio,ratio);context.clearRect(0,0,width,height);
  const ceiling=Math.max(1,...samples.flatMap(p=>[p.down_Bps||0,p.up_Bps||0]));
  for(const [key,color] of [['down_Bps','#ffd642'],['up_Bps','#fa8d73']]) {
    const measured=samples.map((p,i)=>[p[key],i]).filter(([value])=>value!=null);if(measured.length<2)continue;
    context.fillStyle=color;context.beginPath();context.moveTo(2,height-2);
    for(const [value,i]of measured)context.lineTo(2+i*(width-4)/Math.max(1,samples.length-1),height-2-value/ceiling*(height-4));
    context.lineTo(width-2,height-2);context.closePath();context.fill();
  }
}
function protectEntries() {
  const entries=new Map(activityApps().map(a=>[a.path,{...a,verified:true}]));
  for(const path of Object.keys(protectPolicy.app_rules))if(!entries.has(path))entries.set(path,{path,name:path.split('\\').at(-1),verified:false,active_connections:0,destinations:[],history:[]});
  const query=protectSearch.value.trim().toLowerCase();
  return [...entries.values()].filter(a=>(protectMode.value!=='Show configured rules'||Object.hasOwn(protectPolicy.app_rules,a.path))&&(!query||[a.path,a.name,...a.destinations||[]].some(v=>String(v).toLowerCase().includes(query)))).sort((a,b)=>Number(b.active_connections>0)-Number(a.active_connections>0)||Number(b.verified)-Number(a.verified)||a.name.localeCompare(b.name)).slice(0,512);
}
async function changeProtect(edit) {
  if(protectBusy)return;
  protectBusy=true;protectEnable.disabled=protectProfile.disabled=true;protectFeedback.textContent='Saving…';renderProtect();
  try {
    const latest=await api('app-policy');
    const next={protection_enabled:latest.protection_enabled,default_app_profile:latest.default_app_profile,app_rules:{...latest.app_rules}};
    edit(next);await api('app-policy','PUT',next);await loadPolicy();
    protectFeedback.textContent='Saved. New outbound connections read updated rules. Reconnect to re-evaluate existing connections.';
  }catch(e){protectFeedback.textContent=e.message;}
  finally{protectBusy=false;syncProtectToolbar();renderProtect();}
}
function changeAppRule(path,patch){return changeProtect(next=>{next.app_rules[path]={outbound:'allow',profile:next.default_app_profile,...next.app_rules[path],...patch};});}
const protectDetails=modal('protectdetails','Application tunnel details'),protectDetailText=element('pre');
protectDetails.append(protectDetailText,action('Remove explicit rule',async()=>{if(protectSelected)await changeProtect(next=>delete next.app_rules[protectSelected]);protectDetails.close();}));
function showProtectDetails(row) {
  protectSelected=row.path;syncProtectToolbar();
  protectDetailText.textContent=row.path+'\n\n'+(row.verified?'Verified tunnel activity\n'+row.active_connections+' active connections\nPIDs: '+row.pids.join(', ')+'\n'+row.destinations.join('\n'):'Configured rule. No verified tunnel usage in this session.');protectDetails.showModal();
}
function renderProtect() {
  if(active!=='protect')return;
  const entries=protectEntries();
  if(protectSelected&&!entries.some(a=>a.path===protectSelected)){protectSelected=null;syncProtectToolbar();}
  const wanted=new Set(entries.map(a=>a.path));for(const key of protectCache.keys())if(!wanted.has(key))protectCache.delete(key);
  const order=entries.map(a=>a.path).join('\n'),changed=protectRows.dataset.order!==order;
  const nodes=[];
  for(const row of entries) {
    let view=protectCache.get(row.path);
    if(!view) {
      const tr=element('tr',null,{'data-path':row.path,tabindex:0});
      for(let i=0;i<8;i++)tr.append(element('td'));
      const outbound=select(['allow','block'],'allow','Outbound for '+row.name);tr.children[2].append(outbound);
      const canvas=element('canvas',null,{'aria-label':'Traffic history for '+row.name});tr.children[7].append(canvas);
      view={tr,outbound,canvas,row};protectCache.set(row.path,view);
      outbound.onchange=()=>changeAppRule(row.path,{outbound:outbound.value});outbound.onclick=e=>e.stopPropagation();
      tr.onclick=()=>{protectSelected=protectSelected===row.path?null:row.path;syncProtectToolbar();renderProtect();};
      tr.ondblclick=()=>showProtectDetails(view.row);tr.onkeydown=e=>{if(e.key==='Enter')showProtectDetails(view.row);};
    }
    view.row=row;const {tr,outbound,canvas}=view;tr.classList.toggle('selected',row.path===protectSelected);
    tr.children[0].className='app-name';tr.children[0].textContent=row.name;tr.children[0].title=row.path+'\n'+(row.verified?'Verified routed application':'Configured rule; no verified tunnel usage in this session');
    tr.children[1].textContent='Not exposed';tr.children[1].title='The tunnel accepts replies to outbound flows; inbound listening services are not exposed.';
    outbound.value=ruleFor(row.path).outbound;outbound.className=outbound.value==='allow'?'allowed':'blocked';outbound.disabled=protectBusy;
    tr.children[3].textContent=row.version||'—';tr.children[4].textContent=row.destinations[0]?(row.destinations[0]+(row.destinations.length>1?' +'+(row.destinations.length-1)+' more':'')):'—';tr.children[4].title=row.destinations.join('\n');
    tr.children[5].textContent=row.down_Bps==null?'—':bytes(row.down_Bps)+'/s';tr.children[6].textContent=row.up_Bps==null?'—':bytes(row.up_Bps)+'/s';
    drawAppSpark(canvas,row.history||[]);nodes.push(tr);
  }
  if(changed){protectRows.replaceChildren(...nodes);protectRows.dataset.order=order;}
  if(!entries.length&&!protectRows.children.length){const tr=element('tr'),td=element('td',protectSearch.value?'No matching applications.':'No verified application activity in this session.');td.colSpan=8;tr.append(td);protectRows.append(tr);}
}
function protectRuntimeFeedback() {
  if(protectBusy)return;
  if(current.state!=='running')protectFeedback.textContent='Rules apply when the tunnel starts.';
  else if(!current.app_attribution?.available)protectFeedback.textContent='Application attribution is unavailable in this session. Restart the client to use authenticated per-app protection.';
  else if(current.application_policy?.policy_digest===protectPolicy.policy_digest)protectFeedback.textContent='Current rules apply to new outbound tunnel connections. Existing connections retain their original policy; inbound services are not exposed.';
  else protectFeedback.textContent='Saved rules are read for the next new outbound connection. Reconnect to re-evaluate existing connections.';
}
loadPolicy=async function(){const d=await api('app-policy');protectPolicy=d;$('protection').checked=d.protection_enabled;$('defaultprofile').value=d.default_app_profile;$('rules').replaceChildren();for(const[path,rule]of Object.entries(d.app_rules))addRule(path,rule);syncProtectToolbar();renderProtect();};
protectEnable.onchange=()=>{const enabled=protectEnable.checked;return changeProtect(next=>next.protection_enabled=enabled);};
protectProfile.onchange=()=>{const profile=protectProfile.value;return protectSelected?changeAppRule(protectSelected,{profile}):changeProtect(next=>next.default_app_profile=profile);};
protectMode.onchange=protectSearch.oninput=()=>renderProtect();
const updateBeforeProtect=updateState;
updateState=function(doc){updateBeforeProtect(doc);protectRuntimeFeedback();renderProtect();};
const selectBeforeProtect=selectTab;
selectTab=function(id){selectBeforeProtect(id);if(id==='protect'){protectRuntimeFeedback();renderProtect();}};
loadPolicy().catch(e=>protectFeedback.textContent=e.message);
settingsMenu.append(action('Reload interface (keep tunnel)',()=>{settingsDialog.close();if(typeof window.gamebondWindow==='function')return native('reload');location.reload();}));
