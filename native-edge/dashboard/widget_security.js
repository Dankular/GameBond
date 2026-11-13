// Network Scanner > Security: stateful firewall, segmentation, country filter, DNS ad and content blocking, and
// intrusion detection/prevention. All of it runs on the server; this page edits a draft of the server's security
// settings and applies them in one step (the server applies all of it or none of it). Everything the server or a
// blocklist sends is shown with textContent only.
const secStyle = document.createElement('style');
secStyle.textContent = [
  '.sec-nav{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 12px}.sec-nav .seg.active{background:#0f7ae5;color:#fff}',
  '.sec-bar{position:sticky;top:0;z-index:2;display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:8px 12px;margin:0 0 12px;border:1px solid #f0c36a;background:#fff8e6;border-radius:10px}.sec-bar[hidden]{display:none}.sec-bar strong{flex:1;min-width:180px}',
  '.sec-tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:0 0 14px}.sec-tile{border:1px solid #e1e5eb;border-radius:10px;padding:12px 14px}.sec-tile b{display:block;font-size:22px;margin-top:6px;font-variant-numeric:tabular-nums}.sec-tile small{color:#7b8490}',
  '.sec-card{border:1px solid #e1e5eb;border-radius:10px;padding:12px 14px;margin:0 0 12px}.sec-card h3{margin:0 0 4px;font-size:14px;display:flex;gap:8px;align-items:center}.sec-card h3 .sec-badge{margin-left:auto}',
  '.sec-help{color:#6b7480;font-size:12px;margin:3px 0 8px}.sec-note{color:#505762;font-size:12px;margin:4px 0}.sec-warn{color:#a8651b}.sec-bad{color:#c0392b}.sec-ok{color:#00a66c}',
  '.sec-badge{font-size:11px;border-radius:10px;padding:2px 9px;color:#fff;background:#8a93a0}.sec-badge.on{background:#2db36b}.sec-badge.warn{background:#f0a52e}.sec-badge.bad{background:#d64541}',
  '.sec-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:6px 0}.sec-row label{display:flex;gap:6px;align-items:center}.sec-row input[type=text],.sec-row input[type=number],.sec-row select,.sec-cell input[type=text],.sec-cell input[type=number],.sec-cell select{padding:5px 7px;border:1px solid #cfd5dd;border-radius:6px;min-width:0}',
  '.sec-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:6px 14px}.sec-grid label{display:flex;gap:8px;align-items:flex-start;padding:5px 6px;border-radius:6px}.sec-grid label:hover{background:#f4f7fb}.sec-grid small{display:block;color:#7b8490}',
  '.sec-table{width:100%;border-collapse:collapse;font-size:12px}.sec-table th{text-align:left;font-weight:400;color:#7b8490;padding:5px 6px;border-bottom:1px solid #e6e9ed}.sec-table td{padding:4px 6px;border-bottom:1px solid #f0f2f5;vertical-align:middle}.sec-table input[type=text]{width:100%}.sec-table td.num{text-align:right;font-variant-numeric:tabular-nums}.sec-table .tight{width:1%;white-space:nowrap}',
  '.sec-modes{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:10px}.sec-mode{border:2px solid #e1e5eb;border-radius:10px;padding:10px 12px;cursor:pointer;text-align:left;background:transparent;border-radius:10px}.sec-mode.active{border-color:#0f7ae5;background:#eef5ff}.sec-mode b{display:block;margin-bottom:3px}.sec-mode span{color:#6b7480;font-size:12px;display:block}',
  '.sec-chips{display:flex;gap:6px;flex-wrap:wrap;margin:6px 0}.sec-chip{display:inline-flex;gap:6px;align-items:center;border:1px solid #cfd5dd;border-radius:14px;padding:2px 4px 2px 9px;font-size:12px}.sec-chip button{border:0;padding:0 6px;background:transparent;border-radius:10px}',
  '.sec-list{max-height:260px;overflow:auto;border:1px solid #e6e9ed;border-radius:8px;padding:4px 6px}',
  '.sec-sev-high{color:#c0392b;font-weight:600}.sec-sev-medium{color:#a8651b;font-weight:600}.sec-sev-low{color:#5f6b78}',
  '.sec-pre{font-family:Consolas,monospace;font-size:12px}textarea.sec-text{min-height:84px;width:100%}',
  'html[data-theme=dark] .sec-bar{background:#33290f;border-color:#7a6420}html[data-theme=dark] .sec-tile,html[data-theme=dark] .sec-card,html[data-theme=dark] .sec-mode,html[data-theme=dark] .sec-list{border-color:#3a404b}html[data-theme=dark] .sec-mode.active{background:#1a2535;border-color:#4d8ff0}html[data-theme=dark] .sec-help,html[data-theme=dark] .sec-note,html[data-theme=dark] .sec-mode span,html[data-theme=dark] .sec-grid small,html[data-theme=dark] .sec-tile small{color:#aab2bd}html[data-theme=dark] .sec-row input,html[data-theme=dark] .sec-row select,html[data-theme=dark] .sec-cell input,html[data-theme=dark] .sec-cell select{background:#1b1e24;border-color:#343a44;color:#d7dae0}html[data-theme=dark] .sec-grid label:hover{background:#232830}html[data-theme=dark] .sec-table td{border-color:#22262d}html[data-theme=dark] .sec-table th{border-color:#2a2e36}html[data-theme=dark] .sec-chip{border-color:#3a404b}'
].join('');
document.head.append(secStyle);

const secPane = element('div', null, { class: 'sec-pane' }), secSub = element('button', 'Security', { class: 'seg', role: 'tab' });
subTabs.append(secSub);
scanPanel.append(secPane);
secPane.hidden = true;

const SEC_SECTIONS = [['overview', 'Overview'], ['firewall', 'Firewall'], ['countries', 'Countries'], ['dns', 'Ad & content blocking'], ['ids', 'Intrusion detection'], ['pc', 'This PC']];
let secCat = null, secOv = null, secDraft = null, secSection = 'overview', secBusy = false, secMsg = '', secMsgBad = false, secTimer = null, secError = '', secLive = [], secBarEl = null, secBody = null, secLoading = false;

const secClone = v => JSON.parse(JSON.stringify(v));
// The server sends null for an empty list; the form works with real lists and the server accepts them.
function secNorm(s) {
  const o = secClone(s || {});
  o.firewall = o.firewall || {}; o.dns_filter = o.dns_filter || {}; o.ids = o.ids || {};
  const f = o.firewall; f.zones = f.zones || []; f.rules = f.rules || []; f.segmentation = f.segmentation || {}; f.segmentation.allow = f.segmentation.allow || []; f.countries = f.countries || {}; f.countries.codes = f.countries.codes || [];
  const d = o.dns_filter; for (const k of ['upstreams', 'categories', 'enable_lists', 'disable_lists', 'custom_lists', 'block', 'allow', 'exempt']) d[k] = d[k] || [];
  const i = o.ids; i.never_block = i.never_block || []; i.detectors = i.detectors || {};
  return o;
}
const secDirty = () => !!(secDraft && secOv) && JSON.stringify(secNorm(secDraft)) !== JSON.stringify(secNorm(secOv.settings));
const secNum = n => Number(n || 0).toLocaleString();
const secEl = (tag, text, cls, attrs) => { const e = element(tag, text, attrs || {}); if (cls) e.className = cls; return e; };
const secAgo = unix => unix ? ago(unix) : '—';
function secLines(text) { return String(text).split(/[\n,]+/).map(s => s.trim()).filter(Boolean); }
function secCountryName(code) { try { return new Intl.DisplayNames(['en'], { type: 'region' }).of(code) || code; } catch { return code; } }
function secFlag(code) { return String.fromCodePoint(...[...code].map(c => 127397 + c.charCodeAt(0))); }

function secChange(fn) { fn(secDraft); secRefreshBar(); }
function secCheck(label, checked, set, help) {
  const box = element('input', null, { type: 'checkbox' }); box.checked = !!checked; box.onchange = () => secChange(() => set(box.checked));
  const l = secEl('label'); l.append(box, element('span', label));
  if (help) l.title = help;
  return l;
}
function secSelect(options, value, set, aria) {
  const s = element('select', null, { 'aria-label': aria });
  for (const [v, text] of options) s.append(element('option', text, { value: v }));
  s.value = value; s.onchange = () => secChange(() => set(s.value));
  return s;
}
function secText(value, set, aria, attrs) {
  const i = element('input', null, { type: 'text', 'aria-label': aria, ...(attrs || {}) }); i.value = value ?? ''; i.oninput = () => secChange(() => set(i.value));
  return i;
}
function secNumber(value, set, aria, min, max) {
  const i = element('input', null, { type: 'number', 'aria-label': aria, min, max, step: 1 }); i.value = value; i.oninput = () => secChange(() => set(i.value === '' ? 0 : Number(i.value)));
  return i;
}
function secTextarea(lines, set, aria, placeholder) {
  const t = secEl('textarea', null, 'sec-text', { 'aria-label': aria, spellcheck: 'false', placeholder: placeholder || '' }); t.value = (lines || []).join('\n'); t.oninput = () => secChange(() => set(secLines(t.value)));
  return t;
}
function secCard(title, help, badge) {
  const c = secEl('div', null, 'sec-card'), h = secEl('h3', title);
  if (badge) h.append(badge);
  c.append(h); if (help) c.append(secEl('p', help, 'sec-help'));
  return c;
}
const secBadgeEl = (text, kind) => secEl('span', text, 'sec-badge' + (kind ? ' ' + kind : ''));
function secTile(label, value, sub) { const t = secEl('div', null, 'sec-tile'); t.append(element('span', label), secEl('b', value)); if (sub) t.append(secEl('small', sub)); return t; }
function secTable(heads) { const t = secEl('table', null, 'sec-table'), tr = element('tr'); for (const h of heads) tr.append(element('th', h)); const th = element('thead'); th.append(tr); const tb = element('tbody'); t.append(th, tb); return [t, tb]; }
function secRow(tb, values, nums) { const tr = element('tr'); values.forEach((v, i) => { const td = element('td'); if (v instanceof Node) td.append(v); else td.textContent = v ?? '—'; if (nums && nums.includes(i)) td.className = 'num'; tr.append(td); }); tb.append(tr); return tr; }

// ---- data and actions ----
async function secCall(path, method, body) {
  return api(path, method, body);
}
async function secLoad(first) {
  if (secLoading) return;
  secLoading = true;
  try {
    if (!secCat) secCat = await secCall('security/catalog');
    const ov = await secCall('security'); secError = '';
    // The form's handlers hold the draft's inner objects, so the draft is replaced only when it must be: nothing
    // has been edited and the server's settings changed (or the tab was just opened), and then the form is redrawn.
    const wasDirty = secDirty(), before = secOv ? JSON.stringify(secNorm(secOv.settings)) : null;
    secOv = ov;
    let redraw = first || !secBody || !secBody.firstChild;
    if (!secDraft || (!wasDirty && (first || before !== JSON.stringify(secNorm(ov.settings))))) { secDraft = secNorm(ov.settings); redraw = true; }
    if (redraw) secRender(); else { secRefreshBar(); for (const f of secLive) f(); }
  } catch (e) { secError = e.message; secOv = null; if (secSection !== 'pc' || !secBody) secRender(); }
  finally { secLoading = false; }
}
async function secApply() {
  secBusy = true; secMsg = 'Applying…'; secMsgBad = false; secRefreshBar();
  try {
    await secCall('security', 'POST', { settings: secNorm(secDraft) });
    secMsg = 'Applied and saved on the server.'; secMsgBad = false;
    secDraft = null; await secLoad(true);
  } catch (e) { secMsg = e.message; secMsgBad = true; }
  finally { secBusy = false; secRefreshBar(); }
}
async function secDo(name, args) {
  const out = await secCall('security/action', 'POST', { action: name, args: args || {} });
  return out.result;
}
function secSay(text, bad) { secMsg = text; secMsgBad = !!bad; secRefreshBar(true); }
async function secRun(name, args, okText) {
  try { const r = await secDo(name, args); if (okText) secSay(okText); await secLoad(); return r; }
  catch (e) { secSay(e.message, true); return null; }
}

function secRefreshBar(force) {
  if (!secBarEl) return;
  const dirty = secDirty();
  secBarEl.hidden = !dirty && !secMsg && !force;
  secBarEl.replaceChildren();
  if (dirty) {
    const text = secEl('strong', 'You have changes that are not applied yet.');
    const apply = action('Apply to the server', secApply); apply.disabled = secBusy;
    const discard = action('Discard', async () => { secDraft = secNorm(secOv.settings); secMsg = ''; secRender(); }); discard.disabled = secBusy;
    secBarEl.append(text, apply, discard);
  }
  if (secMsg) secBarEl.append(secEl('span', secMsg, secMsgBad ? 'sec-bad' : 'sec-ok', { role: 'status' }));
}

// ---- layout ----
function secRender() {
  secPane.replaceChildren(); secLive = [];
  const nav = secEl('div', null, 'sec-nav', { role: 'tablist' });
  for (const [id, label] of SEC_SECTIONS) {
    const b = secEl('button', label, 'seg' + (id === secSection ? ' active' : ''), { role: 'tab', 'aria-selected': id === secSection });
    b.onclick = () => { secSection = id; secRender(); };
    nav.append(b);
  }
  // "This PC" reads local files and works without the server; every other section needs the server's portal.
  if ((secError || !secOv || !secCat) && secSection !== 'pc') {
    const card = secCard('Security is managed on your server', 'Firewall, country filter, ad and content blocking, and intrusion detection run on the exit server, so they protect every device behind it.');
    card.append(secEl('p', secError || 'Loading…', secError ? 'sec-bad' : 'sec-note'));
    if (/admin portal|set up|password/i.test(secError)) card.append(secEl('p', 'Open Settings, Server admin, and enter the server portal address and password. This page then works through it.', 'sec-note'));
    secPane.append(nav, card); secBody = null; secBarEl = null;
    return;
  }
  secBarEl = secEl('div', null, 'sec-bar', { role: 'region', 'aria-label': 'Unapplied changes' });
  secBody = secEl('div');
  secPane.append(nav, secBarEl, secBody);
  ({ overview: secOverview, firewall: secFirewall, countries: secCountries, dns: secDNS, ids: secIDS, pc: secPC })[secSection](secBody);
  secRefreshBar();
  for (const f of secLive) f();
}

// ---- overview ----
function secOverview(body) {
  const tiles = secEl('div', null, 'sec-tiles'), cards = secEl('div'); body.append(tiles, cards);
  const warnings = secEl('div'); body.append(warnings);
  const quick = secCard('Protection', 'The main switches. Details are on the other tabs. Changes here are applied together with everything else.');
  const row1 = secEl('div', null, 'sec-row'), row2 = secEl('div', null, 'sec-row'), row3 = secEl('div', null, 'sec-row');
  row1.append(secCheck('Firewall', secDraft.firewall.enabled, v => { secDraft.firewall.enabled = v; }, 'Stateful firewall for the tunnel network'));
  row2.append(secCheck('Ad, tracker and content blocking', secDraft.dns_filter.enabled, v => { secDraft.dns_filter.enabled = v; }, 'DNS filtering'));
  row3.append(element('span', 'Intrusion detection'), secSelect([['off', 'Off'], ['detect', 'Detect only'], ['prevent', 'Detect and block']], secDraft.ids.mode, v => { secDraft.ids.mode = v; }, 'Intrusion detection mode'));
  quick.append(row1, row2, row3);
  body.append(quick);
  const events = secCard('Latest security events', 'Newest first. The full list, with what was done about each, is under Intrusion detection.');
  const [t, tb] = secTable(['When', 'Event', 'Device or source', 'Result']);
  events.append(t); body.append(events);
  secLive.push(() => {
    const dns = secOv.dns.server, fw = secOv.firewall, ids = secOv.ids;
    const drops = ['invalid', 'ips', 'geo', 'dot', 'isolate', 'default', 'default_in', 'protect'].reduce((n, k) => n + (fw.counters?.[k]?.packets || 0), 0);
    tiles.replaceChildren(
      secTile('DNS queries', secNum(dns.queries), secNum(dns.blocked) + ' blocked' + (dns.queries ? ' (' + Math.round(100 * dns.blocked / dns.queries) + '%)' : '')),
      secTile('Packets dropped by the firewall', secNum(drops), fw.enabled ? (fw.applied ? 'firewall is enforcing' : 'not applied') : 'firewall is off'),
      secTile('Addresses blocked now', secNum(fw.blocked.length), 'by intrusion prevention'),
      secTile('Packets inspected', secNum(ids.packets), secNum(ids.tracked_devices) + ' devices tracked'));
    warnings.replaceChildren();
    for (const w of fw.warnings || []) warnings.append(secEl('p', w, 'sec-warn'));
    for (const l of secOv.dns.filter.lists || []) if (l.active && l.error) { warnings.append(secEl('p', l.name + ': ' + l.error, 'sec-warn')); break; }
    tb.replaceChildren();
    const ev = (ids.events || []).slice(0, 6);
    if (!ev.length) secRow(tb, ['—', 'Nothing unusual has been seen.', '', '']);
    for (const e of ev) secRow(tb, [secAgo(e.time), e.title + (e.count > 1 ? ' ×' + e.count : ''), e.offender, secActionText(e)]);
  });
}
function secActionText(e) {
  return ({ blocked: 'Blocked for ' + Math.round((e.blocked_for_s || 0) / 60) + ' min', would_block: 'Would have blocked', alert: 'Alert only', block_failed: 'Block failed' + (e.error ? ': ' + e.error : '') })[e.action] || e.action;
}

// ---- firewall ----
let secRuleSeq = 0;
function secNewRuleID() { const ids = new Set(secDraft.firewall.rules.map(r => r.id)); let id; do { id = 'r' + (++secRuleSeq); } while (ids.has(id)); return id; }
function secFirewall(body) {
  const f = secDraft.firewall;
  const status = secEl('p', '', 'sec-note'); body.append(status);
  const base = secCard('Stateful firewall', 'Applies to traffic between your devices and the internet. Replies to connections a device starts are always allowed, so the defaults below are safe to tighten. Rules decide only new connections.');
  const r1 = secEl('div', null, 'sec-row'); r1.append(secCheck('Turn the firewall on', f.enabled, v => { f.enabled = v; }));
  const r2 = secEl('div', null, 'sec-row'); r2.append(element('span', 'Devices to internet by default'), secSelect([['allow', 'Allow'], ['deny', 'Block']], f.default_outbound || 'allow', v => { f.default_outbound = v; }, 'Default outbound'), element('span', 'Internet to devices by default'), secSelect([['allow', 'Allow'], ['deny', 'Block']], f.default_inbound || 'allow', v => { f.default_inbound = v; }, 'Default inbound'));
  const r3 = secEl('div', null, 'sec-row'); r3.append(secCheck('Block DNS over TLS (port 853)', f.block_dot, v => { f.block_dot = v; }, 'Stops devices from bypassing the DNS filter with DoT'), secCheck('Send every device\'s DNS to the filter', f.force_dns, v => { f.force_dns = v; }, 'Redirects port 53 to the filter. Needs the firewall on.'));
  base.append(r1, r2, r3, secEl('p', 'DNS over HTTPS runs on port 443 and cannot be told apart from web traffic by port, so it cannot be blocked here. Devices that use it skip the DNS filter.', 'sec-note'));
  body.append(base);

  // zones and segmentation
  const seg = secCard('Segmentation', 'Group devices into zones, then decide which zones may start connections to which. 10.77.0.2 is the client PC itself; devices are 10.77.0.3 and up.');
  const iso = secEl('div', null, 'sec-row'); iso.append(secCheck('Isolate devices from each other', f.segmentation.isolate_devices, v => { f.segmentation.isolate_devices = v; }, 'Devices cannot start connections to other devices unless allowed below'));
  seg.append(iso);
  const [zt, zb] = secTable(['Zone', 'Members (addresses, comma separated)', '']);
  f.zones.forEach((z, i) => secRow(zb, [secText(z.name, v => { z.name = v; }, 'Zone name', { placeholder: 'for example consoles' }), secText((z.members || []).join(', '), v => { z.members = secLines(v); }, 'Zone members', { placeholder: '10.77.0.3, 10.77.0.4' }), action('Remove', async () => { f.zones.splice(i, 1); secRefreshBar(); secRender(); })]));
  seg.append(zt, (() => { const r = secEl('div', null, 'sec-row'); r.append(action('Add zone', async () => { f.zones.push({ name: '', members: [] }); secRender(); })); return r; })());
  const [pt, pb] = secTable(['Allow connections from zone', 'to zone', '']);
  const zoneOptions = f.zones.filter(z => z.name).map(z => [z.name, z.name]);
  f.segmentation.allow.forEach((p, i) => secRow(pb, [secSelect(zoneOptions.length ? zoneOptions : [['', '(add a zone first)']], p.from, v => { p.from = v; }, 'From zone'), secSelect(zoneOptions.length ? zoneOptions : [['', '(add a zone first)']], p.to, v => { p.to = v; }, 'To zone'), action('Remove', async () => { f.segmentation.allow.splice(i, 1); secRefreshBar(); secRender(); })]));
  seg.append(pt, (() => { const r = secEl('div', null, 'sec-row'); const add = action('Allow zone to zone', async () => { if (zoneOptions.length) { f.segmentation.allow.push({ from: zoneOptions[0][0], to: zoneOptions[0][0] }); secRender(); } }); add.disabled = !zoneOptions.length; r.append(add); return r; })());
  body.append(seg);

  // rules
  const rules = secCard('Rules', 'Checked top to bottom for each new connection; the first match wins. Source and destination can be any, an address, a network such as 10.0.0.0/8, or zone:name. Ports are like 443 or 8000-8100.');
  const [rt, rb] = secTable(['On', 'Action', 'Direction', 'Source', 'Destination', 'Protocol', 'Ports', 'Note', 'Hits', '']);
  const hits = [];
  f.rules.forEach((r, i) => {
    const on = secEl('input', null, null, { type: 'checkbox', 'aria-label': 'Rule enabled' }); on.checked = r.enabled !== false; on.onchange = () => secChange(() => { r.enabled = on.checked; });
    const hit = element('span'); hits.push([r.id, hit]);
    const tools = secEl('span', null, 'sec-cell');
    const up = action('↑', async () => { if (i > 0) { [f.rules[i - 1], f.rules[i]] = [f.rules[i], f.rules[i - 1]]; secRefreshBar(); secRender(); } }), down = action('↓', async () => { if (i < f.rules.length - 1) { [f.rules[i + 1], f.rules[i]] = [f.rules[i], f.rules[i + 1]]; secRefreshBar(); secRender(); } });
    up.setAttribute('aria-label', 'Move rule up'); down.setAttribute('aria-label', 'Move rule down'); up.disabled = i === 0; down.disabled = i === f.rules.length - 1;
    const del = action('Delete', async () => { f.rules.splice(i, 1); secRefreshBar(); secRender(); });
    tools.append(up, down, del);
    const cell = n => { const w = secEl('span', null, 'sec-cell'); w.append(n); return w; };
    secRow(rb, [on,
      cell(secSelect([['allow', 'Allow'], ['deny', 'Block']], r.action || 'allow', v => { r.action = v; }, 'Action')),
      cell(secSelect([['outbound', 'Device to internet'], ['inbound', 'Internet to device'], ['between', 'Device to device']], r.direction || 'outbound', v => { r.direction = v; }, 'Direction')),
      cell(secText(r.source || 'any', v => { r.source = v; }, 'Source', { size: 14 })), cell(secText(r.dest || 'any', v => { r.dest = v; }, 'Destination', { size: 14 })),
      cell(secSelect([['any', 'Any'], ['tcp', 'TCP'], ['udp', 'UDP'], ['icmp', 'ICMP']], r.proto || 'any', v => { r.proto = v; }, 'Protocol')),
      cell(secText((r.ports || []).join(', '), v => { r.ports = secLines(v); }, 'Ports', { size: 12, placeholder: 'any' })),
      cell(secText(r.comment || '', v => { r.comment = v; }, 'Note', { size: 16 })), hit, tools], [8]);
  });
  const addRule = action('Add rule', async () => { f.rules.push({ id: secNewRuleID(), enabled: true, action: 'deny', direction: 'outbound', source: 'any', dest: 'any', proto: 'tcp', ports: [], comment: '' }); secRender(); });
  const scroller = secEl('div'); scroller.style.overflowX = 'auto'; scroller.append(rt);
  rules.append(scroller, (() => { const r = secEl('div', null, 'sec-row'); r.append(addRule, secEl('span', 'Up to ' + secCat.limits.rules + ' rules.', 'sec-note')); return r; })());
  const flush = action('End open connections', async () => { if (confirm('This ends every connection that is open right now, so downloads and calls restart. Continue?')) await secRun('flush_connections', {}, 'Open connections ended.'); });
  rules.append(secEl('p', 'A changed rule does not end a connection that is already open. Use this when you want a new rule to apply to those as well.', 'sec-note'), flush);
  body.append(rules);
  secLive.push(() => {
    const fw = secOv.firewall;
    status.textContent = fw.enabled ? (fw.applied ? 'The firewall is on and enforcing.' : 'The firewall is on but its rules are not applied.') : 'The firewall is off. Nothing on this page is enforced until you turn it on and apply.';
    status.className = 'sec-note ' + (fw.enabled && fw.applied ? 'sec-ok' : 'sec-warn');
    for (const [id, el] of hits) { const c = fw.counters?.[id]; el.textContent = c ? secNum(c.packets) : '0'; }
  });
}

// ---- countries ----
function secCountries(body) {
  const c = secDraft.firewall.countries;
  const card = secCard('Country filter', 'Block or allow traffic by the country of the other end. Country lists come from ipdeny.com and are refreshed daily. Accuracy is that of the lists: VPN, proxy and CDN addresses may not be where they appear to be.');
  const r1 = secEl('div', null, 'sec-row');
  r1.append(secSelect([['off', 'Off'], ['block', 'Block the selected countries'], ['allow', 'Allow only the selected countries']], c.mode || 'off', v => { c.mode = v; secRefreshBar(); }, 'Country filter mode'),
    secSelect([['outbound', 'Traffic to those countries'], ['inbound', 'Traffic from those countries'], ['both', 'Both directions']], c.direction || 'outbound', v => { c.direction = v; }, 'Direction'));
  card.append(r1);
  if (!secDraft.firewall.enabled) card.append(secEl('p', 'The firewall is off, so this filter is not enforced. Turn it on under Firewall.', 'sec-note sec-warn'));
  card.append(secEl('p', 'Allow-only is strict: every country you do not select is blocked, including the DNS and update servers your devices use if they are elsewhere. Add your own country first.', 'sec-note'));
  const chips = secEl('div', null, 'sec-chips'), search = element('input', null, { type: 'text', placeholder: 'Search countries', 'aria-label': 'Search countries' }), list = secEl('div', null, 'sec-list sec-grid');
  const drawChips = () => {
    chips.replaceChildren();
    for (const code of c.codes) {
      const chip = secEl('span', null, 'sec-chip'), x = element('button', '×', { type: 'button', 'aria-label': 'Remove ' + secCountryName(code) });
      x.onclick = () => { c.codes = c.codes.filter(k => k !== code); secRefreshBar(); drawChips(); drawList(); };
      chip.append(element('span', secFlag(code) + ' ' + secCountryName(code)), x); chips.append(chip);
    }
    if (!c.codes.length) chips.append(secEl('span', 'No countries selected.', 'sec-note'));
  };
  const drawList = () => {
    list.replaceChildren();
    const q = search.value.trim().toLowerCase();
    for (const code of secCat.countries) {
      const name = secCountryName(code);
      if (q && !(name.toLowerCase().includes(q) || code.toLowerCase() === q)) continue;
      const box = element('input', null, { type: 'checkbox' }); box.checked = c.codes.includes(code);
      box.onchange = () => { c.codes = box.checked ? [...c.codes, code].sort() : c.codes.filter(k => k !== code); secRefreshBar(); drawChips(); };
      const l = secEl('label'); l.append(box, element('span', secFlag(code) + ' ' + name + ' (' + code + ')')); list.append(l);
    }
  };
  search.oninput = drawList;
  card.append(chips, search, list); drawChips(); drawList();
  body.append(card);
  const st = secCard('Country lists');
  const [t, tb] = secTable(['Country', 'Ranges loaded', 'Updated']); st.append(t);
  st.append((() => { const r = secEl('div', null, 'sec-row'); r.append(action('Refresh country lists now', async () => { await secRun('refresh_countries', {}, 'Country lists refreshed and applied.'); })); return r; })());
  const test = secEl('div', null, 'sec-row'), ip = element('input', null, { type: 'text', placeholder: 'Test an address, for example 203.0.113.9', 'aria-label': 'Address to test', size: 30 }), out = secEl('span', '', 'sec-note');
  test.append(ip, action('Which selected country is it in?', async () => {
    try { const r = await secDo('test_address', { ip: ip.value.trim() }); out.textContent = r.countries.length ? ip.value.trim() + ' is in ' + r.countries.map(secCountryName).join(', ') + '.' : ip.value.trim() + ' is not in any selected country.'; } catch (e) { out.textContent = e.message; }
  }), out);
  st.append(test); body.append(st);
  secLive.push(() => {
    tb.replaceChildren();
    const shown = secOv.countries || [];
    if (!shown.length) secRow(tb, ['None selected yet', '', '']);
    for (const s of shown) secRow(tb, [secFlag(s.code) + ' ' + secCountryName(s.code), s.error ? 'not loaded: ' + s.error : secNum(s.ranges), s.fetched_at ? secAgo(s.fetched_at) : '—']);
  });
}

// ---- DNS: ad, tracker and content blocking ----
function secListOn(d, l) {
  const cat = d.categories.includes(l.category), base = l.default && cat;
  if (d.disable_lists.includes(l.id)) return false;
  return base || d.enable_lists.includes(l.id);
}
function secSetList(d, l, on) {
  const base = l.default && d.categories.includes(l.category);
  d.enable_lists = d.enable_lists.filter(x => x !== l.id); d.disable_lists = d.disable_lists.filter(x => x !== l.id);
  if (on && !base) d.enable_lists.push(l.id);
  if (!on && base) d.disable_lists.push(l.id);
}
function secDNS(body) {
  const d = secDraft.dns_filter;
  const live = secEl('div'), stats = secEl('div', null, 'sec-tiles');
  const master = secCard('Ad, tracker and content blocking', 'Devices ask the server\'s DNS filter (10.77.0.1) where a site is. Names on the lists you choose get no answer, so ads, trackers and unwanted sites do not load, on every device, without installing anything on it. The lists are downloaded when switched on and re-checked regularly, so they stay current.');
  const r1 = secEl('div', null, 'sec-row'); r1.append(secCheck('Turn blocking on', d.enabled, v => { d.enabled = v; }), element('span', 'A blocked name answers'), secSelect([['nxdomain', '"does not exist"'], ['null', '0.0.0.0 (shows an error page quickly)']], d.block_mode || 'nxdomain', v => { d.block_mode = v; }, 'Blocked answer'));
  master.append(r1, secEl('p', 'Devices use the filter when their DNS server is 10.77.0.1. To make every device use it whether or not it was set up that way, turn on “Send every device\'s DNS to the filter” under Firewall.', 'sec-note'));
  body.append(stats, master);

  const cats = secCard('What to block', 'Pick categories. Each one uses the lists recommended for it; fine-tune the lists below.');
  const grid = secEl('div', null, 'sec-grid');
  const listBoxes = [];
  for (const cat of secCat.categories) {
    const box = element('input', null, { type: 'checkbox' }); box.checked = d.categories.includes(cat.id);
    box.onchange = () => { secChange(() => { d.categories = box.checked ? [...d.categories, cat.id] : d.categories.filter(x => x !== cat.id); }); for (const f of listBoxes) f(); };
    const l = secEl('label'), t = secEl('span'); t.append(document.createTextNode(cat.label), secEl('small', cat.help)); l.append(box, t); grid.append(l);
  }
  cats.append(grid); body.append(cats);

  const lists = secCard('Lists', 'The lists behind each category. Several lists often overlap; every domain is counted once and a blocked name is credited to the first list that has it. Turn on more lists for stricter blocking, fewer for less.');
  const bySource = new Map(secCat.sources.map(s => [s.id, { source: s, lists: [] }]));
  for (const l of secCat.lists) (bySource.get(l.source) || bySource.set(l.source, { source: { id: l.source, name: l.source }, lists: [] }).get(l.source)).lists.push(l);
  const status = new Map();
  const statusCells = [];
  for (const { source, lists: ls } of bySource.values()) {
    if (!ls.length && source.verified !== false) continue;
    const det = element('details'), sum = element('summary');
    sum.append(element('b', source.name), document.createTextNode(' · licence ' + (source.license || 'unknown') + ' · '), element('span', ls.length ? ls.length + ' list' + (ls.length === 1 ? '' : 's') : 'reference only'));
    det.append(sum);
    const [t, tb] = secTable(['On', 'List', 'Category', 'Format', 'Domains', 'Status']);
    for (const l of ls) {
      const box = element('input', null, { type: 'checkbox', 'aria-label': 'Use ' + l.name }); box.checked = secListOn(d, l);
      box.onchange = () => secChange(() => secSetList(d, l, box.checked));
      listBoxes.push(() => { box.checked = secListOn(d, l); });
      const doms = element('span'), st = element('span');
      statusCells.push([l.id, doms, st, box]);
      secRow(tb, [box, l.name + (l.default ? '' : ' (extra)'), secCat.categories.find(c => c.id === l.category)?.label || l.category, l.format, doms, st], [4]);
    }
    det.append(t);
    if (source.repo) det.append(secEl('p', 'Source: ' + source.repo + '. The lists are fetched from their publishers when needed and are not copied into GameBond. They remain under their authors\' licences.', 'sec-note'));
    if (source.verified === false) det.append(secEl('p', 'No downloadable list could be verified for this project, so it is shown for reference only.', 'sec-note sec-warn'));
    lists.append(det);
  }
  const rr = secEl('div', null, 'sec-row'); rr.append(action('Update lists now', async () => { secSay('Downloading lists…'); await secRun('refresh_lists', {}, 'Lists updated.'); }), element('span', 'Re-check every'), secNumber(d.refresh_hours || 12, v => { d.refresh_hours = v; }, 'Refresh hours', 1, 168), element('span', 'hours'));
  lists.append(rr);
  body.append(lists);

  // custom lists
  const custom = secCard('Your own lists', 'Add a list by address. It can be a hosts file, a plain list of domains, or an ad-block list; only the domain rules in it are used. Up to ' + secCat.limits.custom_lists + '.');
  const [ct, cb] = secTable(['Name', 'Address (https)', 'Category', '']);
  d.custom_lists.forEach((cl, i) => secRow(cb, [secText(cl.name, v => { cl.name = v; }, 'List name'), secText(cl.url, v => { cl.url = v; }, 'List address', { placeholder: 'https://example.com/list.txt' }), secSelect(secCat.categories.map(c => [c.id, c.label]), cl.category || 'ads', v => { cl.category = v; }, 'Category'), action('Remove', async () => { d.custom_lists.splice(i, 1); secRefreshBar(); secRender(); })]));
  const addCustom = action('Add a list', async () => {
    const used = new Set(d.custom_lists.map(c => c.id)); let n = 1; while (used.has('custom-' + n)) n++;
    d.custom_lists.push({ id: 'custom-' + n, name: '', url: '', category: 'ads' }); secRender();
  }); addCustom.disabled = d.custom_lists.length >= secCat.limits.custom_lists;
  custom.append(ct, (() => { const r = secEl('div', null, 'sec-row'); r.append(addCustom); return r; })());
  body.append(custom);

  // overrides
  const own = secCard('Your own rules', 'One domain per line; subdomains are included. Your allow list always wins, so you can fix a site a list blocks by mistake.');
  const grid2 = secEl('div', null, 'sec-grid');
  const col = (title, help, area) => { const w = secEl('div'); w.append(secEl('b', title), secEl('p', help, 'sec-help'), area); return w; };
  grid2.append(col('Always block', 'These names never resolve.', secTextarea(d.block, v => { d.block = v; }, 'Domains to always block', 'ads.example.com')),
    col('Never block', 'These names always resolve, whatever the lists say.', secTextarea(d.allow, v => { d.allow = v; }, 'Domains to never block', 'example.com')),
    col('Devices that are not filtered', 'Tunnel addresses, one per line, for example a work laptop.', secTextarea(d.exempt, v => { d.exempt = v; }, 'Devices not filtered', '10.77.0.5')));
  own.append(grid2);
  const up = secEl('div', null, 'sec-row'); up.append(element('span', 'Real DNS servers (host:port, one per line)'));
  own.append(up, secTextarea(d.upstreams, v => { d.upstreams = v; }, 'Upstream DNS servers', '1.1.1.1:53'));
  body.append(own);

  // check a domain
  const chk = secCard('Check a name', 'See whether a name is blocked, and by which list.');
  const cr = secEl('div', null, 'sec-row'), dom = element('input', null, { type: 'text', placeholder: 'ads.example.com', 'aria-label': 'Domain to check', size: 30 }), res = secEl('span', '', 'sec-note');
  cr.append(dom, action('Check', async () => {
    try {
      const r = await secDo('check_domain', { domain: dom.value.trim() });
      res.textContent = r.blocked ? dom.value.trim() + ' is blocked by ' + (r.list === 'custom' ? 'your block list' : r.list_name || r.list) + (r.matched && r.matched !== dom.value.trim() ? ' (matched ' + r.matched + ')' : '') + '.' : r.allowed ? dom.value.trim() + ' is on a list but your allow list lets it through.' : dom.value.trim() + ' is not blocked.';
    } catch (e) { res.textContent = e.message; }
  }), res);
  chk.append(cr); body.append(chk);

  // live activity
  const act = secCard('Activity', 'Counts since the server started.');
  const [tt, tbt] = secTable(['Most blocked names', 'Times']); const [ctab, cbt] = secTable(['Device', 'Queries', 'Blocked']); const [rt, rbt] = secTable(['When', 'Device', 'Name', 'Result']);
  const two = secEl('div', null, 'sec-grid'); const a = secEl('div'), b = secEl('div'); a.append(tt); b.append(ctab); two.append(a, b);
  act.append(two, secEl('h3', 'Latest questions'), rt); body.append(act);
  secLive.push(() => {
    const f = secOv.dns.filter, s = secOv.dns.server;
    stats.replaceChildren(secTile('Names blocked', secNum(f.unique_domains), 'from ' + secNum(f.total_domains) + ' list entries, duplicates counted once'), secTile('Questions answered', secNum(s.queries), secNum(s.cached) + ' from cache'), secTile('Questions blocked', secNum(s.blocked)), secTile('Lists with a problem', secNum(f.with_error), f.loading ? f.loading + ' downloading' : ''));
    for (const l of f.lists || []) status.set(l.id, l);
    for (const [id, doms, st] of statusCells) { const l = status.get(id); doms.textContent = l?.active ? secNum(l.domains) : '—'; st.textContent = !l?.active ? 'off' : l.error ? 'problem: ' + l.error : l.updated_at ? 'updated ' + secAgo(l.updated_at) : 'downloading…'; st.className = l?.active && l.error ? 'sec-bad' : ''; }
    tbt.replaceChildren(); for (const e of (s.top_blocked || []).slice(0, 10)) secRow(tbt, [e.domain, secNum(e.count)], [1]);
    if (!tbt.children.length) secRow(tbt, ['Nothing blocked yet', '']);
    cbt.replaceChildren(); for (const e of (s.clients || []).slice(0, 10)) secRow(cbt, [e.client, secNum(e.queries), secNum(e.blocked)], [1, 2]);
    if (!cbt.children.length) secRow(cbt, ['No device has asked yet', '', '']);
    rbt.replaceChildren(); for (const e of (s.recent || []).slice(-15).reverse()) secRow(rbt, [secAgo(e.t), e.client, e.name, e.blocked ? 'blocked' + (e.list ? ' (' + e.list + ')' : '') : e.cached ? 'cached' : 'answered']);
    if (!rbt.children.length) secRow(rbt, ['—', '', '', '']);
  });
}

// ---- intrusion detection and prevention ----
const SEC_MODES = [['off', 'Off', 'Nothing is analysed.'], ['detect', 'Detect (IDS)', 'Watches traffic and reports suspicious behaviour. Nothing is blocked.'], ['prevent', 'Detect and block (IPS)', 'Also blocks the offending address for a while, for detectors set to block.']];
function secIDS(body) {
  const i = secDraft.ids;
  const modes = secCard('Intrusion detection and prevention', 'Watches the traffic of your devices for behaviour that looks like scanning, floods, password guessing, risky services and data theft, in the terms of NIST SP 800-94 (Guide to Intrusion Detection and Prevention Systems). It judges behaviour from packet headers and DNS questions; it does not read the contents of connections, so it cannot recognise a specific exploit.');
  const row = secEl('div', null, 'sec-modes');
  for (const [id, label, text] of SEC_MODES) {
    const b = secEl('button', null, 'sec-mode' + (i.mode === id ? ' active' : ''), { type: 'button', 'aria-pressed': i.mode === id });
    b.append(element('b', label), element('span', text));
    b.onclick = () => { secChange(() => { i.mode = id; }); for (const x of row.children) { const on = x === b; x.classList.toggle('active', on); x.setAttribute('aria-pressed', on); } };
    row.append(b);
  }
  modes.append(row);
  const r = secEl('div', null, 'sec-row');
  r.append(element('span', 'Sensitivity'), secSelect([['low', 'Low (fewer alerts)'], ['medium', 'Medium'], ['high', 'High (more alerts)']], i.sensitivity || 'medium', v => { i.sensitivity = v; }, 'Sensitivity'),
    element('span', 'Block for'), secNumber(i.block_minutes || 10, v => { i.block_minutes = v; }, 'Minutes to block', 1, 1440), element('span', 'minutes (longer each time the same address comes back, up to 24 hours)'));
  modes.append(r);
  modes.append(secEl('p', 'Blocking cuts the offending address off from the tunnel: all traffic to and from it is dropped, open connections included. The server itself (10.77.0.1) and the client PC (10.77.0.2) are never blocked.', 'sec-note'));
  body.append(modes);

  const det = secCard('What it looks for', 'Each detector can be switched off, set to only alert or also block, and have its threshold changed. Sensitivity scales every threshold.');
  const [dt, db] = secTable(['On', 'Detector', 'Severity', 'When', 'Action', 'Threshold', 'Seen']);
  const seen = [];
  for (const spec of secCat.detectors) {
    const cur = i.detectors[spec.kind] || {};
    const get = () => (i.detectors[spec.kind] = i.detectors[spec.kind] || {});
    const on = element('input', null, { type: 'checkbox', 'aria-label': 'Enable ' + spec.title }); on.checked = cur.enabled !== false; on.onchange = () => secChange(() => { get().enabled = on.checked; });
    const name = element('span'); name.append(element('b', spec.title + (spec.inbound ? ' (from the internet)' : '')), secEl('div', spec.help, 'sec-help'));
    const sev = secEl('span', spec.severity, 'sec-sev-' + spec.severity), seenEl = element('span');
    const thr = element('span'), tin = element('input', null, { type: 'number', min: 1, 'aria-label': spec.title + ' threshold' }); tin.placeholder = String(spec.default_threshold); tin.value = cur.threshold || ''; tin.oninput = () => secChange(() => { const v = tin.value === '' ? 0 : Number(tin.value); get().threshold = v; if (!v) delete get().threshold; });
    thr.append(tin, document.createTextNode(' ' + spec.unit));
    seen.push([spec.kind, seenEl]);
    const w = c => { const s = secEl('span', null, 'sec-cell'); s.append(c); return s; };
    secRow(db, [on, name, sev, spec.inbound ? 'inbound' : 'device', w(secSelect([['block', 'Alert and block'], ['alert', 'Alert only']], cur.action || spec.default_action, v => { get().action = v; }, spec.title + ' action')), w(thr), seenEl], [6]);
  }
  det.append(dt); body.append(det);

  const nb = secCard('Never block these addresses', 'They are still reported, but never cut off. One address per line.');
  nb.append(secTextarea(i.never_block, v => { i.never_block = v; }, 'Addresses never blocked', '10.77.0.3')); body.append(nb);

  const blocked = secCard('Blocked right now');
  const [bt, bb] = secTable(['Address', 'Time left', '']); blocked.append(bt);
  const manual = secEl('div', null, 'sec-row'), ip = element('input', null, { type: 'text', placeholder: 'Address to block, for example 203.0.113.9', 'aria-label': 'Address to block', size: 28 });
  manual.append(ip, action('Block for an hour', async () => { await secRun('block', { ip: ip.value.trim(), seconds: 3600 }, ip.value.trim() + ' is blocked for an hour.'); ip.value = ''; }));
  blocked.append(manual); body.append(blocked);

  const ev = secCard('Events', 'Repeats within a minute are merged. “Would have blocked” means the mode is detect-only or the address is on the never-block list.');
  const [et, eb] = secTable(['When', 'Event', 'Source', 'Peer', 'Detail', 'Result']); ev.append(et);
  ev.append((() => { const r = secEl('div', null, 'sec-row'); r.append(action('Clear events', async () => { await secRun('clear_events', {}, 'Events cleared.'); })); return r; })());
  body.append(ev);
  secLive.push(() => {
    const ids = secOv.ids;
    for (const [kind, el] of seen) el.textContent = secNum((ids.detectors || []).find(d => d.kind === kind)?.seen);
    bb.replaceChildren();
    for (const b of secOv.firewall.blocked || []) secRow(bb, [b.ip, Math.max(1, Math.round(b.expires_in_s / 60)) + ' min', action('Unblock', async () => { await secRun('unblock', { ip: b.ip }, b.ip + ' is unblocked.'); })]);
    if (!bb.children.length) secRow(bb, ['Nothing is blocked.', '', '']);
    eb.replaceChildren();
    for (const e of ids.events || []) secRow(eb, [secAgo(e.time), element('span', e.title + (e.count > 1 ? ' ×' + e.count : '')), e.offender, e.peer || '', e.detail, secActionText(e)]);
    if (!eb.children.length) secRow(eb, ['—', 'No events yet.', '', '', '', '']);
  });
}

// ---- sub-tab wiring ----
const secShowBefore = showScannerSub;
showScannerSub = function (which) {
  secShowBefore(which);
  const on = which === 'security';
  secPane.hidden = !on; secSub.classList.toggle('active', on); secSub.setAttribute('aria-selected', on);
  if (on) { secLoad(true); if (!secTimer) secTimer = setInterval(secTick, 3000); }
  else if (secTimer) { clearInterval(secTimer); secTimer = null; }
};
secSub.onclick = () => showScannerSub('security');
function secTick() {
  if (scannerSub !== 'security' || !$('scanner').classList.contains('active') || document.hidden || secBusy || secLoading) return;
  secLoad();
}

// ---- Settings > Ad blocking: the short version of Security > Ad & content blocking ----
const adDialog = modal('adblockdialog', 'Ad blocking'), adBody = element('div');
adDialog.append(adBody);
let adState = null, adMsg = '', adMsgBad = false;
async function adLoad() {
  try {
    if (!secCat) secCat = await secCall('security/catalog');
    adState = await secCall('security');
  } catch (e) { adState = null; adMsg = e.message; adMsgBad = true; }
  adRender();
}
function adRender() {
  adBody.replaceChildren();
  if (!adState) { adBody.append(secEl('p', adMsg || 'Loading…', adMsgBad ? 'sec-bad' : 'sec-note'), secEl('p', 'This works through the server\'s admin portal: open Settings, Server sync (or Server admin) and enter its address and password first.', 'sec-note')); return; }
  const s = secNorm(adState.settings), d = s.dns_filter, st = adState.dns;
  adBody.append(secEl('p', 'Block ads, trackers and other unwanted sites for every device on your tunnel, at the server, without installing anything on the devices. The lists are fetched fresh from their publishers and kept up to date.', 'sec-help'));
  const on = secCheck('Block ads and trackers', d.enabled, v => { d.enabled = v; });
  const row = secEl('div', null, 'sec-row'); row.append(on); adBody.append(row);
  adBody.append(secEl('b', 'Choose what to block'));
  const grid = secEl('div', null, 'sec-grid');
  for (const cat of secCat.categories) {
    const box = element('input', null, { type: 'checkbox' }); box.checked = d.categories.includes(cat.id); box.onchange = () => { d.categories = box.checked ? [...d.categories, cat.id] : d.categories.filter(x => x !== cat.id); };
    const l = secEl('label'), t = secEl('span'); t.append(document.createTextNode(cat.label), secEl('small', cat.help)); l.append(box, t); grid.append(l);
  }
  adBody.append(grid);
  const q = st.server.queries, blocked = st.server.blocked;
  adBody.append(secEl('p', st.filter.enabled ? 'Blocked ' + secNum(blocked) + ' of ' + secNum(q) + ' questions so far, using ' + secNum(st.filter.unique_domains) + ' blocked names.' : 'Blocking is off.', 'sec-note'));
  const r = secEl('div', null, 'row');
  const save = action('Save', async () => {
    try { await secCall('security', 'POST', { settings: s }); adMsg = 'Saved. The lists download in the background.'; adMsgBad = false; secDraft = secDirty() ? secDraft : null; await adLoad(); }
    catch (e) { adMsg = e.message; adMsgBad = true; adRender(); }
  });
  const more = action('More options…', async () => { adDialog.close(); selectTab('scanner'); showScannerSub('security'); secSection = 'dns'; secRender(); });
  r.append(save, more, secEl('span', adMsg, adMsgBad ? 'sec-bad' : 'sec-ok', { role: 'status' }));
  adBody.append(r);
}
settingsMenu.append(action('Ad blocking', () => { settingsDialog.close(); adMsg = ''; adLoad(); showDialog('adblockdialog'); }));
