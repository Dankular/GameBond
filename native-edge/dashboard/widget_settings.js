// Desktop settings use the same config validators as the daemon. No setting
// is applied to the running tunnel until the user reconnects.
const settingsStyle = document.createElement('style');
settingsStyle.textContent = '.fields{display:grid;grid-template-columns:minmax(150px,1fr) minmax(170px,2fr);gap:10px 14px;align-items:center}.fields input,.fields select{width:100%}.fields input[type=checkbox]{width:auto;justify-self:start}.fields label{color:#737d89}fieldset{border:1px solid #e1e5eb;border-radius:8px;padding:16px;margin:12px 0}legend{font-weight:600;padding:0 6px}.help{color:#8f9099;font-size:11px;line-height:1.5}.inline{display:flex;align-items:center;gap:8px}.inline input{flex:1;min-width:0}dialog .wide{width:100%}#dnsrecords td:nth-child(2){width:100px}#dnsrecords td:last-child{width:70px}.settings-menu{display:grid;gap:8px}.settings-menu button{text-align:left}';
document.head.append(settingsStyle);
function element(tag, text, attributes = {}) {
  const el = document.createElement(tag);
  if (text != null) el.textContent = text;
  for (const [key, value] of Object.entries(attributes)) el.setAttribute(key, value);
  return el;
}
function field(label, control, container) {
  const name = element('label', label);
  if (control.id) name.htmlFor = control.id;
  container.append(name, control);
  return control;
}
function input(type, value, label, attributes = {}) {
  const el = element('input', null, { type, 'aria-label': label, ...attributes });
  el.value = value ?? '';
  return el;
}
function action(text, handler) {
  const el = element('button', text, { type: 'button' });
  el.onclick = async (...args) => { if (el.disabled) return; el.disabled = true; try { await handler(...args); } finally { el.disabled = false; if (el.closest('#omractions')) syncOMR(); } };
  return el;
}
function modal(id, title) {
  const dialog = element('dialog', null, { id });
  const close = action('Close', () => dialog.close()); close.className = 'close';
  dialog.append(close, element('h2', title)); document.body.append(dialog);
  return dialog;
}
function numberValue(el, label, integer = false) {
  if (el.value.trim() === '') throw new Error('Enter ' + label.toLowerCase());
  const n = Number(el.value);
  if (!Number.isFinite(n) || (integer && !Number.isInteger(n))) throw new Error('Invalid ' + label.toLowerCase());
  return n;
}


// Per-link form: display caps in decimal GB, save validated integer byte caps.
$('linkconfig').hidden = true;
const linkForms = element('div'); $('linkconfig').before(linkForms);
let storedPolicies = {}, linkEditors = [];
$('linklimits').onclick = async () => {
  try {
    const d = await api('links'); storedPolicies = d.link_policies || {}; linkEditors = []; linkForms.replaceChildren();
    for (let slot = 0; slot < (d.interface_indices || []).length; slot++) {
      const key = String(d.interface_indices[slot]), p = { role: 'primary', upload_mbps: 0, download_mbps: 0, daily_bytes: 0, monthly_bytes: 0, reset_day: 1, overlimit: 'stop', overlimit_mbps: .2, ...storedPolicies[key] };
      const group = element('fieldset'), legend = element('legend', d.interface_names?.[slot] || 'Adapter ' + key), fields = element('div'); fields.className = 'fields'; group.append(legend, fields);
      const usage = current.link_usage?.[key];
      if (usage) group.append(element('p', 'Today ' + bytes(usage.daily_bytes) + ' · Billing cycle ' + bytes(usage.monthly_bytes), { class: 'help' }));
      const editors = {};
      for (const [name, label] of [['role', 'Role'], ['upload_mbps', 'Upload limit (Mbps)'], ['download_mbps', 'Download limit (Mbps)'], ['daily_bytes', 'Daily cap (GB)'], ['monthly_bytes', 'Monthly cap (GB)'], ['reset_day', 'Billing reset day'], ['overlimit', 'At cap'], ['overlimit_mbps', 'Overlimit speed (Mbps)']]) {
        let editor;
        if (name === 'role') editor = select(['primary', 'secondary', 'backup', 'never'], p[name], label);
        else if (name === 'overlimit') editor = select(['stop', 'throttle'], p[name], label);
        else editor = input('number', name.endsWith('_bytes') ? p[name] / 1e9 : p[name], label, { min: name === 'reset_day' ? 1 : 0, max: name.endsWith('_bytes') ? 1e7 : name === 'reset_day' ? 31 : 10000, step: name === 'reset_day' ? 1 : .001 });
        editors[name] = field(label, editor, fields);
      }
      linkEditors.push({ key, editors }); linkForms.append(group);
    }
    if (!linkEditors.length) linkForms.append(element('p', 'Choose a network before setting link limits.'));
    linkForms.append(element('p', '0 means no configured limit. GB = 1,000,000,000 bytes. Usage includes copies and repairs. Save and reconnect to apply.', { class: 'help' }));
    showDialog('linkdialog');
  } catch (e) { $('actionmsg').textContent = e.message; }
};
$('savelinks').onclick = async () => {
  try {
	$('linkmsg').textContent = 'Saving…';
    const policies = { ...storedPolicies };
    for (const { key, editors } of linkEditors) {
      const p = {};
      for (const [name, editor] of Object.entries(editors)) p[name] = editor.tagName === 'SELECT' ? editor.value : numberValue(editor, name, name === 'reset_day');
      p.daily_bytes = Math.round(p.daily_bytes * 1e9); p.monthly_bytes = Math.round(p.monthly_bytes * 1e9); policies[key] = p;
    }
    if (linkEditors.length && linkEditors.every(({ key }) => policies[key].role === 'never')) throw new Error('Keep at least one selected link enabled');
    await api('links', 'PUT', policies); $('linkmsg').textContent = 'Saved; reconnect to apply.';
  } catch (e) { $('linkmsg').textContent = e.message; }
};

// LAN gateway selection only offers adapters which are not VPN uplinks.
const deviceDialog = modal('devicedialog', 'Connected devices');
deviceDialog.append(element('p', 'Connect a device to a spare adapter to share the VPN. Select its adapter and give it a tunnel address. Saving takes effect after reconnecting.'));
const deviceRows = element('div'); deviceDialog.append(deviceRows);
const ps5Search = element('p', 'PS5 — waiting for a UGREEN USB Ethernet adapter.', { role: 'status' }); deviceRows.before(ps5Search);
const deviceMessage = element('p', '', { role: 'status' });
let lanData = {}, lanRows = [];
async function openDevices() {
  try {
    lanData = await api('lan-devices'); deviceRows.replaceChildren(); lanRows = [];
    const ps5Matches = lanData.ps5_adapters || [], confirmedPS5 = ps5Matches.filter(a => a.confirmed);
    ps5Search.textContent = lanData.ps5_adapter_error || (confirmedPS5.length ? 'PS5 — UGREEN USB Ethernet found: ' + confirmedPS5.map(a => a.name).join(', ') + '. Select the dedicated adapter below and save when ready.' : ps5Matches.length ? 'PS5 — USB Ethernet detected, but Windows does not identify it as UGREEN. Confirm the hardware before selecting it.' : 'PS5 — waiting for a UGREEN USB Ethernet adapter. Plug it in, then refresh adapters.');
    const selectedIDs = new Set((lanData.interface_ids || []).map(s => s.toLowerCase())), selectedIndices = new Set(lanData.interface_indices || []), saved = lanData.lan_devices || [];
    const candidates = (lanData.adapters || []).filter(a => !selectedIndices.has(a.index) && !selectedIDs.has(String(a.id).toLowerCase()));
    candidates.sort((a, b) => Number(confirmedPS5.some(d => d.id.toLowerCase() === String(b.id).toLowerCase())) - Number(confirmedPS5.some(d => d.id.toLowerCase() === String(a.id).toLowerCase())));
    for (const old of saved) if (!candidates.some(a => String(a.id).toLowerCase() === String(old.interface_id).toLowerCase())) candidates.push({ id: old.interface_id, index: old.interface_index || 0, name: old.name + ' (offline)', up: false });
    const takenAddresses = new Set([...saved.map(d => d.tunnel_ip), lanData.client_tunnel_ip || '10.77.0.2']);
    const prefix = (lanData.client_tunnel_ip || '10.77.0.2').split('.').slice(0, 3).join('.');
    function nextAddress() { for (let i = 3; i < 255; i++) { const ip = prefix + '.' + i; if (!takenAddresses.has(ip)) { takenAddresses.add(ip); return ip; } } return ''; }
    for (const adapter of candidates) {
      const stored = saved.find(d => String(d.interface_id).toLowerCase() === String(adapter.id).toLowerCase());
      const isPS5 = confirmedPS5.length === 1 && confirmedPS5.some(a => a.id.toLowerCase() === String(adapter.id).toLowerCase()) && !saved.some(d => d.name.toLowerCase() === 'ps5');
      const group = element('fieldset'), use = input('checkbox', '', 'Share through ' + adapter.name); use.checked = Boolean(stored);
      const title = element('label', ' ' + adapter.name); title.prepend(use); group.append(title);
      const fields = element('div'); fields.className = 'fields'; group.append(fields);
      const name = field('Device name', input('text', stored?.name || (isPS5 ? 'PS5' : ''), 'Device name', { maxlength: 32 }), fields);
      const ip = field('Tunnel address', input('text', stored?.tunnel_ip || nextAddress(), 'Device tunnel address'), fields);
      const mac = field('MAC filter (optional)', input('text', stored?.device_mac || '', 'Device MAC address'), fields);
      const dns = field('DNS servers', input('text', (stored?.dns || ['1.1.1.1', '8.8.8.8']).join(', '), 'Device DNS servers'), fields);
      const live = (current.lan_devices || []).find(d => d.name === stored?.name);
      if (live) group.append(element('p', live.error || (live.leased ? 'Device connected and addressed' : live.up ? 'Waiting for an address request' : 'Adapter unavailable'), { class: 'help' }));
      lanRows.push({ adapter, stored, use, name, ip, mac, dns }); deviceRows.append(group);
    }
    deviceMessage.textContent = lanData.adapter_error || (!candidates.length ? 'No spare adapters found.' : ''); showDialog('devicedialog');
  } catch (e) { $('actionmsg').textContent = e.message; }
}
deviceDialog.append(action('Refresh adapters', openDevices), action('Save devices', async () => {
  try {
	deviceMessage.textContent = 'Saving…';
    const devices = lanRows.filter(row => row.use.checked).map(row => ({ ...row.stored, name: row.name.value.trim(), tunnel_ip: row.ip.value.trim(), interface_id: row.adapter.id, interface_index: row.adapter.index, device_mac: row.mac.value.trim(), dns: row.dns.value.split(/[,;\s]+/).filter(Boolean) }));
    await api('lan-devices', 'PUT', devices); deviceMessage.textContent = 'Saved; reconnect to apply.';
  } catch (e) { deviceMessage.textContent = e.message; }
}), deviceMessage);
let ps5Polling = false;
setInterval(async () => {
  if (!deviceDialog.open || ps5Polling) return;
  ps5Polling = true;
  try {
    const latest = await api('lan-devices');
    const matches = latest.ps5_adapters || [], found = matches.filter(a => a.confirmed);
    ps5Search.textContent = latest.ps5_adapter_error || (found.length ? 'PS5 — UGREEN USB Ethernet found: ' + found.map(a => a.name).join(', ') + '. Refresh adapters to configure it.' : matches.length ? 'PS5 — USB Ethernet detected; UGREEN identity unconfirmed. Refresh adapters to review it.' : 'PS5 — waiting for a UGREEN USB Ethernet adapter. Checking every 15 seconds while this window is open.');
  } catch (e) { ps5Search.textContent = e.message; }
  finally { ps5Polling = false; }
}, 15000);

// OMR login checks are explicit, pinned, single attempts. The server keeps the
// password in a private file; fetched tunnel keys never enter the renderer.
const omrDialog = modal('omrdialog', 'OpenMPTCProuter');
omrDialog.append(element('p', 'Gameplay and calls keep using GameBond. Other traffic can use your OpenMPTCProuter server on the same uplinks. Changes apply after reconnecting.'));
const omrFields = element('div'); omrFields.className = 'fields'; omrDialog.append(omrFields);
const omrMode = field('Mode', select(['gamebond', 'both'], 'gamebond', 'OMR mode'), omrFields);
omrMode.options[0].textContent = 'GameBond only'; omrMode.options[1].textContent = 'GameBond + OpenMPTCProuter';
const omrHost = field('Tunnel server IPv4', input('text', '', 'OMR tunnel server'), omrFields);
const omrPort = field('Tunnel UDP port', input('number', 65001, 'OMR tunnel port', { min: 1, max: 65535 }), omrFields);
const omrSource = field('Key source', select(['admin', 'key'], 'admin', 'OMR key source'), omrFields);
omrSource.options[0].textContent = 'Admin login (fetch key)'; omrSource.options[1].textContent = 'Key file';
const omrKey = field('Key file path', input('text', '', 'Glorytun key file'), omrFields);
const omrAdminHost = field('Admin API host (optional)', input('text', '', 'OMR admin host'), omrFields);
const omrAdminPort = field('Admin API port', input('number', 65500, 'OMR admin port', { min: 1, max: 65535 }), omrFields);
const omrUser = field('Username', input('text', 'openmptcprouter', 'OMR username'), omrFields);
const omrPassword = field('Password', input('password', '', 'OMR password', { autocomplete: 'new-password', maxlength: 512 }), omrFields);
const omrPin = field('Certificate public-key pin', input('text', '', 'OMR certificate pin'), omrFields);
const omrIP = field('Tunnel address (optional)', input('text', '', 'OMR tunnel address'), omrFields);
const omrDSCP = field('GameBond classes (DSCP)', input('text', '46, 26', 'GameBond DSCP classes'), omrFields);
const omrMessage = element('p', '', { role: 'status' }), omrLive = element('pre');
let omrStored = {};
function syncOMR() {
  const enabled = omrMode.value === 'both', admin = omrSource.value === 'admin';
  for (const el of [omrHost, omrPort, omrSource, omrIP, omrDSCP]) el.disabled = !enabled;
  omrKey.disabled = !enabled || admin;
  for (const el of [omrAdminHost, omrAdminPort, omrUser, omrPassword, omrPin]) el.disabled = !enabled || !admin;
  for (const button of Array.from($('omractions')?.children || []).slice(0, 2)) button.disabled = !enabled || !admin;
}
omrMode.onchange = syncOMR; omrSource.onchange = syncOMR;
function omrBody() {
  if (omrMode.value === 'gamebond') return { server_type: 'gamebond' };
  const block = { ...omrStored, server: [omrHost.value.trim(), numberValue(omrPort, 'Tunnel port', true)], gamebond_dscp: omrDSCP.value.split(/[,;\s]+/).filter(Boolean).map(value => { if (!/^\d+$/.test(value)) throw Error('DSCP classes must be integers 0 to 63'); return Number(value); }) };
  delete block.admin; delete block.key_file; delete block.tunnel_ip;
  if (omrIP.value.trim()) block.tunnel_ip = omrIP.value.trim();
  if (omrSource.value === 'key') block.key_file = omrKey.value.trim();
  else {
    block.admin = { username: omrUser.value.trim(), password_file: omrStored.admin?.password_file || 'secrets/omr-admin.pass', pin: omrPin.value.trim() };
    if (omrAdminHost.value.trim()) block.admin.host = omrAdminHost.value.trim();
    if (Number(omrAdminPort.value) !== 65500) block.admin.port = numberValue(omrAdminPort, 'Admin port', true);
  }
  return { server_type: 'both', omr: block, ...(omrPassword.value ? { password: omrPassword.value } : {}) };
}
async function openOMR() {
  try {
    const d = await api('omr'); omrStored = d.omr || d.omr_draft || {}; const admin = omrStored.admin || {};
    omrMode.value = d.server_type; omrHost.value = omrStored.server?.[0] || ''; omrPort.value = omrStored.server?.[1] || 65001; omrSource.value = omrStored.key_file ? 'key' : 'admin'; omrKey.value = omrStored.key_file || '';
    omrAdminHost.value = admin.host || ''; omrAdminPort.value = admin.port || 65500; omrUser.value = admin.username || 'openmptcprouter'; omrPin.value = admin.pin || ''; omrPassword.value = '';
    omrPassword.placeholder = admin.password_file ? 'Leave empty to keep the saved password' : 'Password from your VPS configuration';
    omrIP.value = omrStored.tunnel_ip || ''; omrDSCP.value = (omrStored.gamebond_dscp || [46, 26]).join(', ');
    const status = current.omr;
    omrLive.textContent = !status ? 'GameBond only; no OMR tunnel running.' : status.error || (status.active ? 'OpenMPTCProuter leg is active.' : 'Waiting for the OMR leg; bulk traffic stays on GameBond.');
    omrMessage.textContent = ''; syncOMR(); showDialog('omrdialog');
  } catch (e) { $('actionmsg').textContent = e.message; }
}
omrDialog.append(element('div', null, { class: 'row', id: 'omractions' }), omrLive, omrMessage);
$('omractions').append(action('Read certificate pin', async () => {
  try {
    omrMessage.textContent = 'Reading server certificate…';
    const d = await api('omr-check', 'POST', { action: 'pin', host: omrAdminHost.value.trim() || omrHost.value.trim(), port: numberValue(omrAdminPort, 'Admin port', true) });
    const confirmDialog = modal('confirmpin', 'Trust this server?');
    confirmDialog.addEventListener('close', () => confirmDialog.remove(), { once: true });
    confirmDialog.append(element('p', 'Compare this pin with the public-key pin printed by your VPS installer. Only accept it if they match.'), element('pre', d.pin), action('Accept pin', () => { omrPin.value = d.pin; confirmDialog.close(); confirmDialog.remove(); omrMessage.textContent = 'Pin accepted; save or test the login.'; }));
    confirmDialog.showModal();
  } catch (e) { omrMessage.textContent = e.message; }
}), action('Test login', async () => {
  try { omrMessage.textContent = 'Testing login once…'; const d = await api('omr-check', 'POST', { action: 'test', settings: omrBody() }); omrMessage.textContent = 'Login works; the server supplied tunnel settings.' + (d.tunnel_ip ? ' Tunnel address: ' + d.tunnel_ip : ''); }
  catch (e) { omrMessage.textContent = e.message; }
}), action('Save OMR settings', async () => {
  try { omrMessage.textContent = 'Saving…'; await api('omr', 'PUT', omrBody()); omrPassword.value = ''; omrMessage.textContent = 'Saved; reconnect to apply.'; }
  catch (e) { omrMessage.textContent = e.message; }
}));

// Keep the original four network-strip actions; application routing lives in Settings.
$('capturedapps').hidden = true;
const appMode = select(['all', 'selected'], 'all', 'Application routing mode');
appMode.options[0].textContent = 'All apps'; appMode.options[1].textContent = 'Selected apps';
$('appconfig').before(appMode);
appMode.onchange = () => { $('appconfig').disabled = appMode.value === 'all'; };
$('capturedapps').onclick = async () => {
  try { const d = await api('apps'); appMode.value = d.capture_mode || 'all'; $('appconfig').value = (d.cod_executables || []).join('\n'); appMode.onchange(); showDialog('appdialog'); }
  catch (e) { $('actionmsg').textContent = e.message; }
};
$('saveapps').onclick = async () => {
  try { $('appmsg').textContent = 'Saving…'; await api('apps', 'PUT', { capture_mode: appMode.value, cod_executables: $('appconfig').value.split('\n').map(s => s.trim()).filter(Boolean) }); $('appmsg').textContent = 'Saved; reconnect to apply.'; }
  catch (e) { $('appmsg').textContent = e.message; }
};
document.querySelector('.network-actions').append(action('Connected devices', openDevices), action('OpenMPTCProuter', openOMR));
const settingsDialog = modal('settingsdialog', 'Settings'), settingsMenu = element('div'); settingsMenu.className = 'settings-menu'; settingsDialog.append(settingsMenu);
for (const [label, handler] of [['Application routing', () => $('capturedapps').click()], ['Select networks', () => $('selectnetworks').click()], ['Link roles and limits', () => $('linklimits').click()], ['Connected devices', openDevices], ['OpenMPTCProuter', openOMR]]) settingsMenu.append(action(label, () => { settingsDialog.close(); handler(); }));
$('settings').onclick = () => showDialog('settingsdialog');

// Stable identities keep an unplugged selection distinct from an adapter that
// later reuses its interface index, and follow an adapter whose index changed.
$('selectnetworks').onclick = async () => {
  try {
    await loadNetworks(); $('networkchoices').replaceChildren();
    for (const adapter of networks.adapters || []) {
      const row = element('tr'), check = input('checkbox', '', 'Use ' + adapter.name);
      check.value = adapter.index; check.dataset.identity = adapter.id || '';
      check.checked = (networks.interface_indices || []).some((index, slot) => networks.interface_ids?.[slot] ? String(networks.interface_ids[slot]).toLowerCase() === String(adapter.id).toLowerCase() : index === adapter.index);
      const td = element('td'); td.append(check); row.append(td);
      for (const value of [adapter.name + (adapter.up ? '' : ' (offline)'), adapter.addresses?.join(', ') || '—', adapter.gateway || '—']) cell(row, value);
      $('networkchoices').append(row);
    }
    showDialog('networkdialog');
  } catch (e) { $('actionmsg').textContent = e.message; }
};
$('savenetworks').onclick = async () => {
  try {
    const selection = Array.from($('networkchoices').querySelectorAll('input:checked'), check => check.dataset.identity ? { index: Number(check.value), id: check.dataset.identity } : Number(check.value));
    await api('networks', 'PUT', selection); $('networkmsg').textContent = 'Saved; reconnect to apply.'; await loadNetworks();
  } catch (e) { $('networkmsg').textContent = e.message; }
};

// A Go supervisor keeps its PID across restarts; created identifies the tunnel
// session. Saved settings stay visibly pending until that session changes.
let settingsPending = false, settingsSession = null;
const settingsAPI = api, settingsUpdateState = updateState;
api = async function (path, method = 'GET', body) {
  const result = await settingsAPI(path, method, body);
  if (method === 'PUT' && path !== 'app-policy') settingsPending = true;
  return result;
};
updateState = function (doc) {
  const session = doc.state === 'running' && doc.created != null ? String(doc.pid) + ':' + String(doc.created) : null;
  if (session && settingsSession && session !== settingsSession) settingsPending = false;
  if (session) settingsSession = session;
  settingsUpdateState(doc);
  if (settingsPending) $('session').textContent += ' · Settings saved; reconnect to apply';
};
