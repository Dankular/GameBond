// Adoption for the Network Scanner tab: a new device that asks for an address waits here until it is approved
// (or the policy adopts it), then the server is told about its address so it forwards the device's traffic.
// The access lists and the policy live in lan-access.json (see widget_settings.js); this panel is a
// friendlier front for the same API, plus the server sync.
const adoptStyle = document.createElement('style');
adoptStyle.textContent = '.adopt-panel{margin:0 0 14px}.adopt-head{display:flex;gap:12px;align-items:center;flex-wrap:wrap;margin:4px 0 8px}.adopt-head h2{margin:0;font-size:16px}.adopt-head select{margin-left:auto}'
  + '.adopt-card{border:1px solid #e1e5eb;border-radius:10px;padding:12px 14px;margin:0 0 10px;display:grid;gap:8px}.adopt-card.new{border-color:#f5a300;background:#fffaf0}.adopt-card.warn{border-color:#e0a000;background:#fff8e6}.adopt-card.ok{border-color:#bfe5b0;background:#f3fbef}.adopt-card.bad{border-color:#e8a6a3;background:#fdf1f0}'
  + '.adopt-title{display:flex;gap:10px;align-items:center;font-weight:600}.adopt-sub{color:#7b8089;font-size:12px}.adopt-row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.adopt-row label{display:flex;gap:6px;align-items:center}.adopt-row input[type=text],.adopt-field input{padding:5px 8px;border:1px solid #cfd5dd;border-radius:6px}'
  + '.adopt-note{color:#505762;font-size:12px;margin:0}.adopt-field{display:grid;gap:4px;margin:8px 0}.adopt-field span{font-size:12px;color:#505762}';
document.head.append(adoptStyle);
{
  const dark = document.createElement('style');
  dark.textContent = 'html[data-theme=dark] .adopt-card{border-color:#3a404b;background:#1b1e24}html[data-theme=dark] .adopt-card.new{border-color:#b9790a;background:#2a2417}html[data-theme=dark] .adopt-card.warn{background:#2a2417}html[data-theme=dark] .adopt-card.ok{background:#17261a;border-color:#2f5a38}html[data-theme=dark] .adopt-card.bad{background:#2a1a19;border-color:#6a3532}html[data-theme=dark] .adopt-note{color:#aab2bd}html[data-theme=dark] .adopt-row input[type=text],html[data-theme=dark] .adopt-field input{background:#171a1f;color:#e0e3e8;border-color:#3a404b}';
  document.head.append(dark);
}

const adoptPanel = element('div', null, { class: 'adopt-panel' });
scanPanel.insertBefore(adoptPanel, subTabs);
let serverSync = null, serverSyncCheckedAt = 0, adoptBusy = false, adoptMsg = '', adoptFixed = new Map(); // mac -> { on, ip }

async function refreshServerSync(check) {
  try { serverSync = await api('server-sync' + (check ? '?check=1' : '')); if (check) serverSyncCheckedAt = Date.now(); } catch (e) { serverSync = null; }
}

async function adoptCall(body) {
  adoptBusy = true; adoptMsg = ''; renderAdopt();
  try { accessState = await api('lan-access', 'POST', body); } catch (e) { adoptMsg = e.message; }
  adoptBusy = false;
  if (typeof renderAccess === 'function') renderAccess();
  await refreshServerSync(true); renderAdopt();
}

async function adoptSync(restart) {
  adoptBusy = true; adoptMsg = ''; renderAdopt();
  try {
    serverSync = await api('server-sync', 'POST', { restart });
    adoptMsg = serverSync.restarted ? 'The server list was updated and the server is restarting. Devices reconnect in a few seconds.' : serverSync.changed ? 'The server list was updated. It applies when the server restarts.' : 'The server already had every address.';
  } catch (e) { adoptMsg = e.message; await refreshServerSync(true); }
  adoptBusy = false; renderAdopt();
}

function adoptVendor(mac) {
  const hit = (deviceInventory?.devices || []).find(x => macKey(x.mac) === macKey(mac));
  return hit?.vendor || '';
}

function pendingCard(p) {
  const card = element('div', null, { class: 'adopt-card new' }), title = element('div', null, { class: 'adopt-title' });
  title.append(element('span', p.hostname || 'Unknown device'), element('span', 'Waiting for approval', { class: 'chip' }));
  const vendor = adoptVendor(p.mac);
  card.append(title, element('div', p.mac + (vendor ? ' · ' + vendor : '') + ' · asked ' + (p.attempts || 1) + (p.attempts > 1 ? ' times' : ' time') + (p.first ? ' · first seen ' + ago(p.first) : ''), { class: 'adopt-sub' }));
  const fixed = adoptFixed.get(p.mac) || { on: false, ip: '' }, row = element('div', null, { class: 'adopt-row' });
  const toggle = input('checkbox', '', 'Use a fixed IP address'), ip = element('input', null, { type: 'text', placeholder: '10.77.0.x', 'aria-label': 'Fixed IP address', size: 14 });
  toggle.checked = fixed.on; ip.value = fixed.ip; ip.hidden = !fixed.on;
  toggle.onchange = () => { adoptFixed.set(p.mac, { on: toggle.checked, ip: ip.value }); ip.hidden = !toggle.checked; if (toggle.checked) ip.focus(); };
  ip.oninput = () => adoptFixed.set(p.mac, { on: true, ip: ip.value });
  const lab = element('label'); lab.append(toggle, document.createTextNode('Use a fixed IP address'));
  const adopt = action('Adopt', () => adoptCall({ action: 'accept', mac: p.mac, name: p.hostname || '', ip: toggle.checked ? ip.value.trim() : '' }));
  const block = action('Block', () => adoptCall({ action: 'block', mac: p.mac, name: p.hostname || '' }));
  adopt.disabled = block.disabled = adoptBusy;
  row.append(lab, ip, adopt, block); card.append(row);
  return card;
}

function syncCard() {
  const accepted = accessState.accepted || [];
  if (!serverSync) return null;
  if (!serverSync.configured) {
    if (!accepted.length) return null;
    const card = element('div', null, { class: 'adopt-card warn' });
    card.append(element('div', 'The server has not been told about your adopted devices', { class: 'adopt-title' }),
      element('p', 'The server only forwards addresses it has been told about, so an adopted device will not get internet access until its address is added to the server. Set up server sync to do that automatically.', { class: 'adopt-note' }),
      (() => { const r = element('div', null, { class: 'adopt-row' }); r.append(action('Set up server sync', openServerSync)); return r; })());
    return card;
  }
  const missing = serverSync.missing || [];
  if (serverSync.error && !missing.length && !serverSync.restart_needed) {
    const card = element('div', null, { class: 'adopt-card bad' });
    card.append(element('div', 'Could not check the server', { class: 'adopt-title' }), element('p', serverSync.error, { class: 'adopt-note' }));
    const r = element('div', null, { class: 'adopt-row' }); r.append(action('Try again', async () => { await refreshServerSync(true); renderAdopt(); }), action('Server sync settings', openServerSync)); card.append(r);
    return card;
  }
  if (missing.length || serverSync.restart_needed) {
    const card = element('div', null, { class: 'adopt-card warn' });
    const names = missing.map(m => (m.name || m.mac || 'device') + ' (' + m.ip + ')').join(', ');
    card.append(element('div', missing.length ? missing.length + ' adopted device' + (missing.length > 1 ? 's' : '') + ' not on the server yet' : 'Restart the server to apply the new addresses', { class: 'adopt-title' }),
      element('p', (missing.length ? names + '. ' : '') + 'Restarting the server drops every device for a few seconds while it comes back.', { class: 'adopt-note' }));
    if (serverSync.error) card.append(element('p', serverSync.error, { class: 'adopt-note' }));
    const r = element('div', null, { class: 'adopt-row' });
    const both = action(missing.length ? 'Add to server and restart' : 'Restart server', () => adoptSync(true)), only = action('Add to server, restart later', () => adoptSync(false));
    both.disabled = only.disabled = adoptBusy; only.hidden = !missing.length; r.append(both, only); card.append(r);
    return card;
  }
  if ((serverSync.wanted || []).length && serverSync.checked_ago_s != null) {
    const card = element('div', null, { class: 'adopt-card ok' });
    card.append(element('div', 'The server knows all ' + serverSync.wanted.length + ' device address' + (serverSync.wanted.length > 1 ? 'es' : ''), { class: 'adopt-title' }));
    return card;
  }
  return null;
}

function renderAdopt() {
  if (adoptPanel.contains(document.activeElement) && document.activeElement.tagName === 'INPUT') return; // do not wipe what is being typed
  adoptPanel.replaceChildren();
  const pending = accessState.pending || [], mode = accessState.mode || 'closed';
  const head = element('div', null, { class: 'adopt-head' }), sel = element('select', null, { 'aria-label': 'How new devices are adopted' });
  for (const [v, t] of [['ask', 'Admin approval: I approve each new device'], ['auto', 'Automatic: adopt every new device'], ['closed', 'Closed: ignore new devices']]) sel.append(element('option', t, { value: v }));
  sel.value = mode; sel.disabled = adoptBusy;
  sel.onchange = () => adoptCall({ action: 'mode', mode: sel.value });
  head.append(element('h2', 'New devices'), sel); adoptPanel.append(head);
  if (pending.length) { for (const p of pending) adoptPanel.append(pendingCard(p)); }
  else adoptPanel.append(element('p', mode === 'ask' ? 'No new devices are waiting for approval.' : mode === 'auto' ? 'New devices are adopted as soon as they ask for an address, with the next free IP.' : 'New devices that ask for an address are listed but not adopted. Switch to admin approval to adopt them.', { class: 'adopt-note' }));
  const card = syncCard(); if (card) adoptPanel.append(card);
  if (adoptMsg) adoptPanel.append(element('p', adoptMsg, { class: 'adopt-note', role: 'status' }));
}

// Server sync settings.
const syncDialog = modal('serversyncdialog', 'Server sync'), syncUrl = element('input', null, { type: 'text', placeholder: 'https://203.0.113.5:8443', size: 40 }), syncPass = element('input', null, { type: 'password', size: 40, autocomplete: 'off' }), syncPin = element('input', null, { type: 'text', placeholder: 'AB:CD:… (SHA-256 of the portal certificate)', size: 40 });
const syncMsg = element('p', '', { role: 'status', class: 'adopt-note' });
const adoptField = (label, el) => { const w = element('label', null, { class: 'adopt-field' }); w.append(element('span', label), el); return w; };
syncDialog.append(element('p', 'The server only forwards device addresses it has been told about. Give the client the server admin portal so it can add them for you. The portal certificate is normally self-signed, so paste its SHA-256 fingerprint to be sure the client is talking to your server.', { class: 'help' }),
  adoptField('Portal address', syncUrl), adoptField('Admin password', syncPass), adoptField('Certificate fingerprint (SHA-256)', syncPin), syncMsg);
const syncSave = action('Save and test', async () => {
  syncMsg.textContent = 'Logging in…';
  try { await api('server-admin', 'POST', { url: syncUrl.value.trim(), password: syncPass.value, tls_sha256: syncPin.value.trim() }); syncPass.value = ''; syncMsg.textContent = 'Saved. The login worked.'; await refreshServerSync(true); renderAdopt(); }
  catch (e) { syncMsg.textContent = e.message; }
});
const syncClear = action('Remove', async () => { try { await api('server-admin', 'POST', { clear: true }); syncUrl.value = syncPin.value = syncPass.value = ''; syncMsg.textContent = 'Removed.'; await refreshServerSync(false); renderAdopt(); } catch (e) { syncMsg.textContent = e.message; } });
const syncRow = element('div', null, { class: 'adopt-row' }); syncRow.append(syncSave, syncClear); syncDialog.append(syncRow);
async function openServerSync() {
  try { const cur = await api('server-admin'); syncUrl.value = cur.url || ''; syncPin.value = cur.tls_sha256 || ''; syncPass.value = ''; syncPass.placeholder = cur.password_saved ? 'saved: leave empty to keep it' : ''; syncMsg.textContent = ''; } catch (e) { syncMsg.textContent = e.message; }
  showDialog('serversyncdialog');
}
document.querySelector('.network-actions').append(action('Server sync', openServerSync));

(async function adoptLoop() {
  const wantCheck = () => (accessState.accepted || []).length > 0 || (accessState.pending || []).length > 0;
  try { await refreshServerSync(false); if (wantCheck()) await refreshServerSync(true); } catch (e) { /* kept quiet: the panel shows the last state */ }
  renderAdopt();
  setInterval(async () => {
    if (!adoptBusy) { await refreshServerSync(wantCheck() && Date.now() - serverSyncCheckedAt > 30000); renderAdopt(); }
  }, 3000);
})();
