// Setup: one list of the computer's network adapters, and for each one what it is for. An adapter is either an
// internet connection for the tunnel (primary, secondary or backup), a device that shares the VPN (a PS5, for
// example) through its own cable, or not used. It replaces going through "Select networks", "Link roles and
// limits" and "Connected devices" one after another; those stay under Settings for the finer detail.
//
// Roles, as the bonding code treats them (Core bond/sender.go): traffic goes over the primary links; if no primary
// link is usable, over the secondary links; if none of those, over the backup links. A link set to never is not used.
const setupStyle = document.createElement('style');
setupStyle.textContent = [
  '.setup-row{border:1px solid #e1e5eb;border-radius:10px;padding:10px 12px;margin:8px 0}.setup-row.use{border-color:#9cc3f5;background:#f5f9ff}.setup-row.dev{border-color:#bfe5b0;background:#f6fcf2}',
  '.setup-head{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.setup-head b{min-width:140px}.setup-head small{color:#7b8490;flex:1;min-width:160px}.setup-head select{padding:5px 8px;border:1px solid #cfd5dd;border-radius:6px}',
  '.setup-dev[hidden]{display:none}.setup-dev{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:8px 12px;margin-top:8px}.setup-dev label{display:block;font-size:11px;color:#6b7480;margin-bottom:2px}.setup-dev input{width:100%}',
  '.setup-tag{font-size:11px;background:#e7f4e1;color:#2a6a1c;border-radius:10px;padding:2px 8px}.setup-note{color:#505762;font-size:12px;margin:6px 0}.setup-bad{color:#c0392b}.setup-ok{color:#00a66c}',
  'html[data-theme=dark] .setup-row{border-color:#3a404b}html[data-theme=dark] .setup-row.use{background:#17202e;border-color:#2f568f}html[data-theme=dark] .setup-row.dev{background:#17261a;border-color:#2f5a38}html[data-theme=dark] .setup-head small,html[data-theme=dark] .setup-dev label,html[data-theme=dark] .setup-note{color:#aab2bd}html[data-theme=dark] .setup-head select{background:#1b1e24;border-color:#343a44;color:#d7dae0}html[data-theme=dark] .setup-tag{background:#1f3a28;color:#7ddc9a}'
].join('');
document.head.append(setupStyle);

const setupDialog = modal('setupdialog', 'Setup'), setupBody = element('div');
setupDialog.append(setupBody);
let setupData = null, setupRows = [], setupMsg = '', setupBad = false;

const SETUP_USES = [['off', 'Not used'], ['primary', 'Internet: primary'], ['secondary', 'Internet: secondary'], ['backup', 'Internet: backup'], ['device', 'Share the VPN with a device']];
const setupSame = (a, b) => String(a || '').toLowerCase() === String(b || '').toLowerCase();

async function setupLoad(keepMessage) {
  if (keepMessage !== true) { setupMsg = ''; setupBad = false; }
  try {
    const [nets, links, lan] = await Promise.all([api('networks'), api('links'), api('lan-devices')]);
    setupData = { nets, links, lan };
  } catch (e) { setupData = null; setupMsg = e.message; setupBad = true; }
  setupRender();
}

function setupRender() {
  setupBody.replaceChildren(); setupRows = [];
  if (!setupData) { setupBody.append(element('p', setupMsg || 'Loading…', { class: setupBad ? 'setup-bad' : 'setup-note' })); return; }
  const { nets, links, lan } = setupData, saved = lan.lan_devices || [], policies = links.link_policies || {};
  const confirmed = (lan.ps5_adapters || []).filter(a => a.confirmed);
  setupBody.append(element('p', 'Pick what each of this computer\'s network adapters is for. Internet connections carry the tunnel; a device adapter gives a console or other device its own cable into the VPN.', { class: 'setup-note' }));

  const adapters = [...(nets.adapters || [])];
  for (const old of saved) if (!adapters.some(a => setupSame(a.id, old.interface_id))) adapters.push({ id: old.interface_id, index: old.interface_index || 0, name: old.name + ' (offline)', up: false, addresses: [], gateway: '' });
  const selectedIDs = (nets.interface_ids || []).map(String), selectedIdx = nets.interface_indices || [];
  const isUplink = a => selectedIdx.some((index, slot) => selectedIDs[slot] ? setupSame(selectedIDs[slot], a.id) : index === a.index);
  const taken = new Set([lan.client_tunnel_ip || '10.77.0.2', ...saved.map(d => d.tunnel_ip)]);
  const prefix = (lan.client_tunnel_ip || '10.77.0.2').split('.').slice(0, 3).join('.');
  const nextAddress = () => { for (let i = 3; i < 255; i++) { const ip = prefix + '.' + i; if (!taken.has(ip)) { taken.add(ip); return ip; } } return ''; };

  for (const adapter of adapters) {
    const stored = saved.find(d => setupSame(d.interface_id, adapter.id));
    const policy = policies[String(adapter.index)];
    const ps5 = confirmed.length === 1 && confirmed.some(a => setupSame(a.id, adapter.id));
    let use = 'off';
    if (isUplink(adapter)) use = policy && policy.role !== 'never' ? policy.role : 'primary';
    else if (stored) use = 'device';
    const card = element('div', null, { class: 'setup-row' });
    const head = element('div', null, { class: 'setup-head' });
    const select = element('select', null, { 'aria-label': 'Use for ' + adapter.name });
    for (const [v, text] of SETUP_USES) select.append(element('option', text, { value: v }));
    select.value = use;
    head.append(element('b', adapter.name + (adapter.up ? '' : ' (offline)')), element('small', [adapter.addresses?.join(', '), adapter.gateway ? 'gateway ' + adapter.gateway : ''].filter(Boolean).join(' · ') || 'no address'));
    if (ps5 && !stored) head.append(element('span', 'Looks like the PS5 adapter (UGREEN USB Ethernet)', { class: 'setup-tag' }));
    head.append(select); card.append(head);
    const dev = element('div', null, { class: 'setup-dev' });
    const mk = (label, value, aria, attrs) => { const w = element('div'), l = element('label', label), i = input('text', value, aria, attrs); w.append(l, i); dev.append(w); return i; };
    const name = mk('Device name', stored?.name || (ps5 ? 'PS5' : ''), 'Device name', { maxlength: 32, placeholder: 'for example PS5' });
    const ip = mk('Tunnel address', stored?.tunnel_ip || '', 'Device tunnel address');
    const mac = mk('MAC filter (optional)', stored?.device_mac || '', 'Device MAC address');
    const note = element('p', 'The device gets its address from this computer\'s DHCP. To filter its DNS for ads and trackers whatever DNS it uses, turn on “Send every device\'s DNS to the filter” under Network Scanner, Security, Firewall.', { class: 'setup-note' });
    card.append(dev, note);
    const show = () => { card.className = 'setup-row' + (select.value === 'device' ? ' dev' : select.value === 'off' ? '' : ' use'); dev.hidden = note.hidden = select.value !== 'device'; if (select.value === 'device' && !ip.value) ip.value = nextAddress(); };
    select.onchange = show; show();
    setupRows.push({ adapter, stored, policy, select, name, ip, mac });
    setupBody.append(card);
  }
  if (!adapters.length) setupBody.append(element('p', nets.adapter_error || 'No network adapters were found.', { class: 'setup-note' }));

  setupBody.append(element('p', 'Primary links carry your traffic together. If none is usable the secondary links are used, and if none of those the backup links. Changes apply the next time you connect.', { class: 'setup-note' }));
  const bar = element('div', null, { class: 'row' }), msg = element('span', setupMsg, { class: setupBad ? 'setup-bad' : 'setup-ok', role: 'status' });
  const save = action('Save setup', async () => { msg.textContent = 'Saving…'; msg.className = 'setup-note'; try { await setupSave(); setupMsg = 'Saved. Reconnect to apply.'; setupBad = false; await setupLoad(true); } catch (e) { setupMsg = e.message; setupBad = true; msg.textContent = e.message; msg.className = 'setup-bad'; } });
  bar.append(save, action('Refresh adapters', () => setupLoad()), msg);
  setupBody.append(bar);
}

async function setupSave() {
  const { lan, links, nets } = setupData;
  const rows = setupRows.map(r => ({ ...r, use: r.select.value }));
  const internet = rows.filter(r => ['primary', 'secondary', 'backup'].includes(r.use));
  const devices = rows.filter(r => r.use === 'device');
  if (!internet.length) throw new Error('Choose at least one adapter as an internet connection.');
  const names = new Set(), addrs = new Set();
  for (const d of devices) {
    const name = d.name.value.trim(), ip = d.ip.value.trim();
    if (!name) throw new Error('Give the device on ' + d.adapter.name + ' a name.');
    if (names.has(name.toLowerCase())) throw new Error('Two devices are called ' + name + '.');
    if (addrs.has(ip)) throw new Error('Two devices have the address ' + ip + '.');
    names.add(name.toLowerCase()); addrs.add(ip);
  }
  const deviceOf = d => ({ ...d.stored, name: d.name.value.trim(), tunnel_ip: d.ip.value.trim(), interface_id: d.adapter.id, interface_index: d.adapter.index, device_mac: d.mac.value.trim(), dns: d.stored?.dns || ['1.1.1.1', '8.8.8.8'] });
  const final = devices.map(deviceOf);
  // An adapter cannot be an internet link and a device at once, and each save checks the other list, so devices
  // that are changing sides are removed first, then the internet links are saved, then the devices.
  const wasUplink = a => (nets.interface_indices || []).some((index, slot) => nets.interface_ids?.[slot] ? setupSame(nets.interface_ids[slot], a.id) : index === a.index);
  const first = final.filter(d => !wasUplink({ id: d.interface_id, index: d.interface_index }));
  const previous = JSON.stringify(lan.lan_devices || []);
  if (JSON.stringify(first) !== previous) await api('lan-devices', 'PUT', first);
  await api('networks', 'PUT', internet.map(r => ({ index: r.adapter.index, id: r.adapter.id })));
  if (JSON.stringify(final) !== JSON.stringify(first)) await api('lan-devices', 'PUT', final);
  const policies = { ...(links.link_policies || {}) };
  for (const r of internet) policies[String(r.adapter.index)] = { role: 'primary', upload_mbps: 0, download_mbps: 0, daily_bytes: 0, monthly_bytes: 0, reset_day: 1, overlimit: 'stop', overlimit_mbps: .2, ...r.policy, role: r.use };
  await api('links', 'PUT', policies);
}

async function openSetup() { setupMsg = ''; showDialog('setupdialog'); await setupLoad(); }
const setupChip = action('Setup', openSetup);
document.querySelector('.network-actions').prepend(setupChip);
settingsMenu.prepend(action('Setup: connections and devices', () => { settingsDialog.close(); openSetup(); }));
