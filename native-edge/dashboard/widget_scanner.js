// Passive inventory is the default. Only Scan or opt-in Auto-scan starts ICMP.
const scanPanel = document.querySelector('#scanner .panel');
const adapterDetails = element('details'), adapterSummary = element('summary', 'Local adapter inventory');
adapterDetails.append(adapterSummary, scanPanel.querySelector('table'));
scanPanel.replaceChildren();
scanPanel.append(element('h1', 'Network Scanner'));
const scanToolbar = element('div', null, { class: 'row' });
const scanAdapter = element('select', null, { 'aria-label': 'Discovery adapter' });
const scanSubnet = input('text', '', 'Discovery subnet', { placeholder: '192.168.1.0/24' });
const scanButton = action('Scan', startDeviceScan);
const cancelScanButton = action('Cancel scan', cancelDeviceScan);
const scanRefresh = action('Refresh cached devices', () => refreshDeviceInventory(true));
const scanSearch = input('search', '', 'Search devices', { placeholder: 'Search' });
const scanAuto = input('checkbox', '', 'Auto-scan');
const scanAutoLabel = element('label', ' Auto-scan (60 seconds)'); scanAutoLabel.prepend(scanAuto);
scanToolbar.append(scanAdapter, scanSubnet, scanButton, cancelScanButton, scanRefresh, scanSearch, scanAutoLabel);
const scanStatus = element('p', 'Open this tab to read the local neighbor cache.', { role: 'status' });
const scanProgress = element('progress', null, { max: 1, value: 0, 'aria-label': 'Discovery progress' });
const scanTable = element('table');
scanTable.innerHTML = '<thead><tr><th>State</th><th>Type</th><th>Name</th><th>Description</th><th>Location</th><th>System</th><th>IP</th><th>MAC Address</th><th>Last Seen</th><th>First Seen</th></tr></thead>';
const scanRows = element('tbody'); scanTable.append(scanRows);
scanPanel.append(scanToolbar, scanProgress, scanStatus, scanTable, element('p', 'Passive entries come from the local neighbor cache. Scan sends one source-bound ICMP request per address on the selected private subnet (up to 256). Devices can block ICMP; no response does not prove they are offline.', { class: 'help' }), adapterDetails);
let deviceInventory = null, discoveryJob = null, scannerBusy = false, scanPollBusy = false, autoScanAt = 0;
function scanRunning() { return discoveryJob?.state === 'running' || discoveryJob?.state === 'ready'; }
function scanControls() {
  const busy = scannerBusy || scanRunning();
  scanAdapter.disabled = busy; scanSubnet.disabled = busy; scanButton.disabled = busy || !scanAdapter.value;
  scanRefresh.disabled = busy; cancelScanButton.disabled = !scanRunning();
  scanProgress.hidden = !discoveryJob;
  scanProgress.max = Math.max(1, discoveryJob?.total || 1); scanProgress.value = discoveryJob?.completed || 0;
}
function discoveryAdapter() { return deviceInventory?.adapters?.find(a => a.index + ':' + a.address === scanAdapter.value); }
scanAdapter.onchange = () => { scanSubnet.value = discoveryAdapter()?.discovery_subnet || ''; renderDevices(); scanControls(); };
scanSearch.oninput = renderDevices;
function deviceStamp(value) { return value ? new Date(value * 1000).toLocaleString() : '—'; }
function renderDevices() {
  const adapter = discoveryAdapter(), filter = scanSearch.value.trim().toLowerCase();
  const rows = (deviceInventory?.devices || []).filter(d => !adapter || d.interface_index === adapter.index).map(d => ({ ...d }));
  if (discoveryJob && (!adapter || discoveryJob.interface_index === adapter.index)) for (const result of discoveryJob.results || []) {
    if (!result.responded) continue;
    let row = rows.find(d => d.address === result.address);
    if (!row) { row = { address: result.address, first_seen: discoveryJob.started_at }; rows.push(row); }
    row.reachable_now = true; row.rtt_ms = result.rtt_ms; row.last_seen = discoveryJob.finished_at || discoveryJob.started_at;
  }
  scanRows.replaceChildren();
  for (const row of rows) {
    if (filter && ![row.address, row.mac, row.hostname, row.vendor, row.description, row.location, row.system].some(v => String(v || '').toLowerCase().includes(filter))) continue;
    const tr = element('tr');
    const state = row.rtt_ms != null ? 'ICMP ' + row.rtt_ms + ' ms' : row.reachable_now ? 'Reachable' : 'Cached';
    for (const value of [state, row.type || '—', row.hostname || 'Unavailable', row.description || '', row.location || '', row.system || '', row.address, row.mac || '—', deviceStamp(row.last_seen), deviceStamp(row.first_seen)]) cell(tr, value);
    scanRows.append(tr);
  }
  if (!scanRows.children.length) { const tr = element('tr'), td = element('td', filter ? 'No matching devices.' : 'No devices observed on this adapter yet.'); td.colSpan = 10; tr.append(td); scanRows.append(tr); }
}
function renderScanStatus() {
  if (discoveryJob) {
    const answered = (discoveryJob.results || []).filter(r => r.responded).length;
    scanStatus.textContent = discoveryJob.state + ' · ' + discoveryJob.completed + '/' + discoveryJob.total + ' tested · ' + answered + ' ICMP responses' + (discoveryJob.errors?.length ? ' · ' + discoveryJob.errors[0] : '');
  } else scanStatus.textContent = 'Passive inventory: ' + (deviceInventory?.devices?.length || 0) + ' cached devices · no active scan started';
  if (deviceInventory?.coverage?.neighbor_limit_reached || deviceInventory?.coverage?.adapter_limit_reached) scanStatus.textContent += ' · Inventory limit reached; results are incomplete.';
  renderDevices(); scanControls();
}
async function refreshDeviceInventory(force = false) {
  if (scannerBusy || scanRunning()) return;
  scannerBusy = true; scanControls(); scanStatus.textContent = 'Reading local adapters and neighbor cache…';
  try {
    const result = await api('scanner' + (force ? '?refresh=1' : ''));
    const previous = scanAdapter.value, previousSubnet = scanSubnet.value;
    deviceInventory = result.inventory; discoveryJob = result.job;
    scanAdapter.replaceChildren();
    for (const adapter of deviceInventory.adapters || []) if (adapter.up) scanAdapter.append(element('option', adapter.name + ' — ' + adapter.address, { value: adapter.index + ':' + adapter.address }));
    if (Array.from(scanAdapter.options).some(o => o.value === previous)) scanAdapter.value = previous;
    scanSubnet.value = scanAdapter.value === previous ? previousSubnet : discoveryAdapter()?.discovery_subnet || '';
    renderScanStatus();
  } catch (e) { scanStatus.textContent = e.message; scanAuto.checked = false; }
  finally { scannerBusy = false; scanControls(); }
}
async function startDeviceScan() {
  if (scannerBusy || scanRunning()) return;
  const adapter = discoveryAdapter(); if (!adapter) return;
  scannerBusy = true; scanControls(); scanStatus.textContent = 'Validating local adapter and subnet…';
  try {
    discoveryJob = (await api('scanner', 'POST', { action: 'start', subnet: scanSubnet.value.trim(), source: adapter.address, interface_index: adapter.index })).job;
    autoScanAt = Date.now() + 60000; renderScanStatus();
  } catch (e) { scanStatus.textContent = e.message; scanAuto.checked = false; }
  finally { scannerBusy = false; scanControls(); }
}
async function cancelDeviceScan() {
  scanAuto.checked = false;
  try { await api('scanner', 'POST', { action: 'cancel' }); scanStatus.textContent = 'Cancelling discovery…'; }
  catch (e) { scanStatus.textContent = e.message; }
}
scanAuto.onchange = () => { if (scanAuto.checked) startDeviceScan(); };
const selectTabBeforeScanner = selectTab;
selectTab = function(id) { selectTabBeforeScanner(id); if (id === 'scanner') refreshDeviceInventory(); };
setInterval(async () => {
  if (scanPollBusy || scannerBusy) return;
  if (scanRunning()) {
    scanPollBusy = true;
    try {
      const result = await api('scanner?job=1'); discoveryJob = result.job; renderScanStatus();
      if (!scanRunning()) await refreshDeviceInventory(true);
      if (result.history_error) scanStatus.textContent += ' · History: ' + result.history_error;
    }
    catch (e) { scanStatus.textContent = e.message; scanAuto.checked = false; }
    finally { scanPollBusy = false; }
  }
  if (scanAuto.checked && !scanRunning() && Date.now() >= autoScanAt) startDeviceScan();
}, 500);
scanControls();
