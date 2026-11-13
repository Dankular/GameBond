// Network Topology: a map of the exit server, bonded links, this PC and the devices behind it.
// Clicking a device opens its card. Devices that route through the tunnel have measured usage
// (current_status.device_usage); other LAN devices are listed but their traffic is not visible.
const topoStyle = document.createElement('style');
topoStyle.textContent = '.subtabs{display:flex;gap:6px;margin:8px 0 12px}.subtabs .seg.active{background:#0f7ae5;color:#fff}'
  + '.topo-head{text-align:center;font-size:20px;margin:6px 0 10px}.topo-head b{font-weight:500}.topo-head .good{color:#2fb800}.topo-head .fair{color:#f5a300}.topo-head .poor{color:#e0201b}'
  + '.topo-stats{display:flex;gap:10px;flex-wrap:wrap;margin:10px 0}.topo-stat{flex:1;min-width:110px;border:1px solid #e1e5eb;border-radius:10px;padding:8px 10px;text-align:center}.topo-stat strong{display:block;font-size:22px;font-weight:500}.topo-stat span{color:#7b8089}'
  + '.topo-svg{width:100%;height:auto;border:1px solid #e1e5eb;border-radius:10px;background:#fafbfc}.topo-node{cursor:pointer}.topo-node:focus{outline:none}.topo-node:hover rect,.topo-node:focus rect,.topo-node.sel rect{stroke:#0f7ae5;stroke-width:2}'
  + '.dev-card{border:1px solid #e1e5eb;border-radius:10px;padding:14px 16px;margin:14px 0}.dev-card h2{margin:0 0 2px;font-size:16px;display:flex;gap:10px;align-items:center}.dev-card .sub{color:#7b8089;margin:0 0 10px}'
  + '.chip{font-size:11px;border-radius:10px;padding:1px 8px;background:#e8edf3;color:#505762}.chip.good{background:#dff6d5;color:#2a7a00}.chip.poor{background:#fde0df;color:#a8120e}'
  + '.dev-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px}.dev-grid>div{min-width:0}.dev-grid h3{margin:0 0 6px;font-size:12px;text-transform:uppercase;color:#7b8089;font-weight:500}'
  + '.gauges{display:flex;gap:16px;align-items:center}.gauge{text-align:center}.gauge b{display:block;font-size:16px;font-weight:500}.gauge span{color:#7b8089}'
  + '.svc-row{display:grid;grid-template-columns:14px minmax(90px,1.2fr) 2fr 60px;gap:6px;align-items:center;margin:3px 0}.svc-row i{width:10px;height:10px;border-radius:50%;display:inline-block}.svc-bar{height:5px;border-radius:3px;background:#e8edf3;overflow:hidden}.svc-bar div{height:100%}'
  + '.range{display:flex;gap:4px;justify-content:flex-end;margin-bottom:4px}.range .seg.active{background:#0f7ae5;color:#fff}.notice{background:#f4f6f9;border-radius:8px;padding:10px 12px;color:#505762}';
topoStyle.textContent += '.tb-rect{fill:#fff;stroke:#cfd5dd}.tb-title{fill:#393b43}.tb-sub{fill:#7b8089}.tl{stroke:#aab2bd}.tl-label{fill:#505762}.g-bg{fill:#f4f6f9;stroke:#cfd5dd}.d-track{stroke:#e8edf3}.ax{stroke:#cfd5dd}';
document.head.append(topoStyle);

const SVGNS = 'http://www.w3.org/2000/svg';
function svg(tag, attributes = {}, text) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [key, value] of Object.entries(attributes)) el.setAttribute(key, value);
  if (text != null) el.textContent = text;
  return el;
}
function fmtBps(bps) {
  bps = Number(bps) || 0;
  if (bps >= 1e9) return (bps / 1e9).toFixed(2) + ' Gbps';
  if (bps >= 1e6) return (bps / 1e6).toFixed(bps >= 1e7 ? 1 : 2) + ' Mbps';
  if (bps >= 1e3) return (bps / 1e3).toFixed(1) + ' Kbps';
  return Math.round(bps) + ' bps';
}
function macKey(mac) { return String(mac || '').toLowerCase().replace(/[^0-9a-f]/g, ''); }
function ago(unix) {
  if (!unix) return '—';
  const s = Math.max(0, Date.now() / 1000 - unix);
  return s < 90 ? Math.round(s) + ' s ago' : s < 5400 ? Math.round(s / 60) + ' min ago' : s < 172800 ? (s / 3600).toFixed(1) + ' h ago' : Math.round(s / 86400) + ' d ago';
}

// Split the two views of the scanner tab: the existing device list, and the topology.
const topoPane = element('div'), devicesPane = element('div');
devicesPane.append(...Array.from(scanPanel.children).slice(1));
const subTabs = element('div', null, { class: 'subtabs', role: 'tablist' });
const subDevices = element('button', 'Devices', { class: 'seg active', role: 'tab' }), subTopology = element('button', 'Topology', { class: 'seg', role: 'tab' });
subTabs.append(subDevices, subTopology);
scanPanel.append(subTabs, devicesPane, topoPane);
let scannerSub = 'devices';
function showScannerSub(which) {
  scannerSub = which;
  devicesPane.hidden = which !== 'devices'; topoPane.hidden = which !== 'topology';
  subDevices.classList.toggle('active', which === 'devices'); subTopology.classList.toggle('active', which === 'topology');
  subDevices.setAttribute('aria-selected', which === 'devices'); subTopology.setAttribute('aria-selected', which === 'topology');
  if (which === 'topology') renderTopology();
}
subDevices.onclick = () => showScannerSub('devices');
subTopology.onclick = () => showScannerSub('topology');
showScannerSub('devices');

const topoHead = element('div', null, { class: 'topo-head', role: 'status' });
const topoStats = element('div', null, { class: 'topo-stats' });
const topoMap = svg('svg', { class: 'topo-svg', viewBox: '0 0 1060 360', role: 'group', 'aria-label': 'Network topology' });
const topoCard = element('div');
topoPane.append(topoHead, topoStats, topoMap, topoCard);

let selectedDevice = null, usageRange = 60;
const linkRates = new Map(); // slot -> { at, tx, rx, txBps, rxBps }

function updateLinkRates(paths) {
  const now = Date.now();
  for (const p of paths) {
    const prev = linkRates.get(p.slot), tx = Number(p.wire_tx_bytes) || 0, rx = Number(p.wire_rx_bytes) || 0;
    if (prev && now - prev.at >= 800) {
      const dt = (now - prev.at) / 1000;
      linkRates.set(p.slot, { at: now, tx, rx, txBps: Math.max(0, tx - prev.tx) * 8 / dt, rxBps: Math.max(0, rx - prev.rx) * 8 / dt });
    } else if (!prev) linkRates.set(p.slot, { at: now, tx, rx, txBps: 0, rxBps: 0 });
  }
}

// Build the node list: tunnel-routed devices (measured) and other LAN devices (not visible).
function topologyDevices() {
  const usage = current?.device_usage || {}, routed = [], seen = new Set();
  for (const d of current?.lan_devices || []) {
    const key = 'ip:' + d.tunnel_ip;
    if (d.device_mac) seen.add(macKey(d.device_mac));
    routed.push({ key, routed: true, name: d.name || d.tunnel_ip, ip: d.tunnel_ip, mac: d.device_mac || '', adapterMac: d.adapter_mac || '', up: d.up !== false && !d.error,
      present: d.present, leased: d.leased, silent: d.silent_s, error: d.error, lease: d.lease, usage: usage[d.tunnel_ip] || null });
  }
  const others = [];
  for (const d of deviceInventory?.devices || []) {
    if (d.mac && seen.has(macKey(d.mac))) continue;
    if (!d.reachable_now && d.state !== 'Reachable') continue;
    others.push({ key: 'lan:' + (d.mac || d.address), routed: false, name: d.hostname || d.vendor || d.address, ip: d.address, mac: d.mac || '', vendor: d.vendor || '', up: true,
      first: d.first_seen, last: d.last_seen });
  }
  return { routed, others: others.slice(0, 12), extra: Math.max(0, others.length - 12) };
}

function overallHealth(paths) {
  if (!paths.length) return ['poor', 'The tunnel is not connected'];
  const down = paths.filter(p => !p.healthy);
  if (!down.length) return ['good', 'Everything is great!'];
  if (down.length === paths.length) return ['poor', 'All links are down'];
  return ['fair', down.map(p => 'Link ' + (p.slot + 1)).join(', ') + (down.length > 1 ? ' are' : ' is') + ' down; running on the other line'];
}

function nodeBox(x, y, w, h, title, subtitle, state, onActivate, selected) {
  const g = svg('g', { class: 'topo-node' + (selected ? ' sel' : ''), transform: 'translate(' + x + ',' + y + ')' });
  const color = state === 'good' ? '#2fb800' : state === 'poor' ? '#e0201b' : state === 'fair' ? '#f5a300' : '#9aa1ab';
  g.append(svg('rect', { class: 'tb-rect', width: w, height: h, rx: 8 }), svg('circle', { cx: 12, cy: 14, r: 4, fill: color }),
    svg('text', { class: 'tb-title', x: 22, y: 18, 'font-size': 12 }, String(title).slice(0, 27)), svg('text', { class: 'tb-sub', x: 12, y: 36, 'font-size': 11 }, String(subtitle || '').slice(0, 26)));
  if (onActivate) {
    g.setAttribute('tabindex', '0'); g.setAttribute('role', 'button'); g.setAttribute('aria-label', title + (subtitle ? ', ' + subtitle : ''));
    g.onclick = onActivate; g.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onActivate(); } };
  }
  return g;
}
function mapLine(x1, y1, x2, y2, dashed, label) {
  const g = svg('g');
  g.append(svg('line', { class: 'tl', x1, y1, x2, y2, 'stroke-width': 2, 'stroke-dasharray': dashed ? '4 4' : '' }));
  if (label) g.append(svg('text', { x: (x1 + x2) / 2, y: (y1 + y2) / 2 - 5, 'font-size': 10, 'text-anchor': 'middle', class: 'tl-label' }, label));
  return g;
}

function renderTopology() {
  if (!current || current.state === 'unavailable' && !current.transport) { topoHead.textContent = 'Status unavailable'; return; }
  const paths = current?.transport?.paths || [], { routed, others, extra } = topologyDevices();
  updateLinkRates(paths);
  const [health, headline] = overallHealth(paths);
  topoHead.replaceChildren();
  if (health === 'good') { topoHead.append('Everything is ', element('b', 'great', { class: 'good' }), '!'); } else topoHead.append(element('b', headline, { class: health }));
  const totalRx = paths.reduce((s, p) => s + (linkRates.get(p.slot)?.rxBps || 0), 0), totalTx = paths.reduce((s, p) => s + (linkRates.get(p.slot)?.txBps || 0), 0);
  topoStats.replaceChildren();
  for (const [value, label] of [[paths.filter(p => p.healthy).length + '/' + paths.length, 'Links up'], [routed.length, 'Routed devices'], [others.length + (extra ? '+' : ''), 'Other LAN devices'], ['↓ ' + fmtBps(totalRx), 'Wire in (all links)'], ['↑ ' + fmtBps(totalTx), 'Wire out (all links)']]) {
    const box = element('div', null, { class: 'topo-stat' }); box.append(element('strong', String(value)), element('span', label)); topoStats.append(box);
  }

  topoMap.replaceChildren();
  const rowGap = 64, rows = Math.max(paths.length, routed.length + others.length, 2), height = 40 + rows * rowGap;
  topoMap.setAttribute('viewBox', '0 0 1060 ' + height);
  const midY = height / 2 - 24, serverX = 10, linkX = 215, pcX = 420, hubX = 625, devX = 850, w = 180, h = 46;
  const server = nodeBox(serverX, midY, w, h, 'Exit server', current?.peer ? current.peer[0] : '', health === 'poor' ? 'poor' : 'good');
  const pc = nodeBox(pcX, midY, w, h, 'This PC', 'GameBond client', 'good');
  topoMap.append(server, pc);
  const linkY0 = midY + h / 2 - (paths.length - 1) * rowGap / 2 - h / 2;
  paths.forEach((p, i) => {
    const y = linkY0 + i * rowGap, r = linkRates.get(p.slot) || {};
    topoMap.append(mapLine(serverX + w, midY + h / 2, linkX, y + h / 2, false), mapLine(linkX + w, y + h / 2, pcX, midY + h / 2, false));
    topoMap.append(nodeBox(linkX, y, w, h, 'Link ' + (p.slot + 1) + (p.slot === 0 ? ' · Ethernet' : p.slot === 1 ? ' · Hotspot' : ''), '↓ ' + fmtBps(r.rxBps) + '  ↑ ' + fmtBps(r.txBps) + (p.rtt_ms != null ? '  ' + Math.round(p.rtt_ms) + ' ms' : ''), p.healthy ? 'good' : 'poor'));
  });
  // Devices sharing one physical adapter (an access point or switch on it) hang off one adapter node,
  // so the traffic through that adapter is visible as a whole. Other LAN devices attach to the PC.
  const groups = new Map();
  for (const d of routed) { const k = d.adapterMac || 'unknown'; if (!groups.has(k)) groups.set(k, []); groups.get(k).push(d); }
  const hubs = [...groups].map(([mac, devices]) => ({ key: 'adapter:' + mac, mac, devices, name: 'LAN adapter', up: devices.some(d => d.up),
    down: devices.reduce((a, d) => a + (d.usage?.down_bps || 0), 0), upBps: devices.reduce((a, d) => a + (d.usage?.up_bps || 0), 0) }));
  const all = [...hubs.flatMap(g => g.devices), ...others], devY0 = midY + h / 2 - (all.length - 1) * rowGap / 2 - h / 2;
  const placed = new Map(all.map((d, i) => [d.key, devY0 + i * rowGap]));
  for (const hub of hubs) {
    const ys = hub.devices.map(d => placed.get(d.key)), hy = (Math.min(...ys) + Math.max(...ys)) / 2;
    topoMap.append(mapLine(pcX + w, midY + h / 2, hubX, hy + h / 2, false));
    topoMap.append(nodeBox(hubX, hy, w, h, hub.name + ' · ' + hub.devices.length + (hub.devices.length === 1 ? ' device' : ' devices'), '↓ ' + fmtBps(hub.down) + '  ↑ ' + fmtBps(hub.upBps), hub.up ? 'good' : 'poor', () => { selectedDevice = hub.key; renderTopology(); }, selectedDevice === hub.key));
    for (const d of hub.devices) {
      const y = placed.get(d.key);
      topoMap.append(mapLine(hubX + w, hy + h / 2, devX, y + h / 2, false));
      const sub = d.usage ? '↓ ' + fmtBps(d.usage.down_bps) + '  ↑ ' + fmtBps(d.usage.up_bps) : d.ip;
      topoMap.append(nodeBox(devX, y, w, h, d.name, sub, d.up && d.present !== false ? 'good' : 'poor', () => { selectedDevice = d.key; renderTopology(); }, selectedDevice === d.key));
    }
  }
  for (const d of others) {
    const y = placed.get(d.key);
    topoMap.append(mapLine(pcX + w, midY + h / 2, devX, y + h / 2, true));
    topoMap.append(nodeBox(devX, y, w, h, d.name, d.ip + ' · not routed', 'idle', () => { selectedDevice = d.key; renderTopology(); }, selectedDevice === d.key));
  }
  if (extra) topoMap.append(svg('text', { class: 'tb-sub', x: devX, y: height - 8, 'font-size': 11 }, '+' + extra + ' more LAN devices (see the Devices tab)'));
  if (!all.length) topoMap.append(svg('text', { class: 'tb-sub', x: devX, y: midY + 28, 'font-size': 12 }, 'No devices seen yet'));

  const hub = hubs.find(g => g.key === selectedDevice);
  if (hub) renderAdapterCard(hub); else renderDeviceCard(all.find(d => d.key === selectedDevice));
}

function renderAdapterCard(hub) {
  topoCard.replaceChildren();
  const card = element('div', null, { class: 'dev-card' }), title = element('h2', 'LAN adapter');
  title.append(element('span', hub.up ? 'Online' : 'Offline', { class: 'chip ' + (hub.up ? 'good' : 'poor') }));
  card.append(title, element('p', 'Adapter MAC ' + hub.mac + ' · everything below reaches the tunnel through this adapter (for example an access point and the devices connected to it).', { class: 'sub' }));
  const peakDown = Math.max(1, ...hub.devices.map(d => d.usage?.peak_down_bps || 0)), peakUp = Math.max(1, ...hub.devices.map(d => d.usage?.peak_up_bps || 0));
  const gauges = element('div', null, { class: 'gauges' });
  gauges.append(gauge('Download', hub.down, Math.max(peakDown, hub.down), '#2fb800'), gauge('Upload', hub.upBps, Math.max(peakUp, hub.upBps), '#0f7ae5'));
  const now = element('div'); now.append(element('h3', 'Combined usage'), gauges);
  const table = element('table'); table.innerHTML = '<thead><tr><th>Device</th><th>IP</th><th>Down now</th><th>Up now</th><th>Total down</th><th>Total up</th></tr></thead>';
  const body = element('tbody'); table.append(body);
  for (const d of hub.devices) {
    const tr = element('tr'), u = d.usage;
    cell(tr, d.name); cell(tr, d.ip); cell(tr, u ? fmtBps(u.down_bps) : '—'); cell(tr, u ? fmtBps(u.up_bps) : '—'); cell(tr, u ? bytes(u.down_bytes) : '—'); cell(tr, u ? bytes(u.up_bytes) : '—');
    tr.style.cursor = 'pointer'; tr.onclick = () => { selectedDevice = d.key; renderTopology(); }; body.append(tr);
  }
  const list = element('div'); list.append(element('h3', 'Devices behind it'), table);
  const grid = element('div', null, { class: 'dev-grid' }); grid.append(now, list); card.append(grid); topoCard.append(card);
}

const palette = ['#0f7ae5', '#2fb800', '#f5a300', '#9b59d0', '#e0201b', '#00a5b8', '#8c6d46', '#7b8089'];
function renderDeviceCard(d) {
  topoCard.replaceChildren();
  if (!d) { topoCard.append(element('p', 'Select a device on the map to see its details, current usage and history.', { class: 'sub' })); return; }
  const card = element('div', null, { class: 'dev-card' });
  const title = element('h2', d.name); title.append(element('span', d.up ? (d.routed ? 'Online · routed through GameBond' : 'Online · local network only') : 'Offline', { class: 'chip ' + (d.up ? 'good' : 'poor') }));
  card.append(title, element('p', d.ip + (d.mac ? ' · ' + d.mac : ''), { class: 'sub' }));
  const grid = element('div', null, { class: 'dev-grid' });

  const details = element('div'); details.append(element('h3', 'Device'));
  const table = element('table'), body = element('tbody'); table.append(body);
  const rows = d.routed
    ? [['Tunnel IP', d.ip], ['Device MAC', d.mac || 'not seen yet'], ['LAN adapter MAC', d.adapterMac || '—'], ['DHCP lease', d.leased ? 'Leased' : 'Not leased'], ['Last frame', d.silent != null ? Number(d.silent).toFixed(1) + ' s ago' : '—'], ['Problem', d.error || 'None'],
      ['First seen (usage)', d.usage ? deviceStamp(d.usage.first_seen) : '—'], ['Last traffic', d.usage ? ago(d.usage.last_seen) : '—']]
    : [['IP', d.ip], ['MAC', d.mac || '—'], ['Vendor', d.vendor || '—'], ['First seen', deviceStamp(d.first)], ['Last seen', deviceStamp(d.last)], ['Route', 'Local network (not through GameBond)']];
  for (const [k, v] of rows) { const tr = element('tr'); cell(tr, k); cell(tr, v); body.append(tr); }
  details.append(table); grid.append(details);

  if (!d.routed || !d.usage) {
    const note = element('div'); note.append(element('h3', 'Usage'),
      element('p', d.routed ? 'No traffic from this device has crossed the tunnel yet.' : 'Traffic for this device is not visible. It talks to the network directly and never passes through the GameBond tunnel, so there is nothing to measure. Only devices routed through a GameBond LAN adapter have usage data.', { class: 'notice' }));
    grid.append(note); card.append(grid); topoCard.append(card); return;
  }
  const u = d.usage, peakDown = Math.max(u.peak_down_bps || 0, u.down_bps || 0), peakUp = Math.max(u.peak_up_bps || 0, u.up_bps || 0);
  const now = element('div'); now.append(element('h3', 'Current usage'));
  const gauges = element('div', null, { class: 'gauges' });
  gauges.append(gauge('Download', u.down_bps, peakDown, '#2fb800'), gauge('Upload', u.up_bps, peakUp, '#0f7ae5'));
  now.append(gauges, element('p', 'Total ↓ ' + bytes(u.down_bytes) + ' · ↑ ' + bytes(u.up_bytes) + ' · ' + (Number(u.down_packets) + Number(u.up_packets)).toLocaleString() + ' packets', { class: 'sub' }));
  grid.append(now);

  const svcs = u.services || [], total = svcs.reduce((s, r) => s + r.up_bytes + r.down_bytes, 0) || 1;
  const apps = element('div'); apps.append(element('h3', 'Apps and services'), donut(svcs, total));
  svcs.slice(0, 8).forEach((r, i) => {
    const part = r.up_bytes + r.down_bytes, row = element('div', null, { class: 'svc-row' }), dot = element('i'), bar = element('div', null, { class: 'svc-bar' }), fill = element('div');
    dot.style.background = palette[i % palette.length]; fill.style.width = Math.max(2, part / total * 100) + '%'; fill.style.background = palette[i % palette.length]; bar.append(fill);
    row.append(dot, element('span', r.service), bar, element('span', bytes(part), { title: '↓ ' + bytes(r.down_bytes) + ' ↑ ' + bytes(r.up_bytes) })); apps.append(row);
  });
  grid.append(apps); card.append(grid);

  const hist = element('div'); hist.append(element('h3', 'History'));
  const range = element('div', null, { class: 'range' });
  for (const [label, minutes] of [['1 h', 60], ['6 h', 360], ['24 h', 1440]]) {
    const b = element('button', label, { class: 'seg' + (usageRange === minutes ? ' active' : '') }); b.onclick = () => { usageRange = minutes; renderTopology(); }; range.append(b);
  }
  hist.append(range, historyChart(u.history || [], usageRange)); card.append(hist);

  const ports = element('div'); ports.append(element('h3', 'Ports (remote side)'));
  const pt = element('table'); pt.innerHTML = '<thead><tr><th>Proto</th><th>Port</th><th>Service</th><th>Down</th><th>Up</th><th>Packets</th></tr></thead>';
  const pb = element('tbody'); pt.append(pb);
  for (const r of (u.ports || []).slice(0, 12)) { const tr = element('tr'); cell(tr, String(r.proto).toUpperCase()); cell(tr, r.port || '—'); cell(tr, r.service || '—'); cell(tr, bytes(r.down_bytes)); cell(tr, bytes(r.up_bytes)); cell(tr, (r.packets || 0).toLocaleString()); pb.append(tr); }
  ports.append(pt);
  const hosts = element('p', 'Top remote hosts: ' + ((u.remotes || []).slice(0, 5).map(r => r.ip + ' (' + bytes(r.bytes) + ')').join(', ') || '—'), { class: 'sub' });
  ports.append(hosts, element('p', 'Services are inferred from the remote port; the port table counts traffic since the client started, history persists for 24 hours.', { class: 'sub' }));
  card.append(ports); topoCard.append(card);
}

function gauge(label, bps, peak, color) {
  const box = element('div', null, { class: 'gauge' }), s = svg('svg', { width: 84, height: 84, viewBox: '0 0 84 84', role: 'img', 'aria-label': label + ' ' + fmtBps(bps) });
  const id = 'gc' + label, scale = Math.max(peak, 1e6), level = Math.min(1, (bps || 0) / scale), h = 76 * level;
  const clip = svg('clipPath', { id }); clip.append(svg('circle', { cx: 42, cy: 42, r: 38 }));
  s.append(clip, svg('circle', { class: 'g-bg', cx: 42, cy: 42, r: 38, 'stroke-width': 2 }),
    svg('rect', { x: 4, y: 80 - h, width: 76, height: h, fill: color, 'fill-opacity': 0.35, 'clip-path': 'url(#' + id + ')' }));
  box.append(s, element('b', fmtBps(bps)), element('span', label + ' · peak ' + fmtBps(peak)));
  return box;
}
function donut(rows, total) {
  const s = svg('svg', { width: 110, height: 110, viewBox: '0 0 110 110', role: 'img', 'aria-label': 'Traffic by service' }), r = 40, c = 2 * Math.PI * r;
  s.append(svg('circle', { class: 'd-track', cx: 55, cy: 55, r, fill: 'none', 'stroke-width': 16 }));
  let offset = 0;
  rows.slice(0, 8).forEach((row, i) => {
    const len = (row.up_bytes + row.down_bytes) / total * c;
    s.append(svg('circle', { cx: 55, cy: 55, r, fill: 'none', stroke: palette[i % palette.length], 'stroke-width': 16, 'stroke-dasharray': len + ' ' + (c - len), 'stroke-dashoffset': -offset, transform: 'rotate(-90 55 55)' }));
    offset += len;
  });
  return s;
}
// Minute triples [unix, up, down] -> bars of Mbps over the last `minutes`.
function historyChart(history, minutes) {
  const width = 520, height = 150, left = 36, bottom = 18, bins = Math.min(minutes, 60), binMinutes = minutes / bins;
  const nowMin = Math.floor(Date.now() / 60000), start = nowMin - minutes + 1, up = new Array(bins).fill(0), down = new Array(bins).fill(0);
  for (const [t, u, d] of history) {
    const m = Math.floor(t / 60) - start; if (m < 0 || m >= minutes) continue;
    const i = Math.min(bins - 1, Math.floor(m / binMinutes)); up[i] += u; down[i] += d;
  }
  const secs = binMinutes * 60, upM = up.map(v => v * 8 / secs), downM = down.map(v => v * 8 / secs);
  const top = Math.max(1e5, ...upM, ...downM) * 1.1, plot = height - bottom, bw = (width - left) / bins;
  const s = svg('svg', { class: 'topo-svg', viewBox: '0 0 ' + width + ' ' + height, role: 'img', 'aria-label': 'Usage history' });
  s.style.maxWidth = '720px';
  s.append(svg('line', { class: 'ax', x1: left, y1: plot, x2: width, y2: plot }), svg('text', { class: 'tb-sub', x: 2, y: 12, 'font-size': 10 }, fmtBps(top)), svg('text', { class: 'tb-sub', x: 2, y: plot, 'font-size': 10 }, '0'),
    svg('text', { class: 'tb-sub', x: left, y: height - 4, 'font-size': 10 }, minutes >= 60 ? '-' + (minutes / 60) + ' h' : '-' + minutes + ' min'), svg('text', { class: 'tb-sub', x: width, y: height - 4, 'font-size': 10, 'text-anchor': 'end' }, 'Now'));
  for (let i = 0; i < bins; i++) {
    for (const [v, color] of [[downM[i], '#2fb800'], [upM[i], '#0f7ae5']]) {
      const bh = v / top * (plot - 14); if (bh < 0.5) continue;
      const bar = svg('rect', { x: left + i * bw + 0.5, y: plot - bh, width: Math.max(1, bw - 1), height: bh, fill: color, 'fill-opacity': 0.55 });
      bar.append(svg('title', {}, fmtBps(v))); s.append(bar);
    }
  }
  return s;
}

setInterval(() => { if (scannerSub === 'topology' && $('scanner').classList.contains('active')) renderTopology(); }, 1000);
const selectTabBeforeTopology = selectTab;
selectTab = function(id) { selectTabBeforeTopology(id); if (id === 'scanner' && scannerSub === 'topology') renderTopology(); };
