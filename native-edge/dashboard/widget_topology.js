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
topoStyle.textContent += '.tf{fill:none;stroke-linecap:round;stroke-dasharray:5 11;pointer-events:none;stroke-width:calc(2px + 2.5px*var(--i))}.tf.down{stroke:#2fb800;--c:47,184,0}.tf.up{stroke:#0f7ae5;--c:15,122,229}.tf-halo{fill:none;stroke-linecap:round;pointer-events:none;stroke-width:calc(4px + 10px*var(--i));opacity:calc(.08 + .22*var(--i));filter:blur(calc(1px + 3px*var(--i)))}.tf-halo.down{stroke:#2fb800}.tf-halo.up{stroke:#0f7ae5}@keyframes tf-fwd{from{stroke-dashoffset:16}to{stroke-dashoffset:0}}@keyframes tf-rev{from{stroke-dashoffset:0}to{stroke-dashoffset:16}}@keyframes tf-glow{0%,100%{opacity:calc(.5 + .25*var(--i));filter:drop-shadow(0 0 calc(1px + 3px*var(--i)) rgb(var(--c)))}50%{opacity:1;filter:drop-shadow(0 0 calc(3px + 9px*var(--i)) rgb(var(--c)))}}@keyframes tf-halo-pulse{0%,100%{opacity:calc(.05 + .15*var(--i))}50%{opacity:calc(.12 + .35*var(--i))}}@media (prefers-reduced-motion:reduce){.tf,.tf-halo{animation:none!important}}';
topoStyle.textContent += '.port-active{color:#00a66c;font-weight:600}.gl{stroke:#e8edf3;stroke-width:1}'
  + '.topo-pies{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:12px;margin:14px 0}.pie-card{border:1px solid #e1e5eb;border-radius:10px;padding:10px 14px;min-width:0}.pie-card h3{margin:0 0 6px;font-size:12px;text-transform:uppercase;color:#7b8089}'
  + '.pie-body{display:flex;gap:14px;align-items:center}.pie-svg{width:128px;height:128px;flex:none}.pie-track{stroke:#e8edf3}.pie-num{fill:#393b43;font-weight:600}.pie-legend{flex:1;min-width:0;font-size:12px}'
  + '.pie-legend div{display:grid;grid-template-columns:12px minmax(0,1fr) auto;gap:6px;align-items:center;margin:2px 0}.pie-legend i{width:9px;height:9px;border-radius:2px;display:inline-block}.pie-legend span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.pie-legend b{font-weight:500;color:#505762}'
  + '.pie-card .sub{color:#7b8089;font-size:11px;margin:6px 0 0}.tp-panel{margin:6px 0 10px}.tp-panel h4{margin:0 0 2px;font-size:12px;color:#505762;font-weight:600}.tp-legend{display:flex;gap:14px;flex-wrap:wrap;color:#7b8089;font-size:11px;margin:2px 0}.tp-legend i{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}';
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
const topoPies = element('div', null, { class: 'topo-pies' });
topoPane.append(topoHead, topoStats, topoMap, topoPies, topoCard);

let selectedDevice = null, usageRange = 60;
const linkRates = new Map(); // slot -> { at, tx, rx, txBps, rxBps }
const exitRates = new Map(); // exit address -> { at, tx, rx, txBps, rxBps }

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

function updateExitRates(servers) {
  const now = Date.now();
  for (const x of servers) {
    const prev = exitRates.get(x.address), tx = Number(x.wire_tx_bytes) || 0, rx = Number(x.wire_rx_bytes) || 0;
    if (prev && now - prev.at >= 800) {
      const dt = (now - prev.at) / 1000;
      exitRates.set(x.address, { at: now, tx, rx, txBps: Math.max(0, tx - prev.tx) * 8 / dt, rxBps: Math.max(0, rx - prev.rx) * 8 / dt });
    } else if (!prev) exitRates.set(x.address, { at: now, tx, rx, txBps: 0, rxBps: 0 });
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

// activePorts summarises what a routed device is talking on right now: the remote-side ports that carried
// a packet within the last few seconds (the client marks them active). It reports only what the tunnel sees.
function activePorts(usage) {
  if (!usage) return { line: '', tip: '' };
  const act = (usage.ports || []).filter(r => r.active && r.port);
  if (!act.length) return { line: 'No active ports', tip: 'No ports carried traffic in the last 10 seconds' };
  const label = r => String(r.port), parts = [];
  let line = 'Ports ';
  for (const r of act) {
    const next = (parts.length ? line + ' ' : line) + label(r), more = act.length - parts.length - 1;
    if (next.length + (more > 0 ? 3 + String(more).length : 0) > 32 && parts.length) break;
    line = next; parts.push(r);
  }
  if (act.length > parts.length) line += ' +' + (act.length - parts.length);
  const tip = act.map(r => String(r.proto).toUpperCase() + ' ' + r.port + (r.service ? ' ' + r.service : '') + ' · ↓ ' + bytes(r.down_bytes) + ' ↑ ' + bytes(r.up_bytes)).join('\n');
  return { line, tip: 'Active remote ports (traffic in the last 10 seconds)\n' + tip };
}

function nodeBox(x, y, w, h, title, subtitle, state, onActivate, selected, extraLine, tip) {
  const g = svg('g', { class: 'topo-node' + (selected ? ' sel' : ''), transform: 'translate(' + x + ',' + y + ')' });
  const color = state === 'good' ? '#2fb800' : state === 'poor' ? '#e0201b' : state === 'fair' ? '#f5a300' : '#9aa1ab';
  g.append(svg('rect', { class: 'tb-rect', width: w, height: h, rx: 8 }), svg('circle', { cx: 12, cy: 14, r: 4, fill: color }),
    svg('text', { class: 'tb-title', x: 22, y: 18, 'font-size': 12 }, String(title).slice(0, 27)), svg('text', { class: 'tb-sub', x: 12, y: 36, 'font-size': 11 }, String(subtitle || '').slice(0, 26)));
  if (tip) g.append(svg('title', {}, tip));
  (Array.isArray(extraLine) ? extraLine : extraLine ? [extraLine] : []).forEach((t, i) => g.append(svg('text', { class: 'tb-sub', x: 12, y: 51 + i * 13, 'font-size': 10 }, String(t).slice(0, 32))));
  if (onActivate) {
    g.setAttribute('tabindex', '0'); g.setAttribute('role', 'button'); g.setAttribute('aria-label', title + (subtitle ? ', ' + subtitle : ''));
    g.onclick = onActivate; g.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onActivate(); } };
  }
  return g;
}
// Traffic intensity 0..1 on a log scale: ~10 kbps is a faint trickle, 100 Mbps is full.
function flowIntensity(bps) {
  bps = Number(bps) || 0;
  if (bps < 2e3) return 0;
  return Math.min(1, Math.max(0.08, Math.log10(bps / 1e4) / 4 + 0.12));
}
// One direction of a connection: dashes travel along it, a glow pulses over them, and a soft halo
// sits underneath. Speed, thickness and glow all grow with the traffic. The animation phase comes
// from the wall clock so a redraw does not restart it.
//
// Traffic spikes would make the glow jump, so each connection keeps a displayed intensity that eases
// toward the measured one every frame: quickly when traffic rises (tau 0.5 s), slowly when it falls
// (tau 1.6 s). The map is redrawn on every status update; the frame loop below keeps the live
// elements of the latest redraw moving between the redraws.
const flowState = new Map(); // key -> { cur, target, els, seen, phase, forward }
// Dash travel speed in px/s from the smoothed intensity: a slow crawl for a trickle, a rush at line rate.
const flowSpeed = i => 8 + 60 * i + 130 * i * i;
let flowFrame = 0, flowLast = 0, flowLoop = false;
function flowTick(now) {
  const dt = Math.min(0.25, (now - (flowLast || now)) / 1000);
  flowLast = now;
  for (const [key, st] of flowState) {
    const tau = st.target > st.cur ? 0.5 : 1.6;
    st.cur += (st.target - st.cur) * (1 - Math.exp(-dt / tau));
    if (Math.abs(st.target - st.cur) < 0.002) st.cur = st.target;
    for (const el of st.els) el.style.setProperty('--i', st.cur.toFixed(3));
    // The dashes advance by speed x time, so a change of speed bends the motion instead of restarting it.
    if (!(window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches)) st.phase = (st.phase + flowSpeed(st.cur) * dt) % 16;
    if (st.els[1]) st.els[1].setAttribute('stroke-dashoffset', (st.forward ? -st.phase : st.phase).toFixed(2));
    if (Date.now() - st.seen > 10000) flowState.delete(key);
  }
  requestAnimationFrame(flowTick);
}
function flowLayer(g, x1, y1, x2, y2, bps, forward) {
  const key = [x1, y1, x2, y2, forward].join(',');
  let st = flowState.get(key);
  if (!st) { st = { cur: 0, target: 0, els: [], seen: 0, phase: 0, forward }; flowState.set(key, st); }
  st.target = flowIntensity(bps); st.seen = Date.now(); st.els = [];
  if (!flowLoop) { flowLoop = true; requestAnimationFrame(flowTick); }
  const i = st.cur;
  if (i < 0.02 && !st.target) return; // faded out and idle: nothing to draw
  const dx = x2 - x1, dy = y2 - y1, len = Math.hypot(dx, dy) || 1, off = (forward ? 3 : -3), ox = -dy / len * off, oy = dx / len * off;
  const dur = 1.8 - 1.45 * Math.max(i, 0.05), t = (Date.now() / 1000), cls = forward ? 'down' : 'up';
  const attrs = { x1: x1 + ox, y1: y1 + oy, x2: x2 + ox, y2: y2 + oy };
  const halo = svg('line', { ...attrs, class: 'tf-halo ' + cls });
  halo.style.setProperty('--i', i.toFixed(3));
  halo.style.animation = 'tf-halo-pulse ' + (dur * 3).toFixed(2) + 's ease-in-out infinite';
  halo.style.animationDelay = '-' + (t % (dur * 3)).toFixed(3) + 's';
  const line = svg('line', { ...attrs, class: 'tf ' + cls, 'stroke-dashoffset': (forward ? -st.phase : st.phase).toFixed(2) });
  line.style.setProperty('--i', i.toFixed(3));
  line.style.animation = 'tf-glow ' + (dur * 3).toFixed(2) + 's ease-in-out infinite'; // the dashes are moved by flowTick
  line.style.animationDelay = '-' + (t % (dur * 3)).toFixed(3) + 's';
  const title = svg('title'); title.textContent = (forward ? 'Download ' : 'Upload ') + fmtBps(bps);
  line.append(title);
  st.els = [halo, line];
  g.append(halo, line);
}
// flow = { down, up } in bps; down runs from (x1,y1) to (x2,y2), up the other way.
function mapLine(x1, y1, x2, y2, dashed, label, flow) {
  const g = svg('g');
  g.append(svg('line', { class: 'tl', x1, y1, x2, y2, 'stroke-width': 2, 'stroke-dasharray': dashed ? '4 4' : '' }));
  if (flow) { flowLayer(g, x1, y1, x2, y2, flow.down, true); flowLayer(g, x1, y1, x2, y2, flow.up, false); }
  if (label) g.append(svg('text', { x: (x1 + x2) / 2, y: (y1 + y2) / 2 - 5, 'font-size': 10, 'text-anchor': 'middle', class: 'tl-label' }, label));
  return g;
}

const pieColors = ['#0f7ae5', '#2fb800', '#f5a300', '#9b59d0', '#e0201b', '#00a5b8', '#8c6d46', '#7b8089'];
// A donut with a legend, like the UniFi dashboard's Devices / Clients / Deep Packet Inspection rings.
// slices: [{ label, value, text }]; the centre shows the total.
function donutCard(title, slices, centerValue, centerLabel, note) {
  const card = element('div', null, { class: 'pie-card' }), body = element('div', null, { class: 'pie-body' }), legend = element('div', null, { class: 'pie-legend' });
  card.append(element('h3', title));
  const live = slices.filter(x => x.value > 0), total = live.reduce((a, x) => a + x.value, 0), r = 44, c = 2 * Math.PI * r;
  const ring = svg('svg', { viewBox: '0 0 120 120', class: 'pie-svg', role: 'img', 'aria-label': title + ': ' + centerValue + ' ' + centerLabel });
  ring.append(svg('circle', { cx: 60, cy: 60, r, fill: 'none', class: 'pie-track', 'stroke-width': 16 }));
  let off = 0;
  live.forEach((x, i) => {
    x.color = x.color || pieColors[i % pieColors.length];
    const len = x.value / total * c, seg = svg('circle', { cx: 60, cy: 60, r, fill: 'none', stroke: x.color, 'stroke-width': 16, 'stroke-dasharray': len.toFixed(2) + ' ' + (c - len).toFixed(2), 'stroke-dashoffset': (-off).toFixed(2), transform: 'rotate(-90 60 60)' });
    seg.append(svg('title', {}, x.label + ': ' + x.text)); ring.append(seg); off += len;
    const row = element('div'), sw = element('i'); sw.style.background = x.color;
    row.append(sw, element('span', x.label), element('b', x.text)); legend.append(row);
  });
  if (!live.length) legend.append(element('div', 'Nothing to show yet'));
  ring.append(svg('text', { x: 60, y: 58, 'text-anchor': 'middle', class: 'pie-num', 'font-size': centerValue.length > 5 ? 13 : centerValue.length > 3 ? 16 : 20 }, centerValue), svg('text', { x: 60, y: 73, 'text-anchor': 'middle', class: 'tb-sub', 'font-size': 8 }, centerLabel));
  body.append(ring, legend); card.append(body);
  if (note) card.append(element('p', note, { class: 'sub' }));
  return card;
}

function renderPies(routed, others, extra) {
  const online = routed.filter(d => d.up && d.present !== false).length, offline = routed.length - online, lanOnly = others.length + extra;
  const total = routed.length + lanOnly;
  const devices = donutCard('Devices', [
    { label: 'Routed · online', value: online, text: String(online), color: '#2fb800' }, { label: 'Routed · offline', value: offline, text: String(offline), color: '#e0201b' },
    { label: 'LAN only', value: lanOnly, text: String(lanOnly), color: '#9aa1ab' }], String(total), total === 1 ? 'device' : 'devices', 'Routed devices go through GameBond; LAN-only devices are seen by the scanner but not routed.');
  // Clients by vendor: the scanner's inventory knows the vendor for a MAC; anything it cannot name is "Unknown".
  const byMac = new Map((deviceInventory?.devices || []).map(x => [macKey(x.mac), x.vendor || '']));
  const counts = new Map();
  for (const d of [...routed, ...others]) {
    const v = (d.vendor || byMac.get(macKey(d.mac)) || '').trim() || 'Unknown';
    counts.set(v, (counts.get(v) || 0) + 1);
  }
  let vendors = [...counts].sort((a, b) => b[1] - a[1]);
  if (vendors.length > 7) vendors = [...vendors.slice(0, 6), ['Other', vendors.slice(6).reduce((a, x) => a + x[1], 0)]];
  const clients = donutCard('Clients', vendors.map(([label, value]) => ({ label, value, text: String(value) })), String(total), total === 1 ? 'client' : 'clients', 'Grouped by the vendor the scanner reports for each MAC address.');
  // Traffic by class, from each device's port totals since the client started. Classes come from the remote
  // port alone; the tunnel does not inspect packets.
  const cat = new Map();
  for (const u of Object.values(current?.device_usage || {})) for (const c of u.categories || []) cat.set(c.category, (cat.get(c.category) || 0) + (c.up_bytes || 0) + (c.down_bytes || 0));
  const classes = [...cat].sort((a, b) => b[1] - a[1]), sum = classes.reduce((a, x) => a + x[1], 0);
  const dpi = donutCard('Traffic by type', classes.map(([label, value]) => ({ label, value, text: bytes(value) })), bytes(sum), 'traffic', 'Classified by remote port, not by inspecting packets. Counts routed devices since the client started.');
  topoPies.replaceChildren(devices, clients, dpi);
}

// Smooth path through points (Catmull-Rom to cubic Bezier), kept inside [minY, maxY] so a curve never dips below the axis.
function smoothPath(pts, minY, maxY) {
  if (pts.length < 2) return pts.length ? 'M' + pts[0][0].toFixed(1) + ' ' + pts[0][1].toFixed(1) : '';
  const clamp = y => Math.min(maxY, Math.max(minY, y)), f = v => v.toFixed(1);
  let d = 'M' + f(pts[0][0]) + ' ' + f(pts[0][1]);
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
    d += 'C' + f(p1[0] + (p2[0] - p0[0]) / 6) + ' ' + f(clamp(p1[1] + (p2[1] - p0[1]) / 6)) + ' ' + f(p2[0] - (p3[0] - p1[0]) / 6) + ' ' + f(clamp(p2[1] - (p3[1] - p1[1]) / 6)) + ' ' + f(p2[0]) + ' ' + f(p2[1]);
  }
  return d;
}

let chartSeq = 0;
// Throughput as a soft gradient area (the thin line above it is the busiest minute in each bin) with the device's
// TCP handshake latency as a smooth line on the right-hand axis, in the style of the UniFi activity graphs.
function throughputChart(history, latency, minutes, dir) {
  const width = 520, height = 160, left = 44, right = 34, bottom = 18, bins = Math.min(minutes, 60), binMin = minutes / bins;
  const nowMin = Math.floor(Date.now() / 60000), start = nowMin - minutes + 1, mk = () => new Array(bins).fill(0);
  const sum = mk(), peak = mk(), lat = mk(), latN = mk(), idx = t => { const m = Math.floor(t / 60) - start; return m < 0 || m >= minutes ? -1 : Math.min(bins - 1, Math.floor(m / binMin)); };
  for (const [t, u, d] of history) { const i = idx(t); if (i < 0) continue; const v = dir === 'down' ? d : u; sum[i] += v; peak[i] = Math.max(peak[i], v * 8 / 60); }
  for (const [t, r] of latency) { const i = idx(t); if (i < 0) continue; lat[i] += r / 10; latN[i]++; }
  const avg = sum.map(v => v * 8 / (binMin * 60)), ms = lat.map((v, i) => latN[i] ? v / latN[i] : null);
  const top = Math.max(1e5, ...peak, ...avg) * 1.1, latTop = Math.max(10, ...ms.filter(v => v != null)) * 1.2, plot = height - bottom, usable = plot - 14, bw = (width - left - right) / bins;
  const color = dir === 'down' ? '#2fb800' : '#0f7ae5', gid = 'tg' + (++chartSeq), when = i => new Date((start + i * binMin) * 60000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const s = svg('svg', { class: 'topo-svg', viewBox: '0 0 ' + width + ' ' + height, role: 'img', 'aria-label': (dir === 'down' ? 'Download' : 'Upload') + ' throughput and latency' });
  s.style.maxWidth = '720px';
  const defs = svg('defs'), grad = svg('linearGradient', { id: gid, x1: 0, y1: 0, x2: 0, y2: 1 });
  grad.append(svg('stop', { offset: '0%', 'stop-color': color, 'stop-opacity': 0.5 }), svg('stop', { offset: '100%', 'stop-color': color, 'stop-opacity': 0.03 })); defs.append(grad); s.append(defs);
  for (let g = 0; g <= 4; g++) { const y = plot - g / 4 * usable; s.append(svg('line', { class: 'gl', x1: left, y1: y, x2: width - right, y2: y })); }
  s.append(svg('text', { class: 'tb-sub', x: 2, y: plot - usable + 3, 'font-size': 10 }, fmtBps(top)), svg('text', { class: 'tb-sub', x: 2, y: plot + 3, 'font-size': 10 }, '0'),
    svg('text', { class: 'tb-sub', x: width, y: plot - usable + 3, 'font-size': 10, 'text-anchor': 'end' }, Math.round(latTop) + ' ms'), svg('text', { class: 'tb-sub', x: width, y: plot + 3, 'font-size': 10, 'text-anchor': 'end' }, '0'),
    svg('text', { class: 'tb-sub', x: left, y: height - 4, 'font-size': 10 }, minutes >= 60 ? '-' + (minutes / 60) + ' h' : '-' + minutes + ' min'), svg('text', { class: 'tb-sub', x: width - right, y: height - 4, 'font-size': 10, 'text-anchor': 'end' }, 'now'));
  const cx = i => left + (i + 0.5) * bw, yOf = v => plot - v / top * usable;
  const areaPts = avg.map((v, i) => [cx(i), yOf(v)]), area = smoothPath(areaPts, plot - usable, plot);
  s.append(svg('path', { d: area + 'L' + cx(bins - 1).toFixed(1) + ' ' + plot + 'L' + cx(0).toFixed(1) + ' ' + plot + 'Z', fill: 'url(#' + gid + ')' }));
  s.append(svg('path', { d: area, fill: 'none', stroke: color, 'stroke-width': 1.6, 'stroke-linejoin': 'round' }));
  if (peak.some((v, i) => v > avg[i] * 1.05)) s.append(svg('path', { d: smoothPath(peak.map((v, i) => [cx(i), yOf(v)]), plot - usable, plot), fill: 'none', stroke: color, 'stroke-opacity': 0.4, 'stroke-width': 1, 'stroke-dasharray': '3 3' }));
  // Latency: runs of consecutive samples (a gap of up to two quiet bins is bridged) become smooth lines; a lone sample is a dot.
  const runs = []; let last = -99;
  ms.forEach((v, i) => { if (v == null) return; const pt = [cx(i), plot - v / latTop * usable]; if (i - last <= 3 && runs.length) runs[runs.length - 1].push(pt); else runs.push([pt]); last = i; });
  for (const run of runs) s.append(run.length > 1 ? svg('path', { d: smoothPath(run, plot - usable, plot), fill: 'none', stroke: '#f5a300', 'stroke-width': 1.6, 'stroke-linejoin': 'round' }) : svg('circle', { cx: run[0][0], cy: run[0][1], r: 2, fill: '#f5a300' }));
  for (let i = 0; i < bins; i++) { // one hover target per bin with the exact numbers
    const hit = svg('rect', { x: left + i * bw, y: 0, width: bw, height: plot, fill: 'transparent' });
    hit.append(svg('title', {}, when(i) + '\navg ' + fmtBps(avg[i]) + ' · max ' + fmtBps(peak[i]) + '\n' + (ms[i] != null ? 'latency ' + ms[i].toFixed(0) + ' ms' : 'latency: no TCP handshakes'))); s.append(hit);
  }
  return s;
}

function renderTopology() {
  if (!current || current.state === 'unavailable' && !current.transport) { topoHead.textContent = 'Status unavailable'; return; }
  const paths = current?.transport?.paths || [], { routed, others, extra } = topologyDevices();
  updateLinkRates(paths);
  updateExitRates(current?.exit?.servers || []);
  renderPies(routed, others, extra);
  const [health, headline] = overallHealth(paths);
  topoHead.replaceChildren();
  if (health === 'good') { topoHead.append('Everything is ', element('b', 'great', { class: 'good' }), '!'); } else topoHead.append(element('b', headline, { class: health }));
  const totalRx = paths.reduce((s, p) => s + (linkRates.get(p.slot)?.rxBps || 0), 0), totalTx = paths.reduce((s, p) => s + (linkRates.get(p.slot)?.txBps || 0), 0);
  topoStats.replaceChildren();
  for (const [value, label] of [[paths.filter(p => p.healthy).length + '/' + paths.length, 'Links up'], [routed.length, 'Routed devices'], [others.length + (extra ? '+' : ''), 'Other LAN devices'], ['↓ ' + fmtBps(totalRx), 'Wire in (all links)'], ['↑ ' + fmtBps(totalTx), 'Wire out (all links)']]) {
    const box = element('div', null, { class: 'topo-stat' }); box.append(element('strong', String(value)), element('span', label)); topoStats.append(box);
  }

  topoMap.replaceChildren();
  const exit = current?.exit, standbys = (exit?.servers || []).filter(x => !x.active);
  const rowGap = 72, rows = Math.max(paths.length, routed.length + others.length, 2, standbys.length ? Math.ceil(2 + standbys.length * 1.6) : 0), height = 40 + rows * rowGap;
  topoMap.setAttribute('viewBox', '0 0 1060 ' + height);
  const midY = height / 2 - 24, serverX = 10, linkX = 215, pcX = 420, hubX = 625, devX = 850, w = 180, h = 46, dh = 62; // dh: routed-device nodes carry a third line (active ports)
  const onBackup = !!exit?.on_backup;
  const eh = 72, ey = midY + h / 2 - eh / 2, eg = eh + 12; // exit nodes carry rate and total lines, so they are taller
  const exitLines = x => {
    const r = exitRates.get(x.address) || {};
    return ['↓ ' + fmtBps(r.rxBps) + '  ↑ ' + fmtBps(r.txBps), 'total ↓ ' + bytes(x.wire_rx_bytes) + '  ↑ ' + bytes(x.wire_tx_bytes)];
  };
  const activeX = (exit?.servers || []).find(x => x.active) || { address: exit?.active || '', wire_rx_bytes: 0, wire_tx_bytes: 0 };
  const server = nodeBox(serverX, ey, w, eh, exit && standbys.length ? (onBackup ? 'Exit server · backup' : 'Exit server · primary') : 'Exit server', exit?.active || (current?.peer ? current.peer[0] : ''), exit?.searching ? 'fair' : health === 'poor' ? 'poor' : onBackup ? 'fair' : 'good', null, false, exitLines(activeX));
  const pc = nodeBox(pcX, midY, w, h, 'This PC', 'GameBond client', 'good');
  topoMap.append(server, pc);
  // Standby exits hang under the active one, dashed: they carry nothing until the active exit stops answering.
  standbys.forEach((x, i) => {
    const y = ey + (i + 1) * eg, state = x.state === 'reachable' ? 'good' : x.state === 'unreachable' ? 'poor' : 'neutral';
    const label = x.state === 'reachable' ? 'standby · ' + Math.round(x.handshake_ms) + ' ms' : x.state === 'unreachable' ? 'standby · no answer' : 'standby · not probed';
    topoMap.append(mapLine(serverX + w / 2, (i ? y - eg + eh : ey + eh), serverX + w / 2, y, true), nodeBox(serverX, y, w, eh, 'Standby ' + x.address, label, state, null, false, exitLines(x)));
  });
  const linkY0 = midY + h / 2 - (paths.length - 1) * rowGap / 2 - h / 2;
  paths.forEach((p, i) => {
    const y = linkY0 + i * rowGap, r = linkRates.get(p.slot) || {};
    const fl = { down: r.rxBps || 0, up: r.txBps || 0 };
    topoMap.append(mapLine(serverX + w, midY + h / 2, linkX, y + h / 2, false, null, fl), mapLine(linkX + w, y + h / 2, pcX, midY + h / 2, false, null, fl));
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
    topoMap.append(mapLine(pcX + w, midY + h / 2, hubX, hy + h / 2, false, null, { down: hub.down, up: hub.upBps }));
    topoMap.append(nodeBox(hubX, hy, w, h, hub.name + ' · ' + hub.devices.length + (hub.devices.length === 1 ? ' device' : ' devices'), '↓ ' + fmtBps(hub.down) + '  ↑ ' + fmtBps(hub.upBps), hub.up ? 'good' : 'poor', () => { selectedDevice = hub.key; renderTopology(); }, selectedDevice === hub.key));
    for (const d of hub.devices) {
      const y = placed.get(d.key);
      topoMap.append(mapLine(hubX + w, hy + h / 2, devX, y + h / 2, false, null, { down: d.usage?.down_bps || 0, up: d.usage?.up_bps || 0 }));
      const sub = d.usage ? '↓ ' + fmtBps(d.usage.down_bps) + '  ↑ ' + fmtBps(d.usage.up_bps) : d.ip;
      const ap = activePorts(d.usage);
      // Taller than the other nodes but centred on the same row, so the connector still meets its middle.
      topoMap.append(nodeBox(devX, y - (dh - h) / 2, w, dh, d.name, sub, d.up && d.present !== false ? 'good' : 'poor', () => { selectedDevice = d.key; renderTopology(); }, selectedDevice === d.key, ap.line, ap.tip));
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
  const panel = (name, dir) => {
    const p = element('div', null, { class: 'tp-panel' }), color = dir === 'down' ? '#2fb800' : '#0f7ae5', lg = element('div', null, { class: 'tp-legend' });
    lg.innerHTML = '<span><i style="background:' + color + ';opacity:.6"></i>Average</span><span><i style="background:none;border-top:1px dashed ' + color + ';height:0;vertical-align:3px"></i>Busiest minute</span><span><i style="background:#f5a300"></i>Latency (TCP handshake)</span>';
    p.append(element('h4', name), throughputChart(u.history || [], u.latency || [], usageRange, dir), lg); return p;
  };
  hist.append(range, panel('Download throughput & latency', 'down'), panel('Upload throughput & latency', 'up'),
    element('p', (u.latency || []).length ? 'Latency is the round trip from this device to the hosts it connects to, timed from TCP handshakes crossing the tunnel (median per minute).' : 'No TCP connections from this device were timed yet, so there is no latency line.', { class: 'sub' })); card.append(hist);

  const ports = element('div'); ports.append(element('h3', 'Ports (remote side) · ' + (u.active_ports || 0) + ' active'));
  const pt = element('table'); pt.innerHTML = '<thead><tr><th>Proto</th><th>Port</th><th>Service</th><th>Now</th><th>Down</th><th>Up</th><th>Packets</th></tr></thead>';
  const pb = element('tbody'); pt.append(pb);
  for (const r of (u.ports || []).slice(0, 12)) { const tr = element('tr'); cell(tr, String(r.proto).toUpperCase()); cell(tr, r.port || '—'); cell(tr, r.service || '—'); cell(tr, r.active ? 'active' : ago(r.last_seen)).className = r.active ? 'port-active' : ''; cell(tr, bytes(r.down_bytes)); cell(tr, bytes(r.up_bytes)); cell(tr, (r.packets || 0).toLocaleString()); pb.append(tr); }
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

setInterval(() => { if (scannerSub === 'topology' && $('scanner').classList.contains('active')) renderTopology(); }, 1000);
const selectTabBeforeTopology = selectTab;
selectTab = function(id) { selectTabBeforeTopology(id); if (id === 'scanner' && scannerSub === 'topology') renderTopology(); };
