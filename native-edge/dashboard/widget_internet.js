// Internet strip on the topology: round trips to Google, Microsoft and Cloudflare through the tunnel, and a speed
// test across all links together. The client measures both (see the speedtest and internet_ping entries of the
// status document); this strip only shows them and asks for a test.
const internetStyle = document.createElement('style');
internetStyle.textContent = '.inet{display:flex;gap:14px;align-items:center;flex-wrap:wrap;border:1px solid #e1e5eb;border-radius:10px;padding:10px 14px;margin:10px 0}.inet h3{margin:0;font-size:12px;text-transform:uppercase;color:#7b8089}'
  + '.inet-chips{display:flex;gap:8px;flex-wrap:wrap}.inet-chip{display:inline-flex;gap:6px;align-items:baseline;border-radius:999px;padding:3px 12px;background:#eef1f5;font-size:13px}.inet-chip b{font-weight:600}.inet-chip.good{background:#dff6d5;color:#1f6b00}.inet-chip.fair{background:#fff0cc;color:#8a5a00}.inet-chip.poor{background:#fde0df;color:#a8120e}.inet-chip.idle{color:#7b8089}'
  + '.inet-speed{margin-left:auto;display:flex;gap:10px;align-items:center;flex-wrap:wrap}.inet-speed .big{font-size:15px;font-weight:600}.inet-note{color:#7b8089;font-size:12px}.inet-bar{width:140px;height:6px;border-radius:3px;background:#e8edf3;overflow:hidden}.inet-bar i{display:block;height:100%;background:#0f7ae5;transition:width .3s}'
  + 'html[data-theme=dark] .inet{border-color:#3a404b}html[data-theme=dark] .inet-chip{background:#262b33}html[data-theme=dark] .inet-chip.good{background:#17301a;color:#7ddc9a}html[data-theme=dark] .inet-chip.fair{background:#33290f;color:#f0c060}html[data-theme=dark] .inet-chip.poor{background:#3a1b1a;color:#f19a97}html[data-theme=dark] .inet-bar{background:#2a2f38}';
document.head.append(internetStyle);

const internetStrip = element('div', null, { class: 'inet', role: 'group', 'aria-label': 'Internet' });
topoPane.insertBefore(internetStrip, topoMap);
let internetBusy = false, internetMsg = '';
const PING_ORDER = ['Google', 'Microsoft', 'Cloudflare'];

function pingClass(ms) { return ms < 60 ? 'good' : ms < 150 ? 'fair' : 'poor'; }
function fmtMbps(v) { return v >= 1000 ? (v / 1000).toFixed(2) + ' Gbps' : v >= 100 ? Math.round(v) + ' Mbps' : v.toFixed(1) + ' Mbps'; }

async function speedCall(action) {
  internetBusy = true; internetMsg = ''; renderInternet();
  try { await api('speedtest', 'POST', { action }); } catch (e) { internetMsg = e.message; }
  internetBusy = false; renderInternet();
}

let internetSig = '';
function renderInternet() {
  const d = current || {}, running = d.state === 'running', ping = d.internet_ping, st = d.speedtest;
  // Rebuilding the strip every second would swallow a click that lands mid-rebuild and reset a hover tooltip,
  // so it is only redrawn when what it shows has changed (the time bucket keeps the "ago" text fresh).
  const sig = JSON.stringify([running, ping, st, internetBusy, internetMsg, Math.floor(Date.now() / 15000)]);
  if (sig === internetSig) return;
  internetSig = sig;
  internetStrip.replaceChildren();
  const chips = element('div', null, { class: 'inet-chips' });
  const byName = new Map((ping?.results || []).map(r => [r.name, r]));
  for (const name of PING_ORDER) {
    const r = byName.get(name), chip = element('span', null, { class: 'inet-chip' });
    if (!running || !r) { chip.classList.add('idle'); chip.append(name, element('b', running ? 'measuring…' : '—')); chip.title = running ? 'Waiting for the first measurement' : 'Connect to measure'; }
    else if (r.ok) { chip.classList.add(pingClass(r.ms)); chip.append(name, element('b', Math.round(r.ms) + ' ms')); chip.title = name + ': TCP connect time through the tunnel' + (ping.at ? ', measured ' + ago(ping.at) : ''); }
    else { chip.classList.add('poor'); chip.append(name, element('b', r.error === 'timed out' ? 'timeout' : 'failed')); chip.title = name + ': ' + (r.error || 'no answer'); }
    chips.append(chip);
  }
  const left = element('div'); left.append(element('h3', 'Internet'), chips);
  const right = element('div', null, { class: 'inet-speed' });
  if (st?.running) {
    const phase = { latency: 'Measuring latency…', download: 'Testing download…', upload: 'Testing upload…', starting: 'Starting…' }[st.phase] || 'Testing…';
    const bar = element('div', null, { class: 'inet-bar' }), fill = element('i'); fill.style.width = Math.min(100, ((st.elapsed_s || 0) / 17) * 100) + '%'; bar.append(fill);
    right.append(element('span', phase + (st.current_mbps ? ' ' + fmtMbps(st.current_mbps) : ''), { class: 'big' }), bar, action('Cancel', () => speedCall('cancel')));
  } else {
    const last = st?.last;
    if (last) {
      const text = element('span', null, { class: 'big' }); text.textContent = '↓ ' + fmtMbps(last.down_mbps) + '  ↑ ' + fmtMbps(last.up_mbps);
      const sub = element('span', last.latency_ms ? Math.round(last.latency_ms) + ' ms · ' + (last.streams || 4) + ' streams · all links together · ' + ago(last.at) : ago(last.at), { class: 'inet-note' });
      sub.title = 'Moved ' + bytes(last.down_bytes) + ' down and ' + bytes(last.up_bytes) + ' up through ' + (last.server || 'the speed server');
      right.append(text, sub);
    } else right.append(element('span', 'No speed test yet', { class: 'inet-note' }));
    const run = action('Run speed test', () => speedCall('start'));
    run.disabled = !running || internetBusy; run.title = running ? 'Measures download and upload across all links together. Uses up to 250 MB each way.' : 'Connect first';
    right.append(run);
    if (st?.error) right.append(element('span', st.error.error === 'cancelled' ? 'Last test was cancelled' : 'Last attempt failed: ' + st.error.error, { class: 'inet-note' }));
  }
  if (internetMsg) right.append(element('span', internetMsg, { class: 'inet-note', role: 'status' }));
  internetStrip.append(left, right);
}
renderInternet();
setInterval(renderInternet, 1000);
