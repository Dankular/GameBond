// Security > This PC, and a short summary in Issues: which process on this computer did what, from the alert files
// of SentinelWire (the EDR "Rustinel" and the wire monitor "PacketSentinel"). GameBond only reads those files. It
// does not start, stop or configure SentinelWire, and these are detections: nothing is blocked because of them.
// Everything shown comes from files on this PC and is written with textContent only.
let epState = null, epMsg = '', epMsgBad = false, epLast = null, epFilter = 'all', epTimer = null, epLive = null;

async function epLoad() {
  try { epState = await api('endpoint'); epLast = epState; return true; } catch (e) { epMsg = e.message; epMsgBad = true; return false; }
}

const EP_SEV = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
function epSevLabel(s) { return ({ critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' })[s] || s; }

function secPC(body) {
  body.append(secEl('p', 'Shows which program on this computer made a suspicious connection or did something suspicious, using SentinelWire: a host sensor (Rustinel) and a DNS/TLS name monitor (PacketSentinel). GameBond reads the alert files they write, nothing more. These are detections only: nothing is blocked, and anything the sensors cannot see is not shown.', 'sec-help'));
  const setup = secCard('Where SentinelWire writes its alerts', 'Install and start SentinelWire separately, then point these at its log folders. Leave one empty if you only run the other.');
  const form = secEl('div'), status = secEl('div'), list = secEl('div');
  body.append(setup, status, list);
  setup.append(form);
  const draw = () => {
    form.replaceChildren();
    const cfg = epState?.config || { enabled: false, rustinel_dir: '', packetsentinel_dir: '' };
    const on = element('input', null, { type: 'checkbox' }); on.checked = cfg.enabled;
    const l = secEl('label'); l.append(on, element('span', 'Show alerts from this PC'));
    const r1 = secEl('div', null, 'sec-row'); r1.append(l);
    const rd = element('input', null, { type: 'text', size: 52, placeholder: 'C:\\SentinelWire\\logs  (folder with alerts.json.<date>)', 'aria-label': 'Rustinel alert folder' }); rd.value = cfg.rustinel_dir || '';
    const wd = element('input', null, { type: 'text', size: 52, placeholder: 'C:\\SentinelWire\\companion\\logs  (folder with alerts.jsonl)', 'aria-label': 'PacketSentinel alert folder' }); wd.value = cfg.packetsentinel_dir || '';
    const r2 = secEl('div', null, 'sec-row'), r3 = secEl('div', null, 'sec-row');
    r2.append(element('span', 'Host sensor (Rustinel)'), rd); r3.append(element('span', 'Wire monitor (PacketSentinel)'), wd);
    const msg = secEl('span', epMsg, epMsgBad ? 'sec-bad' : 'sec-ok', { role: 'status' });
    const save = action('Save', async () => {
      try { await api('endpoint', 'POST', { enabled: on.checked, rustinel_dir: rd.value.trim(), packetsentinel_dir: wd.value.trim() }); epMsg = 'Saved.'; epMsgBad = false; await epLoad(); draw(); update(); }
      catch (e) { epMsg = e.message; epMsgBad = true; msg.textContent = epMsg; msg.className = 'sec-bad'; } // keep what was typed
    });
    const r4 = secEl('div', null, 'sec-row'); r4.append(save, msg);
    form.append(r1, r2, r3, r4);
  };
  const update = () => {
    status.replaceChildren(); list.replaceChildren();
    const snap = epState?.snapshot;
    if (!snap || !snap.enabled) { status.append(secEl('p', 'Off. Turn it on above once SentinelWire is running.', 'sec-note')); return; }
    for (const s of snap.sources) status.append(secEl('p', (s.name === 'rustinel' ? 'Host sensor' : 'Wire monitor') + ': ' + (s.found ? 'reading ' + s.path + ' (' + s.alerts + ' alerts, updated ' + secAgo(Date.parse(s.updated) / 1000) + ')' : s.error || 'not found'), s.found ? 'sec-ok' : 'sec-warn'));
    if (snap.blind) status.append(secEl('p', 'The host sensor reported it lost events (' + snap.blind_why + ') in the last ten minutes, so some activity in that time was never checked. ' + secNum(snap.lost_events) + ' events lost since GameBond started reading.', 'sec-bad'));
    const tiles = secEl('div', null, 'sec-tiles');
    for (const sev of ['critical', 'high', 'medium', 'low']) tiles.append(secTile(epSevLabel(sev), secNum(snap.counts?.[sev] || 0)));
    list.append(tiles);
    const row = secEl('div', null, 'sec-row'), sel = element('select', null, { 'aria-label': 'Severity filter' });
    for (const [v, t] of [['all', 'All alerts'], ['medium', 'Medium and above'], ['high', 'High and above']]) sel.append(element('option', t, { value: v }));
    sel.value = epFilter; sel.onchange = () => { epFilter = sel.value; update(); };
    row.append(element('span', 'Show'), sel); list.append(row);
    const [t, tb] = secTable(['When', 'Severity', 'What', 'Program', 'Connection', 'From']);
    const min = epFilter === 'all' ? -1 : EP_SEV[epFilter];
    let shown = 0;
    for (const a of snap.alerts) {
      if (EP_SEV[a.severity] < min) continue;
      const prog = a.process ? a.process + (a.pid ? ' (' + a.pid + ')' : '') : '—';
      const tr = secRow(tb, [secAgo(Date.parse(a.time) / 1000), epSevLabel(a.severity), a.title, prog, a.remote ? a.remote + (a.port ? ':' + a.port : '') : '—', a.source === 'rustinel' ? 'Host sensor' : 'Wire monitor']);
      tr.cells[1].className = 'sec-sev-' + (a.severity === 'critical' ? 'high' : a.severity === 'info' ? 'low' : a.severity);
      if (a.exe) tr.cells[3].title = a.exe;
      if (++shown >= 200) break;
    }
    if (!shown) secRow(tb, ['—', '', snap.alerts.length ? 'Nothing at this level.' : 'No alerts yet.', '', '', '']);
    list.append(t);
  };
  draw(); update();
  const poll = async () => { if (await epLoad()) update(); };
  poll();
  epLive = setInterval(() => { if (secSection !== 'pc' || scannerSub !== 'security' || document.hidden || !$('scanner').classList.contains('active')) { clearInterval(epLive); epLive = null; return; } poll(); }, 2000);
  secLive.push(() => {});
}

// ---- Issues tab: a short summary, only when the feature is on ----
setInterval(async () => { if (!document.hidden && (epLast?.snapshot?.enabled || active === 'issues')) await epLoad(); }, 5000);
function epIssuesCard() {
  const snap = epLast?.snapshot, box = $('issuespanel');
  if (!snap || !snap.enabled || !box) return;
  const sec = element('div', null, { class: 'issue-sec' });
  const high = (snap.counts?.critical || 0) + (snap.counts?.high || 0);
  const h = element('h2', 'This PC: programs that raised alerts');
  h.append(element('span', high ? high + ' high' : 'none high', { class: 'issue-badge' + (high ? ' bad' : '') }));
  sec.append(h);
  if (snap.blind) sec.append(element('p', 'The host sensor lost events recently, so some activity was not checked.', { class: 'sub notice' }));
  const top = snap.alerts.filter(a => EP_SEV[a.severity] >= 2).slice(0, 4);
  if (!top.length) sec.append(element('p', 'No medium or higher alerts from the sensors.', { class: 'sub' }));
  for (const a of top) sec.append(element('p', epSevLabel(a.severity) + ': ' + a.title + (a.process ? ' — ' + a.process : '') + (a.remote ? ' → ' + a.remote : ''), { class: 'sub' }));
  const open = element('button', 'Open Security, This PC', { type: 'button' });
  open.onclick = () => { selectTab('scanner'); showScannerSub('security'); secSection = 'pc'; secRender(); };
  sec.append(open);
  box.append(sec);
}
const renderIssuesBeforeEndpoint = renderIssues;
renderIssues = function (d) { renderIssuesBeforeEndpoint(d); epIssuesCard(); };
