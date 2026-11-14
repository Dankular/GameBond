// Errors over time for the Issues tab: stacked bars per time bin, coloured by error type, with a spike
// marker and a per-type table of how often each one happened. The daemon keeps the history (error_history
// in the status document), so it survives closing the widget.
const errStyle = document.createElement('style');
errStyle.textContent = '.err-chart{width:100%;max-width:820px;height:auto;display:block}.err-sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:-1px}'
  + '.err-ok{color:#00a66c;font-weight:600}.err-band{fill:#f5a300;fill-opacity:.13}.err-band.hot{fill:#e0201b;fill-opacity:.16}.err-hit{fill:#e0201b;stroke:#fff;stroke-width:1}.err-sw-band{background:rgba(245,163,0,.35)}.err-sw-hit{background:#e0201b;border-radius:50%!important}.err-spike{fill:#e0201b}.err-table td.num{text-align:right;font-variant-numeric:tabular-nums}.err-help{color:#7b8490}';
document.head.append(errStyle);

// Zoom levels: the window shown and the width of one bar. Windows up to 30 minutes use the 5 second data the
// client keeps for the last hour; longer ones use the per-minute history (24 hours, all that is stored).
const errZoom = [
  { label: '5 min', window: 300, bin: 5 }, { label: '15 min', window: 900, bin: 15 }, { label: '30 min', window: 1800, bin: 30 },
  { label: '1 h', window: 3600, bin: 60 }, { label: '3 h', window: 10800, bin: 180 }, { label: '6 h', window: 21600, bin: 360 },
  { label: '12 h', window: 43200, bin: 720 }, { label: 'All (24 h)', window: 86400, bin: 1440 },
];
let errRange = 3;
const binLabel = sec => sec < 60 ? sec + ' s' : sec < 3600 ? sec / 60 + ' min' : sec / 3600 + ' h';
// Each group owns a hue range and its types are spread across it, so neighbours in a stack can be told apart.
const errHue = { Absorbed: [165, 185], Loss: [0, 48], Local: [195, 250], Protocol: [268, 318], Links: [95, 140] };
function errColor(kinds, i) {
  const k = kinds[i], same = kinds.filter(x => x.group === k.group), n = same.indexOf(k), [lo, hi] = errHue[k.group] || [0, 0];
  const hue = same.length > 1 ? lo + (hi - lo) * n / (same.length - 1) : lo;
  return 'hsl(' + hue.toFixed(0) + ' 70% ' + (n % 2 ? 56 : 42) + '%)';
}

// binErrors folds the per-minute rows into `bins` buckets over the last `minutes`.
function binErrors(rows, kindCount, z) {
  const bins = z.window / z.bin, start = Math.floor(Date.now() / 1000 / z.bin) - bins + 1;
  const per = Array.from({ length: bins }, () => new Array(kindCount).fill(0)), totals = new Array(kindCount).fill(0);
  for (const row of rows || []) {
    const i = Math.floor(row[0] / z.bin) - start; if (i < 0 || i >= bins) continue;
    for (let k = 0; k < kindCount; k++) { per[i][k] += row[1 + k] || 0; totals[k] += row[1 + k] || 0; }
  }
  return { per, totals, bins, binSec: z.bin, startSec: start * z.bin };
}

// spikeBins: bins that stand well above the usual (at least 5 errors and 3x the median busy bin).
function spikeBins(binTotals) {
  const busy = binTotals.filter(v => v > 0).sort((a, b) => a - b);
  if (busy.length < 3) return new Set();
  const limit = Math.max(5, 3 * busy[Math.floor(busy.length / 2)]);
  return new Set(binTotals.map((v, i) => v >= limit ? i : -1).filter(i => i >= 0));
}

// Recovery overlay lines, one per mechanism group, drawn on the right-hand axis.
const recStyle = { Recovery: { color: '#0b7285', dash: '' }, Parity: { color: '#2b8a3e', dash: '5 3' }, Failover: { color: '#e67700', dash: '1.5 3' } };

// analyse lines the error bins up with the recovery bins. An "interception" is a bin where errors and
// recovery activity happen together. The check the chart exists for: do those line up with packets that
// never arrived? A bin with never-arrived packets and no recovery activity is reported separately.
function analyseErrors(kinds, folded, recKinds, recFolded) {
  const neverIdx = kinds.findIndex(k => k.key === 'never_arrived'), n = folded.bins;
  const errTotal = folded.per.map(r => r.reduce((a, b) => a + b, 0)), recTotal = recFolded.per.map(r => r.reduce((a, b, j) => a + (recKinds[j] && recKinds[j].routine ? 0 : b), 0));
  const never = folded.per.map(r => neverIdx >= 0 ? r[neverIdx] : 0);
  // Routine overhead (parity sent) is never counted as recovery: it runs all the time, so it says nothing about an error.
  const reactive = recKinds.map(k => !k.routine);
  const groups = Object.keys(recStyle).map(g => ({ group: g, series: recFolded.per.map(r => recKinds.reduce((a, k, j) => a + (k.group === g && reactive[j] ? r[j] : 0), 0)) }));
  const intercept = Array.from({ length: n }, (_, i) => errTotal[i] > 0 && recTotal[i] > 0);
  let interceptions = 0, aligned = 0, neverBins = 0, uncovered = 0;
  for (let i = 0; i < n; i++) {
    if (intercept[i]) interceptions++;
    if (intercept[i] && never[i] > 0) aligned++;
    if (never[i] > 0) neverBins++;
    if (never[i] > 0 && recTotal[i] === 0) uncovered++;
  }
  return { errTotal, recTotal, never, groups, intercept, interceptions, aligned, neverBins, uncovered };
}

// stabilityBins folds the per-minute connection-state seconds into the chart's bins.
function stabilityBins(rows, z) {
  const bins = z.window / z.bin, start = Math.floor(Date.now() / 1000 / z.bin) - bins + 1;
  const out = Array.from({ length: bins }, () => ({ up: 0, degraded: 0, down: 0 }));
  for (const [t, up, dg, dn] of rows || []) {
    const i = Math.floor(t / z.bin) - start; if (i < 0 || i >= bins) continue;
    const b = out[i]; b.up += up; b.degraded += dg; b.down += dn;
  }
  return out;
}

function errorChart(kinds, folded, windowLabel, an, stab) {
  const { per, bins, binSec, startSec } = folded, width = 760, height = 196, left = 34, right = 40, ribbon = 7, bottom = 18 + ribbon + 4, plot = height - bottom, usable = plot - 16, bw = (width - left - right) / bins;
  const top = Math.max(5, ...an.errTotal) * 1.1, recTop = Math.max(5, ...an.groups.flatMap(g => g.series)) * 1.1, spikes = spikeBins(an.errTotal);
  const s = svg('svg', { class: 'topo-svg err-chart', viewBox: '0 0 ' + width + ' ' + height, role: 'img', 'aria-label': 'Errors, recovery and connection state over time' });
  for (let g = 0; g <= 4; g++) {
    const y = plot - g / 4 * usable;
    s.append(svg('line', { class: 'gl', x1: left, y1: y, x2: width - right, y2: y }), svg('text', { class: 'tb-sub', x: left - 4, y: y + 3, 'font-size': 10, 'text-anchor': 'end' }, String(Math.round(top * g / 4))),
      svg('text', { class: 'tb-sub', x: width - right + 4, y: y + 3, 'font-size': 10 }, String(Math.round(recTop * g / 4))));
  }
  s.append(svg('text', { class: 'tb-sub', x: left, y: height - 4, 'font-size': 10 }, '-' + windowLabel), svg('text', { class: 'tb-sub', x: width - right, y: height - 4, 'font-size': 10, 'text-anchor': 'end' }, 'now'),
    svg('text', { class: 'tb-sub', x: left - 4, y: 9, 'font-size': 9, 'text-anchor': 'end' }, 'errors'), svg('text', { class: 'tb-sub', x: width - right + 4, y: 9, 'font-size': 9 }, 'recovery'));
  const when = i => new Date((startSec + i * binSec) * 1000).toLocaleTimeString([], binSec < 60 ? { hour: '2-digit', minute: '2-digit', second: '2-digit' } : { hour: '2-digit', minute: '2-digit' }) + (binSec > 60 ? ' (+' + binLabel(binSec) + ')' : binSec < 60 ? ' (+' + binSec + ' s)' : '');
  // Interception bands first, so the bars and lines sit on top of them.
  for (let i = 0; i < bins; i++) {
    if (!an.intercept[i]) continue;
    const hot = an.never[i] > 0;
    s.append(svg('rect', { class: hot ? 'err-band hot' : 'err-band', x: left + i * bw, y: 14, width: bw, height: plot - 14 }));
  }
  for (let i = 0; i < bins; i++) {
    let y = plot;
    for (let k = 0; k < kinds.length; k++) {
      const n = per[i][k]; if (!n) continue;
      const h = n / top * usable; y -= h;
      s.append(svg('rect', { x: left + i * bw + 1, y, width: Math.max(1.5, bw - 2), height: Math.max(1, h), rx: 1.5, fill: errColor(kinds, k), 'fill-opacity': 0.9 }));
    }
    if (spikes.has(i)) s.append(svg('path', { class: 'err-spike', d: 'M' + (left + i * bw + bw / 2 - 4) + ' ' + (y - 9) + 'l8 0l-4 7z' }));
  }
  const cx = i => left + (i + 0.5) * bw;
  for (const g of an.groups) {
    if (!g.series.some(v => v > 0)) continue;
    const st = recStyle[g.group];
    s.append(svg('path', { d: smoothPath(g.series.map((v, i) => [cx(i), plot - v / recTop * usable]), plot - usable, plot), fill: 'none', stroke: st.color, 'stroke-width': 1.8, 'stroke-dasharray': st.dash, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
  }
  for (let i = 0; i < bins; i++) if (an.intercept[i] && an.never[i] > 0) s.append(svg('circle', { class: 'err-hit', cx: cx(i), cy: 7, r: 3.5 }));
  // Connection state ribbon: green all links healthy, amber running on fewer links, red no healthy link.
  const ry = plot + 5;
  for (let i = 0; i < bins; i++) {
    const b = stab[i], total = b.up + b.degraded + b.down;
    s.append(svg('rect', { x: left + i * bw, y: ry, width: Math.max(1, bw - (bw > 4 ? 1 : 0)), height: ribbon, rx: 1.5, fill: !total ? '#c9ced6' : b.down ? '#e0201b' : b.degraded ? '#f5a300' : '#2fb800', 'fill-opacity': total ? 0.9 : 0.5 }));
  }
  for (let i = 0; i < bins; i++) {
    const hit = svg('rect', { x: left + i * bw, y: 0, width: bw, height: height - 14, fill: 'transparent' });
    const lines = kinds.map((k, j) => per[i][j] ? k.label + ': ' + per[i][j] : null).filter(Boolean), b = stab[i], total = b.up + b.degraded + b.down;
    const rec = an.groups.map(g => g.series[i] ? g.group + ' ' + g.series[i] : null).filter(Boolean);
    hit.append(svg('title', {}, when(i) + (spikes.has(i) ? ' · spike' : '') + (an.intercept[i] ? '\nErrors and recovery together' + (an.never[i] ? ' · packets never arrived' : '') : '') + '\n' + (lines.length ? lines.join('\n') + '\nErrors: ' + an.errTotal[i] : 'No errors') + '\n' + (rec.length ? 'Recovery: ' + rec.join(' · ') : 'No recovery activity') + '\n' + (total ? 'Links: ' + Math.round(b.up / total * 100) + '% all healthy' + (b.degraded ? ', ' + Math.round(b.degraded / total * 100) + '% degraded' : '') + (b.down ? ', ' + Math.round(b.down / total * 100) + '% down' : '') : 'Links: no data')));
    s.append(hit);
  }
  return s;
}

function errorLegend(recKinds, an) {
  const lg = document.createElement('div'); lg.className = 'tp-legend';
  const line = (g) => '<span><svg width="22" height="8" style="vertical-align:1px;margin-right:4px"><line x1="1" y1="4" x2="21" y2="4" stroke="' + recStyle[g].color + '" stroke-width="2" stroke-dasharray="' + recStyle[g].dash + '"/></svg>' + g + '</span>';
  lg.innerHTML = Object.keys(recStyle).map(line).join('')
    + '<span><i class="err-sw-band"></i>Errors and recovery together</span><span><i class="err-sw-hit"></i>…with packets that never arrived</span>'
    + '<span><i style="background:#2fb800"></i>All links healthy</span><span><i style="background:#f5a300"></i>Degraded</span><span><i style="background:#e0201b"></i>No link</span>';
  return lg;
}

function errorSection(d) {
  const eh = d.error_history, body = document.createElement('div'), sub = 'How often each kind of transport error happened, and which type it was, with the recovery that absorbed it. Spikes are marked with a red triangle. Absorbed means redundancy covered it and nothing was lost: it is listed in the table but is not counted as a fault.';
  if (!eh || !eh.kinds) { body.append(issueNote('This client build does not record an error history yet.')); return issueSection('Errors over time', sub, ['ok', 'not available'], body); }
  const z = errZoom[errRange], fineData = z.bin < 60 && eh.fine ? eh.fine : null, src = fineData || eh;
  const kinds = eh.kinds, recKinds = eh.recovery_kinds || [], folded = binErrors(src.minutes, kinds.length, z), recFolded = binErrors(src.recovery, recKinds.length, z);
  // Absorbed events (a copy lost on one link and covered by the other, a gap that arrived late) are listed in the table
  // but are not faults: the headline, the chart and the spikes count only what was not absorbed.
  const absorbed = kinds.map(k => k.group === 'Absorbed'), absorbedTotal = folded.totals.reduce((a, b, k) => a + (absorbed[k] ? b : 0), 0);
  const chartFolded = { ...folded, per: folded.per.map(r => r.map((v, k) => absorbed[k] ? 0 : v)), totals: folded.totals.map((v, k) => absorbed[k] ? 0 : v) };
  const sum = chartFolded.totals.reduce((a, b) => a + b, 0), stab = stabilityBins(src.stability, z), an = analyseErrors(kinds, chartFolded, recKinds, recFolded);
  const range = document.createElement('div'); range.className = 'range';
  // One slider scales the chart from 5 second bars (last 5 minutes) out to the whole stored history.
  const slider = document.createElement('input'); slider.type = 'range'; slider.min = 0; slider.max = errZoom.length - 1; slider.step = 1; slider.value = errRange; slider.style.cssText = 'width:min(360px,60%);vertical-align:middle';
  slider.setAttribute('aria-label', 'Time scale');
  const readout = document.createElement('span'); readout.style.marginLeft = '10px'; readout.textContent = z.label + ' shown, one bar = ' + binLabel(z.bin);
  slider.oninput = () => { const v = errZoom[+slider.value]; readout.textContent = v.label + ' shown, one bar = ' + binLabel(v.bin); };
  slider.onchange = () => { errRange = +slider.value; renderIssues(current); };
  range.append(slider, readout);
  body.append(range);
  // Connection state over the range, from the per-second link health the client recorded.
  const sec = stab.reduce((a, b) => ({ up: a.up + b.up, degraded: a.degraded + b.degraded, down: a.down + b.down }), { up: 0, degraded: 0, down: 0 }), secTotal = sec.up + sec.degraded + sec.down;
  if (secTotal > 0) {
    const pct = v => (v / secTotal * 100).toFixed(v / secTotal >= 0.9995 || v === 0 ? 0 : 1) + '%';
    body.append(issueNote('Connection up ' + pct(sec.up + sec.degraded) + ' of the time in this range (all links healthy ' + pct(sec.up) + ', degraded ' + pct(sec.degraded) + ', no healthy link ' + pct(sec.down) + ').'));
  }
  if (!sum && !absorbedTotal && !an.recTotal.some(v => v > 0)) {
    const p = document.createElement('p'); p.className = 'err-ok'; p.textContent = 'No errors or recovery activity recorded in this range.'; body.append(p);
    return issueSection('Errors over time', sub, ['ok', 'none'], body);
  }
  body.append(errorChart(kinds, chartFolded, z.label, an, stab), errorLegend(recKinds, an));
  const nv = kinds.findIndex(k => k.key === 'never_arrived'), neverTotal = nv >= 0 ? folded.totals[nv] : 0;
  body.append(issueNote(an.interceptions
    ? 'Errors and recovery coincided in ' + an.interceptions + ' bin' + (an.interceptions === 1 ? '' : 's') + '; ' + an.aligned + ' of them included packets that never arrived'
      + (neverTotal ? ' (' + neverTotal.toLocaleString() + ' in this range)' : '') + '.' + (an.uncovered ? ' ' + an.uncovered + ' bin' + (an.uncovered === 1 ? ' had' : 's had') + ' never-arrived packets with no recovery activity.' : '')
    : 'Errors and recovery did not coincide in any bin' + (neverTotal ? ', yet ' + neverTotal.toLocaleString() + ' packets never arrived (' + an.uncovered + ' bin' + (an.uncovered === 1 ? '' : 's') + ' with no recovery activity).' : '.')));
  const hours = z.window / 3600, order = kinds.map((k, i) => i).filter(i => folded.totals[i] > 0).sort((a, b) => folded.totals[b] - folded.totals[a]);
  const rows = order.map(i => {
    const tr = document.createElement('tr'), k = kinds[i], name = document.createElement('td'), sw = document.createElement('span');
    sw.className = 'err-sw'; sw.style.background = errColor(kinds, i); name.append(sw, k.label);
    const count = issueCell(folded.totals[i].toLocaleString(), 'num'), rate = issueCell((folded.totals[i] / hours).toFixed(folded.totals[i] / hours < 10 ? 1 : 0), 'num'), help = issueCell(k.help); help.classList.add('err-help');
    tr.append(name, issueCell(k.group), count, rate, help); return tr;
  });
  const recOrder = recKinds.map((k, i) => i).filter(i => recFolded.totals[i] > 0).sort((a, b) => recFolded.totals[b] - recFolded.totals[a]);
  for (const i of recOrder) {
    const tr = document.createElement('tr'), k = recKinds[i], name = document.createElement('td'), line = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    line.setAttribute('width', 14); line.setAttribute('height', 8); line.style.marginRight = '6px';
    line.innerHTML = '<line x1="0" y1="4" x2="14" y2="4" stroke="' + recStyle[k.group].color + '" stroke-width="2" stroke-dasharray="' + recStyle[k.group].dash + '"' + (k.routine ? ' stroke-opacity=".4"' : '') + '/>'; name.append(line, k.label);
    const help = issueCell(k.help); help.classList.add('err-help');
    tr.append(name, issueCell(k.group + (k.routine ? ' (always on)' : ' (recovery)')), issueCell(recFolded.totals[i].toLocaleString(), 'num'), issueCell((recFolded.totals[i] / hours).toFixed(recFolded.totals[i] / hours < 10 ? 1 : 0), 'num'), help); rows.push(tr);
  }
  const table = issueTable(['Type', 'Group', 'Count', 'Per hour', 'What it means'], rows); table.classList.add('err-table'); body.append(table);
  const span = z.window >= 86400 ? '24 h' : z.window >= 3600 ? z.window / 3600 + ' h' : z.window / 60 + ' min', soak = absorbedTotal ? ', ' + absorbedTotal.toLocaleString() + ' absorbed by redundancy' : '';
  const badge = sum ? ['warn', sum.toLocaleString() + ' faults in ' + span + soak] : ['ok', 'no faults in ' + span + soak];
  return issueSection('Errors over time', sub, badge, body);
}
