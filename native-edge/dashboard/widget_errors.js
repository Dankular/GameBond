// Errors over time for the Issues tab: stacked bars per time bin, coloured by error type, with a spike
// marker and a per-type table of how often each one happened. The daemon keeps the history (error_history
// in the status document), so it survives closing the widget.
const errStyle = document.createElement('style');
errStyle.textContent = '.err-chart{width:100%;max-width:820px;height:auto;display:block}.err-sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:6px;vertical-align:-1px}'
  + '.err-ok{color:#00a66c;font-weight:600}.err-spike{fill:#e0201b}.err-table td.num{text-align:right;font-variant-numeric:tabular-nums}.err-help{color:#7b8490}';
document.head.append(errStyle);

let errRange = 60;
// Each group owns a hue range and its types are spread across it, so neighbours in a stack can be told apart.
const errHue = { Loss: [0, 48], Local: [195, 250], Protocol: [268, 318], Links: [95, 140] };
function errColor(kinds, i) {
  const k = kinds[i], same = kinds.filter(x => x.group === k.group), n = same.indexOf(k), [lo, hi] = errHue[k.group] || [0, 0];
  const hue = same.length > 1 ? lo + (hi - lo) * n / (same.length - 1) : lo;
  return 'hsl(' + hue.toFixed(0) + ' 70% ' + (n % 2 ? 56 : 42) + '%)';
}

// binErrors folds the per-minute rows into `bins` buckets over the last `minutes`.
function binErrors(rows, kindCount, minutes) {
  const bins = Math.min(minutes, 60), binMin = minutes / bins, start = Math.floor(Date.now() / 60000) - minutes + 1;
  const per = Array.from({ length: bins }, () => new Array(kindCount).fill(0)), totals = new Array(kindCount).fill(0);
  for (const row of rows || []) {
    const m = Math.floor(row[0] / 60) - start; if (m < 0 || m >= minutes) continue;
    const i = Math.min(bins - 1, Math.floor(m / binMin));
    for (let k = 0; k < kindCount; k++) { per[i][k] += row[1 + k] || 0; totals[k] += row[1 + k] || 0; }
  }
  return { per, totals, bins, binMin, start };
}

// spikeBins: bins that stand well above the usual (at least 5 errors and 3x the median busy bin).
function spikeBins(binTotals) {
  const busy = binTotals.filter(v => v > 0).sort((a, b) => a - b);
  if (busy.length < 3) return new Set();
  const limit = Math.max(5, 3 * busy[Math.floor(busy.length / 2)]);
  return new Set(binTotals.map((v, i) => v >= limit ? i : -1).filter(i => i >= 0));
}

function errorChart(kinds, folded, minutes) {
  const { per, bins, binMin, start } = folded, width = 760, height = 170, left = 34, bottom = 18, plot = height - bottom, usable = plot - 16, bw = (width - left - 4) / bins;
  const binTotals = per.map(r => r.reduce((a, b) => a + b, 0)), top = Math.max(5, ...binTotals) * 1.1, spikes = spikeBins(binTotals);
  const s = svg('svg', { class: 'topo-svg err-chart', viewBox: '0 0 ' + width + ' ' + height, role: 'img', 'aria-label': 'Errors over time, by type' });
  for (let g = 0; g <= 4; g++) {
    const y = plot - g / 4 * usable;
    s.append(svg('line', { class: 'gl', x1: left, y1: y, x2: width - 4, y2: y }), svg('text', { class: 'tb-sub', x: left - 4, y: y + 3, 'font-size': 10, 'text-anchor': 'end' }, String(Math.round(top * g / 4 * usable / usable))));
  }
  s.append(svg('text', { class: 'tb-sub', x: left, y: height - 4, 'font-size': 10 }, minutes >= 60 ? '-' + (minutes / 60) + ' h' : '-' + minutes + ' min'), svg('text', { class: 'tb-sub', x: width - 4, y: height - 4, 'font-size': 10, 'text-anchor': 'end' }, 'now'));
  const when = i => new Date((start + i * binMin) * 60000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  for (let i = 0; i < bins; i++) {
    let y = plot;
    for (let k = 0; k < kinds.length; k++) {
      const n = per[i][k]; if (!n) continue;
      const h = n / top * usable; y -= h;
      s.append(svg('rect', { x: left + i * bw + 1, y, width: Math.max(1.5, bw - 2), height: Math.max(1, h), rx: 1.5, fill: errColor(kinds, k) }));
    }
    if (spikes.has(i)) s.append(svg('path', { class: 'err-spike', d: 'M' + (left + i * bw + bw / 2 - 4) + ' ' + (y - 9) + 'l8 0l-4 7z' }));
    const hit = svg('rect', { x: left + i * bw, y: 0, width: bw, height: plot, fill: 'transparent' });
    const lines = kinds.map((k, j) => per[i][j] ? k.label + ': ' + per[i][j] : null).filter(Boolean);
    hit.append(svg('title', {}, when(i) + (spikes.has(i) ? ' · spike' : '') + '\n' + (lines.length ? lines.join('\n') + '\nTotal: ' + binTotals[i] : 'No errors')));
    s.append(hit);
  }
  return s;
}

function errorSection(d) {
  const eh = d.error_history, body = document.createElement('div'), sub = 'How often each kind of transport error happened, and which type it was. Spikes are marked with a red triangle.';
  if (!eh || !eh.kinds) { body.append(issueNote('This client build does not record an error history yet.')); return issueSection('Errors over time', sub, ['ok', 'not available'], body); }
  const kinds = eh.kinds, folded = binErrors(eh.minutes, kinds.length, errRange), sum = folded.totals.reduce((a, b) => a + b, 0);
  const range = document.createElement('div'); range.className = 'range';
  for (const [label, minutes] of [['1 h', 60], ['6 h', 360], ['24 h', 1440]]) {
    const b = document.createElement('button'); b.className = 'seg' + (errRange === minutes ? ' active' : ''); b.textContent = label;
    b.onclick = () => { errRange = minutes; renderIssues(current); }; range.append(b);
  }
  body.append(range);
  if (!sum) {
    const p = document.createElement('p'); p.className = 'err-ok'; p.textContent = 'No errors recorded in this range.'; body.append(p);
    return issueSection('Errors over time', sub, ['ok', 'none'], body);
  }
  body.append(errorChart(kinds, folded, errRange));
  const hours = errRange / 60, order = kinds.map((k, i) => i).filter(i => folded.totals[i] > 0).sort((a, b) => folded.totals[b] - folded.totals[a]);
  const rows = order.map(i => {
    const tr = document.createElement('tr'), k = kinds[i], name = document.createElement('td'), sw = document.createElement('span');
    sw.className = 'err-sw'; sw.style.background = errColor(kinds, i); name.append(sw, k.label);
    const count = issueCell(folded.totals[i].toLocaleString(), 'num'), rate = issueCell((folded.totals[i] / hours).toFixed(folded.totals[i] / hours < 10 ? 1 : 0), 'num'), help = issueCell(k.help); help.classList.add('err-help');
    tr.append(name, issueCell(k.group), count, rate, help); return tr;
  });
  const table = issueTable(['Type', 'Group', 'Count', 'Per hour', 'What it means'], rows); table.classList.add('err-table'); body.append(table);
  const worst = kinds[order[0]];
  return issueSection('Errors over time', sub, ['warn', sum.toLocaleString() + ' in ' + (errRange >= 60 ? errRange / 60 + ' h' : errRange + ' min')], (body.append(issueNote('Most frequent: ' + worst.label + ' (' + folded.totals[order[0]].toLocaleString() + ').')), body));
}
