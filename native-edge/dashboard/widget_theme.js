// Light, dark or follow-the-system theme. The choice is kept in localStorage, which may be blocked
// (private window, cleared site data), so every access is guarded and the page works without it.
const themeStyle = document.createElement('style');
themeStyle.textContent = [
  'html[data-theme=dark]{color-scheme:dark;color:#d7dae0;background:#14161a}',
  'html[data-theme=dark] body{border-color:#2a2e36;background:#14161a}',
  'html[data-theme=dark] button,html[data-theme=dark] select{background:#1f232a;border-color:#343a44;color:#d7dae0}',
  'html[data-theme=dark] button:hover{background:#272c35}',
  'html[data-theme=dark] input,html[data-theme=dark] textarea{background:#1b1e24;border-color:#343a44;color:#d7dae0}',
  'html[data-theme=dark] header,html[data-theme=dark] .toolbar{background:#1a1d23;border-color:#2a2e36}',
  'html[data-theme=dark] nav button,html[data-theme=dark] .toolbar .seg,html[data-theme=dark] .window-controls button,html[data-theme=dark] .session button{background:transparent}',
  'html[data-theme=dark] nav button:hover,html[data-theme=dark] .toolbar .seg:hover{background:#232830}',
  'html[data-theme=dark] nav button.active,html[data-theme=dark] .toolbar .seg.active,html[data-theme=dark] .pill{background:#263050;color:#8fb0ff}',
  'html[data-theme=dark] .window-controls button:hover{background:#2a2e36}',
  'html[data-theme=dark] nav button:not(.active) img,html[data-theme=dark] .window-controls img{filter:brightness(0) invert(.82)}',
  'html[data-theme=dark] .networks,html[data-theme=dark] .traffic-summary,html[data-theme=dark] .session,html[data-theme=dark] th,html[data-theme=dark] .toolbar{border-color:#2a2e36}',
  'html[data-theme=dark] td{border-color:#22262d}html[data-theme=dark] tr:nth-child(even){background:#181b20}',
  'html[data-theme=dark] .stat,html[data-theme=dark] .issue-sec,html[data-theme=dark] fieldset,html[data-theme=dark] .topo-stat,html[data-theme=dark] .dev-card,html[data-theme=dark] .topo-svg{border-color:#2f343d}',
  'html[data-theme=dark] .issue-sec table td,html[data-theme=dark] .issue-sec table th{border-color:#22262d}',
  'html[data-theme=dark] dialog{background:#1c1f25;color:#d7dae0;border-color:#2f343d;box-shadow:0 12px 50px #000a}html[data-theme=dark] dialog::backdrop{background:#000a}',
  'html[data-theme=dark] .graph-wrap{background:#10222a}',
  'html[data-theme=dark] .copy-btn{background:#1f232a;border-color:#343a44;color:#c4cad4}html[data-theme=dark] .copy-btn:hover{background:#272c35}',
  'html[data-theme=dark] .network-card small,html[data-theme=dark] .available,html[data-theme=dark] .help,html[data-theme=dark] .caption,html[data-theme=dark] th,html[data-theme=dark] .traffic-summary .extra,html[data-theme=dark] .issue-sec p.sub,html[data-theme=dark] .issue-sec table th,html[data-theme=dark] .fields label,html[data-theme=dark] .graph-message,html[data-theme=dark] .session,html[data-theme=dark] .journal-time,html[data-theme=dark] .journal-date,html[data-theme=dark] .dev-card .sub,html[data-theme=dark] .topo-stat span,html[data-theme=dark] .gauge span,html[data-theme=dark] .dev-grid h3{color:#8d95a3}',
  'html[data-theme=dark] .traffic-summary .total{color:#b6bfca}',
  'html[data-theme=dark] .accesscard{background:#3a3220;border-color:#7a6420;color:#f1e3b8}',
  'html[data-theme=dark] .journal-card{background:#1b1e24;border-color:#2a2e36}html[data-theme=dark] .journal-card.unread{background:#1a2535;border-color:#2a3b52}',
  'html[data-theme=dark] #protect .selected{background:#263050}html[data-theme=dark] #protect select.allowed{background:#1f3a28;color:#7ddc9a}',
  'html[data-theme=dark] .pie-track,html[data-theme=dark] .gl{stroke:#2a2f38}html[data-theme=dark] .pie-num{fill:#e0e3e8}html[data-theme=dark] .pie-card,html[data-theme=dark] .topo-svg{border-color:#3a404b}html[data-theme=dark] .pie-legend b{color:#aab2bd}',
  'html[data-theme=dark] .tb-rect{fill:#1e2229;stroke:#3a404b}html[data-theme=dark] .tb-title{fill:#e0e3e8}html[data-theme=dark] .tb-sub{fill:#8d95a3}',
  'html[data-theme=dark] .tl{stroke:#566070}html[data-theme=dark] .tl-label{fill:#aab2bd}html[data-theme=dark] .g-bg{fill:#232830;stroke:#3a404b}',
  'html[data-theme=dark] .d-track{stroke:#2a2f38}html[data-theme=dark] .ax{stroke:#3a404b}html[data-theme=dark] .topo-svg{background:#171a1f}',
  'html[data-theme=dark] .chip{background:#2a2f38;color:#c4cad4}html[data-theme=dark] .chip.good{background:#173a1c;color:#7ddc6a}html[data-theme=dark] .chip.poor{background:#43201f;color:#ff9a96}',
  'html[data-theme=dark] .notice{background:#232830;color:#aab2bd}html[data-theme=dark] .svc-bar{background:#2a2f38}',
  'html[data-theme=dark] .subtabs .seg.active,html[data-theme=dark] .range .seg.active{background:#2f6fdf;color:#fff}',
].join('\n');
document.head.append(themeStyle);

const THEME_KEY = 'gamebond-theme', THEME_MODES = ['auto', 'light', 'dark'];
const THEME_LABELS = { auto: '◐ Auto', light: '☀ Light', dark: '☾ Dark' };
const systemDark = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
let themeMode = 'auto';
try { const saved = localStorage.getItem(THEME_KEY); if (THEME_MODES.includes(saved)) themeMode = saved; } catch (e) { /* storage blocked: stay on auto */ }
const themeButton = element('button', null, { id: 'themetoggle', type: 'button' });
function applyTheme() {
  const dark = themeMode === 'dark' || (themeMode === 'auto' && !!systemDark?.matches);
  document.documentElement.dataset.theme = dark ? 'dark' : 'light';
  themeButton.textContent = THEME_LABELS[themeMode];
  themeButton.title = 'Theme: ' + themeMode + '. Click to change.';
  themeButton.setAttribute('aria-label', 'Theme: ' + themeMode + '. Click to change.');
  try { if (typeof current !== 'undefined' && current?.state) renderGraphAfterTheme(); } catch (e) { /* the graph redraws on its next poll */ }
}
function renderGraphAfterTheme() { window.dispatchEvent(new Event('resize')); }
themeButton.onclick = () => {
  themeMode = THEME_MODES[(THEME_MODES.indexOf(themeMode) + 1) % THEME_MODES.length];
  try { localStorage.setItem(THEME_KEY, themeMode); } catch (e) { /* not persisted */ }
  applyTheme();
};
if (systemDark?.addEventListener) systemDark.addEventListener('change', () => { if (themeMode === 'auto') applyTheme(); });
document.querySelector('footer.session').append(themeButton);
applyTheme();
