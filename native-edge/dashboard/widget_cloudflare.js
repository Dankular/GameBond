// Settings: Reverse tunnel (Cloudflare). The user pastes a Cloudflare API token, it is validated, and a new DNS
// record is minted in one of their domains. The client then keeps that name pointed at whichever exit server it is
// using, so the tunnel can be reached by name. The token is kept in a private file by the client and is never shown
// again.
const cfStyle = document.createElement('style');
cfStyle.textContent = '.cf-step{border:1px solid #e1e5eb;border-radius:10px;padding:12px 14px;margin:10px 0}.cf-step.done{border-color:#bfe5b0;background:#f3fbef}.cf-step h4{margin:0 0 6px;font-size:13px}.cf-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:6px 0}'
  + '.cf-row input[type=text],.cf-row input[type=password],.cf-row select{padding:6px 8px;border:1px solid #cfd5dd;border-radius:6px;min-width:0}.cf-name{font-size:16px;font-weight:600;word-break:break-all}.cf-note{color:#505762;font-size:12px;margin:4px 0}.cf-bad{color:#a8120e}.cf-ok{color:#1f6b00}'
  + 'html[data-theme=dark] .cf-step{border-color:#3a404b}html[data-theme=dark] .cf-step.done{background:#17261a;border-color:#2f5a38}html[data-theme=dark] .cf-note{color:#aab2bd}html[data-theme=dark] .cf-row input,html[data-theme=dark] .cf-row select{background:#171a1f;color:#e0e3e8;border-color:#3a404b}';
document.head.append(cfStyle);

const cfDialog = modal('cloudflaredialog', 'Reverse tunnel (Cloudflare)'), cfBody = element('div');
cfDialog.append(cfBody);
let cfState = null, cfZones = [], cfMsg = '', cfBusy = false, cfZonesTried = false;

async function cfCall(body) {
  cfBusy = true; cfMsg = ''; renderCloudflare();
  try { const out = await api('cloudflare', 'POST', body); cfBusy = false; return out; }
  catch (e) { cfBusy = false; cfMsg = e.message; renderCloudflare(); return null; }
}
async function cfReload() { try { cfState = await api('cloudflare'); } catch (e) { cfMsg = e.message; } renderCloudflare(); }

function renderCloudflare() {
  cfBody.replaceChildren();
  if (!cfState) { cfBody.append(element('p', cfMsg || 'Loading…', { class: 'cf-note' })); return; }
  const s = cfState;
  cfBody.append(element('p', 'Give your tunnel a public name that follows your exit server. Paste a Cloudflare API token, check it, and a new DNS record is created for you in one of your domains. The name always points at the exit server in use, and an existing record is never overwritten.', { class: 'help' }));
  if (s.active) return renderCloudflareActive(s);
  // Step 1: the token
  const step1 = element('div', null, { class: 'cf-step' + (s.token_saved ? ' done' : '') });
  step1.append(element('h4', '1. Cloudflare API token' + (s.token_saved ? ' (checked)' : '')));
  if (!s.token_saved) {
    step1.append(element('p', 'In the Cloudflare dashboard open My Profile, API Tokens, Create Token. The token needs the permissions Zone: DNS: Edit and Zone: Zone: Read for your domain.', { class: 'cf-note' }));
    const token = element('input', null, { type: 'password', size: 44, autocomplete: 'off', placeholder: 'Paste the token', 'aria-label': 'Cloudflare API token' });
    const email = element('input', null, { type: 'text', size: 30, placeholder: 'only for a legacy Global API Key: your account email', 'aria-label': 'Account email (legacy key only)' });
    const check = action('Check token', async () => {
      const out = await cfCall({ action: 'validate', token: token.value, email: email.value }); token.value = '';
      if (out?.ok) { cfZones = out.zones || []; cfZonesTried = true; await cfReload(); }
    });
    check.disabled = cfBusy;
    const r1 = element('div', null, { class: 'cf-row' }); r1.append(token, check);
    const r2 = element('div', null, { class: 'cf-row' }); r2.append(email);
    step1.append(r1, r2);
  } else step1.append(element('p', 'The token works and is stored privately. It is never shown again.', { class: 'cf-note cf-ok' }), (() => { const r = element('div', null, { class: 'cf-row' }); r.append(action('Remove token', async () => { if (await cfCall({ action: 'remove' })) { cfZones = []; await cfReload(); } })); return r; })());
  cfBody.append(step1);
  // Step 2: the name
  if (s.token_saved) {
    const step2 = element('div', null, { class: 'cf-step' });
    step2.append(element('h4', '2. Create your name'));
    if (!cfZones.length) {
      cfBody.append(step2); step2.append(element('p', cfZonesTried ? 'No domains are available to this token.' : 'Loading your domains…', { class: 'cf-note' }));
      if (!cfZonesTried) { // once per visit: cfCall redraws the dialog, which must not ask again
        cfZonesTried = true;
        cfCall({ action: 'zones' }).then(out => { if (out?.ok) cfZones = out.zones || []; renderCloudflare(); });
      }
    } else {
      const zone = element('select', null, { 'aria-label': 'Domain' });
      for (const z of cfZones) zone.append(element('option', z.name, { value: z.name }));
      const label = element('input', null, { type: 'text', size: 22, value: s.suggested_label, 'aria-label': 'Name' });
      const preview = element('p', '', { class: 'cf-note' });
      const refresh = () => { preview.textContent = (label.value || '…') + '.' + zone.value + (s.exit_ip ? '  →  ' + s.exit_ip + ' (your exit server)' : '  →  connect first so the record can point at your exit server'); };
      label.oninput = zone.onchange = refresh; refresh();
      const make = action('Create record', async () => {
        const out = await cfCall({ action: 'mint', zone: zone.value, label: label.value });
        if (out?.ok) { cfMsg = 'Created ' + out.name + ' → ' + out.address + '. Reconnect so the client keeps it pointed at the exit server automatically.'; await cfReload(); }
      });
      make.disabled = cfBusy || !s.exit_ip;
      const r = element('div', null, { class: 'cf-row' }); r.append(label, element('span', '.'), zone, make);
      step2.append(r, preview);
      cfBody.append(step2);
    }
  }
  if (cfMsg) cfBody.append(element('p', cfMsg, { class: /^Created/.test(cfMsg) ? 'cf-note cf-ok' : 'cf-note cf-bad', role: 'status' }));
}

function renderCloudflareActive(s) {
  const card = element('div', null, { class: 'cf-step done' }), st = s.status || {};
  card.append(element('h4', 'Your tunnel name'), element('div', s.name, { class: 'cf-name' }));
  const line = st.error ? 'Last update failed: ' + st.error : st.address ? 'Points at ' + st.address + (st.verified_ago_s != null ? ', checked ' + Math.round(st.verified_ago_s) + ' s ago' : '') : 'It will be updated as soon as the tunnel is connected.';
  card.append(element('p', line, { class: 'cf-note ' + (st.error ? 'cf-bad' : '') }));
  const row = element('div', null, { class: 'cf-row' }), del = input('checkbox', '', 'Also delete the DNS record');
  const lab = element('label'); lab.append(del, document.createTextNode(' Also delete the DNS record'));
  row.append(action('Copy name', () => { try { navigator.clipboard.writeText(s.name); cfMsg = 'Copied.'; renderCloudflare(); } catch (e) { /* the name is shown above */ } }),
    action('Remove', async () => { if (await cfCall({ action: 'remove', delete_record: del.checked })) { cfZones = []; await cfReload(); } }), lab);
  card.append(row);
  cfBody.append(card);
  if (cfMsg) cfBody.append(element('p', cfMsg, { class: 'cf-note', role: 'status' }));
}

async function openCloudflare() { cfMsg = ''; cfState = null; cfZonesTried = false; cfZones = []; renderCloudflare(); showDialog('cloudflaredialog'); await cfReload(); }
settingsMenu.append(action('Reverse tunnel (Cloudflare)', () => { settingsDialog.close(); openCloudflare(); }));
