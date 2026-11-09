const journalToolbar = document.querySelector('#logs .toolbar');
const journalKind = select(['Important', 'All events', 'New applications', 'Connection changes'], 'Important', 'Event kind');
const journalPeriod = select(['All Time', 'Today', 'Last Hour'], 'All Time', 'Event period');
const journalRead = action('Mark all as read', async () => {
  try { journalDoc = await api('events', 'POST', { action: 'mark_read' }); renderEvents(); }
  catch (e) { journalError.textContent = e.message; }
});
journalToolbar.prepend(journalKind, journalPeriod, journalRead);
const journalError = element('p', '', { role:'status', class:'notice' }); $('events').before(journalError);
const journalStyle = element('style');
journalStyle.textContent = '#events{padding:0 18px 20px}.journal-date{font-size:12px;color:#5e6b74;margin:18px 0 10px}.journal-card{display:flex;align-items:center;gap:18px;padding:16px;background:#fafbfc;border:1px solid #e6e9ed;border-radius:8px;margin:10px 0}.journal-card.unread{background:#f1f7fc;border-color:#dce9f5}.journal-dot{width:9px;height:9px;border-radius:50%;background:#b3bbc3;flex-shrink:0}.unread .journal-dot{background:#5c91d8}.journal-body{flex:1;overflow-wrap:anywhere}.journal-time{color:#8f969d;font-size:11px;text-align:right;white-space:pre-line}';
document.head.append(journalStyle);
let journalDoc = { events:[], sequence:0, read_through:0 }, journalSignature = '', journalLoading = false;
const journalCards = new Map();
renderEvents = function() {
  if (active !== 'logs') return;
  const signature = JSON.stringify([journalDoc, journalKind.value, journalPeriod.value, $('logfilter').value, new Date().toDateString(), journalPeriod.value === 'Last Hour' ? Math.floor(Date.now()/1000) : 0]);
  if (signature === journalSignature) return;
  journalSignature = signature;
  journalError.textContent = journalDoc.error ? 'History could not be saved: ' + journalDoc.error : '';
  const search = $('logfilter').value.toLowerCase(), now = Date.now(), today = new Date().toDateString();
  const yesterday = new Date(); yesterday.setDate(yesterday.getDate()-1);
  const selected = (journalDoc.events || []).slice().reverse().filter(event => {
    if (journalKind.value === 'New applications' && event.kind !== 'new_app_tunnel_use') return false;
    if (journalKind.value === 'Connection changes' && event.kind !== 'connection_state') return false;
    if (journalPeriod.value === 'Today' && new Date(event.timestamp * 1000).toDateString() !== today) return false;
    if (journalPeriod.value === 'Last Hour' && event.timestamp * 1000 < now - 3600000) return false;
    return !search || [event.text, event.destination, event.application?.name, event.application?.path].some(v => String(v || '').toLowerCase().includes(search));
  }).slice(0,256);
  $('events').replaceChildren(); let previous = '';
  for (const event of selected) {
    const stamp = new Date(event.timestamp * 1000), date = stamp.toDateString();
    if (date !== previous) { $('events').append(element('h3', date === today ? 'Today' : date === yesterday.toDateString() ? 'Yesterday' : stamp.toLocaleDateString([], {day:'numeric',month:'long',year:'numeric'}), {class:'journal-date'})); previous = date; }
    const unread = event.id > journalDoc.read_through;
    const cacheKey = event.id + ':' + unread;
    if (journalCards.has(cacheKey)) { const card = journalCards.get(cacheKey); journalCards.delete(cacheKey); journalCards.set(cacheKey,card); $('events').append(card); continue; }
    const card = element('div', null, {class:'journal-card' + (unread ? ' unread' : ''), 'data-event-id':event.id});
    card.append(element('span', null, {class:'journal-dot', 'aria-label':unread ? 'Unread' : 'Read'}));
    card.append(element('div', event.text + (event.destination ? ' to ' + String(event.destination) : ''), {class:'journal-body'}));
    card.append(element('div', (event.kind === 'new_app_tunnel_use' ? 'First tunnel activity' : 'Connection state') + '\n' + stamp.toLocaleTimeString([], {hour:'numeric',minute:'2-digit'}), {class:'journal-time'}));
    $('events').append(card);
    journalCards.set(cacheKey,card);
    while(journalCards.size>512) journalCards.delete(journalCards.keys().next().value);
  }
  if (!selected.length) $('events').append(element('p', 'No matching tunnel events.'));
};
journalKind.onchange = journalPeriod.onchange = () => { journalSignature='';renderEvents(); };
$('logfilter').oninput = () => renderEvents();
const loadLogsBeforeJournal = loadLogs;
loadLogs = async function() {
  if (journalLoading) return;
  journalLoading = true;
  try { journalDoc = await api('events'); renderEvents(); await loadLogsBeforeJournal(); }
  catch (e) { journalError.textContent = e.message; }
  finally { journalLoading = false; }
};
