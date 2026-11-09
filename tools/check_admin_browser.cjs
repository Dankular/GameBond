// Read-only deployed admin portal check. Requires Playwright and Microsoft Edge.
// Credentials are read from disk and never printed. No config/restart/password
// actions are submitted. The only server mutations are session login/logout.
const fs = require('fs');
const path = require('path');
function credential(text) {
  const labelled = text.match(/^\s*(?:admin\s+)?password\s*[:=]\s*(.+?)\s*$/im);
  if (labelled) return labelled[1];
  const value = text.trim();
  if (!value || /[\r\n]/.test(value)) throw Error('Credential file must contain a password line or a labelled Password: entry');
  return value;
}
module.exports = { credential };
async function main() {
  const args = process.argv.slice(2);
  const option = (name, fallback) => { const i = args.indexOf(name); return i < 0 ? fallback : args[i + 1]; };
  const { chromium } = require(path.resolve(option('--playwright', '.runtime/dashboard-preview/node_modules/playwright')));
  const url = option('--url', 'https://195.154.119.136:9444/');
  const password = credential(fs.readFileSync(option('--credentials', '.runtime/admin-password.txt'), 'utf8'));
  const output = option('--output', 'evidence/admin-browser.json');
  const screenshots = option('--screenshots', '.runtime/admin-browser');
  fs.mkdirSync(screenshots, { recursive:true });
  const browser = await chromium.launch({ channel:'msedge', headless:true });
  try {
    const context = await browser.newContext({ ignoreHTTPSErrors:true, viewport:{width:1280,height:900} });
    const page = await context.newPage(), errors = [];
    page.on('pageerror', e => errors.push(e.message));
    await page.goto(url, {waitUntil:'domcontentloaded',timeout:30000});
    await page.getByRole('heading', {name:'Authorization Required',exact:true}).waitFor();
    await page.locator('input[type=password]').fill(password);
    const response = page.waitForResponse(r => new URL(r.url()).pathname === '/api/login');
    await page.getByRole('button', {name:'Login',exact:true}).click();
    const login = await response;
    if (!login.ok()) throw Error('Portal login rejected (' + login.status() + ')');
    await page.getByRole('heading', {name:'Status',exact:true}).waitFor({timeout:20000});
    await page.screenshot({path:path.join(screenshots,'overview.png')});
    const cookie = (await context.cookies()).find(c => c.name === 'gb_session');
    if (!cookie || !cookie.secure || !cookie.httpOnly || cookie.sameSite !== 'Strict') throw Error('Session cookie flags failed');
    const routes = [['status/uplinks','Uplinks'],['status/queues','QoS & Queues'],['status/bandwidth','Realtime Graphs'],['status/firewall','Firewall (NAT)'],['status/log','System Log'],['network/interfaces','Interfaces'],['network/devices','Connected Devices'],['network/routes','Routing'],['system/config','Configuration'],['system/admin','Administration']];
    const pages = [];
    for (const [route,title] of routes) {
      await page.evaluate(route => location.hash='#/'+route,route);
      await page.getByRole('heading',{name:title,exact:true}).first().waitFor({timeout:20000});
      const failures = await page.locator('#view .bad').allTextContents();
      if (failures.some(t => t.startsWith('Unavailable:'))) throw Error(title + ' failed to render');
      pages.push(title);
      if (title === 'Connected Devices') await page.screenshot({path:path.join(screenshots,'devices.png')});
    }
    await page.evaluate(() => location.hash='#/logout');
    await page.getByRole('heading',{name:'Authorization Required',exact:true}).waitFor();
    if (errors.length) throw Error(errors.join('\n'));
    const report = {observed_at:new Date().toISOString(),url,browser:'headless Edge',login:true,read_pages:pages,session_cookie:{httpOnly:cookie.httpOnly,secure:cookie.secure,sameSite:cookie.sameSite},logout:true,page_errors:errors,tls:'self-signed certificate accepted; trust-chain validation not asserted',server_mutations:'session login/logout only'};
    fs.mkdirSync(path.dirname(output),{recursive:true}); fs.writeFileSync(output,JSON.stringify(report,null,2));
    console.log(JSON.stringify(report));
  } finally { await browser.close(); }
}
if (require.main === module) main().catch(error => {console.error(error.message);process.exitCode=1;});
