/* Export native pseudocode through REA's MCP server. No target execution.
 * Usage: node tools/export-decomp.cjs <absolute rea-agents package dir> [target]
 * Uses the already installed MCP SDK shipped with REA; installs nothing.
 */
const fs = require('node:fs');
const path = require('node:path');
const { createRequire } = require('node:module');
const root = path.resolve(__dirname, '..');
const packageRoot = path.resolve(process.argv[2] || '');
if (!process.argv[2]) throw new Error('Supply absolute installed rea-agents package directory');
const req = createRequire(path.join(packageRoot, 'package.json'));
const { Client } = req('@modelcontextprotocol/client');
const { StdioClientTransport } = req('@modelcontextprotocol/client/stdio');
const target = process.argv[3] || 'C:\\Program Files (x86)\\Speedify\\speedify.exe';
const targetName = path.basename(target).replace(/[^a-zA-Z0-9_.-]/g, '_');
const out = path.join(root, 'evidence', 'full', targetName);
fs.mkdirSync(out, { recursive: true });
const runtime = path.join(root, 'evidence', 'rea-runtime');
fs.mkdirSync(runtime, { recursive: true });
const log = (message) => console.log(new Date().toISOString(), message);
function save(file, data) {
  const dest = path.join(out, file);
  fs.writeFileSync(dest + '.tmp', JSON.stringify(data));
  fs.renameSync(dest + '.tmp', dest);
}
function value(result) {
  if (result.isError) throw new Error(JSON.stringify(result));
  if (result.structuredContent) return result.structuredContent;
  const text = result.content?.filter(x => x.type === 'text').map(x => x.text).join('\n');
  if (!text) throw new Error('Missing REA result');
  return JSON.parse(text);
}
async function main() {
  const transport = new StdioClientTransport({
    command: process.execPath, args: [path.join(packageRoot, 'scripts', 'rea.mjs'), 'mcp'],
    cwd: root, stderr: 'pipe', maxBufferSize: 128 * 1024 * 1024,
    env: { ...process.env, TEMP: runtime, TMP: runtime,
      GHIDRA_INSTALL_DIR: process.env.GHIDRA_INSTALL_DIR || path.join(root, '.tools', 'ghidra'),
      JAVA_HOME: process.env.JAVA_HOME || 'C:\\Program Files\\Eclipse Adoptium\\jdk-25.0.4.101-hotspot',
      REA_GHIDRA_STARTUP_TIMEOUT_MS: '3600000' }
  });
  const stderr = fs.createWriteStream(path.join(out, 'rea-stderr.log'), { flags: 'a' });
  transport.stderr?.pipe(stderr);
  const client = new Client({ name: 'gamebond-evidence-export', version: '0.1.0' }, { capabilities: {} });
  const call = async (name, args = {}) => value(await client.callTool({ name, arguments: args }, { timeout: 3700000 }));
  let opened = false;
  try {
    await client.connect(transport);
    const catalog = await client.listTools();
    save('tool-catalog.json', catalog);
    for (const name of ['open_binary', 'list_procedures', 'batch_decompile', 'export_evidence_bundle', 'close_binary']) {
      if (!catalog.tools.some(t => t.name === name)) throw new Error('REA tool missing: ' + name);
    }
    const identity = await call('open_binary', { path: target, provider_id: 'ghidra' });
    opened = true;
    save('identity.json', identity);
    log('REA MCP target opened; awaiting complete Ghidra analysis (extended process-local deadline)');
    const inventory = await call('list_procedures');
    save('inventory.json', inventory);
    const rows = inventory.normalized_result;
    if (!Array.isArray(rows)) throw new Error('Unexpected procedure inventory schema');
    const internal = rows.filter(r => !r.procedure?.external);
    const manifest = {
      target: identity, inventory_evidence_id: inventory.evidence_id,
      total_procedures: rows.length, external: rows.length - internal.length,
      internal: internal.length, attempted: 0, successful: 0, failed: 0,
      completed: false, results: [], limitations: inventory.limitations,
      note: 'Pseudocode only. Completeness is relative to Ghidra-discovered internal procedures; external imports have no body. Warnings retained. No original source/server recovery.'
    };
    log(`Inventory: ${rows.length} procedures; ${internal.length} internal`);
    // One bounded batch at a time; successful files are reusable on resume.
    for (let offset = 0; offset < internal.length; offset += 32) {
      const addresses = internal.slice(offset, offset + 32).map(r => r.address);
      const filename = `batch-${String(offset).padStart(6, '0')}.json`;
      const existing = path.join(out, filename);
      let result;
      if (fs.existsSync(existing)) {
        result = JSON.parse(fs.readFileSync(existing, 'utf8'));
        if (result.target_sha256 !== identity.result.sha256 || JSON.stringify(result.addresses) !== JSON.stringify(addresses)) {
          throw new Error('Saved batch identity differs; use a fresh output directory');
        }
        result = result.result;
      } else {
        result = await call('batch_decompile', { addresses });
        save(filename, { target_sha256: identity.result.sha256, addresses, result });
      }
      const batch = result.normalized_result;
      if (!batch || !Array.isArray(batch.items) || batch.total !== addresses.length) {
        throw new Error('Unexpected batch_decompile schema or count');
      }
      manifest.attempted += addresses.length;
      manifest.successful += batch.succeeded;
      manifest.failed += batch.failed;
      manifest.results.push({ file: filename, addresses, evidence_id: result.evidence_id,
        summary: { total: batch.total, succeeded: batch.succeeded, failed: batch.failed } });
      save('manifest.json', manifest);
      log(`Decompiled/recorded ${manifest.attempted}/${internal.length}`);
    }
    await call('export_evidence_bundle', { path: path.join(out, 'evidence-bundle.json'), overwrite: true });
    manifest.completed = true;
    manifest.finished_at = new Date().toISOString();
    // Detailed per-item successes/failures remain in the batch records. Build
    // readable per-function files separately using extract-decomp.py.
    save('manifest.json', manifest);
    log('All discovered internal procedures attempted; evidence saved');
  } catch (error) {
    save('failure.json', { time: new Date().toISOString(), message: String(error), stack: error.stack });
    throw error;
  } finally {
    if (opened) {
      try { await call('close_binary'); } catch (e) { log('close_binary: ' + e); }
    }
    await client.close();
    stderr.end();
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
