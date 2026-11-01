import { loadProductConfig } from '../src/product/config.mjs';
import { startProductServer } from '../src/product/server.mjs';

const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--config') throw new Error('Usage: node scripts/start.mjs --config <configuration.json>');
const runtime = await startProductServer(await loadProductConfig(args[1]));
let closing = false;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, async () => {
  if (closing) return; closing = true;
  try { await runtime.close(); process.exitCode = 0; } catch { process.exitCode = 1; }
});
