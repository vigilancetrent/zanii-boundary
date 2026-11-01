import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { AppError } from '../src/protocol.mjs';
import { loadProbe } from '../src/product/probes.mjs';

export async function runProbe(args) {
  const options = {};
  if (args.length !== 4) throw new AppError(400, 'PROBE_CONFIG_AND_MODE_REQUIRED');
  for (let index = 0; index < args.length; index += 2) {
    if (!['--config', '--mode'].includes(args[index]) || options[args[index]] || !args[index + 1]) throw new AppError(400, 'INVALID_PROBE_ARGUMENTS'); options[args[index]] = args[index + 1];
  }
  const probe = await loadProbe(options['--config']); return probe.run(options['--mode']);
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { const result = await runProbe(process.argv.slice(2)); process.stdout.write(result.mode === 'metrics' ? result.metrics : `${JSON.stringify(result)}\n`); }
  catch (error) { process.stderr.write(`${JSON.stringify({ status: 'BLOCKED', code: error instanceof AppError ? error.code : 'PROBE_FAILED' })}\n`); process.exitCode = 1; }
}
