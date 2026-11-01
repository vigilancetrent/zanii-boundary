import { resolve, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { AppError } from '../src/protocol.mjs';
import { readOperationsFile } from '../src/product/operations-config.mjs';
import { parseProbeServerConfig } from '../src/product/probe-server.mjs';
import { createConfiguredProbe } from '../src/product/probes.mjs';

/** Runs inside the existing probe container; no host publication or caller-selected destination is needed. */
export async function runProbeTarget(args) {
  if (![6, 8].includes(args.length)) throw new AppError(400, 'INVALID_PROBE_TARGET_ARGUMENTS'); const options = {};
  for (let index = 0; index < args.length; index += 2) { const name = args[index]; if (!['--config', '--target', '--mode', '--traceparent'].includes(name) || options[name] || !args[index + 1]) throw new AppError(400, 'INVALID_PROBE_TARGET_ARGUMENTS'); options[name] = args[index + 1]; }
  if (!['gateway', 'resource'].includes(options['--target']) || !['live', 'startup', 'ready', 'metrics'].includes(options['--mode'])) throw new AppError(400, 'INVALID_PROBE_TARGET_ARGUMENTS');
  const config = parseProbeServerConfig(JSON.parse(await readOperationsFile(options['--config']))); const target = config.targets.find((target) => target.name === options['--target']);
  if (!target) throw new AppError(400, 'PROBE_TARGET_UNCONFIGURED'); const probe = await createConfiguredProbe(target.probe, { baseDirectory: dirname(resolve(options['--config'])) });
  return probe.run(options['--mode'], { traceparent: options['--traceparent'] });
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { process.stdout.write(JSON.stringify(await runProbeTarget(process.argv.slice(2))) + '\n'); }
  catch (error) { process.stderr.write(JSON.stringify({ status: 'BLOCKED', code: error instanceof AppError ? error.code : 'PROBE_TARGET_FAILED' }) + '\n'); process.exitCode = 1; }
}
