import { resolve, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { z } from 'zod';
import { AppError } from '../src/protocol.mjs';
import { readOperationsFile } from '../src/product/operations-config.mjs';
import { provisionGrafanaDatasources } from '../src/product/monitoring.mjs';

export async function runMonitoringProvision(args) {
  if (args.length !== 2 || args[0] !== '--config') throw new AppError(400, 'MONITORING_PROVISION_CONFIG_REQUIRED');
  const file = z.string().min(1).max(4096); const schema = z.object({ version: z.literal(1), root: file, caFile: file, certFile: file, keyFile: file, output: file }).strict();
  let config; try { config = schema.parse(JSON.parse(await readOperationsFile(args[1]))); } catch { throw new AppError(400, 'INVALID_MONITORING_PROVISION_CONFIGURATION'); }
  const base = dirname(resolve(args[1])); return provisionGrafanaDatasources({ root: resolve(base, config.root), caFile: resolve(base, config.caFile), certFile: resolve(base, config.certFile), keyFile: resolve(base, config.keyFile), output: resolve(base, config.output) });
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { process.stdout.write(JSON.stringify(await runMonitoringProvision(process.argv.slice(2))) + '\n'); }
  catch (error) { process.stderr.write(JSON.stringify({ status: 'BLOCKED', code: error instanceof AppError ? error.code : 'MONITORING_PROVISION_FAILED' }) + '\n'); process.exitCode = 1; }
}
