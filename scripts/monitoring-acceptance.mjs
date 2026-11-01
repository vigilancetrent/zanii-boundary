import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { AppError } from '../src/protocol.mjs';
import { validateMonitoringBundle } from '../src/product/monitoring.mjs';
import { loadMonitoringAcceptance } from '../src/product/monitoring-acceptance.mjs';

export async function runMonitoringCommand(args) {
  if (args.length === 1 && args[0] === '--static') return validateMonitoringBundle();
  if ((args.length !== 2 && args.length !== 3) || args[0] !== '--config' || !args[1] || args.length === 3 && args[2] !== '--execute') throw new AppError(400, 'MONITORING_CONFIG_REQUIRED');
  return loadMonitoringAcceptance(args[1], { execute: args[2] === '--execute' });
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { const result = await runMonitoringCommand(process.argv.slice(2)); process.stdout.write(JSON.stringify(result) + '\n'); if (result.status === 'BLOCKED') process.exitCode = 2; }
  catch (error) { process.stderr.write(JSON.stringify({ status: 'BLOCKED', deploymentAccepted: false, code: error instanceof AppError ? error.code : 'MONITORING_ACCEPTANCE_FAILED' }) + '\n'); process.exitCode = 2; }
}
