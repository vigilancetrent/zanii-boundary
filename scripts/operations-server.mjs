import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { AppError } from '../src/protocol.mjs';
import { loadProductConfig } from '../src/product/config.mjs';
import { startProductServer } from '../src/product/server.mjs';

/** Administrative endpoints use the same verified mTLS/JWT transport and separate operator scopes. */
export async function runOperationsServer(configPath) {
  const settings = await loadProductConfig(configPath);
  if (!settings.config.operations) throw new AppError(400, 'OPERATIONS_CONFIGURATION_REQUIRED');
  return startProductServer(settings);
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  let runtime; let closing;
  try {
    if (process.argv.length !== 4 || process.argv[2] !== '--config') throw new AppError(400, 'INVALID_OPERATIONS_ARGUMENTS');
    runtime = await runOperationsServer(process.argv[3]);
    const close = () => closing ??= runtime.close().catch(() => { process.exitCode = 1; });
    for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, close);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ code: error instanceof AppError ? error.code : 'OPERATIONS_START_FAILED' })}\n`);
    process.exitCode = 1; await runtime?.close();
  }
}
