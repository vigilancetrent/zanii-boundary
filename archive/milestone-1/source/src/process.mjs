import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { exactObject, AppError } from './protocol.mjs';
import { startResource } from './resource.mjs';
import { startBroker } from './broker.mjs';

/** IPC-only service entrypoint: credentials never appear in argv or stdout. */
export function runServiceProcess() {
  if (typeof process.send !== 'function') throw new AppError(400, 'IPC_REQUIRED');
  let service;
  let starting = false;
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    await service?.close();
    if (process.connected) process.disconnect();
  };
  process.on('disconnect', () => { void stop(); });
  process.on('SIGTERM', () => { void stop(); });
  process.on('message', async (message) => {
    try {
      if (message && typeof message === 'object' && 'type' in message && message.type === 'close') {
        exactObject(message, ['type']); await stop(); return;
      }
      const input = /** @type {{version:unknown,role:unknown,configuration:unknown}} */ (exactObject(message, ['version', 'role', 'configuration']));
      if (starting || stopping || input.version !== 1 || (input.role !== 'resource' && input.role !== 'broker')) throw new AppError(400, 'INVALID_CONFIGURATION');
      starting = true;
      service = await (input.role === 'resource' ? startResource(input.configuration) : startBroker(input.configuration));
      if (stopping) { await service.close(); return; }
      process.send?.({ type: 'ready', origin: service.origin });
    } catch {
      process.send?.({ type: 'failure', code: 'SERVICE_START_FAILED' });
      await stop();
      process.exitCode = 1;
    }
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { runServiceProcess(); }
  catch { process.stderr.write('IPC service launch required.\n'); process.exitCode = 1; }
}
