import { loadProbeServer } from '../src/product/probe-server.mjs';
import { AppError } from '../src/protocol.mjs';
try {
  const args = process.argv.slice(2); if (args.length !== 2 || args[0] !== '--config') throw new AppError(400, 'PROBE_SERVER_CONFIG_REQUIRED');
  const server = await loadProbeServer(args[1]); let closing;
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => closing ??= server.close().catch(() => { process.exitCode = 1; }));
} catch (error) { process.stderr.write(`${JSON.stringify({ status: 'BLOCKED', code: error instanceof AppError ? error.code : 'PROBE_SERVER_START_FAILED' })}\n`); process.exitCode = 1; }
