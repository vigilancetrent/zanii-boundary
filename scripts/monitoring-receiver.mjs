import { loadMonitoringReceiver } from '../src/product/monitoring-receiver.mjs';
import { AppError } from '../src/protocol.mjs';
const args = process.argv.slice(2);
try {
  if (args.length !== 2 || args[0] !== '--config') throw new AppError(400, 'MONITOR_RECEIVER_CONFIG_REQUIRED');
  const server = await loadMonitoringReceiver(args[1]); let closing;
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => closing ??= server.close().catch(() => { process.exitCode = 1; }));
} catch (error) { process.stderr.write(`${JSON.stringify({ status: 'BLOCKED', code: error instanceof AppError ? error.code : 'MONITOR_RECEIVER_START_FAILED' })}\n`); process.exitCode = 1; }
