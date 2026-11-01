import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { AppError } from '../src/protocol.mjs';
import { loadOperationsConfig } from '../src/product/operations-config.mjs';
import { createAlertEvent, createConfiguredAlertDelivery } from '../src/product/alerts.mjs';

/** Acceptance sends only to an explicitly configured loopback receiver, never to human channels. */
export async function runAlertCheck(configPath) {
  const { config, material } = await loadOperationsConfig(configPath); const settings = /** @type {any} */ (config.services.alerts);
  if (config.role !== 'worker' || !settings || !['127.0.0.1', '[::1]'].includes(new URL(settings.origin).hostname)) throw new AppError(400, 'CONTROLLED_LOCAL_ALERT_RECEIVER_REQUIRED');
  const sender = await createConfiguredAlertDelivery(settings, { baseDirectory: material.baseDirectory });
  try {
    const event = createAlertEvent({ key: material.auditKey, tenantId: 'system', kind: 'dependency-unavailable', severity: 'warning', code: 'CONTROLLED_LOCAL_ACCEPTANCE' });
    const first = await sender.deliver(event); const duplicate = await sender.deliver(event);
    if (first.duplicate || !duplicate.duplicate) throw new AppError(502, 'ALERT_DEDUPLICATION_NOT_VERIFIED');
    return { passed: true, controlledLocalReceiver: true, authenticatedReceipt: first.delivered, duplicateSuppressed: duplicate.duplicate,
      humanOnCallAcceptance: 'not-validated' };
  } finally { await sender.close(); material.encryptionKey?.fill(0); material.auditKey?.fill(0); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    if (process.argv.length !== 4 || process.argv[2] !== '--config') throw new AppError(400, 'INVALID_OPERATIONS_ARGUMENTS');
    process.stdout.write(`${JSON.stringify(await runAlertCheck(process.argv[3]))}\n`);
  } catch (error) { process.stderr.write(`${JSON.stringify({ code: error instanceof AppError ? error.code : 'ALERT_ACCEPTANCE_FAILED' })}\n`); process.exitCode = 1; }
}
