import { resolve, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createPublicKey } from 'node:crypto';
import { z } from 'zod';
import { AppError } from '../src/protocol.mjs';
import { readOperationsFile } from '../src/product/operations-config.mjs';
import { verifyMonitoringReceipt } from '../src/product/monitoring-receiver.mjs';

export async function runMonitoringReceiptVerify(args) {
  if (args.length !== 2 || args[0] !== '--config') throw new AppError(400, 'MONITORING_RECEIPT_CONFIG_REQUIRED');
  const path = z.string().min(1).max(4096); const config = z.object({ version: z.literal(1), envelopeFile: path, publicKeyFile: path, kind: z.enum(['alert', 'trace', 'log']), id: z.string().min(1).max(128), after: z.number().int().min(0), deployment: z.unknown() }).strict().parse(JSON.parse(await readOperationsFile(args[1])));
  const baseDirectory = dirname(resolve(args[1]));
  const receipt = verifyMonitoringReceipt(JSON.parse(await readOperationsFile(config.envelopeFile, { baseDirectory })), createPublicKey(await readOperationsFile(config.publicKeyFile, { baseDirectory })), { kind: config.kind, id: config.id, after: config.after, expectedDeployment: config.deployment });
  return { status: 'RECEIPT_VERIFIED', deploymentAccepted: false, kind: receipt.kind, deploymentMode: receipt.deployment.mode, humanAcknowledgement: false };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { process.stdout.write(JSON.stringify(await runMonitoringReceiptVerify(process.argv.slice(2))) + '\n'); }
  catch (error) { process.stderr.write(JSON.stringify({ status: 'BLOCKED', code: error instanceof AppError ? error.code : 'MONITORING_RECEIPT_VERIFICATION_FAILED' }) + '\n'); process.exitCode = 1; }
}
