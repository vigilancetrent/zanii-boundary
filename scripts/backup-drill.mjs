import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { performance } from 'node:perf_hooks';
import { AppError } from '../src/protocol.mjs';
import { parseStorageArguments, runStorageServices } from './storage-services.mjs';

/** Restore requires a separate, freshly migrated target and an externally pinned catalogue digest. */
export async function runBackupDrill(options) {
  for (const name of ['config', 'tenant', 'input', 'expected-sha256', 'target-config'])
    if (typeof options[name] !== 'string' || !options[name]) throw new AppError(400, 'BACKUP_DRILL_CONFIGURATION_REQUIRED');
  const start = performance.now();
  const verified = await runStorageServices({ command: 'backup-verify', options });
  const restored = await runStorageServices({ command: 'backup-restore', options });
  if (verified.verified !== true || restored.restored !== true || restored.quarantined !== true
      || restored.requiresReauthorization !== true || restored.sourceFencePending !== true
      || verified.manifest.checkpoint.sequence !== restored.checkpoint.sequence
      || verified.manifest.checkpoint.hash !== restored.checkpoint.hash) throw new AppError(409, 'BACKUP_DRILL_CHECKPOINT_MISMATCH');
  return { passed: true, actualRestore: true, elapsedMs: Math.round(performance.now() - start),
    checkpointSequence: restored.checkpoint.sequence, snapshotVerified: true, separateEmptyTarget: true,
    quarantined: restored.quarantined === true, requiresReauthorization: true, sourceFencePending: true,
    hostRecoveryObjective: 'requires-measurement-in-operator-environment' };
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const { options } = parseStorageArguments(['backup-restore', ...process.argv.slice(2)]);
    process.stdout.write(`${JSON.stringify({ status: 'PASS', ...await runBackupDrill(options) })}\n`);
  } catch (error) { process.stderr.write(`${JSON.stringify({ status: 'BLOCKED', code: error instanceof AppError ? error.code : 'BACKUP_DRILL_FAILED' })}\n`); process.exitCode = 1; }
}
