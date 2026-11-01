import { open } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppError, MAX_JSON_BYTES } from '../src/protocol.mjs';
import { verifyEvidence } from '../src/evidence.mjs';

/** Bound allocation even when an input file changes after opening. */
async function readBounded(path, maximum) {
  const file = await open(path, 'r');
  try {
    const stat = await file.stat();
    if (!stat.isFile() || stat.size > maximum) throw new AppError(400, 'INVALID_FILE');
    const bytes = Buffer.alloc(maximum + 1); let total = 0;
    while (total <= maximum) {
      const result = await file.read(bytes, total, bytes.length - total, null);
      total += result.bytesRead;
      if (result.bytesRead === 0) break;
    }
    if (total > maximum) throw new AppError(400, 'FILE_TOO_LARGE');
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, total));
  } finally { await file.close(); }
}

/** Both paths must be explicit. Never use an embedded or automatically discovered trust key. */
export async function verifyFiles(bundlePath, pinnedKeyPath) {
  if (typeof bundlePath !== 'string' || typeof pinnedKeyPath !== 'string' || !bundlePath || !pinnedKeyPath) throw new AppError(400, 'TRUST_KEY_REQUIRED');
  try {
    const envelope = JSON.parse(await readBounded(bundlePath, MAX_JSON_BYTES * 2));
    const key = await readBounded(pinnedKeyPath, 2_048);
    return verifyEvidence(envelope, key);
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError(403, 'INVALID_EXPERIMENT_EVIDENCE');
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  (async () => {
    if (args.length !== 2) throw new AppError(400, 'TRUST_KEY_REQUIRED');
    process.stdout.write(`${JSON.stringify(await verifyFiles(args[0], args[1]), null, 2)}\n`);
  })().catch((error) => { process.stderr.write(`${JSON.stringify({ ok: false, error: { code: error instanceof AppError ? error.code : 'VERIFICATION_FAILED' } })}\n`); process.exitCode = 1; });
}
