import { open, lstat, mkdir, rename, unlink, statfs } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve, join } from 'node:path';
import { hostname } from 'node:os';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import { AppError } from '../protocol.mjs';
import { routeTemplate } from './observability.mjs';

export const loggingSchema = z.object({ directory: z.string().min(1).max(4096), maxBytes: z.number().int().min(4096).max(67108864).default(8388608),
  files: z.number().int().min(1).max(10).default(3), maxQueueBytes: z.number().int().min(4096).max(1048576).default(65536), required: z.boolean().default(true) }).strict();
const record = z.object({ at: z.string().datetime(), level: z.enum(['info', 'warn', 'error']),
  event: z.enum(['http.request', 'http.security', 'maintenance.job', 'maintenance.worker']), requestId: z.string().regex(/^[A-Za-z0-9._:@-]{1,128}$/).optional(),
  traceparent: z.string().regex(/^00-[a-f0-9]{32}-[a-f0-9]{16}-0[01]$/).optional(), route: z.string().max(128).optional(),
  method: z.enum(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'OTHER']).optional(), status: z.number().int().min(100).max(599).optional(),
  durationMs: z.number().nonnegative().max(3600000).optional(), actor: z.string().regex(/^[a-f0-9]{24}$/).optional(), tenant: z.string().regex(/^[a-f0-9]{24}$/).optional(),
  kind: z.enum(['receipt-recovery', 'audit-archive', 'backup', 'retention', 'object-cleanup', 'privacy-export', 'privacy-delete', 'key-rotation', 'alert-delivery']).optional(),
  state: z.enum(['started', 'succeeded', 'failed', 'running', 'idle', 'error', 'stopped']).optional(), code: z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/).optional() }).strict();

/** Dedicated role-owned files, bounded queue and per-instance rotation; caller bodies cannot become log fields.
 * @param {any} raw @param {any} options */
export async function createConfiguredLogSink(raw, { baseDirectory = process.cwd(), instanceId = hostname() } = {}) {
  const parsed = loggingSchema.safeParse(raw); if (!parsed.success) throw new AppError(400, 'INVALID_LOG_CONFIGURATION'); const config = parsed.data;
  const directory = resolve(baseDirectory, config.directory); await mkdir(directory, { recursive: true, mode: 0o2750 });
  const parent = await lstat(directory);
  const safe = (stat) => stat.isFile() && !stat.isSymbolicLink() && (process.platform === 'win32' || stat.uid === process.getuid() && !(stat.mode & 0o027));
  if (!parent.isDirectory() || parent.isSymbolicLink() || process.platform !== 'win32' && (parent.uid !== process.getuid() || parent.mode & 0o027)) throw new AppError(400, 'UNSAFE_LOG_DIRECTORY');
  const prefix = `runtime-${createHash('sha256').update(instanceId).digest('hex').slice(0, 16)}.jsonl`; const path = join(directory, prefix);
  let file; let bytes = 0; let queuedBytes = 0; let dropped = 0; let failures = 0; let fault = false; let closed = false; let tail = Promise.resolve();
  const checked = async (name) => { try { const stat = await lstat(name); if (!safe(stat)) throw new AppError(400, 'UNSAFE_LOG_FILE'); return stat; } catch (error) { if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return null; throw error; } };
  async function connect() {
    await checked(path); file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_APPEND | (constants.O_NOFOLLOW ?? 0), 0o640);
    const stat = await file.stat(); if (!safe(stat)) { await file.close(); throw new AppError(400, 'UNSAFE_LOG_FILE'); } bytes = stat.size;
  }
  async function rotate() {
    await file.sync(); await file.close(); file = undefined;
    for (let index = config.files - 1; index >= 1; index--) {
      const source = index === 1 ? path : `${path}.${index - 1}`; const target = `${path}.${index}`;
      if (!await checked(source)) continue;
      if (await checked(target)) await unlink(target); await rename(source, target);
    }
    if (config.files === 1 && await checked(path)) await unlink(path); await connect();
  }
  await connect();
  return Object.freeze({
    write(value) {
      let entry;
      try { entry = record.parse(typeof value === 'string' ? JSON.parse(value) : value); if (entry.route && routeTemplate(entry.route) !== entry.route) throw new Error('route'); }
      catch { dropped++; return false; }
      const line = Buffer.from(`${JSON.stringify(entry)}\n`);
      if (closed || line.length > 4096 || queuedBytes + line.length > config.maxQueueBytes) { dropped++; return false; }
      queuedBytes += line.length;
      tail = tail.then(async () => {
        if (!file) await connect(); if (bytes + line.length > config.maxBytes) await rotate();
        let written = 0; while (written < line.length) { const result = await file.write(line, written, line.length - written); if (!result.bytesWritten) throw new Error('write'); written += result.bytesWritten; }
        bytes += written; fault = false;
      }).catch(() => { failures++; fault = true; }).finally(() => { queuedBytes -= line.length; });
      return true;
    },
    status() { return { configured: true, required: config.required, healthy: !closed && !fault && queuedBytes < config.maxQueueBytes, queuedBytes, dropped, failures }; },
    async disk() { const stat = await statfs(directory, { bigint: true }); return { freeBytes: Number(stat.bavail * stat.bsize), totalBytes: Number(stat.blocks * stat.bsize) }; },
    async flush() { await tail; if (file) await file.sync(); if (fault) throw new AppError(503, 'LOG_SINK_UNAVAILABLE'); },
    async close() { if (closed) return; closed = true; await tail; try { if (file) await file.sync(); } finally { await file?.close(); file = undefined; } },
  });
}
