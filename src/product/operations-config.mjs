import { open, lstat } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { z } from 'zod';
import { AppError } from '../protocol.mjs';
import { loggingSchema } from './logging.mjs';

const age = z.number().int().min(100).max(365 * 86400000);
export const operationsPolicySchema = z.object({
  required: z.boolean().default(false),
  worker: z.object({ required: z.boolean().default(true), maxHeartbeatAgeMs: age.default(60000),
    maxDeadLetters: z.number().int().min(0).max(1000000).default(0), maxPendingAgeMs: age.default(300000) }).strict().optional(),
  archive: z.object({ required: z.boolean().default(true), maxAgeMs: age.default(3600000) }).strict().optional(),
  backup: z.object({ required: z.boolean().default(true), maxAgeMs: age.default(86400000) }).strict().optional(),
}).strict();
export const operationsServicesSchema = z.object(Object.fromEntries(
  ['objects', 'archive', 'backup', 'alerts', 'zanii', 'privacy', 'secrets'].map((name) => [name, z.unknown().optional()]))).strict();
export const productOperationsSchema = z.object({ policy: operationsPolicySchema.optional(), services: operationsServicesSchema.optional() }).strict();

export function parseOperationsPolicy(value) {
  try { return operationsPolicySchema.parse(value ?? {}); }
  catch { throw new AppError(400, 'INVALID_OPERATIONS_POLICY'); }
}

/** Open the checked file itself so an operator-path replacement cannot redirect a credential read. */
export async function readOperationsFile(path, { baseDirectory = process.cwd(), secret = false, maxBytes = 65536 } = {}) {
  if (typeof path !== 'string' || !path || path.length > 4096 || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 1048576)
    throw new AppError(400, 'UNSAFE_OPERATIONS_FILE');
  const full = resolve(baseDirectory, path); let handle;
  try {
    const before = await lstat(full);
    if (!before.isFile() || before.isSymbolicLink() || before.size > maxBytes
      || secret && process.platform !== 'win32' && (before.mode & 0o077)) throw new Error('unsafe');
    handle = await open(full, 'r'); const current = await handle.stat();
    if (!current.isFile() || current.dev !== before.dev || current.ino !== before.ino || current.size > maxBytes
      || secret && process.platform !== 'win32' && (current.mode & 0o077)) throw new Error('changed');
    const bytes = Buffer.alloc(maxBytes + 1); const { bytesRead } = await handle.read(bytes);
    if (bytesRead > maxBytes) throw new Error('overflow');
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, bytesRead));
  } catch { throw new AppError(400, 'UNSAFE_OPERATIONS_FILE'); }
  finally { await handle?.close(); }
}

const path = z.string().min(1).max(4096);
const workerSchema = z.object({
  version: z.literal(1), role: z.enum(['worker', 'archive', 'backup', 'rotator', 'migrator']), realm: z.enum(['gateway', 'resource']),
  storage: z.object({ backend: z.enum(['sqlite', 'postgres']), path: path.optional(), encryptionKeyFile: path.optional(),
    auditKeyFile: path.optional(), keyringFile: path.optional(), retentionMs: age.default(86400000), postgres: z.object({ credentialsFile: path, caFile: path,
      maxConnections: z.number().int().min(1).max(100).default(4), acquireTimeoutMs: z.number().int().min(10).max(10000).default(1000),
      queryTimeoutMs: z.number().int().min(10).max(30000).default(2000), statementTimeoutMs: z.number().int().min(10).max(30000).default(1500),
      lockTimeoutMs: z.number().int().min(1).max(10000).default(500) }).strict().optional() }).strict(),
  worker: z.object({ ownerId: z.string().min(1).max(128).optional(), pollIntervalMs: z.number().int().min(10).max(60000).default(1000),
    leaseMs: z.number().int().min(100).max(3600000).default(30000), timeoutMs: z.number().int().min(100).max(3600000).default(20000),
    batchSize: z.number().int().min(1).max(100).default(10) }).strict(),
  services: operationsServicesSchema.default({}),
  policy: operationsPolicySchema.optional(), telemetry: z.record(z.string(), z.unknown()).optional(),
  logging: loggingSchema.optional(),
  keyVerification: z.object({ archivePublicKeyFile: path.optional(), backupPublicKeyFile: path.optional() }).strict().optional(),
  recovery: z.object({ fenceVerifier: z.record(z.string(), z.unknown()) }).strict().optional(),
}).strict();

export function parseOperationsConfig(value) {
  try {
    const parsed = workerSchema.parse(value);
    if (parsed.storage.backend === 'sqlite' ? !parsed.storage.path || parsed.storage.postgres : !parsed.storage.postgres) throw new Error('backend');
    if (parsed.worker.timeoutMs >= parsed.worker.leaseMs) throw new Error('lease');
    if (parsed.role !== 'worker' && parsed.storage.backend === 'sqlite') throw new Error('role');
    if (['worker', 'rotator'].includes(parsed.role) && (!parsed.storage.encryptionKeyFile || !parsed.storage.auditKeyFile)) throw new Error('keys');
    if (['archive', 'backup', 'migrator'].includes(parsed.role) && (parsed.storage.encryptionKeyFile || parsed.storage.auditKeyFile || parsed.storage.keyringFile)) throw new Error('ciphertext-role-separation');
    if ((parsed.keyVerification || parsed.recovery) && parsed.role !== 'rotator') throw new Error('rotator-settings');
    return parsed;
  } catch { throw new AppError(400, 'INVALID_OPERATIONS_CONFIGURATION'); }
}

/** Worker configurations deliberately have no HTTP issuer/signing-key requirements. */
export async function loadOperationsConfig(path) {
  let config;
  const baseDirectory = dirname(resolve(path));
  try { config = parseOperationsConfig(JSON.parse(await readOperationsFile(path))); }
  catch (error) { throw error instanceof AppError ? error : new AppError(400, 'INVALID_OPERATIONS_CONFIGURATION'); }
  const key = async (name) => {
    const text = (await readOperationsFile(config.storage[name], { baseDirectory, secret: true, maxBytes: 128 })).trim();
    if (!/^[a-f0-9]{64}$/i.test(text)) throw new AppError(400, 'INVALID_OPERATIONS_KEY');
    return Buffer.from(text, 'hex');
  };
  const encryptionKey = config.storage.encryptionKeyFile ? await key('encryptionKeyFile') : undefined;
  const auditKey = config.storage.auditKeyFile ? await key('auditKeyFile') : undefined;
  const keyring = config.storage.keyringFile
    ? JSON.parse(await readOperationsFile(config.storage.keyringFile, { baseDirectory, secret: true })) : undefined;
  let postgres;
  if (config.storage.postgres) {
    const connection = z.object({ host: z.string().min(1).max(253), port: z.number().int().min(1).max(65535),
      database: z.string().min(1).max(128), user: z.string().min(1).max(128), password: z.string().min(1).max(4096) }).strict()
      .parse(JSON.parse(await readOperationsFile(config.storage.postgres.credentialsFile, { baseDirectory, secret: true })));
    postgres = { connection, ca: await readOperationsFile(config.storage.postgres.caFile, { baseDirectory }) };
  }
  return { config: { ...config, storage: { ...config.storage, ...(config.storage.path ? { path: resolve(baseDirectory, config.storage.path) } : {}) } },
    material: { baseDirectory, encryptionKey, auditKey, ...(keyring ? { keyring } : {}), ...(postgres ? { postgres } : {}) } };
}
