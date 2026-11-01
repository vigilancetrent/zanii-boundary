import { resolve, dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { open } from 'node:fs/promises';
import { Pool } from 'pg';
import { z } from 'zod';
import { AppError, identifier } from '../src/protocol.mjs';
import { loadOperationsConfig } from '../src/product/operations-config.mjs';
import { openConfiguredStore } from '../src/product/async-store.mjs';
import { createConfiguredObjectStorage } from '../src/adapters/object-storage.mjs';
import { createConfiguredSecretProvider, readProtectedJson, readProtectedFile, readKeyFile } from '../src/product/secret-provider.mjs';
import { createConfiguredAuditArchive } from '../src/product/audit-archive.mjs';
import { createConfiguredBackup } from '../src/product/backup.mjs';
import { restorePostgresSnapshot } from '../src/product/postgres-store.mjs';

const commands = ['object-policy', 'secret-check', 'archive', 'backup', 'backup-verify', 'backup-restore'];
export function parseStorageArguments(args) {
  const [command, ...rest] = args; const options = {}; const allowed = ['config', 'tenant', 'input', 'output', 'expected-sha256', 'target-config'];
  if (!commands.includes(command) || rest.length % 2) throw new AppError(400, 'INVALID_STORAGE_COMMAND');
  for (let index = 0; index < rest.length; index += 2) {
    const name = rest[index].slice(2);
    if (!rest[index].startsWith('--') || !allowed.includes(name) || !rest[index + 1] || Object.hasOwn(options, name)) throw new AppError(400, 'INVALID_STORAGE_ARGUMENTS');
    options[name] = rest[index + 1];
  }
  return { command, options };
}
/** @param {any} request */
export async function runStorageServices({ command, options }) {
  const required = (name) => { if (typeof options[name] !== 'string' || !options[name]) throw new AppError(400, 'STORAGE_CONFIGURATION_REQUIRED'); return options[name]; };
  if (!commands.includes(command)) throw new AppError(400, 'INVALID_STORAGE_COMMAND');
  const { config, material } = await loadOperationsConfig(required('config')); const baseDirectory = material.baseDirectory;
  let store; /** @type {any} */ let service; let targetPool; let targetEncryptionKey; let targetAuditKey;
  try {
    if (command === 'object-policy') {
      service = await createConfiguredObjectStorage(config.services.objects, { baseDirectory }); return await service.verifyBucketPolicy();
    }
    if (command === 'secret-check') {
      service = await createConfiguredSecretProvider(config.services.secrets, { baseDirectory });
      const settings = /** @type {any} */ (config.services.secrets);
      const names = Object.keys(settings.type === 'file' ? settings.files : settings.paths); const records = [];
      for (const name of names) { const value = await service.get(name); records.push({ name, expiresAt: value.expiresAt, ...(value.version ? { version: value.version } : {}) }); }
      return { verified: true, ...service.status(), records };
    }
    const tenantId = identifier(required('tenant')); const role = command === 'archive' ? 'archive' : 'backup';
    if (config.role !== role || config.storage.backend !== 'postgres') throw new AppError(400, 'SEPARATE_POSTGRES_STORAGE_ROLE_REQUIRED');
    store = await openConfiguredStore({ config: { ...config, role: config.realm, storage: { ...config.storage, postgres: { ...config.storage.postgres, role } }, limits: { requestTimeoutMs: config.worker.timeoutMs } }, material });
    if (command === 'archive') {
      service = await createConfiguredAuditArchive(config.services.archive, { store, baseDirectory }); return await service.archive(tenantId);
    }
    service = await createConfiguredBackup(config.services.backup, { store, baseDirectory, restoreSnapshot: restorePostgresSnapshot });
    if (command === 'backup') {
      const output = await service.backup(tenantId);
      if (options.output) { const file = await open(resolve(options.output), 'wx', 0o600); try { await file.writeFile(JSON.stringify(output)); await file.sync(); } finally { await file.close(); } }
      return output;
    }
    const input = await readProtectedJson(required('input'), { maxBytes: 1048576 }); const catalogue = { reference: input.reference, catalogueSha256: input.catalogueSha256 };
    const expectedSha256 = required('expected-sha256'); if (!/^[a-f\d]{64}$/.test(expectedSha256)) throw new AppError(400, 'BACKUP_PIN_REQUIRED');
    if (command === 'backup-verify') return await service.verify(catalogue, { tenantId, expectedSha256 });
    const targetPath = resolve(required('target-config')); const targetBase = dirname(targetPath);
    const path = z.string().min(1).max(4096);
    const targetSchema = z.object({ realm: z.enum(['gateway', 'resource']), credentialsFile: path, caFile: path, encryptionKeyFile: path, auditKeyFile: path, keyringFile: path.optional() }).strict();
    let target; try { target = targetSchema.parse(await readProtectedJson(targetPath, { secret: true })); } catch { throw new AppError(400, 'INVALID_RESTORE_TARGET_CONFIGURATION'); }
    const connectionSchema = z.object({ host: z.string().min(1).max(253), port: z.number().int().min(1).max(65535), database: z.string().min(1).max(128), user: z.string().min(1).max(128), password: z.string().min(1).max(4096) }).strict();
    let connection; try { connection = connectionSchema.parse(await readProtectedJson(target.credentialsFile, { baseDirectory: targetBase, secret: true })); } catch { throw new AppError(400, 'INVALID_RESTORE_TARGET_CREDENTIALS'); }
    targetEncryptionKey = await readKeyFile(target.encryptionKeyFile, { baseDirectory: targetBase }); targetAuditKey = await readKeyFile(target.auditKeyFile, { baseDirectory: targetBase });
    const keyring = target.keyringFile ? await readProtectedJson(target.keyringFile, { baseDirectory: targetBase, secret: true }) : undefined;
    targetPool = new Pool({ ...connection, ssl: { ca: await readProtectedFile(target.caFile, { baseDirectory: targetBase }), rejectUnauthorized: true }, max: 1, connectionTimeoutMillis: 3000, query_timeout: 30000, statement_timeout: 30000 });
    return await service.restore(catalogue, { tenantId, expectedSha256, allowNewTarget: true, target: { pool: targetPool, realm: target.realm, encryptionKey: targetEncryptionKey, auditKey: targetAuditKey, keyring } });
  } finally {
    service?.close?.(); await store?.close?.(); await targetPool?.end();
    material.encryptionKey?.fill?.(0); material.auditKey?.fill?.(0); targetEncryptionKey?.fill(0); targetAuditKey?.fill(0);
  }
}

if (import.meta.url === pathToFileURL(resolve(process.argv[1] ?? '')).href) {
  try { const result = await runStorageServices(parseStorageArguments(process.argv.slice(2))); process.stdout.write(`${JSON.stringify({ status: 'PASS', result })}\n`); }
  catch (error) { process.stderr.write(`${JSON.stringify({ status: 'BLOCKED', code: error instanceof AppError ? error.code : 'STORAGE_ACCEPTANCE_FAILED' })}\n`); process.exitCode = 1; }
}
