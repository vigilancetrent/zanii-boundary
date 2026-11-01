import { createHash, createHmac, createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import { mkdir, open, unlink, lstat, realpath, link } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import canonicalize from 'canonicalize';
import { AppError, exactObject, identifier, positiveInteger } from '../protocol.mjs';
import { signingKeys, signedValue, verifySignedValue } from './audit-archive.mjs';
import { readProtectedFile, readKeyFile } from './secret-provider.mjs';
import { createConfiguredObjectStorage } from '../adapters/object-storage.mjs';
import { effectiveDeadline, requestContext } from './context.mjs';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fail = (code = 'INVALID_BACKUP_EVIDENCE') => { throw new AppError(400, code); };
const hex = (value) => typeof value === 'string' && /^[a-f\d]{64}$/.test(value);

/** Dedicated backup-owned encrypted spool. No application decryption key is required. */
export async function createSnapshotJournal({ directory, key, maxBytes = 67108864 }) {
  if (!(key instanceof Uint8Array) || key.length !== 32) fail('INVALID_BACKUP_JOURNAL_KEY');
  positiveInteger(maxBytes, 67108864); await mkdir(directory, { recursive: true, mode: 0o700 });
  const before = await lstat(directory); if (!before.isDirectory() || before.isSymbolicLink() || process.platform !== 'win32' && (before.mode & 0o077)) fail('UNSAFE_BACKUP_JOURNAL');
  const root = await realpath(directory); const secret = Buffer.from(key); let closed = false;
  const pathFor = (tenantId, id) => { identifier(tenantId); identifier(id); if (closed) fail('BACKUP_JOURNAL_CLOSED'); return join(root, createHmac('sha256', secret).update(canonicalize([tenantId, id])).digest('hex') + '.snapshot'); };
  async function read(tenantId, id) {
    let raw; try { raw = await readProtectedFile(pathFor(tenantId, id), { secret: true, maxBytes: maxBytes + 4096 }); }
    catch (error) { if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return null; throw error; }
    try {
      const newline = raw.indexOf(10); if (newline < 1 || newline > 2048) fail();
      const header = JSON.parse(raw.subarray(0, newline).toString()); exactObject(header, ['version', 'tenantId', 'id', 'sha256', 'bytes', 'iv', 'tag']);
      if (header.version !== 1 || header.tenantId !== tenantId || header.id !== id || !hex(header.sha256) || !Number.isSafeInteger(header.bytes) || header.bytes > maxBytes) fail();
      const aad = canonicalize({ version: 1, tenantId, id, sha256: header.sha256, bytes: header.bytes });
      const decipher = createDecipheriv('aes-256-gcm', secret, Buffer.from(header.iv, 'base64url')); decipher.setAAD(Buffer.from(aad)); decipher.setAuthTag(Buffer.from(header.tag, 'base64url'));
      const snapshot = Buffer.concat([decipher.update(raw.subarray(newline + 1)), decipher.final()]);
      if (snapshot.length !== header.bytes || hash(snapshot) !== header.sha256) fail(); return snapshot;
    } catch { fail('BACKUP_JOURNAL_INTEGRITY'); }
  }
  return Object.freeze({
    read,
    async write(tenantId, id, snapshot) {
      if (!(snapshot instanceof Uint8Array) || snapshot.length > maxBytes) fail('BACKUP_TOO_LARGE');
      const existing = await read(tenantId, id); if (existing) { if (hash(existing) !== hash(snapshot)) fail('BACKUP_JOURNAL_CONFLICT'); return; }
      const base = { version: 1, tenantId, id, sha256: hash(snapshot), bytes: snapshot.length }; const iv = randomBytes(12);
      const cipher = createCipheriv('aes-256-gcm', secret, iv); cipher.setAAD(Buffer.from(canonicalize(base)));
      const encrypted = Buffer.concat([cipher.update(snapshot), cipher.final()]);
      const finalPath = pathFor(tenantId, id); const temporaryPath = finalPath + '.' + randomUUID() + '.pending';
      const file = await open(temporaryPath, 'wx', 0o600);
      try { await file.writeFile(Buffer.concat([Buffer.from(JSON.stringify({ ...base, iv: iv.toString('base64url'), tag: cipher.getAuthTag().toString('base64url') }) + '\n'), encrypted])); await file.sync(); }
      finally { await file.close(); }
      try { await link(temporaryPath, finalPath); }
      catch (error) {
        if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error;
        const winner = await read(tenantId, id); if (!winner || hash(winner) !== hash(snapshot)) fail('BACKUP_JOURNAL_CONFLICT');
      }
      await unlink(temporaryPath);
      if (process.platform !== 'win32') { const parent = await open(root, 'r'); try { await parent.sync(); } finally { await parent.close(); } }
    },
    async remove(tenantId, id) { try { await unlink(pathFor(tenantId, id)); } catch (error) { if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error; } },
    close() { closed = true; secret.fill(0); },
  });
}

function snapshotShape(snapshot, tenantId, maximum) {
  if (!(snapshot instanceof Uint8Array) || snapshot.length > maximum) fail('BACKUP_TOO_LARGE');
  let value; try { value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(snapshot)); } catch { fail(); }
  if (value.version !== 1 || value.kind !== 'postgres-snapshot' || value.tenantId !== tenantId || !['gateway', 'resource'].includes(value.realm)
      || !Number.isSafeInteger(value.schemaVersion) || value.schemaVersion < 2 || !value.tables || !value.keyEpoch
      || value.checkpoint?.tenantId !== tenantId || !Number.isSafeInteger(value.checkpoint.sequence) || !hex(value.checkpoint.hash)) fail();
  return value;
}
function snapshotKeyIds(snapshot) {
  const keys = new Set([snapshot.keyEpoch.activeKeyId]);
  const walk = (value, depth = 0) => {
    if (depth > 12 || value === null) return;
    if (typeof value === 'string' && value.startsWith('{')) { try { const box = JSON.parse(value); if (typeof box.kid === 'string') keys.add(box.kid); else if (box.v === 1 || box.version === 1) keys.add('legacy-v1'); } catch { /* Encrypted rows can also contain ordinary JSON text. */ } }
    else if (Array.isArray(value)) for (const child of value) walk(child, depth + 1);
    else if (typeof value === 'object') for (const child of Object.values(value)) walk(child, depth + 1);
  };
  walk(snapshot.tables); return [...keys].filter((id) => typeof id === 'string').sort();
}

/** Real per-tenant PostgreSQL logical snapshots; SQLite files are never labelled PostgreSQL backups. */
export function createBackupService({ store, objectStorage, signingKey, publicKey, restoreSnapshot, snapshotJournal, retentionMs = 31536000000, maxSnapshotBytes = 67108864, now = Date.now }) {
  positiveInteger(retentionMs); positiveInteger(maxSnapshotBytes, 67108864);
  const keys = signingKeys(signingKey, publicKey); let lastVerifiedAt = null; let lastSnapshotAt = null;
  const capacityRequiredBytes = maxSnapshotBytes * 12 + 64 * 1024 * 1024;
  const hasCapacity = () => typeof process.availableMemory === 'function' && process.availableMemory() >= capacityRequiredBytes;
  const capacity = () => { if (!hasCapacity()) throw new AppError(503, 'BACKUP_MEMORY_PRESSURE'); };
  if (typeof store.exportSnapshot !== 'function' || !objectStorage.status().requireLock) throw new AppError(400, 'BACKUP_AUTHORITY_REQUIRED');
  const record = async (tenantId, value, lease) => {
    if (typeof store.writeBackupCatalogue !== 'function') throw new AppError(503, 'BACKUP_CATALOGUE_AUTHORITY_REQUIRED');
    await store.writeBackupCatalogue(tenantId, value, { lease });
  };
  /** @param {any} catalogue @param {any} options */
  async function verifyBackup(catalogue, { tenantId, expectedSha256, deadlineAt } = {}) {
    capacity();
    deadlineAt = effectiveDeadline({ deadlineAt, timeoutMs: 300000 });
    identifier(tenantId); exactObject(catalogue, ['reference', 'catalogueSha256']);
    if (!hex(expectedSha256) || catalogue.catalogueSha256 !== expectedSha256) fail('BACKUP_PIN_REQUIRED');
    const raw = await objectStorage.get(catalogue.reference, { tenantId, id: catalogue.reference.id, purpose: 'backup', deadlineAt });
    if (hash(raw) !== expectedSha256) fail('BACKUP_DIGEST_MISMATCH');
    let signed; try { signed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(raw)); } catch { fail(); }
    const manifest = verifySignedValue(signed, keys.publicKey);
    exactObject(manifest, ['version', 'purpose', 'tenantId', 'id', 'realm', 'schemaVersion', 'checkpoint', 'snapshotSha256', 'snapshotBytes', 'keyIds', 'createdAt', 'retainUntil', 'chunks']);
    if (manifest.version !== 1 || manifest.purpose !== 'agent-runtime-postgres-backup' || manifest.tenantId !== tenantId || manifest.id !== catalogue.reference.id
        || !hex(manifest.snapshotSha256) || !Number.isSafeInteger(manifest.snapshotBytes) || manifest.snapshotBytes < 1 || manifest.snapshotBytes > maxSnapshotBytes
        || !Array.isArray(manifest.chunks) || manifest.chunks.length < 1 || manifest.chunks.length > 4096
        || !Number.isSafeInteger(manifest.createdAt) || manifest.createdAt <= 0 || !Number.isSafeInteger(manifest.retainUntil) || manifest.retainUntil <= manifest.createdAt
        || !Array.isArray(manifest.keyIds) || manifest.keyIds.length > 128) fail();
    await objectStorage.verifyRetention(catalogue.reference, { tenantId, minimumUntil: manifest.retainUntil, deadlineAt });
    const chunks = []; let length = 0;
    for (let i = 0; i < manifest.chunks.length; i++) {
      const chunk = manifest.chunks[i]; exactObject(chunk, ['index', 'sha256', 'bytes', 'reference']);
      if (chunk.index !== i || !hex(chunk.sha256) || !Number.isSafeInteger(chunk.bytes) || chunk.bytes < 1 || length + chunk.bytes > manifest.snapshotBytes) fail();
      const bytes = await objectStorage.get(chunk.reference, { tenantId, id: `${manifest.id}-part-${i}`, purpose: 'backup', deadlineAt });
      if (bytes.length !== chunk.bytes || hash(bytes) !== chunk.sha256) fail('BACKUP_DIGEST_MISMATCH');
      await objectStorage.verifyRetention(chunk.reference, { tenantId, minimumUntil: manifest.retainUntil, deadlineAt });
      length += bytes.length; chunks.push(bytes);
    }
    const snapshot = Buffer.concat(chunks);
    if (length !== manifest.snapshotBytes || hash(snapshot) !== manifest.snapshotSha256) fail('BACKUP_DIGEST_MISMATCH');
    const value = snapshotShape(snapshot, tenantId, maxSnapshotBytes);
    if (canonicalize(value.checkpoint) !== canonicalize(manifest.checkpoint) || value.realm !== manifest.realm || value.schemaVersion !== manifest.schemaVersion
        || canonicalize(snapshotKeyIds(value)) !== canonicalize(manifest.keyIds)) fail();
    if (Date.now() >= deadlineAt) throw new AppError(504, 'STORAGE_DEADLINE');
    lastSnapshotAt = manifest.createdAt; lastVerifiedAt = now();
    return { verified: true, manifest, signedManifest: signed, snapshot, catalogue };
  }
  return Object.freeze({
    /** @param {string} tenantId @param {any} options */
    async backup(tenantId, { id = randomUUID(), deadlineAt } = {}) {
      identifier(tenantId); identifier(id);
      capacity();
      if (id.length > 96) fail('INVALID_BACKUP_ID');
      deadlineAt = effectiveDeadline({ deadlineAt, timeoutMs: 300000 });
      const lease = typeof store.claimBackupLease === 'function' ? await store.claimBackupLease(tenantId, id, { ownerId: randomUUID(), ttlMs: Math.min(3600000, deadlineAt - Date.now() + 5000) }) : null;
      if (typeof store.claimBackupLease === 'function' && !lease) throw new AppError(409, 'BACKUP_BUSY');
      try {
      const prior = typeof store.readBackupCatalogue === 'function' ? await store.readBackupCatalogue(tenantId, id) : null;
      if (prior?.status === 'complete') {
        const catalogue = { reference: prior.reference, catalogueSha256: prior.catalogueSha256 };
        await verifyBackup(catalogue, { tenantId, expectedSha256: catalogue.catalogueSha256, deadlineAt });
        return { ...catalogue, checkpoint: prior.checkpoint, snapshotSha256: prior.snapshotSha256, capturedAt: lastSnapshotAt, verifiedAt: lastVerifiedAt, duplicate: true };
      }
      if (prior && !snapshotJournal) throw new AppError(409, 'BACKUP_RECOVERY_REQUIRED');
      const createdAt = prior?.createdAt ?? now(); const retainUntil = prior?.retainUntil ?? createdAt + retentionMs;
      if (!prior) await record(tenantId, { id, status: 'pending', createdAt, retainUntil }, lease);
      // exportSnapshot ends its REPEATABLE READ transaction before any provider request.
      const journaled = snapshotJournal ? await snapshotJournal.read(tenantId, id) : null;
      const snapshot = journaled ?? await store.exportSnapshot(tenantId, { maxBytes: maxSnapshotBytes });
      if (prior?.snapshotSha256 && hash(snapshot) !== prior.snapshotSha256) fail('BACKUP_JOURNAL_CONFLICT');
      const value = snapshotShape(snapshot, tenantId, maxSnapshotBytes);
      if (snapshotJournal && !journaled) await snapshotJournal.write(tenantId, id, snapshot);
      await record(tenantId, { id, status: 'pending', createdAt, retainUntil, snapshotSha256: hash(snapshot), checkpoint: value.checkpoint, keyIds: snapshotKeyIds(value) }, lease);
      const chunks = []; const chunkBytes = objectStorage.status().maxBytes;
      for (let offset = 0, index = 0; offset < snapshot.length; offset += chunkBytes, index++) {
        if (lease) await store.assertBackupLease(lease);
        if (Date.now() >= deadlineAt) throw new AppError(504, 'STORAGE_DEADLINE');
        const bytes = snapshot.subarray(offset, offset + chunkBytes);
        const reference = await objectStorage.put({ tenantId, id: `${id}-part-${index}`, purpose: 'backup', bytes, retentionUntil: retainUntil }, { deadlineAt });
        chunks.push({ index, sha256: hash(bytes), bytes: bytes.length, reference });
      }
      const manifest = { version: 1, purpose: 'agent-runtime-postgres-backup', tenantId, id, realm: value.realm, schemaVersion: value.schemaVersion,
        checkpoint: value.checkpoint, snapshotSha256: hash(snapshot), snapshotBytes: snapshot.length, keyIds: snapshotKeyIds(value), createdAt, retainUntil, chunks };
      const signedManifest = signedValue(manifest, keys.privateKey); const bytes = Buffer.from(canonicalize(signedManifest));
      if (bytes.length > objectStorage.status().maxBytes) fail('BACKUP_CATALOGUE_TOO_LARGE');
      if (lease) await store.assertBackupLease(lease);
      if (Date.now() >= deadlineAt) throw new AppError(504, 'STORAGE_DEADLINE');
      const reference = await objectStorage.put({ tenantId, id, purpose: 'backup', bytes, retentionUntil: retainUntil }, { deadlineAt });
      const catalogue = { reference, catalogueSha256: hash(bytes) };
      await verifyBackup(catalogue, { tenantId, expectedSha256: catalogue.catalogueSha256, deadlineAt });
      lastVerifiedAt = now();
      if (Date.now() >= deadlineAt) throw new AppError(504, 'STORAGE_DEADLINE');
      await record(tenantId, { id, status: 'complete', createdAt, retainUntil, lastVerifiedAt, reference, signedManifest,
        catalogueSha256: catalogue.catalogueSha256, snapshotSha256: manifest.snapshotSha256, checkpoint: value.checkpoint, keyIds: manifest.keyIds }, lease);
      if (snapshotJournal) await snapshotJournal.remove(tenantId, id);
      return { ...catalogue, checkpoint: value.checkpoint, snapshotSha256: manifest.snapshotSha256, capturedAt: lastSnapshotAt, verifiedAt: lastVerifiedAt };
      } finally { if (lease) await store.releaseBackupLease(lease); }
    },
    async verify(catalogue, options) { const result = await verifyBackup(catalogue, options); return { verified: true, manifest: result.manifest, catalogue: result.catalogue }; },
    /** @param {any} catalogue @param {any} options */
    async restore(catalogue, { tenantId, expectedSha256, allowNewTarget, target, deadlineAt } = {}) {
      if (allowNewTarget !== true || typeof restoreSnapshot !== 'function') fail('NEW_RESTORE_TARGET_REQUIRED');
      deadlineAt = effectiveDeadline({ deadlineAt, timeoutMs: 300000 });
      const result = await verifyBackup(catalogue, { tenantId, expectedSha256, deadlineAt });
      return requestContext.run({ ...requestContext.getStore(), deadlineAt }, () => restoreSnapshot({ ...target, snapshot: result.snapshot, expectedSha256: result.manifest.snapshotSha256, allowNewTarget: true }));
    },
    status: () => ({ ...objectStorage.status(), configured: true, kind: 'encrypted-postgres-logical-backup', capturedAt: lastSnapshotAt, lastSnapshotAt, lastVerifiedAt, maxSnapshotBytes, capacityRequiredBytes, healthy: hasCapacity() }),
    close: () => { snapshotJournal?.close(); objectStorage.close(); },
  });
}

/** @param {any} raw @param {any} options */
export async function createConfiguredBackup(raw, { store, restoreSnapshot, baseDirectory = process.cwd() }) {
  exactObject(raw, ['objectStorage', 'signingKeyFile', 'publicKeyFile', 'spoolDirectory', 'spoolKeyFile'], ['retentionMs', 'maxSnapshotBytes']);
  if (typeof store.claimBackupLease !== 'function' || typeof store.assertBackupLease !== 'function' || typeof store.releaseBackupLease !== 'function') throw new AppError(400, 'BACKUP_LEASE_AUTHORITY_REQUIRED');
  const objectStorage = await createConfiguredObjectStorage(raw.objectStorage, { baseDirectory });
  let journal;
  try {
    const key = await readKeyFile(raw.spoolKeyFile, { baseDirectory });
    try { journal = await createSnapshotJournal({ directory: resolve(baseDirectory, raw.spoolDirectory), key, maxBytes: raw.maxSnapshotBytes }); } finally { key.fill(0); }
    return createBackupService({ store, objectStorage, restoreSnapshot, snapshotJournal: journal, signingKey: await readProtectedFile(raw.signingKeyFile, { baseDirectory, secret: true }),
    publicKey: await readProtectedFile(raw.publicKeyFile, { baseDirectory }), retentionMs: raw.retentionMs, maxSnapshotBytes: raw.maxSnapshotBytes }); }
  catch (error) { journal?.close(); objectStorage.close(); throw error; }
}
