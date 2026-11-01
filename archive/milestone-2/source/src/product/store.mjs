import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import canonicalize from 'canonicalize';
import { AppError, exactObject, identifier, positiveInteger } from '../protocol.mjs';

const NAMESPACES = new Set(['tasks', 'approvals', 'flows', 'memory', 'incidents', 'learning-examples', 'learning-candidates',
  'learning-active', 'learning-promotions', 'operations', 'a2a', 'coverage', 'outbox', 'metadata',
  'documents', 'deliveries', 'resource-operations']);
const MAX_VALUE_BYTES = 65_536;
const MAX_DATABASE_BYTES = 128 * 1024 * 1024;
const ACTIVE = new Set(['reserved', 'dispatched', 'unknown']);
const NEXT = { reserved: ['dispatched', 'failed', 'unknown'], dispatched: ['succeeded', 'failed', 'unknown'], unknown: ['succeeded', 'failed'] };
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const bad = (code = 'INVALID_STORE_INPUT', status = 400) => { throw new AppError(status, code); };

function keyMaterial(value) {
  const bytes = typeof value === 'string' && /^[a-f\d]{64}$/i.test(value) ? Buffer.from(value, 'hex') : value;
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) bad('INVALID_ENCRYPTION_KEY');
  return Buffer.from(bytes);
}
function scope(tenant, namespace, id) {
  identifier(tenant); identifier(namespace); if (!NAMESPACES.has(namespace)) bad();
  if (id !== undefined) identifier(id);
}
function json(value) {
  let bytes;
  try { bytes = canonicalize(value); } catch { bad(); }
  if (typeof bytes !== 'string' || Buffer.byteLength(bytes) > MAX_VALUE_BYTES) bad('STORE_VALUE_TOO_LARGE');
  return bytes;
}
function equal(a, b) {
  const x = Buffer.from(a ?? ''); const y = Buffer.from(b ?? '');
  return x.length === y.length && timingSafeEqual(x, y);
}
function safeFile(path, { existing = false } = {}) {
  if (typeof path !== 'string' || !path || path.length > 4096 || path === ':memory:') bad('INVALID_STORAGE_PATH');
  const full = resolve(path);
  if (existsSync(full) && (lstatSync(full).isSymbolicLink() || !lstatSync(full).isFile())) bad('INVALID_STORAGE_PATH');
  if (existing && !existsSync(full)) bad('STORAGE_FILE_MISSING');
  return full;
}

/** Single-host durable store. Network callbacks must never be placed inside transaction(). */
export function openStore({ path, encryptionKey, auditKey = encryptionKey, maxBytes = MAX_DATABASE_BYTES }) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 65_536 || maxBytes > MAX_DATABASE_BYTES) bad('INVALID_STORAGE_CAPACITY');
  const fullPath = safeFile(path);
  const key = keyMaterial(encryptionKey); const chainKey = keyMaterial(auditKey);
  mkdirSync(dirname(fullPath), { recursive: true, mode: 0o700 });
  const existing = existsSync(fullPath) && lstatSync(fullPath).size > 0;
  const db = new DatabaseSync(fullPath);
  let depth = 0; let closed = false;
  db.exec('PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;');
  const pageSize = Number(db.prepare('PRAGMA page_size').get().page_size);
  db.exec(`PRAGMA max_page_count=${Math.floor(maxBytes / pageSize)};`);
  if (Number(db.prepare('PRAGMA max_page_count').get().max_page_count) * pageSize > maxBytes) { db.close(); bad('STORE_EXCEEDS_CAPACITY', 503); }
  const version = db.prepare('PRAGMA user_version').get().user_version;
  if (existing && version !== 1) { db.close(); bad('UNSUPPORTED_STORE_VERSION', 500); }
  db.exec(`CREATE TABLE IF NOT EXISTS objects (
    tenant TEXT NOT NULL, namespace TEXT NOT NULL, id TEXT NOT NULL, encrypted TEXT NOT NULL, expires INTEGER,
    PRIMARY KEY(tenant,namespace,id), CHECK(expires IS NULL OR expires>0)) STRICT;
    CREATE INDEX IF NOT EXISTS objects_expiry ON objects(expires);
    CREATE TABLE IF NOT EXISTS operations (
    tenant TEXT NOT NULL, id TEXT NOT NULL, task TEXT NOT NULL, root TEXT NOT NULL, digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('reserved','dispatched','unknown','succeeded','failed')),
    encrypted TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL, PRIMARY KEY(tenant,id)) STRICT;
    CREATE INDEX IF NOT EXISTS operations_state ON operations(tenant,state,updated);
    CREATE TABLE IF NOT EXISTS usage (tenant TEXT NOT NULL, root TEXT NOT NULL, consumed INTEGER NOT NULL CHECK(consumed>=0), mac TEXT NOT NULL,
    PRIMARY KEY(tenant,root)) STRICT;
    CREATE TABLE IF NOT EXISTS audit (tenant TEXT NOT NULL, sequence INTEGER NOT NULL, previous TEXT NOT NULL,
    hash TEXT NOT NULL, mac TEXT NOT NULL, encrypted TEXT NOT NULL, at INTEGER NOT NULL,
    PRIMARY KEY(tenant,sequence)) STRICT;
    PRAGMA user_version=1;`);
  const encrypt = (value, aad) => {
    const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(aad)); const encrypted = Buffer.concat([cipher.update(json(value), 'utf8'), cipher.final()]);
    return JSON.stringify({ v: 1, iv: iv.toString('base64url'), data: encrypted.toString('base64url'), tag: cipher.getAuthTag().toString('base64url') });
  };
  const decrypt = (value, aad) => {
    try {
      const box = JSON.parse(value); if (box.v !== 1) throw new Error('Version');
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(box.iv, 'base64url'));
      decipher.setAAD(Buffer.from(aad)); decipher.setAuthTag(Buffer.from(box.tag, 'base64url'));
      return JSON.parse(Buffer.concat([decipher.update(Buffer.from(box.data, 'base64url')), decipher.final()]).toString('utf8'));
    } catch { bad('STORE_INTEGRITY_ERROR', 500); }
  };
  const objectAAD = (tenant, namespace, id, expires) => JSON.stringify(['object', tenant, namespace, id, expires]);
  const operationAAD = (tenant, id) => JSON.stringify(['operation', tenant, id]);
  const usageMac = (tenant, root, consumed) => createHmac('sha256', chainKey).update(JSON.stringify(['usage', tenant, root, consumed])).digest('hex');
  const rawGet = (tenant, namespace, id) => db.prepare('SELECT encrypted,expires FROM objects WHERE tenant=? AND namespace=? AND id=?').get(tenant, namespace, id);
  const get = (tenant, namespace, id) => {
    scope(tenant, namespace, id); const row = rawGet(tenant, namespace, id);
    if (!row) return null;
    const value = decrypt(row.encrypted, objectAAD(tenant, namespace, id, row.expires));
    if (row.expires !== null && Number(row.expires) <= Date.now()) return null;
    return value;
  };
  const put = (tenant, namespace, id, value, { expiresAt = null } = {}) => {
    scope(tenant, namespace, id); if (expiresAt !== null) positiveInteger(expiresAt);
    if (!rawGet(tenant, namespace, id) && Number(db.prepare('SELECT count(*) AS n FROM objects WHERE tenant=? AND namespace=?').get(tenant, namespace).n) >= 50_000) bad('STORE_QUOTA', 429);
    const encrypted = encrypt(value, objectAAD(tenant, namespace, id, expiresAt));
    db.prepare('INSERT INTO objects(tenant,namespace,id,encrypted,expires) VALUES(?,?,?,?,?) ON CONFLICT(tenant,namespace,id) DO UPDATE SET encrypted=excluded.encrypted,expires=excluded.expires').run(tenant, namespace, id, encrypted, expiresAt);
    return JSON.parse(json(value));
  };
  const transaction = (fn) => {
    if (typeof fn !== 'function' || fn.constructor.name === 'AsyncFunction') bad('ASYNC_TRANSACTION', 500);
    if (depth) { const value = fn(); if (value?.then) bad('ASYNC_TRANSACTION', 500); return value; }
    db.exec('BEGIN IMMEDIATE'); depth += 1;
    try { const result = fn(); if (result?.then) bad('ASYNC_TRANSACTION', 500); db.exec('COMMIT'); return result; }
    catch (error) {
      try { if (db.isTransaction) db.exec('ROLLBACK'); } catch { bad('STORE_ROLLBACK_FAILED', 503); }
      if (error && typeof error === 'object' && 'errcode' in error && error.errcode === 13) bad('STORE_CAPACITY_ERROR', 503);
      throw error;
    } finally { depth -= 1; }
  };
  const getOperation = (tenant, id) => {
    scope(tenant, 'operations', id); const row = db.prepare('SELECT * FROM operations WHERE tenant=? AND id=?').get(tenant, id);
    if (!row) return null;
    const value = decrypt(row.encrypted, operationAAD(tenant, id));
    if (value.status !== row.state || value.taskId !== row.task || value.rootTaskId !== row.root || value.actionDigest !== row.digest
        || value.createdAt !== row.created || value.updatedAt !== row.updated) bad('STORE_INTEGRITY_ERROR', 500);
    return value;
  };
  const appendAudit = ({ tenantId, actorId, event, target = null, data = null, at = Date.now() }) => transaction(() => {
    identifier(tenantId); identifier(actorId); identifier(event); if (target !== null) identifier(target); positiveInteger(at);
    const tail = db.prepare('SELECT sequence,hash FROM audit WHERE tenant=? ORDER BY sequence DESC LIMIT 1').get(tenantId);
    const sequence = Number(tail?.sequence ?? 0) + 1; if (sequence > 1_000_000) bad('AUDIT_QUOTA', 429);
    const previous = tail?.hash ?? '0'.repeat(64);
    const encrypted = encrypt({ actorId, event, target, data }, JSON.stringify(['audit', tenantId, sequence]));
    const digest = hash(json({ tenantId, sequence, previous, encrypted, at }));
    const mac = createHmac('sha256', chainKey).update(digest).digest('hex');
    db.prepare('INSERT INTO audit VALUES(?,?,?,?,?,?,?)').run(tenantId, sequence, previous, digest, mac, encrypted, at);
    return { tenantId, sequence, hash: digest, mac, at };
  });
  const reserveOperation = (input) => transaction(() => {
    const { tenantId, taskId, rootTaskId = taskId, operationId, actionDigest, action, policyDigest,
      toolVersion, maxActions, approvalId, requiresApproval = false, now = Date.now() } = input;
    for (const id of [tenantId, taskId, rootTaskId, operationId, actionDigest, policyDigest]) identifier(id);
    positiveInteger(now); positiveInteger(maxActions, 1_000_000); identifier(String(toolVersion));
    const task = get(tenantId, 'tasks', taskId); const root = get(tenantId, 'tasks', rootTaskId);
    if (!task || !root || task.revoked || root.revoked || task.expiresAt <= now || root.expiresAt <= now) bad('TASK_UNAVAILABLE', 403);
    if ((task.rootTaskId ?? task.id) !== rootTaskId) bad('TASK_ROOT_MISMATCH', 403);
    const lineage = []; const visited = new Set(); let current = task;
    while (current) {
      if (visited.has(current.id) || lineage.length >= 16 || current.revoked || current.expiresAt <= now) bad('TASK_LINEAGE_INVALID', 403);
      visited.add(current.id); lineage.push(current);
      if (!current.parentId) break;
      current = get(tenantId, 'tasks', current.parentId);
      if (!current) bad('TASK_LINEAGE_INVALID', 403);
    }
    if (lineage.at(-1).id !== rootTaskId) bad('TASK_ROOT_MISMATCH', 403);
    if (root.maxActions !== maxActions) bad('ROOT_QUOTA_MISMATCH', 403);
    const existingOperation = getOperation(tenantId, operationId);
    if (existingOperation) {
      if (existingOperation.actionDigest !== actionDigest || existingOperation.taskId !== taskId) bad('IDEMPOTENCY_CONFLICT', 409);
      return { created: false, operation: existingOperation };
    }
    for (const ancestor of lineage) {
      positiveInteger(ancestor.maxActions, 1_000_000);
      const usage = db.prepare('SELECT consumed,mac FROM usage WHERE tenant=? AND root=?').get(tenantId, ancestor.id);
      const count = usage?.consumed ?? 0;
      if (usage && !equal(usage.mac, usageMac(tenantId, ancestor.id, count))) bad('STORE_INTEGRITY_ERROR', 500);
      if (count >= ancestor.maxActions) bad(ancestor.id === rootTaskId ? 'ROOT_QUOTA' : 'TASK_QUOTA', 429);
    }
    if (requiresApproval && !approvalId) bad('APPROVAL_REQUIRED', 403);
    if (approvalId) {
      const approval = get(tenantId, 'approvals', approvalId);
      if (!approval || approval.used || approval.taskId !== taskId || approval.actionDigest !== actionDigest
          || approval.policyDigest !== policyDigest || String(approval.toolVersion) !== String(toolVersion)
          || approval.expiresAt <= now || approval.approverId === task.actorId) bad('APPROVAL_INVALID', 403);
      put(tenantId, 'approvals', approvalId, { ...approval, used: true }, { expiresAt: approval.expiresAt });
    }
    const operation = { id: operationId, tenantId, taskId, rootTaskId, actionDigest, action, policyDigest,
      toolVersion, status: 'reserved', createdAt: now, updatedAt: now, result: null };
    db.prepare('INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?)').run(tenantId, operationId, taskId, rootTaskId, actionDigest, 'reserved', encrypt(operation, operationAAD(tenantId, operationId)), now, now);
    for (const ancestor of lineage) {
      const consumed = Number(db.prepare('SELECT consumed FROM usage WHERE tenant=? AND root=?').get(tenantId, ancestor.id)?.consumed ?? 0) + 1;
      db.prepare('INSERT INTO usage VALUES(?,?,?,?) ON CONFLICT(tenant,root) DO UPDATE SET consumed=excluded.consumed,mac=excluded.mac').run(tenantId, ancestor.id, consumed, usageMac(tenantId, ancestor.id, consumed));
    }
    appendAudit({ tenantId, actorId: task.actorId, event: 'operation.reserved', target: operationId, data: { actionDigest, taskId, rootTaskId }, at: now });
    return { created: true, operation };
  });
  const transitionOperation = (tenant, id, status, result = null) => transaction(() => {
    const operation = getOperation(tenant, id); if (!operation) bad('OPERATION_NOT_FOUND', 404);
    if (!(NEXT[operation.status] ?? []).includes(status)) bad('INVALID_OPERATION_TRANSITION', 409);
    const next = { ...operation, status, result, updatedAt: Date.now() };
    db.prepare('UPDATE operations SET state=?,encrypted=?,updated=? WHERE tenant=? AND id=? AND state=?').run(status, encrypt(next, operationAAD(tenant, id)), next.updatedAt, tenant, id, operation.status);
    appendAudit({ tenantId: tenant, actorId: 'runtime', event: `operation.${status}`, target: id, data: { actionDigest: operation.actionDigest } });
    return next;
  });
  const verifyAudit = (tenant, expectedCheckpoint) => {
    identifier(tenant); const rows = db.prepare('SELECT * FROM audit WHERE tenant=? ORDER BY sequence').iterate(tenant);
    let previous = '0'.repeat(64); let sequence = 0; let lastMac;
    for (const row of rows) {
      sequence += 1;
      const digest = hash(json({ tenantId: tenant, sequence, previous, encrypted: row.encrypted, at: row.at }));
      if (row.sequence !== sequence || row.previous !== previous || row.hash !== digest
          || !equal(row.mac, createHmac('sha256', chainKey).update(digest).digest('hex'))) bad('AUDIT_INTEGRITY_ERROR', 500);
      decrypt(row.encrypted, JSON.stringify(['audit', tenant, sequence])); previous = digest; lastMac = row.mac;
    }
    const checkpoint = { tenantId: tenant, sequence, hash: previous, mac: lastMac ?? createHmac('sha256', chainKey).update(previous).digest('hex') };
    if (expectedCheckpoint && (expectedCheckpoint.tenantId !== tenant || expectedCheckpoint.sequence !== sequence
        || !equal(expectedCheckpoint.hash, checkpoint.hash) || !equal(expectedCheckpoint.mac, checkpoint.mac))) bad('AUDIT_CHECKPOINT_MISMATCH', 500);
    return { ok: true, ...checkpoint };
  };
  try {
    const sentinel = rawGet('system', 'metadata', 'key-check');
    if (existing && !sentinel) bad('STORE_KEY_CHECK_MISSING', 500);
    if (sentinel) { if (get('system', 'metadata', 'key-check')?.marker !== 'agent-runtime-store-v1') bad('STORE_KEY_MISMATCH', 500); }
    else put('system', 'metadata', 'key-check', { marker: 'agent-runtime-store-v1' });
  } catch (error) { db.close(); throw error; }
  return Object.freeze({
    path: fullPath, get, put, transaction, getOperation, reserveOperation, transitionOperation, appendAudit, verifyAudit,
    checkpoint: (tenant) => { const value = verifyAudit(tenant); return { tenantId: value.tenantId, sequence: value.sequence, hash: value.hash, mac: value.mac }; },
    list(tenant, namespace, { limit = 50, after = '' } = {}) {
      scope(tenant, namespace); positiveInteger(limit, 100); if (after) identifier(after);
      const rows = db.prepare('SELECT id,encrypted,expires FROM objects WHERE tenant=? AND namespace=? AND id>? AND (expires IS NULL OR expires>?) ORDER BY id LIMIT ?').all(tenant, namespace, after, Date.now(), limit + 1);
      const page = rows.slice(0, limit).map((row) => ({ id: row.id, value: decrypt(row.encrypted, objectAAD(tenant, namespace, row.id, row.expires)), expiresAt: row.expires }));
      return { items: page, next: rows.length > limit ? page.at(-1).id : null };
    },
    delete(tenant, namespace, id) { scope(tenant, namespace, id); return db.prepare('DELETE FROM objects WHERE tenant=? AND namespace=? AND id=?').run(tenant, namespace, id).changes; },
    /** Authenticate a bounded batch before deleting; tampered expiry must not erase evidence. */
    purgeExpired(now = Date.now(), { limit = 100 } = {}) {
      positiveInteger(now); positiveInteger(limit, 1000);
      return transaction(() => {
        const rows = db.prepare('SELECT tenant,namespace,id,encrypted,expires FROM objects WHERE expires IS NOT NULL AND expires<=? ORDER BY expires,tenant,namespace,id LIMIT ?').all(now, limit);
        for (const row of rows) decrypt(row.encrypted, objectAAD(row.tenant, row.namespace, row.id, row.expires));
        let removed = 0;
        for (const row of rows) removed += Number(db.prepare('DELETE FROM objects WHERE tenant=? AND namespace=? AND id=? AND expires=?').run(row.tenant, row.namespace, row.id, row.expires).changes);
        return removed;
      });
    },
    queryAudit(tenant, { limit = 50, after = 0 } = {}) {
      identifier(tenant); positiveInteger(limit, 100); if (!Number.isSafeInteger(after) || after < 0) bad();
      return db.prepare('SELECT * FROM audit WHERE tenant=? AND sequence>? ORDER BY sequence LIMIT ?').all(tenant, after, limit).map((row) => ({ tenantId: tenant, sequence: row.sequence, previous: row.previous, hash: row.hash, mac: row.mac, at: row.at, ...decrypt(row.encrypted, JSON.stringify(['audit', tenant, row.sequence])) }));
    },
    /** Ciphertext-only pages permit public verification without exposing business data or HMAC keys.
     * @param {string} tenant @param {{limit?:number,after?:number,through?:number}} options */
    exportAudit(tenant, { limit = 100, after = 0, through } = {}) {
      identifier(tenant); positiveInteger(limit, 100);
      if (!Number.isSafeInteger(after) || after < 0) bad();
      const maximum = through === undefined ? verifyAudit(tenant).sequence
        : Number(db.prepare('SELECT max(sequence) AS n FROM audit WHERE tenant=?').get(tenant).n ?? 0);
      const end = through ?? maximum;
      if (!Number.isSafeInteger(end) || end < after || end > maximum) bad('INVALID_AUDIT_RANGE');
      const tail = end ? db.prepare('SELECT hash FROM audit WHERE tenant=? AND sequence=?').get(tenant, end) : null;
      const raw = db.prepare('SELECT sequence,previous,hash,mac,encrypted,at FROM audit WHERE tenant=? AND sequence>? AND sequence<=? ORDER BY sequence LIMIT ?').all(tenant, after, end, limit);
      const rows = raw.map((row) => {
        const digest = hash(json({ tenantId: tenant, sequence: row.sequence, previous: row.previous, encrypted: row.encrypted, at: row.at }));
        if (row.hash !== digest || !equal(row.mac, createHmac('sha256', chainKey).update(digest).digest('hex'))) bad('AUDIT_INTEGRITY_ERROR', 500);
        decrypt(row.encrypted, JSON.stringify(['audit', tenant, row.sequence]));
        return { tenantId: tenant, sequence: row.sequence, previous: row.previous, hash: row.hash, encrypted: row.encrypted, at: row.at };
      });
      const last = Number(rows.at(-1)?.sequence ?? after);
      return { checkpoint: { tenantId: tenant, sequence: end, hash: tail?.hash ?? '0'.repeat(64) }, after, next: last < end ? last : null, rows };
    },
    /** Retain terminal idempotency tombstones; uncertain effects are never purged or retried. */
    pruneOperationResults(tenant, { before, limit = 100, now = Date.now() }) {
      identifier(tenant); positiveInteger(before); positiveInteger(now); positiveInteger(limit, 1000);
      if (before > now) bad('INVALID_RETENTION_CUTOFF');
      return transaction(() => {
        const cursor = get(tenant, 'metadata', 'retention-operation-cursor') ?? { updated: 0, id: '' };
        const rows = db.prepare("SELECT id,updated FROM operations WHERE tenant=? AND state IN ('succeeded','failed') AND updated<=? AND (updated>? OR (updated=? AND id>?)) ORDER BY updated,id LIMIT ?")
          .all(tenant, before, cursor.updated, cursor.updated, cursor.id, limit);
        let removed = 0;
        for (const row of rows) {
          const operation = getOperation(tenant, row.id);
          if (operation.result === null) continue;
          const next = { ...operation, result: null, resultExpiredAt: now };
          db.prepare('UPDATE operations SET encrypted=? WHERE tenant=? AND id=?').run(encrypt(next, operationAAD(tenant, row.id)), tenant, row.id);
          removed += 1;
        }
        const last = rows.at(-1);
        put(tenant, 'metadata', 'retention-operation-cursor', last ? { updated: last.updated, id: last.id } : { updated: 0, id: '' });
        if (removed) appendAudit({ tenantId: tenant, actorId: 'runtime', event: 'retention.results', data: { removed, before }, at: now });
        return { examined: rows.length, removed };
      });
    },
    recoverUnknown(tenant) {
      identifier(tenant); const rows = db.prepare("SELECT id FROM operations WHERE tenant=? AND state IN ('reserved','dispatched') LIMIT 10000").all(tenant);
      return rows.map((row) => transitionOperation(tenant, row.id, 'unknown'));
    },
    /** @param {string} tenant @param {{limit?:number,status?:string}} options */
    listOperations(tenant, { limit = 50, status } = {}) {
      identifier(tenant); positiveInteger(limit, 100); if (status && ![...ACTIVE, 'succeeded', 'failed'].includes(status)) bad();
      const rows = status ? db.prepare('SELECT id FROM operations WHERE tenant=? AND state=? ORDER BY updated LIMIT ?').all(tenant, status, limit)
        : db.prepare('SELECT id FROM operations WHERE tenant=? ORDER BY updated LIMIT ?').all(tenant, limit);
      return rows.map((row) => getOperation(tenant, row.id));
    },
    backup(destination) {
      const target = safeFile(destination); if (existsSync(target) || existsSync(`${target}.manifest.json`)) bad('BACKUP_DESTINATION_EXISTS', 409);
      if (Number(db.prepare('PRAGMA page_count').get().page_count) * pageSize > maxBytes) bad('BACKUP_TOO_LARGE');
      mkdirSync(dirname(target), { recursive: true, mode: 0o700 }); const bytes = Buffer.from(db.serialize());
      if (bytes.length > maxBytes) bad('BACKUP_TOO_LARGE');
      writeFileSync(target, bytes, { flag: 'wx', mode: 0o600 }); const fd = openSync(target, 'r+'); try { fsyncSync(fd); } finally { closeSync(fd); }
      const manifest = { version: 1, bytes: bytes.length, sha256: hash(bytes), createdAt: Date.now() };
      writeFileSync(`${target}.manifest.json`, JSON.stringify(manifest), { flag: 'wx', mode: 0o600 }); return manifest;
    },
    close() { if (!closed) { db.close(); key.fill(0); chainKey.fill(0); closed = true; } },
  });
}

/** Restore to a new path; callers retain trusted manifests/keys separately. */
export function restoreStore({ backupPath, path, encryptionKey, auditKey = encryptionKey, expectedSha256 }) {
  const source = safeFile(backupPath, { existing: true }); const target = safeFile(path);
  if (existsSync(target)) bad('RESTORE_DESTINATION_EXISTS', 409);
  if (lstatSync(source).size > 128 * 1024 * 1024) bad('BACKUP_TOO_LARGE');
  const manifestPath = safeFile(`${source}.manifest.json`, { existing: true });
  if (lstatSync(manifestPath).size > 4096) bad('INVALID_BACKUP_MANIFEST');
  const bytes = readFileSync(source); let manifest;
  try { manifest = JSON.parse(readFileSync(manifestPath, 'utf8')); } catch { bad('INVALID_BACKUP_MANIFEST'); }
  exactObject(manifest, ['version', 'bytes', 'sha256', 'createdAt']);
  positiveInteger(manifest.bytes, MAX_DATABASE_BYTES); positiveInteger(manifest.createdAt);
  if (typeof manifest.sha256 !== 'string' || !/^[a-f\d]{64}$/.test(manifest.sha256)
      || (expectedSha256 !== undefined && !equal(expectedSha256, manifest.sha256))) bad('BACKUP_TRUST_MISMATCH', 500);
  if (manifest.version !== 1 || manifest.bytes !== bytes.length || manifest.sha256 !== hash(bytes)
      || !bytes.subarray(0, 16).equals(Buffer.from('SQLite format 3\0'))) bad('BACKUP_INTEGRITY_ERROR', 500);
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 }); writeFileSync(target, bytes, { flag: 'wx', mode: 0o600 });
  return openStore({ path: target, encryptionKey, auditKey });
}
