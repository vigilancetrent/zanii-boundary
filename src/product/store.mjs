import { AsyncLocalStorage } from 'node:async_hooks';
import { DatabaseSync } from 'node:sqlite';
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { closeSync, existsSync, fsyncSync, lstatSync, mkdirSync, openSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import canonicalize from 'canonicalize';
import { AppError, exactObject, identifier, positiveInteger } from '../protocol.mjs';
import { STORE_NAMESPACES, createStorageCodec, leaseResource } from './storage-crypto.mjs';

export const OWNED_SQLITE_TRANSACTION = Symbol('owned-sqlite-transaction');
export const BOUNDED_SQLITE_CALL = Symbol('bounded-sqlite-call');

const NAMESPACES = new Set(['tasks', 'approvals', 'flows', 'memory', 'incidents', 'learning-examples', 'learning-candidates',
  'learning-active', 'learning-promotions', 'operations', 'a2a', 'coverage', 'outbox', 'metadata',
  'documents', 'deliveries', 'resource-operations', ...STORE_NAMESPACES]);
const MAX_VALUE_BYTES = 65_536;
const MAX_DATABASE_BYTES = 128 * 1024 * 1024;
const ACTIVE = new Set(['reserved', 'dispatched', 'unknown']);
const NEXT = { reserved: ['dispatched', 'failed', 'unknown'], dispatched: ['succeeded', 'failed', 'unknown'], unknown: ['succeeded', 'failed'] };
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const validateJob=(job,id,tenant)=>{if(!job||job.version!==1||job.id!==id||job.tenantId!==tenant||!['queued','retry','running','done','dead'].includes(job.state))bad('INVALID_MAINTENANCE_JOB');positiveInteger(job.dueAt);};
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
export function openStore({ path, encryptionKey, auditKey = encryptionKey, keyring = undefined, maxBytes = MAX_DATABASE_BYTES, busyTimeoutMs = 5000, transactionTimeoutMs = 5000, role = 'app' }) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 262_144 || maxBytes > MAX_DATABASE_BYTES) bad('INVALID_STORAGE_CAPACITY');
  const fullPath = safeFile(path);
  const key = keyMaterial(encryptionKey); const chainKey = keyMaterial(auditKey);
  mkdirSync(dirname(fullPath), { recursive: true, mode: 0o700 });
  const existing = existsSync(fullPath) && lstatSync(fullPath).size > 0;
  const db = new DatabaseSync(fullPath);
  let depth = 0; let closed = false;const maintenanceOwnership=new AsyncLocalStorage();
  if (!Number.isSafeInteger(busyTimeoutMs) || busyTimeoutMs < 1 || busyTimeoutMs > 5000) bad('INVALID_STORAGE_TIMEOUT');
  positiveInteger(transactionTimeoutMs, 60000);
  db.exec(`PRAGMA foreign_keys=ON; PRAGMA busy_timeout=${busyTimeoutMs}; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;`);
  let activeBusyTimeoutMs=busyTimeoutMs;
  /** @param {()=>any} work @param {{deadlineAt:number}} options */
  const boundedCall=(work,{deadlineAt})=>{
    if(closed)bad('STORE_CLOSED',503);const remaining=Math.floor(deadlineAt-Date.now());if(!Number.isSafeInteger(remaining)||remaining<=0)bad('DATABASE_TIMEOUT',503);
    const previous=activeBusyTimeoutMs;const bounded=Math.min(previous,remaining);
    if(bounded!==previous){db.exec(`PRAGMA busy_timeout=${bounded}`);activeBusyTimeoutMs=bounded;}
    try{return work();}
    catch(error){if(error&&typeof error==='object'&&'errcode' in error&&typeof error.errcode==='number'&&[5,6].includes(error.errcode&255))bad('DATABASE_TIMEOUT',503);throw error;}
    finally{if(!closed&&activeBusyTimeoutMs!==previous){db.exec(`PRAGMA busy_timeout=${previous}`);activeBusyTimeoutMs=previous;}}
  };
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
    CREATE TABLE IF NOT EXISTS leases (tenant TEXT NOT NULL,resource TEXT NOT NULL,owner TEXT NOT NULL,fence INTEGER NOT NULL,expires INTEGER NOT NULL,mac TEXT NOT NULL, PRIMARY KEY(tenant,resource)) STRICT;
    CREATE INDEX IF NOT EXISTS operations_retention ON operations(tenant,updated,id) WHERE state IN ('succeeded','failed');
    PRAGMA user_version=1;`);
  const codec = createStorageCodec({ encryptionKey, auditKey, keyring });
  const { encrypt, decrypt } = codec;
  if (!['app','worker','rotator'].includes(role)) bad('INVALID_STORAGE_ROLE');
  db.function('runtime_rotator', () => role === 'rotator' ? 1 : 0);
  const maintenanceUp=readFileSync(new URL('../../migrations/sqlite/003_maintenance.up.sql',import.meta.url),'utf8');
  const maintenanceDown=readFileSync(new URL('../../migrations/sqlite/003_maintenance.down.sql',import.meta.url),'utf8');const maintenanceChecksum=hash(`${maintenanceUp}\0${maintenanceDown}`);
  db.exec('CREATE TABLE IF NOT EXISTS runtime_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL) STRICT;');
  const maintenanceVersion=db.prepare('SELECT checksum FROM runtime_migrations WHERE version=3').get();if(maintenanceVersion&&maintenanceVersion.checksum!==maintenanceChecksum){db.close();codec.close();key.fill(0);chainKey.fill(0);bad('MIGRATION_CHECKSUM_MISMATCH',409);}
  db.exec(maintenanceUp);db.prepare('INSERT OR IGNORE INTO runtime_migrations VALUES(3,?)').run(maintenanceChecksum);
  for(const name of ['retiring_id','retirement_proof','retirement_state'])if(!db.prepare('PRAGMA table_info(key_epochs)').all().some(row=>row.name===name))db.exec(`ALTER TABLE key_epochs ADD COLUMN ${name} TEXT`);
  const priorKey = db.prepare("SELECT encrypted FROM objects WHERE tenant='system' AND namespace='metadata' AND id='key-check'").get();
  db.prepare('INSERT OR IGNORE INTO key_epochs(singleton,version,active_id,frozen) VALUES(1,1,?,0)').run(priorKey ? JSON.parse(String(priorKey.encrypted)).kid ?? 'legacy' : codec.activeKeyId);
  for (const table of ['objects','operations','audit']) for (const action of ['INSERT','UPDATE']) db.exec(`CREATE TRIGGER IF NOT EXISTS ${table}_epoch_${action.toLowerCase()} BEFORE ${action} ON ${table} BEGIN
    SELECT CASE WHEN COALESCE(json_extract(NEW.encrypted,'$.kid'),'legacy')<>(SELECT active_id FROM key_epochs WHERE singleton=1) OR ((SELECT frozen FROM key_epochs WHERE singleton=1)=1 AND runtime_rotator()<>1) THEN RAISE(ABORT,'WRITE_EPOCH_REJECTED') END; END;`);
  for(const action of ['INSERT','UPDATE'])db.exec(`CREATE TRIGGER IF NOT EXISTS leases_epoch_${action.toLowerCase()} BEFORE ${action} ON leases WHEN ${action==='INSERT'?'NEW.expires>0':'NEW.expires>OLD.expires'} BEGIN SELECT CASE WHEN (SELECT frozen FROM key_epochs WHERE singleton=1)=1 THEN RAISE(ABORT,'WRITE_EPOCH_REJECTED') END; END;`);
  const readAuditBase=(tenant)=>{const row=db.prepare('SELECT * FROM audit_bases WHERE tenant=?').get(tenant);return row?{sequence:Number(row.sequence),hash:String(row.hash),reference:JSON.parse(String(row.reference)),signedManifest:JSON.parse(String(row.manifest))}:{sequence:0,hash:'0'.repeat(64)};};
  const epoch=()=>{const row=db.prepare('SELECT * FROM key_epochs WHERE singleton=1').get();return {version:row.version,activeKeyId:String(row.active_id),healthy:String(row.active_id)===codec.activeKeyId,frozen:!!row.frozen,retirement:row.retiring_id?{keyId:String(row.retiring_id),proofHash:String(row.retirement_proof),state:String(row.retirement_state)}:null};};
  const objectAAD = (tenant, namespace, id, expires) => JSON.stringify(['object', tenant, namespace, id, expires]);
  const operationAAD = (tenant, id) => JSON.stringify(['operation', tenant, id]);
  const usageMac = (tenant, root, consumed) => createHmac('sha256', chainKey).update(JSON.stringify(['usage', tenant, root, consumed])).digest('hex');
  const leaseMac = (tenant, resource, owner, fence, expires) => codec.mac(json(['lease', tenant, resource, owner, fence, expires]));
  const readLease = (tenantId, resource) => {
    identifier(tenantId); leaseResource(resource);
    const row = db.prepare('SELECT * FROM leases WHERE tenant=? AND resource=?').get(tenantId, resource);
    if (!row) return null;
    if (!equal(row.mac, leaseMac(tenantId, resource, row.owner, row.fence, row.expires))) bad('STORE_INTEGRITY_ERROR', 500);
    return { tenantId, resource, ownerId: String(row.owner), fence: Number(row.fence), expiresAt: Number(row.expires) };
  };
  const assertLease = (lease, { now = Date.now() } = {}) => {
    exactObject(lease, ['tenantId', 'resource', 'ownerId', 'fence', 'expiresAt']); identifier(lease.ownerId); positiveInteger(lease.fence); positiveInteger(now);
    const current = readLease(lease.tenantId, lease.resource);
    if (!current || current.ownerId !== lease.ownerId || current.fence !== lease.fence || current.expiresAt <= now) bad('LEASE_LOST', 409);
    return current;
  };
  const operationLive = (operation, now) => {
    if (!operation.lease) return false;
    const lease = readLease(operation.tenantId, operation.lease.resource);
    return lease && lease.ownerId === operation.lease.ownerId && lease.fence === operation.lease.fence && lease.expiresAt > now;
  };
  const rawGet = (tenant, namespace, id) => db.prepare('SELECT encrypted,expires FROM objects WHERE tenant=? AND namespace=? AND id=?').get(tenant, namespace, id);
  const get = (tenant, namespace, id) => {
    scope(tenant, namespace, id); const row = rawGet(tenant, namespace, id);
    if (!row) return null;
    const value = decrypt(row.encrypted, objectAAD(tenant, namespace, id, row.expires));
    if (row.expires !== null && Number(row.expires) <= Date.now()) return null;
    return value;
  };
  const put = (tenant, namespace, id, value, { expiresAt = null } = {}) => transaction(() => {
    scope(tenant, namespace, id); if (expiresAt !== null) positiveInteger(expiresAt);
    if (!rawGet(tenant, namespace, id) && Number(db.prepare('SELECT count(*) AS n FROM objects WHERE tenant=? AND namespace=?').get(tenant, namespace).n) >= 50_000) bad('STORE_QUOTA', 429);
    const encrypted = encrypt(value, objectAAD(tenant, namespace, id, expiresAt));
    if(namespace==='jobs') validateJob(value,id,tenant);
    db.prepare('INSERT OR IGNORE INTO tenants VALUES(?)').run(tenant);
    db.prepare('INSERT INTO objects(tenant,namespace,id,encrypted,expires) VALUES(?,?,?,?,?) ON CONFLICT(tenant,namespace,id) DO UPDATE SET encrypted=excluded.encrypted,expires=excluded.expires').run(tenant, namespace, id, encrypted, expiresAt);
    if(namespace==='jobs') db.prepare('INSERT INTO job_index VALUES(?,?,?,?,?) ON CONFLICT(tenant,id) DO UPDATE SET state=excluded.state,kind=excluded.kind,due=excluded.due').run(tenant,id,value.state,value.kind,value.dueAt);
    return JSON.parse(json(value));
  });
  const transaction = (fn) => {
    if (typeof fn !== 'function' || fn.constructor.name === 'AsyncFunction') bad('ASYNC_TRANSACTION', 500);
    if (depth) { const value = fn(); if (value?.then) bad('ASYNC_TRANSACTION', 500); return value; }
    db.exec('BEGIN IMMEDIATE'); depth += 1;
    try { const result = fn(); if (result?.then) bad('ASYNC_TRANSACTION', 500);const maintenance=maintenanceOwnership.getStore();if(maintenance)assertLease(maintenance.lease);db.exec('COMMIT'); return result; }
    catch (error) {
      try { if (db.isTransaction) db.exec('ROLLBACK'); } catch { bad('STORE_ROLLBACK_FAILED', 503); }
      if (error && typeof error === 'object' && 'errcode' in error && error.errcode === 13) bad('STORE_CAPACITY_ERROR', 503);
      if (error instanceof Error && error.message.includes('WRITE_EPOCH_REJECTED')) bad('WRITE_EPOCH_REJECTED',409);
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
    const base=readAuditBase(tenantId);const sequence = Number(tail?.sequence ?? base.sequence) + 1; if (!Number.isSafeInteger(sequence)) bad('AUDIT_SEQUENCE_EXHAUSTED',503);
    if(sequence-base.sequence>1000000)bad('AUDIT_ARCHIVE_BACKPRESSURE',503);
    db.prepare('INSERT OR IGNORE INTO tenants VALUES(?)').run(tenantId);
    const previous = tail?.hash ?? base.hash;
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
    const ownership = input.lease ? assertLease(input.lease, { now }) : null;
    if (ownership && (ownership.tenantId !== tenantId || ownership.resource !== `operation:${operationId}`)) bad('LEASE_SCOPE_MISMATCH', 403);
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
      toolVersion, status: 'reserved', createdAt: now, updatedAt: now, result: null, ...(ownership ? { lease: ownership } : {}) };
    db.prepare('INSERT INTO operations VALUES(?,?,?,?,?,?,?,?,?)').run(tenantId, operationId, taskId, rootTaskId, actionDigest, 'reserved', encrypt(operation, operationAAD(tenantId, operationId)), now, now);
    for (const ancestor of lineage) {
      const consumed = Number(db.prepare('SELECT consumed FROM usage WHERE tenant=? AND root=?').get(tenantId, ancestor.id)?.consumed ?? 0) + 1;
      db.prepare('INSERT INTO usage VALUES(?,?,?,?) ON CONFLICT(tenant,root) DO UPDATE SET consumed=excluded.consumed,mac=excluded.mac').run(tenantId, ancestor.id, consumed, usageMac(tenantId, ancestor.id, consumed));
    }
    appendAudit({ tenantId, actorId: task.actorId, event: 'operation.reserved', target: operationId, data: { actionDigest, taskId, rootTaskId }, at: now });
    return { created: true, operation };
  });
  const transitionOperation = (tenant, id, status, result = null, { lease = undefined, recoverExpired = false, now = Date.now() } = {}) => transaction(() => {
    const operation = getOperation(tenant, id); if (!operation) bad('OPERATION_NOT_FOUND', 404);
    let transitionLease;
    if (operation.lease) {
      if (recoverExpired) { if (status !== 'unknown' || operationLive(operation, now)) bad('LEASE_LOST', 409); }
      else {
        const owner = assertLease(lease, { now });
        const observedTerminal = operation.status === 'unknown' && ['succeeded', 'failed'].includes(status) && owner.fence >= operation.lease.fence;
        if (owner.tenantId !== tenant || owner.resource !== operation.lease.resource || !observedTerminal && (owner.ownerId !== operation.lease.ownerId || owner.fence !== operation.lease.fence)) bad('LEASE_LOST', 409);
        transitionLease = owner;
      }
    }
    if (!(NEXT[operation.status] ?? []).includes(status)) bad('INVALID_OPERATION_TRANSITION', 409);
    const next = { ...operation, status, result, updatedAt: Date.now(), ...(transitionLease ? { lease: transitionLease } : {}) };
    db.prepare('UPDATE operations SET state=?,encrypted=?,updated=? WHERE tenant=? AND id=? AND state=?').run(status, encrypt(next, operationAAD(tenant, id)), next.updatedAt, tenant, id, operation.status);
    appendAudit({ tenantId: tenant, actorId: 'runtime', event: `operation.${status}`, target: id, data: { actionDigest: operation.actionDigest } });
    return next;
  });
  const verifyAudit = (tenant, expectedCheckpoint) => {
    identifier(tenant); const rows = db.prepare('SELECT * FROM audit WHERE tenant=? ORDER BY sequence').iterate(tenant);
    const base=readAuditBase(tenant);let previous = base.hash; let sequence = base.sequence; let lastMac;
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
    getJobTombstone(tenant,id){scope(tenant,'jobs',id);const row=db.prepare('SELECT record,mac FROM job_tombstones WHERE tenant=? AND id=?').get(tenant,id);if(!row)return null;const record=String(row.record);if(!equal(row.mac,codec.mac(json(['job-tombstone',tenant,id,record]))))bad('STORE_INTEGRITY_ERROR',500);return JSON.parse(record);},
    putJobTombstone(tenant,value){scope(tenant,'jobs',value.id);const record=json(value);const mac=codec.mac(json(['job-tombstone',tenant,value.id,record]));db.prepare('INSERT OR IGNORE INTO job_tombstones VALUES(?,?,?,?)').run(tenant,value.id,record,mac);return value;},
    withMaintenanceLease(claim,work){return maintenanceOwnership.run({lease:claim.lease},work);},
    keyEpoch:epoch,
    pruneSubjectOperationResults(tenant,subject,{limit=100,after=''}={}){identifier(tenant);identifier(subject.id);positiveInteger(limit,100);if(after)identifier(after);return transaction(()=>{const rows=db.prepare('SELECT id FROM operations WHERE tenant=? AND id>? ORDER BY id LIMIT ?').all(tenant,after,limit+1);let removed=0;for(const row of rows.slice(0,limit)){const operation=getOperation(tenant,row.id);const task=subject.kind==='actor'?get(tenant,'tasks',operation.taskId):null;if(subject.kind==='document'?operation.action?.documentId!==subject.id:task?.actorId!==subject.id)continue;const next={...operation,result:null,privacyRedactedAt:Date.now(),...(operation.status==='unknown'?{}:{action:{kind:operation.action?.kind,documentId:operation.action?.documentId}})};db.prepare('UPDATE operations SET encrypted=? WHERE tenant=? AND id=?').run(encrypt(next,operationAAD(tenant,row.id)),tenant,row.id);removed++;}return {examined:Math.min(rows.length,limit),removed,next:rows.length>limit?rows[limit-1].id:null};});},
    retainedKeyRecords({after='',limit=100}={}){if(role!=='rotator')bad('DATABASE_ROLE_DENIED',403);positiveInteger(limit,100);if(typeof after!=='string'||after.length>1024)bad();const rows=db.prepare("SELECT * FROM (SELECT 'archive:'||tenant||':'||printf('%016d',sequence) AS cursor,'archive' AS kind,tenant,manifest AS record FROM archive_segments UNION ALL SELECT 'intent:'||tenant||':'||id,'archive-intent',tenant,record FROM archive_intents WHERE json_extract(record,'$.status') IS NOT 'complete' UNION ALL SELECT 'backup:'||tenant||':'||id,'backup',tenant,record FROM backup_catalogues) entries WHERE cursor>? ORDER BY cursor LIMIT ?").all(after,limit+1);return {items:rows.slice(0,limit).map(row=>({kind:String(row.kind),tenantId:String(row.tenant),record:JSON.parse(String(row.record))})),next:rows.length>limit?String(rows[limit-1].cursor):null};},
    beginKeyRetirement({expectedVersion,keyId,referenceProofHash}){if(role!=='rotator')bad('DATABASE_ROLE_DENIED',403);identifier(keyId);if(!/^[a-f0-9]{64}$/.test(referenceProofHash))bad('INVALID_KEY_RETIREMENT_PROOF');return transaction(()=>{const current=epoch();if(!current.frozen||current.version!==expectedVersion||current.retirement||current.activeKeyId===keyId||db.prepare('SELECT count(*) AS n FROM leases WHERE expires>?').get(Date.now()).n)bad('WRITE_EPOCH_CONFLICT',409);db.prepare("UPDATE key_epochs SET retiring_id=?,retirement_proof=?,retirement_state='sealed',version=version+1 WHERE singleton=1").run(keyId,referenceProofHash);return {version:epoch().version,keyId,referenceProofHash,state:'sealed',frozen:true};});},
    finishKeyRetirement({expectedVersion,keyId,referenceProofHash}){if(role!=='rotator')bad('DATABASE_ROLE_DENIED',403);return transaction(()=>{const current=epoch();if(!current.frozen||current.version!==expectedVersion||current.retirement?.keyId!==keyId||current.retirement?.proofHash!==referenceProofHash)bad('WRITE_EPOCH_CONFLICT',409);db.prepare("UPDATE key_epochs SET retiring_id=NULL,retirement_state='complete',version=version+1 WHERE singleton=1").run();return {version:epoch().version,keyId,state:'complete',frozen:true};});},
    freezeWrites({expectedVersion}){if(role!=='rotator')bad('DATABASE_ROLE_DENIED',403);return transaction(()=>{if(epoch().retirement||epoch().version!==expectedVersion)bad('WRITE_EPOCH_CONFLICT',409);db.prepare('UPDATE key_epochs SET frozen=1,version=version+1 WHERE singleton=1').run();return epoch();});},
    activateKeyEpoch({expectedVersion,activeKeyId}){identifier(activeKeyId);if(role!=='rotator')bad('DATABASE_ROLE_DENIED',403);return transaction(()=>{if(epoch().retirement||epoch().version!==expectedVersion||!epoch().frozen||db.prepare('SELECT count(*) AS n FROM leases WHERE expires>?').get(Date.now()).n)bad('WRITE_EPOCH_CONFLICT',409);db.prepare('UPDATE key_epochs SET active_id=?,version=version+1 WHERE singleton=1').run(activeKeyId);return epoch();});},
    unfreezeWrites({expectedVersion}){if(role!=='rotator')bad('DATABASE_ROLE_DENIED',403);return transaction(()=>{if(epoch().retirement||epoch().version!==expectedVersion||!epoch().frozen)bad('WRITE_EPOCH_CONFLICT',409);db.prepare('UPDATE key_epochs SET frozen=0,version=version+1 WHERE singleton=1').run();return epoch();});},
    activeLeaseCount({now=Date.now()}={}){if(role!=='rotator')bad('DATABASE_ROLE_DENIED',403);const rows=db.prepare('SELECT tenant,resource FROM leases WHERE expires>?').all(now);for(const row of rows)readLease(row.tenant,row.resource);return rows.length;},
    listDueJobs(tenant,{now=Date.now(),limit=10,kinds=undefined}={}){identifier(tenant);positiveInteger(now);positiveInteger(limit,100);return db.prepare("SELECT id,state,due FROM job_index WHERE tenant=? AND state IN ('queued','retry','running') AND due<=?"+(kinds?' AND kind IN ('+kinds.map(()=>'?').join(',')+')':'')+" ORDER BY due,id LIMIT ?").all(tenant,now,...(kinds??[]),limit).map(row=>{const job=get(tenant,'jobs',row.id);validateJob(job,row.id,tenant);if(job.state!==row.state||job.dueAt!==row.due)bad('STORE_INTEGRITY_ERROR',500);return job;});},
    listDeadJobs(tenant,{now=Date.now(),limit=100}={}){identifier(tenant);positiveInteger(limit,100);return db.prepare("SELECT id FROM job_index WHERE tenant=? AND state='dead' AND due<=? ORDER BY due,id LIMIT ?").all(tenant,now,limit).map(row=>get(tenant,'jobs',row.id));},
    jobStatus(tenant,{now=Date.now()}={}){identifier(tenant);positiveInteger(now);const result={queued:0,retry:0,running:0,dead:0,done:0,due:0,oldestDueAt:null};for(const row of db.prepare('SELECT state,count(*) AS n FROM job_index WHERE tenant=? GROUP BY state').all(tenant))result[String(row.state)]=Number(row.n);const due=db.prepare("SELECT count(*) AS n,min(due) AS oldest FROM job_index WHERE tenant=? AND state IN ('queued','retry','running') AND due<=?").get(tenant,now);result.due=Number(due.n);result.oldestDueAt=due.oldest===null?null:Number(due.oldest);return result;},
    writeRoleHeartbeat(record){identifier(record.ownerId);return transaction(()=>{put('system','metadata',`worker-${record.ownerId}`,record);db.prepare("INSERT INTO maintenance_heartbeats VALUES('system','worker',?,?) ON CONFLICT(tenant,kind,id) DO UPDATE SET record=excluded.record").run(record.ownerId,json(record));return record;});},
    workerStatus({limit=100,after=''}={}){positiveInteger(limit,100);const rows=db.prepare("SELECT id,record FROM maintenance_heartbeats WHERE tenant='system' AND kind='worker' AND id>? ORDER BY json_extract(record,'$.at') DESC,id LIMIT ?").all(after,limit+1);return {items:rows.slice(0,limit).map(row=>JSON.parse(String(row.record))),next:rows.length>limit?String(rows[limit-1].id):null};},
    async [OWNED_SQLITE_TRANSACTION](work, { deadlineAt = Date.now() + transactionTimeoutMs } = {}) {
      if (typeof work !== 'function') bad();
      if (depth) return work();
      boundedCall(()=>db.exec('BEGIN IMMEDIATE'),{deadlineAt}); depth += 1;
      try { if (Date.now() >= deadlineAt) bad('DATABASE_TIMEOUT', 503); const value = await work(); if (Date.now() >= deadlineAt) bad('DATABASE_TIMEOUT', 503);const maintenance=maintenanceOwnership.getStore();if(maintenance)assertLease(maintenance.lease);boundedCall(()=>db.exec('COMMIT'),{deadlineAt}); return value; }
      catch (error) { if (db.isTransaction) db.exec('ROLLBACK'); throw error; }
      finally { depth -= 1; }
    },
    [BOUNDED_SQLITE_CALL]:boundedCall,
    path: fullPath, transactionTimeoutMs, role, get, put, transaction, getOperation, reserveOperation, transitionOperation, appendAudit, verifyAudit, assertLease,
    storageUsage(){let bytes=0;for(const path of [fullPath,`${fullPath}-wal`,`${fullPath}-shm`]){try{const stat=lstatSync(path);if(!stat.isFile()||stat.isSymbolicLink())bad('SIGNAL_UNAVAILABLE',503);bytes+=stat.size;}catch(error){if(!error||typeof error!=='object'||!('code' in error)||error.code!=='ENOENT')bad('SIGNAL_UNAVAILABLE',503);}}return {bytes};},
    claimLease(tenantId, resource, { ownerId, ttlMs, now = Date.now() }) {
      identifier(tenantId); leaseResource(resource); identifier(ownerId); positiveInteger(ttlMs, 3600000); positiveInteger(now);
      return transaction(() => {
        const prior = readLease(tenantId, resource);
        if (prior?.expiresAt > now) return prior.ownerId === ownerId ? prior : null;
        const fence = (prior?.fence ?? 0) + 1; const expiresAt = now + ttlMs;
        db.prepare('INSERT INTO leases VALUES(?,?,?,?,?,?) ON CONFLICT(tenant,resource) DO UPDATE SET owner=excluded.owner,fence=excluded.fence,expires=excluded.expires,mac=excluded.mac')
          .run(tenantId, resource, ownerId, fence, expiresAt, leaseMac(tenantId, resource, ownerId, fence, expiresAt));
        return { tenantId, resource, ownerId, fence, expiresAt };
      });
    },
    renewLease(lease, { ttlMs, now = Date.now() }) {
      positiveInteger(ttlMs, 3600000);
      return transaction(() => { let owner; try { owner = assertLease(lease, { now }); } catch (error) { if (error instanceof AppError && error.code === 'LEASE_LOST') return null; throw error; }
        const expiresAt = now + ttlMs;
        db.prepare('UPDATE leases SET expires=?,mac=? WHERE tenant=? AND resource=?').run(expiresAt, leaseMac(owner.tenantId, owner.resource, owner.ownerId, owner.fence, expiresAt), owner.tenantId, owner.resource);
        return { ...owner, expiresAt };
      });
    },
    releaseLease(lease) {
      return transaction(() => { const current = readLease(lease.tenantId, lease.resource);
        if (!current || current.ownerId !== lease.ownerId || current.fence !== lease.fence) return false;
        db.prepare('UPDATE leases SET expires=0,mac=? WHERE tenant=? AND resource=?').run(leaseMac(current.tenantId, current.resource, current.ownerId, current.fence, 0), current.tenantId, current.resource); return true;
      });
    },
    listTenants({ limit = 100, after = '' } = {}) {
      positiveInteger(limit, 1000); if (after) identifier(after);
      const rows = db.prepare("SELECT tenant FROM tenants WHERE tenant!='system' AND tenant>? ORDER BY tenant LIMIT ?").all(after, limit + 1);
      const items = rows.slice(0, limit).map((row) => row.tenant); return { items, next: rows.length > limit ? items.at(-1) : null };
    },
    queryPlans(tenant) {
      identifier(tenant);
      return { backend: 'sqlite', plans: {
        objects: db.prepare("EXPLAIN QUERY PLAN SELECT id FROM objects WHERE tenant=? AND namespace='documents' AND id>'' ORDER BY id LIMIT 100").all(tenant),
        expiry: db.prepare('EXPLAIN QUERY PLAN SELECT id FROM objects WHERE expires<=? ORDER BY expires LIMIT 100').all(Date.now()),
        operations: db.prepare("EXPLAIN QUERY PLAN SELECT id FROM operations WHERE tenant=? AND state IN ('succeeded','failed') AND updated<=? ORDER BY updated,id LIMIT 100").all(tenant, Date.now()),
        audit: db.prepare('EXPLAIN QUERY PLAN SELECT sequence FROM audit WHERE tenant=? AND sequence>0 ORDER BY sequence LIMIT 100').all(tenant),
      } };
    },
    keyReferences() {
      const references = {};
      for (const table of ['objects', 'operations', 'audit']) {
        for (const row of db.prepare(`SELECT * FROM ${table}`).iterate()) {
          const aad = table === 'objects' ? objectAAD(row.tenant, row.namespace, row.id, row.expires) : table === 'operations' ? operationAAD(row.tenant, row.id) : JSON.stringify(['audit', row.tenant, row.sequence]);
          decrypt(row.encrypted, aad);
          const id = codec.keyId(row.encrypted); references[id] = (references[id] ?? 0) + 1;
        }
      }
      return references;
    },
    rekeyRecords({ limit = 100, after = '' } = {}) {
      positiveInteger(limit, 1000);
      let cursor = { table: 'objects', tenant: '', namespace: '', id: '' };
      if (after) {
        if (typeof after !== 'string' || !/^[A-Za-z0-9_-]{1,2048}$/.test(after)) bad();
        try { cursor = JSON.parse(Buffer.from(after, 'base64url').toString('utf8')); } catch { bad(); }
        exactObject(cursor, ['table', 'tenant', 'namespace', 'id']); if (!['objects', 'operations'].includes(cursor.table)) bad();
      }
      return transaction(() => {
        let examined = 0; let rotated = 0; let last = cursor;
        for (const table of cursor.table === 'objects' ? ['objects', 'operations'] : ['operations']) {
          const from = cursor.table === table ? cursor : { tenant: '', namespace: '', id: '' };
          const rows = table === 'objects'
            ? db.prepare('SELECT tenant,namespace,id,encrypted,expires FROM objects WHERE (tenant,namespace,id)>(?,?,?) ORDER BY tenant,namespace,id LIMIT ?').all(from.tenant, from.namespace, from.id, limit - examined + 1)
            : db.prepare('SELECT tenant,id,encrypted FROM operations WHERE (tenant,id)>(?,?) ORDER BY tenant,id LIMIT ?').all(from.tenant, from.id, limit - examined + 1);
          for (const row of rows) {
            if (examined === limit) return { examined, rotated, next: Buffer.from(JSON.stringify(last)).toString('base64url'), auditCiphertextPreserved: true };
            const aad = table === 'objects' ? objectAAD(row.tenant, row.namespace, row.id, row.expires) : operationAAD(row.tenant, row.id);
            const value = decrypt(row.encrypted, aad);
            if (codec.keyId(row.encrypted) !== codec.activeKeyId) {
              if (table === 'objects') db.prepare('UPDATE objects SET encrypted=? WHERE tenant=? AND namespace=? AND id=?').run(encrypt(value, aad), row.tenant, row.namespace, row.id);
              else db.prepare('UPDATE operations SET encrypted=? WHERE tenant=? AND id=?').run(encrypt(value, aad), row.tenant, row.id);
              rotated++;
            }
            examined++; last = { table, tenant: String(row.tenant), namespace: String(row.namespace ?? ''), id: String(row.id) };
          }
        }
        return { examined, rotated, next: null, auditCiphertextPreserved: true };
      });
    },
    assertKeyRetirable(keyId, { backupReferences = undefined } = {}) {
      if (!Number.isSafeInteger(backupReferences) || backupReferences < 0) bad();
      let count = backupReferences;
      for (const table of ['objects', 'operations', 'audit']) for (const row of db.prepare(`SELECT * FROM ${table}`).iterate()) {
        const aad = table === 'objects' ? objectAAD(row.tenant, row.namespace, row.id, row.expires) : table === 'operations' ? operationAAD(row.tenant, row.id) : JSON.stringify(['audit', row.tenant, row.sequence]);
        decrypt(row.encrypted, aad); if (codec.keyId(row.encrypted) === keyId) count++;
      }
      return codec.assertRetirable(keyId, count);
    },
    checkpoint: (tenant) => { const value = verifyAudit(tenant); return { tenantId: value.tenantId, sequence: value.sequence, hash: value.hash, mac: value.mac }; },
    list(tenant, namespace, { limit = 50, after = '' } = {}) {
      scope(tenant, namespace); positiveInteger(limit, 100); if (after) identifier(after);
      const rows = db.prepare('SELECT id,encrypted,expires FROM objects WHERE tenant=? AND namespace=? AND id>? AND (expires IS NULL OR expires>?) ORDER BY id LIMIT ?').all(tenant, namespace, after, Date.now(), limit + 1);
      const page = rows.slice(0, limit).map((row) => ({ id: row.id, value: decrypt(row.encrypted, objectAAD(tenant, namespace, row.id, row.expires)), expiresAt: row.expires }));
      return { items: page, next: rows.length > limit ? page.at(-1).id : null };
    },
    delete(tenant, namespace, id) { scope(tenant, namespace, id);return transaction(()=>{if(namespace==='jobs')db.prepare('DELETE FROM job_index WHERE tenant=? AND id=?').run(tenant,id);return db.prepare('DELETE FROM objects WHERE tenant=? AND namespace=? AND id=?').run(tenant, namespace, id).changes;}); },
    /** Authenticate a bounded batch before deleting; tampered expiry must not erase evidence. */
    purgeExpired(now = Date.now(), { limit = 100, tenantId = undefined } = {}) {
      positiveInteger(now); positiveInteger(limit, 1000);
      if (tenantId) identifier(tenantId);
      return transaction(() => {
        const rows = tenantId
          ? db.prepare('SELECT tenant,namespace,id,encrypted,expires FROM objects WHERE tenant=? AND expires IS NOT NULL AND expires<=? ORDER BY expires,tenant,namespace,id LIMIT ?').all(tenantId, now, limit)
          : db.prepare('SELECT tenant,namespace,id,encrypted,expires FROM objects WHERE expires IS NOT NULL AND expires<=? ORDER BY expires,tenant,namespace,id LIMIT ?').all(now, limit);
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
      const base=readAuditBase(tenant);if(after===0)after=base.sequence;if(after<base.sequence)bad('INVALID_AUDIT_RANGE');
      const maximum = through === undefined ? verifyAudit(tenant).sequence
        : Number(db.prepare('SELECT max(sequence) AS n FROM audit WHERE tenant=?').get(tenant).n ?? base.sequence);
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
      return { checkpoint: { tenantId: tenant, sequence: end, hash: tail?.hash ?? base.hash }, ...(base.sequence?{base}:{}), after, next: last < end ? last : null, rows };
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
    recoverUnknown(tenant, { now = Date.now(), limit = 10000 } = {}) {
      identifier(tenant); positiveInteger(now); positiveInteger(limit, 10000);
      const rows = db.prepare("SELECT id FROM operations WHERE tenant=? AND state IN ('reserved','dispatched') ORDER BY updated,id LIMIT ?").all(tenant, limit);
      return rows.filter((row) => !operationLive(getOperation(tenant, row.id), now)).map((row) => transitionOperation(tenant, row.id, 'unknown', null, { recoverExpired: true, now }));
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
      mkdirSync(dirname(target), { recursive: true, mode: 0o700 });const backupId=hash(target);const createdAt=Date.now();
      transaction(()=>{if(epoch().frozen||epoch().retirement)bad('MAINTENANCE_FROZEN',409);db.prepare('INSERT INTO backup_catalogues VALUES(?,?,?)').run('system',backupId,json({id:backupId,status:'pending',createdAt,reference:{path:target},keyIds:[]}));});
      const snapshot=transaction(()=>{const keyIds=new Set();for(const table of ['objects','operations','audit'])for(const row of db.prepare(`SELECT encrypted FROM ${table}`).iterate())keyIds.add(JSON.parse(String(row.encrypted)).kid??'legacy-v1');const bytes=Buffer.from(db.serialize());db.prepare('UPDATE backup_catalogues SET record=? WHERE tenant=? AND id=?').run(json({id:backupId,status:'pending',createdAt,reference:{path:target},keyIds:[...keyIds]}),'system',backupId);return {bytes,keyIds:[...keyIds]};});const {bytes,keyIds}=snapshot;
      if (bytes.length > maxBytes) bad('BACKUP_TOO_LARGE');
      writeFileSync(target, bytes, { flag: 'wx', mode: 0o600 }); const fd = openSync(target, 'r+'); try { fsyncSync(fd); } finally { closeSync(fd); }
      const manifest = { version: 1, bytes: bytes.length, sha256: hash(bytes), createdAt: Date.now() };
      transaction(()=>{if(epoch().retirement)bad('KEY_RETIREMENT_SEALED',409);db.prepare('UPDATE backup_catalogues SET record=? WHERE tenant=? AND id=?').run(json({id:backupId,status:'complete',createdAt:manifest.createdAt,reference:{path:target},keyIds,manifest}),'system',backupId);});
      writeFileSync(`${target}.manifest.json`, JSON.stringify(manifest), { flag: 'wx', mode: 0o600 }); return manifest;
    },
    close() { if (!closed) { db.close(); key.fill(0); chainKey.fill(0); codec.close(); closed = true; } },
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

/** Local-only archive fixture. SQLite file ownership remains its security boundary. */
export function openSqliteArchivePort({path}) {
  const full=safeFile(path,{existing:true});const db=new DatabaseSync(full);db.exec('PRAGMA busy_timeout=1000');
  const baseOf=(tenant)=>{const row=db.prepare('SELECT * FROM audit_bases WHERE tenant=?').get(tenant);return row?{sequence:Number(row.sequence),hash:String(row.hash),reference:JSON.parse(String(row.reference)),signedManifest:JSON.parse(String(row.manifest))}:{sequence:0,hash:'0'.repeat(64)};};
  return Object.freeze({backend:'sqlite',shared:false,async:false,
    listTenants({after='',limit=100}={}){positiveInteger(limit,1000);if(after)identifier(after);const rows=db.prepare("SELECT tenant FROM tenants WHERE tenant!='system' AND tenant>? ORDER BY tenant LIMIT ?").all(after,limit+1);return {items:rows.slice(0,limit).map(row=>row.tenant),next:rows.length>limit?rows[limit-1].tenant:null};},
    prepareArchiveIntent(tenant,record){identifier(tenant);identifier(record.id);if(record.status!=='pending'||!record.signedManifest||!Array.isArray(record.keyIds))bad('INVALID_ARCHIVE_INTENT');db.exec('BEGIN IMMEDIATE');try{if(db.prepare('SELECT frozen FROM key_epochs WHERE singleton=1').get().frozen)bad('MAINTENANCE_FROZEN',409);db.prepare('INSERT OR IGNORE INTO archive_intents VALUES(?,?,?)').run(tenant,record.id,json(record));const saved=JSON.parse(String(db.prepare('SELECT record FROM archive_intents WHERE tenant=? AND id=?').get(tenant,record.id).record));db.exec('COMMIT');return saved;}catch(error){if(db.isTransaction)db.exec('ROLLBACK');throw error;}},
    readArchiveIntent(tenant,id){identifier(tenant);identifier(id);const row=db.prepare('SELECT record FROM archive_intents WHERE tenant=? AND id=?').get(tenant,id);return row?JSON.parse(String(row.record)):null;},
    readArchiveSegment(tenant,{after=undefined,limit=100,through=undefined}={}){identifier(tenant);positiveInteger(limit,100);const base=baseOf(tenant);const start=after??base.sequence;const tail=db.prepare('SELECT sequence,hash FROM audit WHERE tenant=? ORDER BY sequence DESC LIMIT 1').get(tenant)??base;const end=through??tail.sequence;if(!Number.isSafeInteger(start)||start<base.sequence||!Number.isSafeInteger(end)||end<start||end>tail.sequence)bad('INVALID_AUDIT_RANGE');const endRow=end===base.sequence?base:db.prepare('SELECT hash FROM audit WHERE tenant=? AND sequence=?').get(tenant,end);const rows=db.prepare('SELECT sequence,previous,hash,encrypted,at FROM audit WHERE tenant=? AND sequence>? AND sequence<=? ORDER BY sequence LIMIT ?').all(tenant,start,end,limit).map(row=>({tenantId:tenant,sequence:Number(row.sequence),previous:String(row.previous),hash:String(row.hash),encrypted:String(row.encrypted),at:Number(row.at)}));let previous=start===base.sequence?base.hash:db.prepare('SELECT hash FROM audit WHERE tenant=? AND sequence=?').get(tenant,start)?.hash;for(const row of rows){if(row.previous!==previous||row.hash!==hash(canonicalize({tenantId:tenant,sequence:row.sequence,previous,encrypted:row.encrypted,at:row.at})))bad('AUDIT_INTEGRITY_ERROR',500);previous=row.hash;}const last=rows.at(-1)?.sequence??start;return {base,rows,checkpoint:{tenantId:tenant,sequence:end,hash:endRow.hash},next:last<end?last:null};},
    commitArchivedPrefix(tenant,{expectedBase,checkpoint,reference,signedManifest}){identifier(tenant);if(checkpoint?.tenantId!==tenant||!signedManifest||!reference)bad('INVALID_ARCHIVE_CHECKPOINT');db.exec('BEGIN IMMEDIATE');try{if(db.prepare('SELECT retiring_id FROM key_epochs WHERE singleton=1').get().retiring_id)bad('KEY_RETIREMENT_SEALED',409);const base=baseOf(tenant);if(base.sequence!==expectedBase.sequence||base.hash!==expectedBase.hash||checkpoint.sequence<=base.sequence)bad('ARCHIVE_PREFIX_CONFLICT',409);const row=db.prepare('SELECT hash FROM audit WHERE tenant=? AND sequence=?').get(tenant,checkpoint.sequence);const count=db.prepare('SELECT count(*) AS n FROM audit WHERE tenant=? AND sequence>? AND sequence<=?').get(tenant,base.sequence,checkpoint.sequence).n;if(row?.hash!==checkpoint.hash||count!==checkpoint.sequence-base.sequence)bad('ARCHIVE_PREFIX_INVALID');db.prepare('INSERT INTO audit_bases VALUES(?,?,?,?,?) ON CONFLICT(tenant) DO UPDATE SET sequence=excluded.sequence,hash=excluded.hash,reference=excluded.reference,manifest=excluded.manifest').run(tenant,checkpoint.sequence,checkpoint.hash,json(reference),json(signedManifest));db.prepare('INSERT INTO archive_segments VALUES(?,?,?,?)').run(tenant,checkpoint.sequence,json(reference),json(signedManifest));if(signedManifest.manifest?.id){const row=db.prepare('SELECT record FROM archive_intents WHERE tenant=? AND id=?').get(tenant,signedManifest.manifest.id);if(row)db.prepare('UPDATE archive_intents SET record=? WHERE tenant=? AND id=?').run(json({...JSON.parse(String(row.record)),status:'complete'}),tenant,signedManifest.manifest.id);}db.prepare('DELETE FROM audit WHERE tenant=? AND sequence<=?').run(tenant,checkpoint.sequence);db.exec('COMMIT');return baseOf(tenant);}catch(error){if(db.isTransaction)db.exec('ROLLBACK');throw error;}},
    health:()=>({healthy:true,backend:'sqlite',shared:false}),close:()=>db.close(),
  });
}
