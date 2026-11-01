import { AsyncLocalStorage } from 'node:async_hooks';
import { Pool } from 'pg';
import { isIP } from 'node:net';
import { AppError, exactObject, identifier, positiveInteger } from '../protocol.mjs';
import { createStorageCodec, storeFailure as bad, storeScope as scope, storeJson as json, storeHash as hash,
  objectAAD, operationAAD, auditAAD, constantEqual as equal, leaseResource } from './storage-crypto.mjs';
import { databaseRealm, migrationFiles } from './migrations.mjs';
import { effectiveDeadline, remainingBudget, withSpan } from './context.mjs';

const NEXT = { reserved: ['dispatched', 'failed', 'unknown'], dispatched: ['succeeded', 'failed', 'unknown'], unknown: ['succeeded', 'failed'] };
const SNAPSHOT_TABLES=['objects','operations','usage','audit','leases','audit_bases','job_index','backup_catalogues','archive_segments','archive_intents','job_tombstones'];
const rowHashInput=({tenantId,sequence,previous,encrypted,at})=>({tenantId,sequence,previous,encrypted,at});
const validateJobIndex = (job, id, tenant) => {
  if (!job || job.version !== 1 || job.id !== id || job.tenantId !== tenant || !['queued','retry','running','done','dead'].includes(job.state)) bad('INVALID_MAINTENANCE_JOB');
  positiveInteger(job.dueAt);
};
const normalize = (row) => Object.fromEntries(Object.entries(row).map(([key, value]) => {
  if (value !== null && ['sequence', 'at', 'expires', 'created', 'updated', 'fence', 'consumed'].includes(key)) {
    const number = Number(value); if (!Number.isSafeInteger(number)) bad('STORE_INTEGRITY_ERROR', 500); return [key, number];
  }
  return [key, value];
}));

/** Real shared authority. Every transaction uses one acquired client, never Pool.query.
 * https://node-postgres.com/features/transactions
 * @param {any} options */
export async function openPostgresStore({ pool: suppliedPool, connection, ca, realm, role = 'app', encryptionKey, auditKey = encryptionKey,
  keyring, maxConnections = 10, acquireTimeoutMs = 1000, queryTimeoutMs = 2000, statementTimeoutMs = 1500, lockTimeoutMs = 500, sqlFixture = false } = {}) {
  const schema = databaseRealm(realm); if (!['app', 'worker', 'rotator', 'archive', 'backup'].includes(role)) bad('INVALID_STORAGE_ROLE');
  for (const value of [maxConnections, acquireTimeoutMs, queryTimeoutMs, statementTimeoutMs, lockTimeoutMs]) positiveInteger(value, 30000);
  if (maxConnections > 100 || statementTimeoutMs > queryTimeoutMs || lockTimeoutMs > statementTimeoutMs) bad('INVALID_STORAGE_TIMEOUT');
  if (sqlFixture && !suppliedPool) bad('INVALID_SQL_FIXTURE');
  if (!suppliedPool) {
    exactObject(connection, ['host', 'port', 'database', 'user', 'password']);
    for (const key of ['host', 'database', 'user', 'password']) if (typeof connection[key] !== 'string' || !connection[key] || connection[key].length > 4096) bad('INVALID_POSTGRES_CONNECTION');
    if (!isIP(connection.host) && !/^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/.test(connection.host)) bad('INVALID_POSTGRES_CONNECTION');
    if (['PGOPTIONS', 'PGBINARY', 'PGREPLICATION'].some((name) => process.env[name])) bad('AMBIENT_POSTGRES_CONFIGURATION');
    positiveInteger(connection.port, 65535);
    if (typeof ca !== 'string' || !ca.includes('BEGIN CERTIFICATE')) bad('POSTGRES_TLS_REQUIRED');
  }
  const pool = suppliedPool ?? new Pool({ host: connection.host, port: connection.port, database: connection.database, user: connection.user, password: connection.password,
    ssl: { ca, rejectUnauthorized: true }, max: maxConnections,
    connectionTimeoutMillis: acquireTimeoutMs, query_timeout: queryTimeoutMs, statement_timeout: statementTimeoutMs,
    lock_timeout: lockTimeoutMs, idleTimeoutMillis: 10000, application_name: `agent-runtime-${realm}`,
    sslnegotiation: 'postgres', client_encoding: 'UTF8', options: '-c client_encoding=UTF8' });
  const keyless = ['archive', 'backup'].includes(role);
  /** @type {any} */ const codec = keyless ? { close() {} } : createStorageCodec({ encryptionKey, auditKey, keyring });
  const context = new AsyncLocalStorage(); const maintenanceOwnership=new AsyncLocalStorage();let closed = false; let poolFaulted = false;
  if (!suppliedPool) pool.on('error', () => { poolFaulted = true; });
  const rawQuery = (client, deadlineAt, text, values = []) => client.query({ text, values, query_timeout: Math.min(queryTimeoutMs, remainingBudget(deadlineAt)) });
  async function requireRestrictedSession(client, deadlineAt) {
    if (sqlFixture) return;
    const other = realm === 'gateway' ? 'runtime_resource' : 'runtime_gateway';
    const row = (await rawQuery(client, deadlineAt, `SELECT r.rolsuper,r.rolbypassrls,r.rolcreatedb,r.rolcreaterole,
      pg_has_role(session_user,$1,'MEMBER') AS expected_role,
      pg_has_role(session_user,$2,'MEMBER') OR pg_has_role(session_user,$3,'MEMBER') AS cross_realm,
      EXISTS(SELECT 1 FROM pg_namespace n WHERE n.nspname=$4 AND pg_has_role(session_user,n.nspowner,'MEMBER')) AS schema_owner,
      pg_has_role(session_user,'pg_write_all_data','MEMBER') OR pg_has_role(session_user,'pg_read_all_data','MEMBER') OR
      pg_has_role(session_user,'pg_execute_server_program','MEMBER') OR pg_has_role(session_user,'pg_read_server_files','MEMBER') OR
      pg_has_role(session_user,'pg_write_server_files','MEMBER') OR pg_has_role(session_user,'pg_database_owner','MEMBER') OR
      EXISTS(SELECT 1 FROM pg_roles p WHERE (p.rolsuper OR p.rolbypassrls OR p.rolcreaterole OR p.rolcreatedb) AND pg_has_role(session_user,p.oid,'MEMBER')) AS broad_role,
      pg_has_role(session_user,$5,'MEMBER') AS worker_role
      FROM pg_roles r WHERE r.rolname=session_user`, [`${schema}_${role}`, `${other}_app`, `${other}_worker`, schema, `${schema}_worker`])).rows[0];
    if (!row || !row.expected_role || row.rolsuper || row.rolbypassrls || row.rolcreatedb || row.rolcreaterole || row.cross_realm || row.schema_owner || row.broad_role || role === 'app' && row.worker_role) bad('UNSAFE_DATABASE_CREDENTIAL', 403);
    const tables = ['objects', 'operations', 'usage', 'audit', 'leases', 'job_tombstones', 'job_index', 'audit_bases', 'backup_catalogues', 'archive_segments', 'archive_intents', 'archive_jobs', 'backup_jobs', 'maintenance_heartbeats'];
    const separated = (await rawQuery(client, deadlineAt, `SELECT EXISTS(SELECT 1 FROM pg_roles r WHERE r.rolname=ANY($1) AND pg_has_role(session_user,r.oid,'MEMBER')) AS unsafe`, [['app','worker','archive','backup','rotator'].filter((suffix) => suffix !== role).map((suffix) => `${schema}_${suffix}`).concat(['archive','backup','rotator'].map((suffix) => `${other}_${suffix}`))])).rows[0];
    if (separated?.unsafe) bad('UNSAFE_DATABASE_CREDENTIAL', 403);
    const posture = (await rawQuery(client, deadlineAt, `WITH principals AS (SELECT rolname::text AS name FROM pg_roles WHERE pg_has_role(session_user,oid,'MEMBER')) SELECT
      EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN principals p WHERE n.nspname=$1 AND has_schema_privilege(p.name,n.oid,'CREATE')) AS schema_create,
      EXISTS(SELECT 1 FROM pg_namespace n CROSS JOIN principals p WHERE n.nspname=$2 AND has_schema_privilege(p.name,n.oid,'USAGE,CREATE')) AS cross_schema,
      EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN principals p WHERE n.nspname=$2 AND c.relkind IN ('r','p','v','m','f')
        AND (has_table_privilege(p.name,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          OR has_any_column_privilege(p.name,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))) AS cross_table,
      (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=ANY($3)
        AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity) AS protected_tables,
      (SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=$1 AND c.relname=ANY($3)) AS isolation_policies,
      (SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname=$1 AND c.relname=ANY($3) AND p.polname='tenant_isolation' AND p.polpermissive AND p.polcmd='*'
        AND p.polroles=ARRAY[0]::oid[] AND pg_get_expr(p.polqual,p.polrelid)=$4 AND pg_get_expr(p.polwithcheck,p.polrelid)=$4) AS valid_isolation_policies,
      EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN principals p WHERE n.nspname=$1 AND c.relname=ANY($3)
        AND (has_table_privilege(p.name,c.oid,CASE WHEN c.relname IN ('audit','job_tombstones') THEN 'UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
          WHEN c.relname IN ('objects','job_index') OR ($5='archive' AND c.relname='archive_jobs') OR ($5='backup' AND c.relname='backup_jobs') THEN 'TRUNCATE,REFERENCES,TRIGGER' WHEN c.relname IN ('audit_bases','backup_catalogues','archive_segments','archive_intents','archive_jobs','backup_jobs','maintenance_heartbeats') THEN 'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER' ELSE 'DELETE,TRUNCATE,REFERENCES,TRIGGER' END)
          OR has_any_column_privilege(p.name,c.oid,CASE WHEN c.relname IN ('audit','job_tombstones') THEN 'UPDATE,REFERENCES' WHEN c.relname IN ('audit_bases','backup_catalogues','archive_segments','archive_intents','maintenance_heartbeats') OR (c.relname='archive_jobs' AND $5<>'archive') OR (c.relname='backup_jobs' AND $5<>'backup') THEN 'INSERT,UPDATE,REFERENCES' ELSE 'REFERENCES' END))) AS destructive_grant,
      EXISTS(SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN principals p WHERE n.nspname=$1
        AND ((c.relname='schema_version' AND (has_table_privilege(p.name,c.oid,'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          OR has_any_column_privilege(p.name,c.oid,'INSERT,UPDATE,REFERENCES')))
          OR (c.relname='key_epochs' AND (has_table_privilege(p.name,c.oid,'INSERT,DELETE,TRUNCATE,REFERENCES,TRIGGER') OR ( $5::text<>'rotator' AND (has_table_privilege(p.name,c.oid,'UPDATE') OR has_any_column_privilege(p.name,c.oid,'UPDATE')))))
          OR (c.relname='tenants' AND (has_table_privilege(p.name,c.oid,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
          OR has_any_column_privilege(p.name,c.oid,'SELECT,INSERT,UPDATE,REFERENCES'))))) AS metadata_grant,
      EXISTS(SELECT 1 FROM pg_proc f JOIN pg_namespace n ON n.oid=f.pronamespace CROSS JOIN principals p WHERE n.nspname=$1
        AND has_function_privilege(p.name,f.oid,'EXECUTE') AND
        ((f.proname IN ('archive_prefix','prepare_archive_intent') AND $5<>'archive') OR
         (f.proname='write_backup_catalogue' AND $5<>'backup') OR
         (f.proname IN ('active_lease_count','retained_key_records') AND $5<>'rotator') OR
         (f.proname='maintenance_admission' AND $5 NOT IN ('archive','backup')) OR
         (f.proname='write_maintenance_heartbeat' AND $5 NOT IN ('archive','backup','worker')) OR
         (f.proname='list_tenants' AND $5='app'))) AS function_grant
      `, [schema, other, tables, "(tenant = current_setting('runtime.tenant_id'::text, true))", role])).rows[0];
    if (!posture || Number(posture.protected_tables) !== tables.length || Number(posture.isolation_policies) !== tables.length || Number(posture.valid_isolation_policies) !== tables.length || posture.schema_create || posture.cross_schema || posture.cross_table || posture.destructive_grant || posture.metadata_grant || posture.function_grant) bad('UNSAFE_DATABASE_CREDENTIAL', 403);
  }
  async function acquire(deadlineAt) {
    const expiresAt = Date.now() + Math.min(acquireTimeoutMs, remainingBudget(deadlineAt));
    let abandoned = false; let timer; let candidate; let released = false;
    const release = () => { if (candidate && !released) { released = true; candidate.release(); } };
    const timeout = new Promise((_, reject) => { timer = setTimeout(() => {
      abandoned = true; release(); reject(new AppError(503, 'DATABASE_ACQUIRE_TIMEOUT'));
    }, Math.max(1, expiresAt - Date.now())); });
    // Start after installing the timer. A blocking pool implementation can also exhaust
    // the budget before its resolved client reaches the microtask queue.
    const pending = Promise.resolve().then(() => pool.connect()).then((client) => {
      candidate = client;
      if (abandoned || Date.now() >= expiresAt) {
        abandoned = true; release(); throw new AppError(503, 'DATABASE_ACQUIRE_TIMEOUT');
      }
      return client;
    });
    try { return await Promise.race([pending, timeout]); }
    catch (error) { abandoned = true; release(); throw error; }
    finally { clearTimeout(timer); }
  }
  async function q(text, values = []) {
    const owned = context.getStore(); if (!owned?.active) bad('TRANSACTION_REQUIRED', 500);
    return withSpan('store.query', { 'db.system.name': 'postgresql', 'db.operation.name': text.split(' ', 1)[0] }, async () => {
      const result = await owned.client.query({ text, values, query_timeout: Math.min(queryTimeoutMs, remainingBudget(owned.deadlineAt)) });
      return { ...result, rows: result.rows.map(normalize) };
    });
  }
  async function bindTenant(tenantId) {
    identifier(tenantId); const owned = context.getStore();
    if (owned.tenantId && owned.tenantId !== tenantId) bad('TENANT_TRANSACTION_MISMATCH', 403);
    if (!owned.tenantId) {
      owned.tenantId = tenantId;
      await q("SELECT set_config('runtime.tenant_id',$1,true)", [tenantId]);
      // Serializes all authority changes for one tenant, including absent-row admission races.
      if(!owned.readOnly){await q('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`${schema}:${tenantId}`]);
      if (!keyless) await q(`SELECT ${schema}.register_tenant($1)`, [tenantId]);}
    }
  }
  async function transaction(work, { tenantId = undefined, readOnly = false } = {}) {
    if (closed) bad('STORE_CLOSED', 503); if (typeof work !== 'function') bad();
    const parent = context.getStore();
    if (parent?.active) { if (tenantId) await bindTenant(tenantId); return work(); }
    const deadlineAt = effectiveDeadline({ timeoutMs: acquireTimeoutMs + queryTimeoutMs }); const client = await acquire(deadlineAt);
    const owner = { active: true, client, tenantId: null, deadlineAt,readOnly };
    let releaseError; let phase = 'setup';
    try {
      await requireRestrictedSession(client, deadlineAt);
      await rawQuery(client, deadlineAt, readOnly ? 'BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY' : 'BEGIN');
      await rawQuery(client, deadlineAt, `SET LOCAL ROLE ${schema}_${role}`);
      await rawQuery(client, deadlineAt, `SET LOCAL search_path TO ${schema},pg_catalog`);
      await rawQuery(client, deadlineAt, "SELECT set_config('statement_timeout',$1,true),set_config('lock_timeout',$2,true)", [String(Math.min(statementTimeoutMs, remainingBudget(deadlineAt))), String(Math.min(lockTimeoutMs, remainingBudget(deadlineAt)))]);
      return await context.run(owner, async () => {
        phase = 'work';
        if (tenantId) await bindTenant(tenantId);
        const value = await work();
        const maintenance=maintenanceOwnership.getStore();if(maintenance){const lease=maintenance.lease;const table=keyless?(role==='archive'?'archive_jobs':'backup_jobs'):'leases';const row=(await q(keyless?`SELECT owner,fence,expires FROM ${table} WHERE tenant=$1 AND id=$2`:'SELECT owner,fence,expires FROM leases WHERE tenant=$1 AND resource=$2',[lease.tenantId,keyless?lease.resource.slice(4):lease.resource])).rows[0];if(!row||row.owner!==lease.ownerId||row.fence!==lease.fence||row.expires<=Date.now())bad('LEASE_LOST',409);}
        remainingBudget(deadlineAt); phase = 'commit'; await rawQuery(client, deadlineAt, 'COMMIT'); poolFaulted = false; return value;
      });
    } catch (error) {
      const rawCode = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
      if (phase === 'commit' || !(error instanceof AppError) && (!/^[0-9A-Z]{5}$/.test(rawCode) || rawCode.startsWith('08'))) releaseError = new Error('DATABASE_CONNECTION_UNCERTAIN');
      try { await rawQuery(client, Date.now() + Math.min(500, queryTimeoutMs), 'ROLLBACK'); }
      catch { releaseError = new Error('DATABASE_ROLLBACK_UNCONFIRMED'); poolFaulted = true; }
      if (error instanceof AppError) throw error;
      const code = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
      if (['57014', '55P03'].includes(String(code))) throw new AppError(503, 'DATABASE_TIMEOUT');
      if (code === '55000') throw new AppError(409, 'WRITE_EPOCH_REJECTED');
      if (code === '42501') throw new AppError(403, 'DATABASE_ROLE_DENIED');
      throw new AppError(503, 'DATABASE_OPERATION_FAILED');
    } finally { owner.active = false; client.release(releaseError); }
  }
  const scoped = (tenant, work) => transaction(work, { tenantId: tenant });
  const readAuditBase = async (tenant) => {
    const row = (await q('SELECT * FROM audit_bases WHERE tenant=$1',[tenant])).rows[0];
    return row ? { sequence: row.sequence, hash: row.hash, reference: JSON.parse(row.reference), signedManifest: JSON.parse(row.manifest) } : { sequence: 0, hash: '0'.repeat(64) };
  };
  const allTenants = async () => {const tenants=['system'];let after='';do{const page=await service.listTenants({after,limit:100});tenants.push(...page.items);after=page.next;}while(after);return tenants;};
  const rawObject = async (tenant, namespace, id) => (await q('SELECT encrypted,expires FROM objects WHERE tenant=$1 AND namespace=$2 AND id=$3', [tenant, namespace, id])).rows[0];
  async function get(tenant, namespace, id) {
    scope(tenant, namespace, id);
    return scoped(tenant, async () => {
      const row = await rawObject(tenant, namespace, id); if (!row) return null;
      const value = codec.decrypt(row.encrypted, objectAAD(tenant, namespace, id, row.expires));
      return row.expires !== null && row.expires <= Date.now() ? null : value;
    });
  }
  async function put(tenant, namespace, id, value, { expiresAt = null } = {}) {
    scope(tenant, namespace, id); if (expiresAt !== null) positiveInteger(expiresAt);
    return scoped(tenant, async () => {
      if (!await rawObject(tenant, namespace, id) && Number((await q('SELECT count(*) AS n FROM objects WHERE tenant=$1 AND namespace=$2', [tenant, namespace])).rows[0].n) >= 50000) bad('STORE_QUOTA', 429);
      await q('INSERT INTO objects VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant,namespace,id) DO UPDATE SET encrypted=excluded.encrypted,expires=excluded.expires',
        [tenant, namespace, id, codec.encrypt(value, objectAAD(tenant, namespace, id, expiresAt)), expiresAt]);
      if (namespace === 'jobs') { validateJobIndex(value, id, tenant); await q('INSERT INTO job_index VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant,id) DO UPDATE SET state=excluded.state,kind=excluded.kind,due=excluded.due', [tenant,id,value.state,value.kind,value.dueAt]); }
      return JSON.parse(json(value));
    });
  }
  async function getOperation(tenant, id) {
    scope(tenant, 'operations', id);
    return scoped(tenant, async () => {
      const row = (await q('SELECT * FROM operations WHERE tenant=$1 AND id=$2', [tenant, id])).rows[0]; if (!row) return null;
      const value = codec.decrypt(row.encrypted, operationAAD(tenant, id));
      if (value.status !== row.state || value.taskId !== row.task || value.rootTaskId !== row.root || value.actionDigest !== row.digest || value.createdAt !== row.created || value.updatedAt !== row.updated) bad('STORE_INTEGRITY_ERROR', 500);
      return value;
    });
  }
  async function appendAudit({ tenantId, actorId, event, target = null, data = null, at = Date.now() }) {
    identifier(tenantId); identifier(actorId); identifier(event); if (target !== null) identifier(target); positiveInteger(at);
    return scoped(tenantId, async () => {
      const tail = (await q('SELECT sequence,hash FROM audit WHERE tenant=$1 ORDER BY sequence DESC LIMIT 1', [tenantId])).rows[0];
      const base = await readAuditBase(tenantId); const sequence = (tail?.sequence ?? base.sequence) + 1; if (!Number.isSafeInteger(sequence)) bad('AUDIT_SEQUENCE_EXHAUSTED', 503);
      if (sequence-base.sequence > 1000000) bad('AUDIT_ARCHIVE_BACKPRESSURE',503);
      const previous = tail?.hash ?? base.hash; const encrypted = codec.encrypt({ actorId, event, target, data }, auditAAD(tenantId, sequence));
      const digest = hash(json({ tenantId, sequence, previous, encrypted, at }, 131072)); const mac = codec.mac(digest);
      await q('INSERT INTO audit VALUES($1,$2,$3,$4,$5,$6,$7)', [tenantId, sequence, previous, digest, mac, encrypted, at]);
      return { tenantId, sequence, hash: digest, mac, at };
    });
  }
  const leaseMac = (lease) => codec.mac(json(['lease', lease.tenantId, lease.resource, lease.ownerId, lease.fence, lease.expiresAt]));
  async function readLease(tenantId, resource) {
    identifier(tenantId); leaseResource(resource);
    const row = (await q('SELECT * FROM leases WHERE tenant=$1 AND resource=$2', [tenantId, resource])).rows[0]; if (!row) return null;
    const lease = { tenantId, resource, ownerId: row.owner, fence: row.fence, expiresAt: row.expires };
    if (!equal(row.mac, leaseMac(lease))) bad('STORE_INTEGRITY_ERROR', 500); return lease;
  }
  async function assertLease(lease, { now = Date.now() } = {}) {
    exactObject(lease, ['tenantId', 'resource', 'ownerId', 'fence', 'expiresAt']); identifier(lease.ownerId); positiveInteger(lease.fence); positiveInteger(now);
    return scoped(lease.tenantId, async () => {
      const current = await readLease(lease.tenantId, lease.resource);
      if (!current || current.ownerId !== lease.ownerId || current.fence !== lease.fence || current.expiresAt <= now) bad('LEASE_LOST', 409); return current;
    });
  }
  async function reserveOperation(input) {
    const { tenantId, taskId, rootTaskId = taskId, operationId, actionDigest, action, policyDigest, toolVersion, maxActions,
      approvalId, requiresApproval = false, now = Date.now() } = input;
    for (const id of [tenantId, taskId, rootTaskId, operationId, actionDigest, policyDigest]) identifier(id);
    positiveInteger(now); positiveInteger(maxActions, 1000000); identifier(String(toolVersion));
    return scoped(tenantId, async () => {
      if (!input.lease) bad('OPERATION_LEASE_REQUIRED', 403); const lease = await assertLease(input.lease, { now });
      if (lease.tenantId !== tenantId || lease.resource !== `operation:${operationId}`) bad('LEASE_SCOPE_MISMATCH', 403);
      const task = await get(tenantId, 'tasks', taskId); const root = await get(tenantId, 'tasks', rootTaskId);
      if (!task || !root || task.revoked || root.revoked || task.expiresAt <= now || root.expiresAt <= now) bad('TASK_UNAVAILABLE', 403);
      if ((task.rootTaskId ?? task.id) !== rootTaskId) bad('TASK_ROOT_MISMATCH', 403);
      const lineage = []; const seen = new Set(); let current = task;
      while (current) {
        if (seen.has(current.id) || lineage.length >= 16 || current.revoked || current.expiresAt <= now) bad('TASK_LINEAGE_INVALID', 403);
        seen.add(current.id); lineage.push(current); if (!current.parentId) break;
        current = await get(tenantId, 'tasks', current.parentId); if (!current) bad('TASK_LINEAGE_INVALID', 403);
      }
      if (lineage.at(-1).id !== rootTaskId) bad('TASK_ROOT_MISMATCH', 403);
      if (root.maxActions !== maxActions) bad('ROOT_QUOTA_MISMATCH', 403);
      const existing = await getOperation(tenantId, operationId);
      if (existing) { if (existing.actionDigest !== actionDigest || existing.taskId !== taskId) bad('IDEMPOTENCY_CONFLICT', 409); return { created: false, operation: existing }; }
      for (const ancestor of lineage) {
        positiveInteger(ancestor.maxActions, 1000000);
        const usage = (await q('SELECT consumed,mac FROM usage WHERE tenant=$1 AND root=$2', [tenantId, ancestor.id])).rows[0]; const count = usage?.consumed ?? 0;
        if (usage && !equal(usage.mac, codec.usageMac(tenantId, ancestor.id, count))) bad('STORE_INTEGRITY_ERROR', 500);
        if (count >= ancestor.maxActions) bad(ancestor.id === rootTaskId ? 'ROOT_QUOTA' : 'TASK_QUOTA', 429);
      }
      if (requiresApproval && !approvalId) bad('APPROVAL_REQUIRED', 403);
      if (approvalId) {
        const approval = await get(tenantId, 'approvals', approvalId);
        if (!approval || approval.used || approval.taskId !== taskId || approval.actionDigest !== actionDigest || approval.policyDigest !== policyDigest
          || String(approval.toolVersion) !== String(toolVersion) || approval.expiresAt <= now || approval.approverId === task.actorId) bad('APPROVAL_INVALID', 403);
        await put(tenantId, 'approvals', approvalId, { ...approval, used: true }, { expiresAt: approval.expiresAt });
      }
      const operation = { id: operationId, tenantId, taskId, rootTaskId, actionDigest, action, policyDigest, toolVersion, status: 'reserved', createdAt: now, updatedAt: now, result: null, lease };
      await q('INSERT INTO operations VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)', [tenantId, operationId, taskId, rootTaskId, actionDigest, 'reserved', codec.encrypt(operation, operationAAD(tenantId, operationId)), now, now]);
      for (const ancestor of lineage) {
        const consumed = ((await q('SELECT consumed FROM usage WHERE tenant=$1 AND root=$2', [tenantId, ancestor.id])).rows[0]?.consumed ?? 0) + 1;
        await q('INSERT INTO usage VALUES($1,$2,$3,$4) ON CONFLICT(tenant,root) DO UPDATE SET consumed=excluded.consumed,mac=excluded.mac', [tenantId, ancestor.id, consumed, codec.usageMac(tenantId, ancestor.id, consumed)]);
      }
      await appendAudit({ tenantId, actorId: task.actorId, event: 'operation.reserved', target: operationId, data: { actionDigest, taskId, rootTaskId }, at: now });
      return { created: true, operation };
    });
  }
  async function operationLive(operation, now) {
    if (!operation.lease) return false; const lease = await readLease(operation.tenantId, operation.lease.resource);
    return lease && lease.ownerId === operation.lease.ownerId && lease.fence === operation.lease.fence && lease.expiresAt > now;
  }
  async function transitionOperation(tenant, id, status, result = null, { lease = undefined, recoverExpired = false, now = Date.now() } = {}) {
    return scoped(tenant, async () => {
      const operation = await getOperation(tenant, id); if (!operation) bad('OPERATION_NOT_FOUND', 404);
      let ownership;
      if (recoverExpired) { if (status !== 'unknown' || await operationLive(operation, now)) bad('LEASE_LOST', 409); }
      else {
        ownership = await assertLease(lease, { now });
        const observedTerminal = operation.status === 'unknown' && ['succeeded', 'failed'].includes(status) && ownership.fence >= operation.lease.fence;
        if (ownership.tenantId !== tenant || ownership.resource !== operation.lease.resource || !observedTerminal && (ownership.ownerId !== operation.lease.ownerId || ownership.fence !== operation.lease.fence)) bad('LEASE_LOST', 409);
      }
      if (!(NEXT[operation.status] ?? []).includes(status)) bad('INVALID_OPERATION_TRANSITION', 409);
      const next = { ...operation, status, result, updatedAt: Date.now(), ...(ownership ? { lease: ownership } : {}) };
      await q('UPDATE operations SET state=$1,encrypted=$2,updated=$3 WHERE tenant=$4 AND id=$5 AND state=$6', [status, codec.encrypt(next, operationAAD(tenant, id)), next.updatedAt, tenant, id, operation.status]);
      await appendAudit({ tenantId: tenant, actorId: 'runtime', event: `operation.${status}`, target: id, data: { actionDigest: operation.actionDigest } }); return next;
    });
  }
  async function verifyAudit(tenant, expectedCheckpoint) {
    return scoped(tenant, async () => {
      const base = await readAuditBase(tenant); let sequence = base.sequence; let previous = base.hash; let lastMac;
      while (true) {
        const rows = (await q('SELECT * FROM audit WHERE tenant=$1 AND sequence>$2 ORDER BY sequence LIMIT 100', [tenant, sequence])).rows;
        for (const row of rows) {
          sequence++; const digest = hash(json({ tenantId: tenant, sequence, previous, encrypted: row.encrypted, at: row.at }, 131072));
          if (row.sequence !== sequence || row.previous !== previous || row.hash !== digest || !equal(row.mac, codec.mac(digest))) bad('AUDIT_INTEGRITY_ERROR', 500);
          codec.decrypt(row.encrypted, auditAAD(tenant, sequence)); previous = digest; lastMac = row.mac;
        }
        if (rows.length < 100) break;
      }
      const value = { tenantId: tenant, sequence, hash: previous, mac: lastMac ?? codec.mac(previous) };
      if (expectedCheckpoint && (expectedCheckpoint.tenantId !== tenant || expectedCheckpoint.sequence !== sequence || !equal(expectedCheckpoint.hash, previous) || !equal(expectedCheckpoint.mac, value.mac))) bad('AUDIT_CHECKPOINT_MISMATCH', 500);
      return { ok: true, ...value };
    });
  }
  const service = {
    async: true, backend: 'postgres', shared: true, realm, role, path: null, sqlFixture,
    async health() { return { healthy: !closed && !poolFaulted, backend: 'postgres', realm, pool: { total: pool.totalCount ?? 0, idle: pool.idleCount ?? 0, waiting: pool.waitingCount ?? 0, maximum: maxConnections } }; },
    async storageUsage(){try{return await transaction(async()=>{const bytes=Number((await q('SELECT pg_database_size(current_database()) AS bytes')).rows[0]?.bytes);if(!Number.isSafeInteger(bytes)||bytes<0)bad('SIGNAL_UNAVAILABLE',503);return {bytes};});}catch{bad('SIGNAL_UNAVAILABLE',503);}},
    get, put, transaction, getOperation, reserveOperation, transitionOperation, appendAudit, verifyAudit, assertLease,
    async getJobTombstone(tenant,id){scope(tenant,'jobs',id);return scoped(tenant,async()=>{const row=(await q('SELECT record,mac FROM job_tombstones WHERE tenant=$1 AND id=$2',[tenant,id])).rows[0];if(!row)return null;if(!equal(row.mac,codec.mac(json(['job-tombstone',tenant,id,row.record]))))bad('STORE_INTEGRITY_ERROR',500);return JSON.parse(row.record);});},
    async putJobTombstone(tenant,value){scope(tenant,'jobs',value.id);const record=json(value);return scoped(tenant,async()=>{await q('INSERT INTO job_tombstones VALUES($1,$2,$3,$4) ON CONFLICT(tenant,id) DO NOTHING',[tenant,value.id,record,codec.mac(json(['job-tombstone',tenant,value.id,record]))]);return value;});},
    async pruneSubjectOperationResults(tenant,subject,{limit=100,after=''}={}){identifier(tenant);positiveInteger(limit,100);if(after)identifier(after);identifier(subject.id);return scoped(tenant,async()=>{const rows=(await q('SELECT id FROM operations WHERE tenant=$1 AND id>$2 ORDER BY id LIMIT $3',[tenant,after,limit+1])).rows;let removed=0;for(const row of rows.slice(0,limit)){const operation=await getOperation(tenant,row.id);const task=subject.kind==='actor'?await get(tenant,'tasks',operation.taskId):null;if(subject.kind==='document'?operation.action?.documentId!==subject.id:task?.actorId!==subject.id)continue;const next={...operation,result:null,privacyRedactedAt:Date.now(),...(operation.status==='unknown'?{}:{action:{kind:operation.action?.kind,documentId:operation.action?.documentId}})};await q('UPDATE operations SET encrypted=$1 WHERE tenant=$2 AND id=$3',[codec.encrypt(next,operationAAD(tenant,row.id)),tenant,row.id]);removed++;}return {examined:Math.min(rows.length,limit),removed,next:rows.length>limit?rows[limit-1].id:null};});},
    withMaintenanceLease(claim,work){return maintenanceOwnership.run({lease:claim.lease},work);},
    maintenanceStore(){
      if(!keyless)bad('DATABASE_ROLE_DENIED',403);const table=role==='archive'?'archive_jobs':'backup_jobs';const kind=role==='archive'?'audit-archive':'backup';
      const read=async(tenant,id)=>{const row=(await q(`SELECT * FROM ${table} WHERE tenant=$1 AND id=$2`,[tenant,id])).rows[0];if(!row)return null;const job=JSON.parse(row.job);if(job.tenantId!==tenant||job.id!==id||job.kind!==kind||job.state!==row.state||job.dueAt!==Number(row.due))bad('MAINTENANCE_JOURNAL_INTEGRITY',500);return job;};
      const leaseRead=async(tenant,id)=>{const row=(await q(`SELECT owner,fence,expires FROM ${table} WHERE tenant=$1 AND id=$2`,[tenant,id])).rows[0];return row?{tenantId:tenant,resource:`job:${id}`,ownerId:row.owner,fence:Number(row.fence),expiresAt:Number(row.expires)}:null;};
      const assert=async(lease,{now=Date.now()}={})=>{const current=await leaseRead(lease.tenantId,lease.resource.slice(4));if(!current||current.ownerId!==lease.ownerId||current.fence!==lease.fence||current.expiresAt<=now)bad('LEASE_LOST',409);return current;};
      return Object.freeze({async:true,backend:'postgres',shared:true,role,transaction,
        get:(tenant,namespace,id)=>{if(namespace!=='jobs')bad('DATABASE_ROLE_DENIED',403);identifier(id);return scoped(tenant,()=>read(tenant,id));},
        put:(tenant,namespace,id,job,{expiresAt=null}={})=>{if(namespace!=='jobs'||job.kind!==kind||Object.keys(job.payload??{}).length)bad('DATABASE_ROLE_DENIED',403);validateJobIndex(job,id,tenant);return scoped(tenant,async()=>{await q(`INSERT INTO ${table}(tenant,id,job,state,due) VALUES($1,$2,$3,$4,$5) ON CONFLICT(tenant,id) DO UPDATE SET job=excluded.job,state=excluded.state,due=excluded.due`,[tenant,id,json({...job,...(expiresAt?{payloadExpiresAt:expiresAt}:{})},16384),job.state,job.dueAt]);return job;});},
        list:(tenant,namespace,{limit=50,after=''}={})=>{if(namespace!=='jobs')bad('DATABASE_ROLE_DENIED',403);positiveInteger(limit,100);return scoped(tenant,async()=>{const rows=(await q(`SELECT id FROM ${table} WHERE tenant=$1 AND id>$2 ORDER BY id LIMIT $3`,[tenant,after,limit+1])).rows;const items=[];for(const row of rows.slice(0,limit))items.push({id:row.id,value:await read(tenant,row.id)});return {items,next:rows.length>limit?rows[limit-1].id:null};});},
        listDueJobs:(tenant,{now=Date.now(),limit=10}={})=>scoped(tenant,async()=>{const rows=(await q(`SELECT id FROM ${table} WHERE tenant=$1 AND state IN ('queued','retry','running') AND due<=$2 ORDER BY due,id LIMIT $3`,[tenant,now,limit])).rows;return Promise.all(rows.map(row=>read(tenant,row.id)));}),
        compactCompletedJobs:(tenant,{now=Date.now(),limit=100}={})=>{positiveInteger(limit,100);return scoped(tenant,async()=>{const rows=(await q(`SELECT id,job FROM ${table} WHERE tenant=$1 AND state='done' AND (job::jsonb->>'payloadExpiresAt')::bigint<=$2 AND job::jsonb->>'compacted' IS DISTINCT FROM 'true' ORDER BY (job::jsonb->>'payloadExpiresAt')::bigint,id LIMIT $3`,[tenant,now,limit])).rows;for(const row of rows){const job=JSON.parse(row.job);const compact={version:1,id:job.id,tenantId:tenant,kind:job.kind,digest:job.digest,state:'done',dueAt:job.dueAt,completedAt:job.updatedAt,expired:true,compacted:true};await q(`UPDATE ${table} SET job=$1 WHERE tenant=$2 AND id=$3 AND state='done'`,[json(compact),tenant,row.id]);}return {compacted:rows.length};});},
        listDeadJobs:(tenant,{now=Date.now(),limit=100}={})=>scoped(tenant,async()=>{const rows=(await q(`SELECT id FROM ${table} WHERE tenant=$1 AND state='dead' AND due<=$2 ORDER BY due,id LIMIT $3`,[tenant,now,limit])).rows;return Promise.all(rows.map(row=>read(tenant,row.id)));}),
        jobStatus:(tenant,{now=Date.now()}={})=>scoped(tenant,async()=>{const result={queued:0,retry:0,running:0,dead:0,done:0,due:0,oldestDueAt:null};for(const row of (await q(`SELECT state,count(*) AS n FROM ${table} WHERE tenant=$1 GROUP BY state`,[tenant])).rows)result[row.state]=Number(row.n);const due=(await q(`SELECT count(*) AS n,min(due) AS oldest FROM ${table} WHERE tenant=$1 AND state IN ('queued','retry','running') AND due<=$2`,[tenant,now])).rows[0];result.due=Number(due.n);result.oldestDueAt=due.oldest===null?null:Number(due.oldest);return result;}),
        claimLease:(tenant,resource,{ownerId,ttlMs,now=Date.now()})=>{identifier(ownerId);positiveInteger(ttlMs,3600000);if(!resource.startsWith('job:'))bad('DATABASE_ROLE_DENIED',403);return scoped(tenant,async()=>{await q(`SELECT ${schema}.maintenance_admission()`);const prior=await leaseRead(tenant,resource.slice(4));if(!prior)bad('JOB_NOT_FOUND',404);if(prior.expiresAt>now)return prior.ownerId===ownerId?prior:null;await q(`UPDATE ${table} SET owner=$1,fence=fence+1,expires=$2 WHERE tenant=$3 AND id=$4`,[ownerId,now+ttlMs,tenant,resource.slice(4)]);return leaseRead(tenant,resource.slice(4));});},
        assertLease:(lease,options)=>scoped(lease.tenantId,()=>assert(lease,options)),
        renewLease:(lease,{ttlMs,now=Date.now()})=>scoped(lease.tenantId,async()=>{await assert(lease,{now});await q(`UPDATE ${table} SET expires=$1 WHERE tenant=$2 AND id=$3`,[now+ttlMs,lease.tenantId,lease.resource.slice(4)]);return {...lease,expiresAt:now+ttlMs};}),
        releaseLease:(lease)=>scoped(lease.tenantId,async()=>{const current=await leaseRead(lease.tenantId,lease.resource.slice(4));if(current?.ownerId!==lease.ownerId||current.fence!==lease.fence)return false;await q(`UPDATE ${table} SET expires=0 WHERE tenant=$1 AND id=$2`,[lease.tenantId,lease.resource.slice(4)]);return true;}),
      });
    },
    async writeRoleHeartbeat(record){if(!['worker','archive','backup'].includes(role))bad('DATABASE_ROLE_DENIED',403);identifier(record.ownerId);return scoped('system',async()=>{await q(`SELECT ${schema}.write_maintenance_heartbeat($1)`,[json(record,8192)]);return record;});},
    async listDueJobs(tenant,{now=Date.now(),limit=10,kinds=undefined}={}) {
      identifier(tenant); positiveInteger(now); positiveInteger(limit,100);
      return scoped(tenant,async()=>{
        const rows=(await q("SELECT id,state,due FROM job_index WHERE tenant=$1 AND state IN ('queued','retry','running') AND due<=$2 AND ($4::text[] IS NULL OR kind=ANY($4)) ORDER BY due,id LIMIT $3",[tenant,now,limit,kinds??null])).rows;
        const jobs=[]; for(const row of rows){ const job=await get(tenant,'jobs',row.id); validateJobIndex(job,row.id,tenant); if(job.state!==row.state||job.dueAt!==Number(row.due)) bad('STORE_INTEGRITY_ERROR',500); jobs.push(job); } return jobs;
      });
    },
    async listDeadJobs(tenant,{now=Date.now(),limit=100}={}){positiveInteger(limit,100);return scoped(tenant,async()=>{const rows=(await q("SELECT id FROM job_index WHERE tenant=$1 AND state='dead' AND due<=$2 ORDER BY due,id LIMIT $3",[tenant,now,limit])).rows;return Promise.all(rows.map(row=>get(tenant,'jobs',row.id)));});},
    async jobStatus(tenant,{now=Date.now()}={}) {
      identifier(tenant); positiveInteger(now);
      return scoped(tenant,async()=>{ const rows=(await q('SELECT state,count(*) AS n,min(due) AS oldest FROM job_index WHERE tenant=$1 GROUP BY state',[tenant])).rows;
        const result={queued:0,retry:0,running:0,dead:0,done:0,due:0,oldestDueAt:null}; for(const row of rows)result[row.state]=Number(row.n);
        const due=(await q("SELECT count(*) AS n,min(due) AS oldest FROM job_index WHERE tenant=$1 AND state IN ('queued','retry','running') AND due<=$2",[tenant,now])).rows[0];result.due=Number(due.n);result.oldestDueAt=due.oldest===null?null:Number(due.oldest);return result; });
    },
    async workerStatus({limit=100,after=''}={}){positiveInteger(limit,100);return scoped('system',async()=>{const rows=(await q("SELECT DISTINCT ON(kind) kind,id,record FROM maintenance_heartbeats WHERE tenant='system' AND kind>$1 ORDER BY kind,(record::jsonb->>'at')::bigint DESC,id LIMIT $2",[after,limit+1])).rows;return {items:rows.slice(0,limit).map(row=>({...JSON.parse(row.record),role:row.kind})),next:rows.length>limit?rows[limit-1].kind:null};});},
    async keyEpoch() { return transaction(async()=>{ const row=(await q('SELECT * FROM key_epochs WHERE singleton')).rows[0];return {version:Number(row.version),activeKeyId:row.active_id,healthy:keyless||row.active_id===codec.activeKeyId,frozen:row.frozen,retirement:row.retiring_id?{keyId:row.retiring_id,proofHash:row.retirement_proof,state:row.retirement_state}:null}; }); },
    async beginKeyRetirement({expectedVersion,keyId,referenceProofHash}){if(role!=='rotator')bad('DATABASE_ROLE_DENIED',403);identifier(keyId);if(!/^[a-f0-9]{64}$/.test(referenceProofHash))bad('INVALID_KEY_RETIREMENT_PROOF');return transaction(async()=>{const row=(await q(`UPDATE key_epochs SET retiring_id=$1,retirement_proof=$2,retirement_state='sealed',version=version+1 WHERE singleton AND frozen AND NOT quarantined AND version=$3 AND active_id<>$1 AND retiring_id IS NULL AND ${schema}.active_lease_count()=0 RETURNING version`,[keyId,referenceProofHash,expectedVersion])).rows[0];if(!row)bad('WRITE_EPOCH_CONFLICT',409);return {version:Number(row.version),keyId,referenceProofHash,state:'sealed',frozen:true};});},
    async finishKeyRetirement({expectedVersion,keyId,referenceProofHash}){if(role!=='rotator')bad('DATABASE_ROLE_DENIED',403);identifier(keyId);return transaction(async()=>{const row=(await q("UPDATE key_epochs SET retiring_id=NULL,retirement_state='complete',version=version+1 WHERE singleton AND frozen AND version=$1 AND retiring_id=$2 AND retirement_proof=$3 AND retirement_state='sealed' RETURNING version",[expectedVersion,keyId,referenceProofHash])).rows[0];if(!row)bad('WRITE_EPOCH_CONFLICT',409);return {version:Number(row.version),keyId,state:'complete',frozen:true};});},
    async retainedKeyRecords({after='',limit=100}={}){if(role!=='rotator')bad('DATABASE_ROLE_DENIED',403);positiveInteger(limit,100);if(typeof after!=='string'||after.length>1024)bad();return transaction(async()=>{const rows=(await q(`SELECT * FROM ${schema}.retained_key_records($1,$2)`,[after,limit+1])).rows;return {items:rows.slice(0,limit).map(row=>({kind:row.kind,tenantId:row.tenant_id,record:JSON.parse(row.record)})),next:rows.length>limit?rows[limit-1].cursor:null};});},
    async restoreStatus(){return transaction(async()=>{const row=(await q('SELECT quarantined,restore_sha FROM key_epochs WHERE singleton')).rows[0];return {quarantined:row.quarantined,requiresReauthorization:!!row.restore_sha,sourceFencePending:row.quarantined,restoreSha256:row.restore_sha};});},
    async releaseRestoreQuarantine({expectedVersion,expectedRestoreSha256,sourceFenceVerified=false}){if(role!=='rotator'||sourceFenceVerified!==true)bad('RESTORE_SOURCE_FENCE_REQUIRED',403);return transaction(async()=>{const row=(await q('UPDATE key_epochs SET quarantined=false,version=version+1 WHERE singleton AND quarantined AND frozen AND retiring_id IS NULL AND version=$1 AND restore_sha=$2 RETURNING version',[expectedVersion,expectedRestoreSha256])).rows[0];if(!row)bad('WRITE_EPOCH_CONFLICT',409);return {version:Number(row.version),frozen:true,quarantined:false,requiresReauthorization:true};});},
    async freezeWrites({expectedVersion}) { if(role!=='rotator')bad('DATABASE_ROLE_DENIED',403);return transaction(async()=>{const row=(await q('UPDATE key_epochs SET frozen=true,version=version+1 WHERE singleton AND retiring_id IS NULL AND version=$1 RETURNING *',[expectedVersion])).rows[0];if(!row)bad('WRITE_EPOCH_CONFLICT',409);return {version:Number(row.version),activeKeyId:row.active_id,frozen:row.frozen,retirement:row.retiring_id?{keyId:row.retiring_id,proofHash:row.retirement_proof,state:row.retirement_state}:null};}); },
    async activateKeyEpoch({expectedVersion,activeKeyId}) { identifier(activeKeyId);if(role!=='rotator')bad('DATABASE_ROLE_DENIED',403);return transaction(async()=>{const row=(await q(`UPDATE key_epochs SET active_id=$1,version=version+1 WHERE singleton AND frozen AND NOT quarantined AND retiring_id IS NULL AND version=$2 AND ${schema}.active_lease_count()=0 RETURNING *`,[activeKeyId,expectedVersion])).rows[0];if(!row)bad('WRITE_EPOCH_CONFLICT',409);return {version:Number(row.version),activeKeyId:row.active_id,frozen:row.frozen,retirement:row.retiring_id?{keyId:row.retiring_id,proofHash:row.retirement_proof,state:row.retirement_state}:null};}); },
    async unfreezeWrites({expectedVersion}) {if(role!=='rotator')bad('DATABASE_ROLE_DENIED',403);return transaction(async()=>{const row=(await q('UPDATE key_epochs SET frozen=false,version=version+1 WHERE singleton AND frozen AND NOT quarantined AND retiring_id IS NULL AND version=$1 RETURNING *',[expectedVersion])).rows[0];if(!row)bad('WRITE_EPOCH_CONFLICT',409);return {version:Number(row.version),activeKeyId:row.active_id,frozen:row.frozen,retirement:row.retiring_id?{keyId:row.retiring_id,proofHash:row.retirement_proof,state:row.retirement_state}:null};}); },
    async activeLeaseCount({now=Date.now()}={}) {if(role!=='rotator')bad('DATABASE_ROLE_DENIED',403);for(const tenant of await allTenants()){await scoped(tenant,async()=>{const rows=(await q('SELECT * FROM leases WHERE tenant=$1 AND expires>$2',[tenant,now])).rows;for(const row of rows)if(!equal(row.mac,leaseMac({tenantId:tenant,resource:row.resource,ownerId:row.owner,fence:row.fence,expiresAt:row.expires})))bad('STORE_INTEGRITY_ERROR',500);return rows.length;});}return transaction(async()=>Number((await q(`SELECT ${schema}.active_lease_count() AS n`)).rows[0].n));},
    async readArchiveSegment(tenant,{after=undefined,limit=100,through=undefined}={}) {
      if(!['archive','backup'].includes(role))bad('DATABASE_ROLE_DENIED',403);identifier(tenant);positiveInteger(limit,100);
      return scoped(tenant,async()=>{ const base=await readAuditBase(tenant);const start=after??base.sequence;if(!Number.isSafeInteger(start)||start<base.sequence)bad('INVALID_AUDIT_RANGE');const tail=(await q('SELECT sequence,hash FROM audit WHERE tenant=$1 ORDER BY sequence DESC LIMIT 1',[tenant])).rows[0]??base; const end=through??tail.sequence;if(!Number.isSafeInteger(end)||end<start||end>tail.sequence)bad('INVALID_AUDIT_RANGE');const endRow=end===base.sequence?base:(await q('SELECT sequence,hash FROM audit WHERE tenant=$1 AND sequence=$2',[tenant,end])).rows[0];const rows=(await q('SELECT sequence,previous,hash,encrypted,at FROM audit WHERE tenant=$1 AND sequence>$2 AND sequence<=$3 ORDER BY sequence LIMIT $4',[tenant,start,end,limit])).rows.map((row)=>({tenantId:tenant,...row}));let previous=start===base.sequence?base.hash:(await q('SELECT hash FROM audit WHERE tenant=$1 AND sequence=$2',[tenant,start])).rows[0]?.hash;for(const row of rows){if(row.previous!==previous||row.hash!==hash(json(rowHashInput(row),131072)))bad('AUDIT_INTEGRITY_ERROR',500);previous=row.hash;}const last=rows.at(-1)?.sequence??start;return {base,rows,checkpoint:{tenantId:tenant,sequence:end,hash:endRow.hash},next:last<end?last:null};});
    },
    async prepareArchiveIntent(tenant,record){if(role!=='archive')bad('DATABASE_ROLE_DENIED',403);identifier(tenant);identifier(record.id);if(record.status!=='pending'||!record.signedManifest||!Array.isArray(record.keyIds))bad('INVALID_ARCHIVE_INTENT');return scoped(tenant,async()=>JSON.parse((await q(`SELECT ${schema}.prepare_archive_intent($1,$2,$3) AS record`,[tenant,record.id,json(record)])).rows[0].record));},
    async readArchiveIntent(tenant,id){if(role!=='archive')bad('DATABASE_ROLE_DENIED',403);identifier(tenant);identifier(id);return scoped(tenant,async()=>{const row=(await q('SELECT record FROM archive_intents WHERE tenant=$1 AND id=$2',[tenant,id])).rows[0];return row?JSON.parse(row.record):null;});},
    async commitArchivedPrefix(tenant,{expectedBase,checkpoint,reference,signedManifest}) {if(role!=='archive')bad('DATABASE_ROLE_DENIED',403);identifier(tenant);if(checkpoint?.tenantId!==tenant||!reference||typeof reference!=='object'||!signedManifest)bad('INVALID_ARCHIVE_CHECKPOINT');return scoped(tenant,async()=>{await q(`SELECT ${schema}.archive_prefix($1,$2,$3,$4,$5,$6,$7)`,[tenant,expectedBase.sequence,expectedBase.hash,checkpoint.sequence,checkpoint.hash,json(reference,8192),json(signedManifest,65536)]);return readAuditBase(tenant);});},
    async exportSnapshot(tenant,{maxBytes=67108864}={}) {
      if(role!=='backup')bad('DATABASE_ROLE_DENIED',403);identifier(tenant);positiveInteger(maxBytes,67108864);
      return transaction(async()=>{const epoch=await service.keyEpoch();if(epoch.frozen)bad('MAINTENANCE_FROZEN',409);const tables={};let bytes=0;for(const table of SNAPSHOT_TABLES){tables[table]=[];let offset=0;while(true){const page=(await q(`SELECT * FROM ${table} WHERE tenant=$1 ORDER BY ${table==='objects'?'tenant,namespace,id':table==='operations'||table==='job_index'||table==='backup_catalogues'||table==='archive_intents'||table==='job_tombstones'?'tenant,id':table==='audit'||table==='archive_segments'?'tenant,sequence':table==='usage'?'tenant,root':table==='leases'?'tenant,resource':'tenant'} LIMIT 100 OFFSET $2`,[tenant,offset])).rows;for(const row of page){bytes+=Buffer.byteLength(JSON.stringify(row));if(bytes>maxBytes)bad('BACKUP_TOO_LARGE',413);tables[table].push(row);}if(page.length<100)break;offset+=100;}}const base=tables.audit_bases[0]??{sequence:0,hash:'0'.repeat(64)};const tail=tables.audit.at(-1)??base;const snapshot=Buffer.from(JSON.stringify({version:1,kind:'postgres-snapshot',realm,tenantId:tenant,schemaVersion:2,keyEpoch:epoch,tables,checkpoint:{tenantId:tenant,sequence:tail.sequence,hash:tail.hash}}));if(snapshot.length>maxBytes)bad('BACKUP_TOO_LARGE',413);return snapshot;},{tenantId:tenant,readOnly:true});
    },
    async claimBackupLease(tenant,id,{ownerId,ttlMs,now=Date.now()}){if(role!=='backup')bad('DATABASE_ROLE_DENIED',403);identifier(id);const resourceId=`ownership-${hash(id)}`;const journal=service.maintenanceStore();return scoped(tenant,async()=>{if(!await journal.get(tenant,'jobs',resourceId))await journal.put(tenant,'jobs',resourceId,{version:1,id:resourceId,tenantId:tenant,kind:'backup',payload:{},state:'done',dueAt:Number.MAX_SAFE_INTEGER});return journal.claimLease(tenant,`job:${resourceId}`,{ownerId,ttlMs,now});});},
    assertBackupLease(lease){if(role!=='backup')bad('DATABASE_ROLE_DENIED',403);return service.maintenanceStore().assertLease(lease);},
    renewBackupLease(lease,options){if(role!=='backup')bad('DATABASE_ROLE_DENIED',403);return service.maintenanceStore().renewLease(lease,options);},
    releaseBackupLease(lease){if(role!=='backup')bad('DATABASE_ROLE_DENIED',403);return service.maintenanceStore().releaseLease(lease);},
    async writeBackupCatalogue(tenant,record,{lease=undefined}={}){if(role!=='backup')bad('DATABASE_ROLE_DENIED',403);identifier(tenant);identifier(record.id);if(!['pending','complete'].includes(record.status))bad('INVALID_BACKUP_CATALOGUE');if(record.status==='complete'&&(!record.signedManifest||!record.snapshotSha256||!Array.isArray(record.keyIds)))bad('INVALID_BACKUP_CATALOGUE');return scoped(tenant,async()=>{if(!lease||lease.tenantId!==tenant||lease.resource!==`job:ownership-${hash(record.id)}`)bad('BACKUP_OWNERSHIP_REQUIRED',409);await service.maintenanceStore().assertLease(lease);await q(`SELECT ${schema}.write_backup_catalogue($1,$2,$3)`,[tenant,record.id,json(record)]);return record;});},
    async readBackupCatalogue(tenant,id){identifier(tenant);identifier(id);return scoped(tenant,async()=>{const row=(await q('SELECT record FROM backup_catalogues WHERE tenant=$1 AND id=$2',[tenant,id])).rows[0];return row?JSON.parse(row.record):null;});},
    async listBackupCatalogues(tenant,{limit=100,after=''}={}){identifier(tenant);positiveInteger(limit,100);if(after)identifier(after);return scoped(tenant,async()=>{const rows=(await q('SELECT id,record FROM backup_catalogues WHERE tenant=$1 AND id>$2 ORDER BY id LIMIT $3',[tenant,after,limit+1])).rows;return {items:rows.slice(0,limit).map(row=>JSON.parse(row.record)),next:rows.length>limit?rows[limit-1].id:null};});},
    async archiveStatus(tenant){identifier(tenant);return scoped(tenant,async()=>{const base=await readAuditBase(tenant);return {configured:base.sequence>0,checkpoint:{tenantId:tenant,sequence:base.sequence,hash:base.hash},signedManifest:base.signedManifest??null,reference:base.reference??null};});},
    async backupStatus(tenant){identifier(tenant);return scoped(tenant,async()=>{const latest=(await q("SELECT record FROM backup_catalogues WHERE tenant=$1 AND record::jsonb->>'status'='complete' ORDER BY (record::jsonb->>'createdAt')::bigint DESC,(record::jsonb->>'lastVerifiedAt')::bigint DESC,id DESC LIMIT 1",[tenant])).rows[0];const pending=(await q("SELECT count(*) AS n FROM backup_catalogues WHERE tenant=$1 AND record::jsonb->>'status'='pending'",[tenant])).rows[0];const record=latest?JSON.parse(latest.record):null;return {configured:true,lastSuccessAt:record?.lastVerifiedAt??null,lastSnapshotAt:record?.signedManifest?.manifest?.createdAt??record?.createdAt??null,pending:Number(pending.n),truncated:false};});},

    async checkpoint(tenant) { const { tenantId, sequence, hash: digest, mac } = await verifyAudit(tenant); return { tenantId, sequence, hash: digest, mac }; },
    async list(tenant, namespace, { limit = 50, after = '' } = {}) {
      scope(tenant, namespace); positiveInteger(limit, 100); if (after) identifier(after);
      return scoped(tenant, async () => {
        const rows = (await q('SELECT id,encrypted,expires FROM objects WHERE tenant=$1 AND namespace=$2 AND id>$3 AND (expires IS NULL OR expires>$4) ORDER BY id LIMIT $5', [tenant, namespace, after, Date.now(), limit + 1])).rows;
        const items = rows.slice(0, limit).map((row) => ({ id: row.id, value: codec.decrypt(row.encrypted, objectAAD(tenant, namespace, row.id, row.expires)), expiresAt: row.expires }));
        return { items, next: rows.length > limit ? items.at(-1).id : null };
      });
    },
    async delete(tenant, namespace, id) { scope(tenant, namespace, id); return scoped(tenant, async () => { if(namespace==='jobs') await q('DELETE FROM job_index WHERE tenant=$1 AND id=$2',[tenant,id]); return (await q('DELETE FROM objects WHERE tenant=$1 AND namespace=$2 AND id=$3', [tenant, namespace, id])).rowCount; }); },
    async claimLease(tenantId, resource, { ownerId, ttlMs, now = Date.now() }) {
      identifier(tenantId); leaseResource(resource); identifier(ownerId); positiveInteger(ttlMs, 3600000); positiveInteger(now);
      return scoped(tenantId, async () => {
        const prior = await readLease(tenantId, resource); if (prior?.expiresAt > now) return prior.ownerId === ownerId ? prior : null;
        const lease = { tenantId, resource, ownerId, fence: (prior?.fence ?? 0) + 1, expiresAt: now + ttlMs };
        await q('INSERT INTO leases VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(tenant,resource) DO UPDATE SET owner=excluded.owner,fence=excluded.fence,expires=excluded.expires,mac=excluded.mac', [tenantId, resource, ownerId, lease.fence, lease.expiresAt, leaseMac(lease)]); return lease;
      });
    },
    async renewLease(lease, { ttlMs, now = Date.now() }) {
      positiveInteger(ttlMs, 3600000);
      return scoped(lease.tenantId, async () => {
        let owner; try { owner = await assertLease(lease, { now }); } catch (error) { if (error instanceof AppError && error.code === 'LEASE_LOST') return null; throw error; }
        const renewed = { ...owner, expiresAt: now + ttlMs };
        await q('UPDATE leases SET expires=$1,mac=$2 WHERE tenant=$3 AND resource=$4', [renewed.expiresAt, leaseMac(renewed), renewed.tenantId, renewed.resource]); return renewed;
      });
    },
    async releaseLease(lease) {
      return scoped(lease.tenantId, async () => {
        const owner = await readLease(lease.tenantId, lease.resource); if (!owner || owner.ownerId !== lease.ownerId || owner.fence !== lease.fence) return false;
        const released = { ...owner, expiresAt: 0 }; await q('UPDATE leases SET expires=0,mac=$1 WHERE tenant=$2 AND resource=$3', [leaseMac(released), owner.tenantId, owner.resource]); return true;
      });
    },
    async listTenants({ limit = 100, after = '' } = {}) {
      positiveInteger(limit, 1000); if (after) identifier(after); if (!['worker','rotator','archive','backup'].includes(role)) bad('DATABASE_ROLE_DENIED', 403);
      return transaction(async () => {
        const rows = (await q(`SELECT * FROM ${schema}.list_tenants($1,$2)`, [after, limit + 1])).rows; const items = rows.slice(0, limit).map((row) => row.tenant);
        return { items, next: rows.length > limit ? items.at(-1) : null };
      });
    },
    async recoverUnknown(tenant, { now = Date.now(), limit = 10000 } = {}) {
      positiveInteger(now); positiveInteger(limit, 10000);
      return scoped(tenant, async () => {
        const rows = (await q("SELECT id FROM operations WHERE tenant=$1 AND state IN ('reserved','dispatched') ORDER BY updated,id LIMIT $2", [tenant, limit])).rows;
        const recovered = [];
        for (const row of rows) if (!await operationLive(await getOperation(tenant, row.id), now)) recovered.push(await transitionOperation(tenant, row.id, 'unknown', null, { recoverExpired: true, now }));
        return recovered;
      });
    },
    async listOperations(tenant, { limit = 50, status = undefined } = {}) {
      positiveInteger(limit, 100); if (status && !['reserved', 'dispatched', 'unknown', 'succeeded', 'failed'].includes(status)) bad();
      return scoped(tenant, async () => {
        const rows = (await q(status ? 'SELECT id FROM operations WHERE tenant=$1 AND state=$2 ORDER BY updated,id LIMIT $3' : 'SELECT id FROM operations WHERE tenant=$1 ORDER BY updated,id LIMIT $2', status ? [tenant, status, limit] : [tenant, limit])).rows;
        return Promise.all(rows.map((row) => getOperation(tenant, row.id)));
      });
    },
    async queryAudit(tenant, { limit = 50, after = 0 } = {}) {
      positiveInteger(limit, 100); if (!Number.isSafeInteger(after) || after < 0) bad();
      return scoped(tenant, async () => (await q('SELECT * FROM audit WHERE tenant=$1 AND sequence>$2 ORDER BY sequence LIMIT $3', [tenant, after, limit])).rows
        .map((row) => ({ tenantId: tenant, sequence: row.sequence, previous: row.previous, hash: row.hash, mac: row.mac, at: row.at, ...codec.decrypt(row.encrypted, auditAAD(tenant, row.sequence)) })));
    },
    async exportAudit(tenant, { limit = 100, after = 0, through = undefined } = {}) {
      positiveInteger(limit, 100); if (!Number.isSafeInteger(after) || after < 0) bad();
      return scoped(tenant, async () => {
        const base=await readAuditBase(tenant);if(after===0)after=base.sequence;if(after<base.sequence)bad('INVALID_AUDIT_RANGE');
        const maximum = through === undefined ? (await verifyAudit(tenant)).sequence : Number((await q('SELECT max(sequence) AS n FROM audit WHERE tenant=$1', [tenant])).rows[0].n ?? base.sequence);
        const end = through ?? maximum; if (!Number.isSafeInteger(end) || end < after || end > maximum) bad('INVALID_AUDIT_RANGE');
        const tail = end ? (await q('SELECT hash FROM audit WHERE tenant=$1 AND sequence=$2', [tenant, end])).rows[0] : null;
        const raw = (await q('SELECT * FROM audit WHERE tenant=$1 AND sequence>$2 AND sequence<=$3 ORDER BY sequence LIMIT $4', [tenant, after, end, limit])).rows;
        const rows = raw.map((row) => {
          const digest = hash(json({ tenantId: tenant, sequence: row.sequence, previous: row.previous, encrypted: row.encrypted, at: row.at }, 131072));
          if (row.hash !== digest || !equal(row.mac, codec.mac(digest))) bad('AUDIT_INTEGRITY_ERROR', 500); codec.decrypt(row.encrypted, auditAAD(tenant, row.sequence));
          return { tenantId: tenant, sequence: row.sequence, previous: row.previous, hash: row.hash, encrypted: row.encrypted, at: row.at };
        });
        const last = rows.at(-1)?.sequence ?? after; return { checkpoint: { tenantId: tenant, sequence: end, hash: tail?.hash ?? base.hash }, ...(base.sequence?{base}:{}), after, next: last < end ? last : null, rows };
      });
    },
    async purgeExpired(now = Date.now(), { limit = 100, tenantId = undefined } = {}) {
      positiveInteger(now); positiveInteger(limit, 1000);
      if (!tenantId) {
        if (!['worker','rotator','archive','backup'].includes(role)) bad('DATABASE_ROLE_DENIED', 403);
        const cursor = await get('system', 'metadata', 'retention-tenant-cursor');
        const page = await service.listTenants({ limit: 100, after: cursor?.after ?? '' }); let removed = 0; let last = '';
        for (const tenant of page.items) { if (removed >= limit) break; removed += await service.purgeExpired(now, { limit: limit - removed, tenantId: tenant }); last = tenant; }
        await put('system', 'metadata', 'retention-tenant-cursor', { after: last || '' }); return removed;
      }
      return scoped(tenantId, async () => {
        const rows = (await q('SELECT namespace,id,encrypted,expires FROM objects WHERE tenant=$1 AND expires IS NOT NULL AND expires<=$2 ORDER BY expires,id LIMIT $3', [tenantId, now, limit])).rows;
        for (const row of rows) codec.decrypt(row.encrypted, objectAAD(tenantId, row.namespace, row.id, row.expires));
        for (const row of rows) await q('DELETE FROM objects WHERE tenant=$1 AND namespace=$2 AND id=$3 AND expires=$4', [tenantId, row.namespace, row.id, row.expires]); return rows.length;
      });
    },
    async pruneOperationResults(tenant, { before, limit = 100, now = Date.now() }) {
      positiveInteger(before); positiveInteger(now); positiveInteger(limit, 1000); if (before > now) bad('INVALID_RETENTION_CUTOFF');
      return scoped(tenant, async () => {
        const cursor = await get(tenant, 'metadata', 'retention-operation-cursor') ?? { updated: 0, id: '' };
        const rows = (await q("SELECT id,updated FROM operations WHERE tenant=$1 AND state IN ('succeeded','failed') AND updated<=$2 AND (updated>$3 OR (updated=$3 AND id>$4)) ORDER BY updated,id LIMIT $5", [tenant, before, cursor.updated, cursor.id, limit])).rows;
        let removed = 0;
        for (const row of rows) {
          const op = await getOperation(tenant, row.id); if (op.result === null) continue;
          await q('UPDATE operations SET encrypted=$1 WHERE tenant=$2 AND id=$3', [codec.encrypt({ ...op, result: null, resultExpiredAt: now }, operationAAD(tenant, row.id)), tenant, row.id]); removed++;
        }
        const last = rows.at(-1); await put(tenant, 'metadata', 'retention-operation-cursor', last ? { updated: last.updated, id: last.id } : { updated: 0, id: '' });
        if (removed) await appendAudit({ tenantId: tenant, actorId: 'runtime', event: 'retention.results', data: { removed, before }, at: now }); return { examined: rows.length, removed };
      });
    },
    async queryPlans(tenant) {
      return scoped(tenant, async () => {
        const results = {};
        /** @type {Array<[string,string,any[]]>} */
        const definitions = [
          ['objects', "SELECT id FROM objects WHERE tenant=$1 AND namespace='documents' AND id>'' ORDER BY id LIMIT 100", [tenant]],
          ['operations', "SELECT id FROM operations WHERE tenant=$1 AND state='succeeded' ORDER BY updated LIMIT 100", [tenant]],
          ['audit', 'SELECT sequence FROM audit WHERE tenant=$1 AND sequence>0 ORDER BY sequence LIMIT 100', [tenant]],
        ];
        for (const [name, text, values] of definitions) results[name] = (await q(`EXPLAIN (FORMAT JSON) ${text}`, values)).rows;
        return { backend: 'postgres', realm, plans: results };
      });
    },
    async keyReferences({ tenantId = undefined } = {}) {
      if (!tenantId) {
        const total = {}; let after = '';
        do { const page = await service.listTenants({ limit: 100, after });
          for (const tenant of ['system', ...page.items]) {
            if (tenant === 'system' && after) continue;
            for (const [id, count] of Object.entries(await service.keyReferences({ tenantId: tenant }))) total[id] = (total[id] ?? 0) + count;
          }
          after = page.next;
        } while (after); return total;
      }
      return scoped(tenantId, async () => {
        const references = {};
        for (const table of ['objects', 'operations', 'audit']) {
          let offset = 0;
          while (true) {
            const order = table === 'objects' ? 'namespace,id' : table === 'operations' ? 'id' : 'sequence';
            const rows = (await q(`SELECT * FROM ${table} WHERE tenant=$1 ORDER BY ${order} LIMIT 100 OFFSET $2`, [tenantId, offset])).rows;
            for (const row of rows) {
              const aad = table === 'objects' ? objectAAD(tenantId, row.namespace, row.id, row.expires) : table === 'operations' ? operationAAD(tenantId, row.id) : auditAAD(tenantId, row.sequence);
              codec.decrypt(row.encrypted, aad); const id = codec.keyId(row.encrypted); references[id] = (references[id] ?? 0) + 1;
            }
            if (rows.length < 100) break; offset += rows.length;
          }
        }
        return references;
      });
    },
    async rekeyRecords({ tenantId = undefined, limit = 100, after = '' } = {}) {
      identifier(tenantId); positiveInteger(limit, 1000); let cursor = { table: 'objects', namespace: '', id: '' };
      if (after) {
        if (typeof after !== 'string' || !/^[A-Za-z0-9_-]{1,2048}$/.test(after)) bad();
        try { cursor = JSON.parse(Buffer.from(after, 'base64url').toString('utf8')); } catch { bad(); }
        exactObject(cursor, ['table', 'namespace', 'id']); if (!['objects', 'operations'].includes(cursor.table)) bad();
        if (cursor.namespace) identifier(cursor.namespace); if (cursor.id) identifier(cursor.id);
      }
      return scoped(tenantId, async () => {
        let examined = 0; let rotated = 0; let last = cursor;
        for (const table of cursor.table === 'objects' ? ['objects', 'operations'] : ['operations']) {
          const from = cursor.table === table ? cursor : { namespace: '', id: '' };
          const rows = (await q(table === 'objects'
            ? 'SELECT * FROM objects WHERE tenant=$1 AND (namespace,id)>($2,$3) ORDER BY namespace,id LIMIT $4'
            : 'SELECT * FROM operations WHERE tenant=$1 AND id>$2 ORDER BY id LIMIT $3',
          table === 'objects' ? [tenantId, from.namespace, from.id, limit - examined + 1] : [tenantId, from.id, limit - examined + 1])).rows;
          for (const row of rows) {
            if (examined === limit) return { examined, rotated, next: Buffer.from(JSON.stringify(last)).toString('base64url'), auditCiphertextPreserved: true };
            const aad = table === 'objects' ? objectAAD(tenantId, row.namespace, row.id, row.expires) : operationAAD(tenantId, row.id); const value = codec.decrypt(row.encrypted, aad);
            if (codec.keyId(row.encrypted) !== codec.activeKeyId) {
              if (table === 'objects') await q('UPDATE objects SET encrypted=$1 WHERE tenant=$2 AND namespace=$3 AND id=$4', [codec.encrypt(value, aad), tenantId, row.namespace, row.id]);
              else await q('UPDATE operations SET encrypted=$1 WHERE tenant=$2 AND id=$3', [codec.encrypt(value, aad), tenantId, row.id]);
              rotated++;
            }
            examined++; last = { table, namespace: row.namespace ?? '', id: row.id };
          }
        }
        return { examined, rotated, next: null, auditCiphertextPreserved: true };
      });
    },
    async assertKeyRetirable(keyId, { tenantId = undefined, backupReferences = undefined } = {}) {
      if (!Number.isSafeInteger(backupReferences) || backupReferences < 0) bad('BACKUP_KEY_INVENTORY_REQUIRED');
      if (tenantId !== undefined) bad('GLOBAL_KEY_INVENTORY_REQUIRED', 409);
      return codec.assertRetirable(keyId, ((await service.keyReferences())[keyId] ?? 0) + backupReferences);
    },
    async backup() { bad('POSTGRES_BACKUP_PROVIDER_REQUIRED', 503); },
    async close() { if (!closed) { closed = true; codec.close(); if (!suppliedPool) await pool.end(); } },
  };
  try {
    const files = await migrationFiles();
    await scoped('system', async () => {
      const rows = (await q(`SELECT version,checksum FROM ${schema}.schema_version ORDER BY version`)).rows;
      if (rows.length !== files.length || rows.some((row,index) => row.version !== files[index].version || row.checksum !== files[index].checksum)) bad('STORE_SCHEMA_REQUIRED',503);
      if (keyless) return;
      if (['app','worker'].includes(role)) await q(`SELECT ${schema}.initialize_epoch($1)`,[codec.activeKeyId]);
      const sentinel = await get('system', 'metadata', 'key-check');
      if (sentinel && sentinel.marker !== 'agent-runtime-store-v1') bad('STORE_KEY_MISMATCH', 500);
      if (!sentinel && role !== 'rotator') await put('system', 'metadata', 'key-check', { marker: 'agent-runtime-store-v1' });
    });
  } catch (error) { codec.close(); if (!suppliedPool) await pool.end(); throw error; }
  if (keyless) return Object.freeze(Object.fromEntries(['async','backend','shared','realm','role','health','listTenants','withMaintenanceLease','maintenanceStore','writeRoleHeartbeat','workerStatus','prepareArchiveIntent','readArchiveIntent','readArchiveSegment','commitArchivedPrefix','exportSnapshot','keyEpoch','restoreStatus','claimBackupLease','assertBackupLease','renewBackupLease','releaseBackupLease','writeBackupCatalogue','readBackupCatalogue','listBackupCatalogues','archiveStatus','backupStatus','close'].filter((name)=>name!=='commitArchivedPrefix'||role==='archive').map((name)=>[name,service[name]])));
  return Object.freeze(service);
}

export const openPostgresArchivePort=(options)=>openPostgresStore({...options,role:'archive'});
export const openPostgresBackupPort=(options)=>openPostgresStore({...options,role:'backup'});

/** Offline migrator-only restore. The target must have been freshly migrated and contain no business state. */
export async function restorePostgresSnapshot({pool,realm,snapshot,expectedSha256,allowNewTarget=false,encryptionKey,auditKey=encryptionKey,keyring,timeoutMs=30000,acquireTimeoutMs=1000}) {
  const schema=databaseRealm(realm);if(!allowNewTarget||!Buffer.isBuffer(snapshot)||snapshot.length>67108864||typeof expectedSha256!=='string'||!equal(hash(snapshot),expectedSha256))bad('BACKUP_TRUST_MISMATCH',409);
  let value;try{value=JSON.parse(snapshot.toString('utf8'));}catch{bad('INVALID_BACKUP_MANIFEST');}
  exactObject(value,['version','kind','realm','tenantId','schemaVersion','keyEpoch','tables','checkpoint']);identifier(value.tenantId);
  if(value.version!==1||value.kind!=='postgres-snapshot'||value.realm!==realm||value.schemaVersion!==2||Object.keys(value.tables).sort().join()!==[...SNAPSHOT_TABLES].sort().join())bad('INVALID_BACKUP_MANIFEST');
  const codec=createStorageCodec({encryptionKey,auditKey,keyring});
  const columns={objects:['tenant','namespace','id','encrypted','expires'],operations:['tenant','id','task','root','digest','state','encrypted','created','updated'],usage:['tenant','root','consumed','mac'],audit:['tenant','sequence','previous','hash','mac','encrypted','at'],leases:['tenant','resource','owner','fence','expires','mac'],audit_bases:['tenant','sequence','hash','reference','manifest'],job_index:['tenant','id','state','kind','due'],backup_catalogues:['tenant','id','record'],archive_intents:['tenant','id','record'],job_tombstones:['tenant','id','record','mac'],archive_segments:['tenant','sequence','reference','manifest']};
  const base=value.tables.audit_bases[0]??{sequence:0,hash:'0'.repeat(64)};let sequence=Number(base.sequence);let previous=base.hash;
  try{
    for(const table of SNAPSHOT_TABLES){if(!Array.isArray(value.tables[table]))bad('INVALID_BACKUP_MANIFEST');for(const row of value.tables[table]){exactObject(row,columns[table]);if(row.tenant!==value.tenantId)bad('BACKUP_TENANT_MISMATCH',403);
      if(row.encrypted){const aad=table==='objects'?objectAAD(row.tenant,row.namespace,row.id,row.expires):table==='operations'?operationAAD(row.tenant,row.id):auditAAD(row.tenant,row.sequence);const plain=codec.decrypt(row.encrypted,aad);if(table==='objects'&&['tasks','approvals'].includes(row.namespace)){row.encrypted=codec.encrypt(row.namespace==='tasks'?{...plain,revoked:true,restoredRevoked:true}:{...plain,used:true,restoredRevoked:true},aad);}}
      if(table==='audit'){sequence++;const digest=hash(json({tenantId:row.tenant,sequence,previous,encrypted:row.encrypted,at:Number(row.at)},131072));if(Number(row.sequence)!==sequence||row.previous!==previous||row.hash!==digest||!equal(row.mac,codec.mac(digest)))bad('AUDIT_INTEGRITY_ERROR',500);previous=digest;}
      if(table==='job_tombstones'&&!equal(row.mac,codec.mac(json(['job-tombstone',row.tenant,row.id,row.record]))))bad('STORE_INTEGRITY_ERROR',500);
      if(table==='usage'&&!equal(row.mac,codec.usageMac(row.tenant,row.root,Number(row.consumed))))bad('STORE_INTEGRITY_ERROR',500);
      if(table==='leases'&&!equal(row.mac,codec.mac(json(['lease',row.tenant,row.resource,row.owner,Number(row.fence),Number(row.expires)]))))bad('STORE_INTEGRITY_ERROR',500);
    }}
    if(value.checkpoint.tenantId!==value.tenantId||Number(value.checkpoint.sequence)!==sequence||value.checkpoint.hash!==previous||value.keyEpoch.activeKeyId!==codec.activeKeyId)bad('BACKUP_KEY_OR_CHECKPOINT_MISMATCH',409);
    const client=await boundedRestoreClient(pool,{timeoutMs,acquireTimeoutMs});try{await client.query('BEGIN');await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))',[`${schema}:offline-restore`]);
      const files=await migrationFiles();const versions=(await client.query(`SELECT version,checksum FROM ${schema}.schema_version ORDER BY version`)).rows;if(versions.length!==files.length||versions.some((row,index)=>row.version!==files[index].version||row.checksum!==files[index].checksum))bad('STORE_SCHEMA_REQUIRED',503);
      for(const table of [...SNAPSHOT_TABLES,'tenants'])if((await client.query(`SELECT 1 FROM ${schema}.${table} LIMIT 1`)).rows.length)bad('RESTORE_DESTINATION_EXISTS',409);
      await client.query(`UPDATE ${schema}.key_epochs SET active_id=$1,version=$2,frozen=false WHERE singleton`,[value.keyEpoch.activeKeyId,value.keyEpoch.version]);
      await client.query("SELECT set_config('runtime.tenant_id',$1,true)",[value.tenantId]);
      for(const table of SNAPSHOT_TABLES)for(const row of value.tables[table])await client.query(`INSERT INTO ${schema}.${table}(${columns[table].join(',')}) VALUES(${columns[table].map((_,index)=>'$'+(index+1)).join(',')})`,columns[table].map(key=>row[key]));
      if(value.tenantId!=='system'){await client.query("SELECT set_config('runtime.tenant_id','system',true)");await client.query(`INSERT INTO ${schema}.objects VALUES('system','metadata','key-check',$1,NULL)`,[codec.encrypt({marker:'agent-runtime-store-v1'},objectAAD('system','metadata','key-check',null))]);await client.query(`INSERT INTO ${schema}.tenants VALUES('system') ON CONFLICT DO NOTHING`);}
      await client.query(`INSERT INTO ${schema}.tenants VALUES($1) ON CONFLICT DO NOTHING`,[value.tenantId]);await client.query(`UPDATE ${schema}.key_epochs SET frozen=true,quarantined=true,restore_sha=$1,version=version+1 WHERE singleton`,[expectedSha256]);await client.query('COMMIT');return {restored:true,quarantined:true,requiresReauthorization:true,sourceFencePending:true,realm,tenantId:value.tenantId,checkpoint:value.checkpoint,sha256:expectedSha256};
    }catch(error){await client.query('ROLLBACK').catch(()=>{});throw error;}finally{client.release();}
  }finally{codec.close();}
}

async function boundedRestoreClient(pool,{timeoutMs,acquireTimeoutMs}){
  positiveInteger(timeoutMs,60000);positiveInteger(acquireTimeoutMs,10000);const deadline=effectiveDeadline({timeoutMs});let abandoned=false;let timer;let raw;const acquireExpiresAt=Math.min(deadline,Date.now()+acquireTimeoutMs);
  try{raw=await Promise.race([Promise.resolve().then(()=>pool.connect()).then(client=>{if(abandoned||Date.now()>=acquireExpiresAt){client.release(new Error('RESTORE_ACQUIRE_TIMEOUT'));throw new AppError(503,'DATABASE_ACQUIRE_TIMEOUT');}return client;}),new Promise((_,reject)=>{timer=setTimeout(()=>{abandoned=true;reject(new AppError(503,'DATABASE_ACQUIRE_TIMEOUT'));},Math.min(acquireTimeoutMs,remainingBudget(deadline)));})]);}finally{clearTimeout(timer);}
  let uncertain=false;return {async query(text,values=[]){const cleanup=text==='ROLLBACK';const remaining=cleanup?500:Math.min(5000,remainingBudget(deadline));let queryTimer;try{return await Promise.race([raw.query({text,values,query_timeout:remaining}),new Promise((_,reject)=>{queryTimer=setTimeout(()=>{uncertain=true;reject(new AppError(503,'DATABASE_TIMEOUT'));},remaining);})]);}finally{clearTimeout(queryTimer);}},release(){raw.release(uncertain?new Error('RESTORE_CONNECTION_UNCERTAIN'):undefined);}};
}
