import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { openPostgresStore } from '../src/product/postgres-store.mjs';
import { migratePostgres } from '../src/product/migrations.mjs';
import { requestContext } from '../src/product/context.mjs';

/** PGlite is one PostgreSQL engine/session, serialized here; not a TCP/replication acceptance fixture. */
async function fixture(t) {
  const db = new PGlite(); await db.waitReady; t.after(() => db.close()); let tail = Promise.resolve();
  const pool = { async connect() { let release; const gate = new Promise((done) => { release = done; }); const prior = tail; tail = prior.then(() => gate); await prior;
    return { async query(input, values) {
      if (typeof input === 'string' && values === undefined) return (await db.exec(input)).at(-1) ?? { rows: [] };
      return db.query(typeof input === 'string' ? input : input.text, typeof input === 'string' ? values : input.values);
    }, release }; } };
  await migratePostgres({ pool, realm: 'gateway' }); await migratePostgres({ pool, realm: 'resource' });
  const keys = { encryptionKey: randomBytes(32), auditKey: randomBytes(32) };
  await assert.rejects(openPostgresStore({ pool, realm: 'gateway', ...keys }), { code: 'UNSAFE_DATABASE_CREDENTIAL' });
  const a = await openPostgresStore({ pool, realm: 'gateway', ...keys, sqlFixture: true }); const b = await openPostgresStore({ pool, realm: 'gateway', ...keys, sqlFixture: true });
  const resourceKeys = { encryptionKey: randomBytes(32), auditKey: randomBytes(32) };
  const resource = await openPostgresStore({ pool, realm: 'resource', ...resourceKeys, sqlFixture: true });
  t.after(async () => { await a.close(); await b.close(); await resource.close(); });
  return { a, b, resource, db, pool, keys, resourceKeys };
}

test('real PostgreSQL SQL enforces shared authority, RLS/realms, rollback, leases and reversible migrations', async (t) => {
  const { a, b, resource, db, pool, keys, resourceKeys } = await fixture(t); const now = Date.now(); const tenant = 'company';
  await a.put(tenant, 'tasks', 'task', { id: 'task', rootTaskId: 'task', parentId: null, actorId: 'agent', expiresAt: now + 60000, maxActions: 1 });
  assert.equal((await b.get(tenant, 'tasks', 'task')).actorId, 'agent'); assert.equal(await b.get('foreign', 'tasks', 'task'), null);
  assert.equal(await resource.get(tenant, 'tasks', 'task'), null);
  await assert.rejects(a.transaction(async () => { await a.put(tenant, 'memory', 'rollback', { text: 'never' }); throw new Error('abort'); }, { tenantId: tenant }), { code: 'DATABASE_OPERATION_FAILED' });
  assert.equal(await b.get(tenant, 'memory', 'rollback'), null);
  await assert.rejects(a.transaction(() => a.get('foreign', 'tasks', 'task'), { tenantId: tenant }), { code: 'TENANT_TRANSACTION_MISMATCH' });
  const leaseA = await a.claimLease(tenant, 'operation:one', { ownerId: 'one', ttlMs: 30000 });
  const leaseB = await b.claimLease(tenant, 'operation:two', { ownerId: 'two', ttlMs: 30000 });
  const input = (id, lease) => ({ tenantId: tenant, taskId: 'task', operationId: id, actionDigest: `digest-${id}`, action: { id, kind: 'read', documentId: 'guide' }, policyDigest: 'policy', toolVersion: 'v1', maxActions: 1, lease });
  const race = await Promise.allSettled([a.reserveOperation(input('one', leaseA)), b.reserveOperation(input('two', leaseB))]);
  assert.equal(race.filter((row) => row.status === 'fulfilled').length, 1); assert.equal(race.find((row) => row.status === 'rejected').reason.code, 'ROOT_QUOTA');
  assert.equal((await a.verifyAudit(tenant)).sequence, 1); assert.deepEqual(await b.recoverUnknown(tenant), []);
  await assert.rejects(a.listTenants(), { code: 'DATABASE_ROLE_DENIED' });
  const worker = await openPostgresStore({ pool, realm: 'gateway', role: 'worker', ...keys, sqlFixture: true });
  assert.ok((await worker.listTenants()).items.includes(tenant)); assert.ok((await worker.keyReferences()).legacy >= 4); await worker.close();
  await a.releaseLease(leaseA);await b.releaseLease(leaseB);
  const original = await a.exportAudit(tenant); const nextKey = randomBytes(32);
  const rotated = await openPostgresStore({ pool, realm: 'gateway', role: 'rotator', encryptionKey: nextKey, auditKey: keys.auditKey,
    keyring: { activeKeyId: 'new', legacyKeyId: 'old', keys: { old: keys.encryptionKey.toString('hex'), new: nextKey.toString('hex') } }, sqlFixture: true });
  let epoch=await rotated.freezeWrites({expectedVersion:(await rotated.keyEpoch()).version});await rotated.activateKeyEpoch({expectedVersion:epoch.version,activeKeyId:'new'});
  for (const tenantId of ['system', tenant]) { let after = ''; do { after = (await rotated.rekeyRecords({ tenantId, limit: 1, after })).next; } while (after); }
  assert.equal((await rotated.get(tenant, 'tasks', 'task')).actorId, 'agent'); assert.deepEqual(await rotated.exportAudit(tenant), original);
  await assert.rejects(rotated.assertKeyRetirable('old', { backupReferences: 0 }), { code: 'KEY_STILL_REFERENCED' }); await rotated.close();
  await resource.put('tenant-a', 'memory', 'note', { text: 'a' }); await resource.put('tenant-b', 'memory', 'note', { text: 'b' });
  const resourceNext = randomBytes(32);
  const resourceRotation = await openPostgresStore({ pool, realm: 'resource', role: 'rotator', encryptionKey: resourceNext, auditKey: resourceKeys.auditKey,
    keyring: { activeKeyId: 'new', legacyKeyId: 'old', keys: { old: resourceKeys.encryptionKey.toString('hex'), new: resourceNext.toString('hex') } }, sqlFixture: true });
  epoch=await resourceRotation.freezeWrites({expectedVersion:(await resourceRotation.keyEpoch()).version});await resourceRotation.activateKeyEpoch({expectedVersion:epoch.version,activeKeyId:'new'});
  await resourceRotation.rekeyRecords({ tenantId: 'system' }); await resourceRotation.rekeyRecords({ tenantId: 'tenant-a' });
  assert.equal((await resourceRotation.keyReferences({ tenantId: 'tenant-a' })).old, undefined);
  await assert.rejects(resourceRotation.assertKeyRetirable('old', { tenantId: 'tenant-a', backupReferences: 0 }), { code: 'GLOBAL_KEY_INVENTORY_REQUIRED' });
  await assert.rejects(resourceRotation.assertKeyRetirable('old', { backupReferences: 0 }), { code: 'KEY_STILL_REFERENCED' });
  await resourceRotation.rekeyRecords({ tenantId: 'tenant-b' }); assert.equal(await resourceRotation.assertKeyRetirable('old', { backupReferences: 0 }), true); await resourceRotation.close();
  await db.query('SET ROLE runtime_gateway_app');
  await assert.rejects(db.query('SELECT * FROM runtime_resource.objects'), /permission denied/);
  await assert.rejects(db.query('DELETE FROM runtime_gateway.audit'), /permission denied/);
  await db.query('RESET ROLE');
  await migratePostgres({ pool, realm: 'resource', direction: 'down', allowDestructive: true,allowDecommission:true });
  await migratePostgres({ pool, realm: 'resource' });
  assert.ok((await a.queryPlans(tenant)).plans.objects);
});

test('PostgreSQL connection rejects DSN overrides and plaintext Unix socket paths before any connection', async () => {
  const base = { realm: 'gateway', encryptionKey: randomBytes(32), ca: '-----BEGIN CERTIFICATE-----',
    connection: { host: 'db.company.invalid', port: 5432, database: 'runtime', user: 'restricted', password: 'not-a-real-password' } };
  await assert.rejects(openPostgresStore({ ...base, connection: { ...base.connection, connectionString: 'postgres://invalid/?sslmode=disable' } }), { code: 'INVALID_INPUT' });
  await assert.rejects(openPostgresStore({ ...base, connection: { ...base.connection, host: '/var/run/postgresql' } }), { code: 'INVALID_POSTGRES_CONNECTION' });
});

test('restricted PostgreSQL sessions reject direct privilege and forced-RLS drift before accessing authority', async (t) => {
  const { db, pool, keys } = await fixture(t);
  await db.exec('CREATE ROLE runtime_test_login LOGIN NOINHERIT; GRANT runtime_gateway_app TO runtime_test_login; SET SESSION AUTHORIZATION runtime_test_login;');
  const accepted = await openPostgresStore({ pool, realm: 'gateway', ...keys }); await accepted.close();
  const rejected = async () => {
    await db.exec('SET SESSION AUTHORIZATION runtime_test_login');
    await assert.rejects(openPostgresStore({ pool, realm: 'gateway', ...keys }), { code: 'UNSAFE_DATABASE_CREDENTIAL' });
    await db.exec('SET SESSION AUTHORIZATION postgres');
  };
  await db.exec('SET SESSION AUTHORIZATION postgres; GRANT DELETE ON runtime_gateway.audit TO runtime_gateway_app;');
  await rejected();
  await db.exec('REVOKE DELETE ON runtime_gateway.audit FROM runtime_gateway_app; GRANT UPDATE(encrypted) ON runtime_gateway.audit TO runtime_gateway_app;');
  await rejected();
  await db.exec('REVOKE UPDATE(encrypted) ON runtime_gateway.audit FROM runtime_gateway_app; ALTER TABLE runtime_gateway.objects DISABLE ROW LEVEL SECURITY;');
  await rejected();
  await db.exec('ALTER TABLE runtime_gateway.objects ENABLE ROW LEVEL SECURITY; ALTER TABLE runtime_gateway.leases NO FORCE ROW LEVEL SECURITY;');
  await rejected();
  await db.exec('ALTER TABLE runtime_gateway.leases FORCE ROW LEVEL SECURITY; GRANT USAGE ON SCHEMA runtime_resource TO runtime_test_login;');
  await rejected();
  await db.exec('REVOKE USAGE ON SCHEMA runtime_resource FROM runtime_test_login; GRANT SELECT ON runtime_resource.objects TO runtime_test_login;');
  await rejected();
  await db.exec('REVOKE SELECT ON runtime_resource.objects FROM runtime_test_login;');
  await db.exec('GRANT SELECT(encrypted) ON runtime_resource.objects TO runtime_test_login;');
  await rejected();
  await db.exec('REVOKE SELECT(encrypted) ON runtime_resource.objects FROM runtime_test_login;');
  await db.exec('CREATE POLICY unexpected_policy ON runtime_gateway.objects USING (true) WITH CHECK (true);');
  await rejected();
  await db.exec('DROP POLICY unexpected_policy ON runtime_gateway.objects; ALTER POLICY tenant_isolation ON runtime_gateway.objects USING (true);');
  await rejected();
  await db.exec("ALTER POLICY tenant_isolation ON runtime_gateway.objects USING (tenant=current_setting('runtime.tenant_id',true));");
  await db.exec('GRANT EXECUTE ON FUNCTION runtime_gateway.archive_prefix(text,bigint,text,bigint,text,text,text) TO runtime_gateway_app');await rejected();
  await db.exec('REVOKE EXECUTE ON FUNCTION runtime_gateway.archive_prefix(text,bigint,text,bigint,text,text,text) FROM runtime_gateway_app; GRANT UPDATE(sequence) ON runtime_gateway.audit_bases TO runtime_gateway_app');await rejected();
  await db.exec('REVOKE UPDATE(sequence) ON runtime_gateway.audit_bases FROM runtime_gateway_app; GRANT UPDATE(active_id) ON runtime_gateway.key_epochs TO runtime_gateway_app');await rejected();
  await db.exec('REVOKE UPDATE(active_id) ON runtime_gateway.key_epochs FROM runtime_gateway_app');

});

test('PostgreSQL acquisition and credential setup consume the same invocation deadline', async () => {
  const queries = []; const deadlineAt = Date.now() + 2000;
  const pool = { async connect() { await new Promise((done) => setTimeout(done, 25)); return {
    async query(input) { queries.push({ input, at: Date.now() }); return { rows: [{ rolsuper: true }] }; }, release() {},
  }; } };
  await assert.rejects(requestContext.run({ deadlineAt }, () => openPostgresStore({ pool, realm: 'gateway', encryptionKey: randomBytes(32) })), { code: 'UNSAFE_DATABASE_CREDENTIAL' });
  assert.ok(queries[0].input.query_timeout <= deadlineAt - queries[0].at + 2);
  assert.ok(queries[0].input.query_timeout < 2000);
  let connects = 0; let releases = 0; let sent = 0;
  const late = { async connect() { connects++; await new Promise((done) => setTimeout(done, 80)); return { query() { sent++; return { rows: [] }; }, release() { releases++; } }; } };
  await assert.rejects(requestContext.run({ deadlineAt: Date.now() + 50 }, () => openPostgresStore({ pool: late, realm: 'gateway', encryptionKey: randomBytes(32) })), (error) => ['DATABASE_ACQUIRE_TIMEOUT', 'TRANSPORT_DEADLINE'].includes(error.code));
  await new Promise((done) => setTimeout(done, 100)); assert.equal(sent, 0); assert.equal(releases, connects);
});

test('a synchronously blocking PostgreSQL acquisition releases its late client exactly once without queries', async () => {
  let releases = 0; let queries = 0;
  const pool = { connect() {
    const until = Date.now() + 40;
    while (Date.now() < until) { /* Simulate a pool hook blocking past its invocation budget. */ }
    return Promise.resolve({ query() { queries++; return { rows: [] }; }, release() { releases++; } });
  } };
  await assert.rejects(requestContext.run({ deadlineAt: Date.now() + 20 }, () => openPostgresStore({
    pool, realm: 'gateway', encryptionKey: randomBytes(32),
  })), (error) => ['DATABASE_ACQUIRE_TIMEOUT', 'TRANSPORT_DEADLINE'].includes(error.code));
  await new Promise((done) => setImmediate(done));
  assert.equal(queries, 0); assert.equal(releases, 1);
});
