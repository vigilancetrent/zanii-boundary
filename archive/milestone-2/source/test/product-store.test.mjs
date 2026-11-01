import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { openStore, restoreStore } from '../src/product/store.mjs';

function fixture(t) {
  const base = resolve('.test-data'); mkdirSync(base, { recursive: true });
  const directory = mkdtempSync(join(base, 'store-')); const key = randomBytes(32); const auditKey = randomBytes(32);
  let store = openStore({ path: join(directory, 'runtime.db'), encryptionKey: key, auditKey });
  t.after(() => { store.close(); const target = resolve(directory); assert.ok(target.startsWith(`${base}\\`) || target.startsWith(`${base}/`)); rmSync(target, { recursive: true, force: true }); });
  return { directory, key, auditKey, get store() { return store; }, reopen() { store.close(); store = openStore({ path: join(directory, 'runtime.db'), encryptionKey: key, auditKey }); return store; } };
}
const task = (id = 'root', patch = {}) => ({ id, rootTaskId: 'root', parentId: null, tenantId: 'tenant-a', actorId: 'agent-a',
  expiresAt: Date.now() + 60_000, maxActions: 3, revoked: false, ...patch });
const reserve = (patch = {}) => ({ tenantId: 'tenant-a', taskId: 'root', rootTaskId: 'root', operationId: 'op-1',
  actionDigest: 'digest-1', action: { kind: 'read', documentId: 'guide' }, policyDigest: 'policy-1', toolVersion: '1', maxActions: 3, ...patch });

test('disk store encrypts values, scopes every key, paginates and expires payloads', (t) => {
  const f = fixture(t); const s = f.store;
  s.put('tenant-a', 'memory', 'a', { text: 'sensitive-business-payload' });
  s.put('tenant-a', 'memory', 'b', { text: 'second' });
  assert.equal(s.get('tenant-b', 'memory', 'a'), null);
  assert.equal(s.list('tenant-a', 'memory', { limit: 1 }).next, 'a');
  assert.equal(s.list('tenant-a', 'memory', { limit: 1, after: 'a' }).items[0].id, 'b');
  s.put('tenant-a', 'memory', 'old', { text: 'expire' }, { expiresAt: Date.now() - 1 });
  assert.equal(s.get('tenant-a', 'memory', 'old'), null); assert.equal(s.purgeExpired(), 1);
  f.reopen(); assert.equal(f.store.get('tenant-a', 'memory', 'a').text, 'sensitive-business-payload');
  assert.equal(readFileSync(join(f.directory, 'runtime.db')).includes(Buffer.from('sensitive-business-payload')), false);
});

test('transaction rollback prevents partial state and refuses async callbacks', (t) => {
  const { store } = fixture(t);
  assert.throws(() => store.transaction(() => { store.put('tenant-a', 'memory', 'one', { ok: true }); throw new Error('injected'); }));
  assert.equal(store.get('tenant-a', 'memory', 'one'), null);
  assert.throws(() => store.transaction(async () => {}), { code: 'ASYNC_TRANSACTION' });
});

test('durable idempotency binds arguments and restart recovery never replays dispatch', (t) => {
  const f = fixture(t); f.store.put('tenant-a', 'tasks', 'root', task());
  assert.equal(f.store.reserveOperation(reserve()).created, true);
  assert.equal(f.store.reserveOperation(reserve()).created, false);
  assert.throws(() => f.store.reserveOperation(reserve({ actionDigest: 'other' })), { code: 'IDEMPOTENCY_CONFLICT' });
  f.store.transitionOperation('tenant-a', 'op-1', 'dispatched'); f.reopen();
  assert.equal(f.store.recoverUnknown('tenant-a')[0].status, 'unknown');
  assert.equal(f.store.getOperation('tenant-b', 'op-1'), null);
  assert.equal(f.store.reserveOperation(reserve()).created, false);
  f.store.transitionOperation('tenant-a', 'op-1', 'succeeded', { observed: true });
  assert.equal(f.store.reserveOperation(reserve()).operation.result.observed, true);
  assert.throws(() => f.store.transitionOperation('tenant-a', 'op-1', 'dispatched'), { code: 'INVALID_OPERATION_TRANSITION' });
});

test('one-use exact approvals and aggregate ancestor quotas reserve atomically', async (t) => {
  const { store } = fixture(t); store.put('tenant-a', 'tasks', 'root', task());
  store.put('tenant-a', 'approvals', 'approval-1', { id: 'approval-1', tenantId: 'tenant-a', taskId: 'root', actionDigest: 'digest-1',
    policyDigest: 'policy-1', toolVersion: '1', expiresAt: Date.now() + 10_000, used: false, approverId: 'reviewer' });
  assert.throws(() => store.reserveOperation(reserve({ requiresApproval: true })), { code: 'APPROVAL_REQUIRED' });
  store.reserveOperation(reserve({ approvalId: 'approval-1', requiresApproval: true }));
  assert.throws(() => store.reserveOperation(reserve({ operationId: 'op-2', approvalId: 'approval-1', requiresApproval: true })), { code: 'APPROVAL_INVALID' });
  store.put('tenant-a', 'tasks', 'child', task('child', { parentId: 'root', maxActions: 1 }));
  store.reserveOperation(reserve({ operationId: 'child-1', taskId: 'child' }));
  assert.throws(() => store.reserveOperation(reserve({ operationId: 'child-2', taskId: 'child' })), { code: 'TASK_QUOTA' });
  const attempts = await Promise.all(Array.from({ length: 5 }, (_, i) => Promise.resolve().then(() => {
    try { return store.reserveOperation(reserve({ operationId: `race-${i}` })).created; } catch (e) { assert.equal(e.code, 'ROOT_QUOTA'); return false; }
  })));
  assert.equal(attempts.filter(Boolean).length, 1);
});

test('parent revocation blocks an existing child even if its own grant remains valid', (t) => {
  const { store } = fixture(t); store.put('tenant-a', 'tasks', 'root', task());
  store.put('tenant-a', 'tasks', 'middle', task('middle', { parentId: 'root' }));
  store.put('tenant-a', 'tasks', 'child', task('child', { parentId: 'middle' }));
  store.put('tenant-a', 'tasks', 'middle', task('middle', { parentId: 'root', revoked: true }));
  assert.throws(() => store.reserveOperation(reserve({ taskId: 'child' })), { code: 'TASK_LINEAGE_INVALID' });
});

test('audit chains reject tampering and externally retained checkpoint detects truncation', (t) => {
  const f = fixture(t); f.store.appendAudit({ tenantId: 'tenant-a', actorId: 'operator', event: 'task.created', target: 'root' });
  const checkpoint = f.store.checkpoint('tenant-a'); assert.equal(f.store.verifyAudit('tenant-a', checkpoint).ok, true);
  f.store.close(); const raw = new DatabaseSync(join(f.directory, 'runtime.db'));
  raw.prepare('DELETE FROM audit WHERE tenant=?').run('tenant-a'); raw.close(); f.reopen();
  assert.throws(() => f.store.verifyAudit('tenant-a', checkpoint), { code: 'AUDIT_CHECKPOINT_MISMATCH' });
});

test('consistent backup restores encrypted data and never overwrites an existing target', (t) => {
  const f = fixture(t); f.store.put('tenant-a', 'memory', 'note', { text: 'private-note' });
  const backup = join(f.directory, 'snapshot.db'); const manifest = f.store.backup(backup); assert.ok(manifest.bytes > 0);
  const target = join(f.directory, 'restored.db'); const restored = restoreStore({ backupPath: backup, path: target, encryptionKey: f.key, auditKey: f.auditKey });
  try { assert.equal(restored.get('tenant-a', 'memory', 'note').text, 'private-note'); } finally { restored.close(); }
  assert.throws(() => restoreStore({ backupPath: backup, path: target, encryptionKey: f.key }), { code: 'RESTORE_DESTINATION_EXISTS' });
});

test('ciphertext transplant and wrong encryption keys fail closed', (t) => {
  const f = fixture(t); f.store.put('tenant-a', 'memory', 'note', { text: 'private-note' }); f.store.close();
  assert.throws(() => openStore({ path: join(f.directory, 'runtime.db'), encryptionKey: randomBytes(32), auditKey: f.auditKey }), { code: 'STORE_INTEGRITY_ERROR' });
  const raw = new DatabaseSync(join(f.directory, 'runtime.db'));
  raw.prepare("UPDATE objects SET id='other' WHERE tenant='tenant-a' AND namespace='memory'").run(); raw.close(); f.reopen();
  assert.throws(() => f.store.get('tenant-a', 'memory', 'other'), { code: 'STORE_INTEGRITY_ERROR' });
});

test('disk-capacity failure rolls back operation, approval consumption, quota and audit together', (t) => {
  const base = resolve('.test-data'); mkdirSync(base, { recursive: true });
  const directory = mkdtempSync(join(base, 'capacity-'));
  const store = openStore({ path: join(directory, 'runtime.db'), encryptionKey: randomBytes(32), maxBytes: 131_072 });
  t.after(() => { store.close(); assert.ok(resolve(directory).startsWith(`${base}\\`) || resolve(directory).startsWith(`${base}/`)); rmSync(directory, { recursive: true, force: true }); });
  store.put('tenant-a', 'tasks', 'root', task());
  assert.throws(() => store.transaction(() => {
    store.reserveOperation(reserve());
    for (let i = 0; i < 10; i += 1) store.put('tenant-a', 'memory', `fill-${i}`, { text: 'x'.repeat(60_000) });
  }), { code: 'STORE_CAPACITY_ERROR' });
  assert.equal(store.getOperation('tenant-a', 'op-1'), null);
  assert.equal(store.verifyAudit('tenant-a').sequence, 0);
  assert.equal(store.reserveOperation(reserve()).created, true);
});

test('encrypted metadata and usage counters cannot be changed without detection', (t) => {
  const f = fixture(t); f.store.put('tenant-a', 'tasks', 'root', task());
  f.store.reserveOperation(reserve()); f.store.close();
  const raw = new DatabaseSync(join(f.directory, 'runtime.db'));
  raw.prepare("UPDATE usage SET consumed=0 WHERE tenant='tenant-a'").run(); raw.close(); f.reopen();
  assert.throws(() => f.store.reserveOperation(reserve({ operationId: 'quota-bypass' })), { code: 'STORE_INTEGRITY_ERROR' });
  f.store.close(); const raw2 = new DatabaseSync(join(f.directory, 'runtime.db'));
  raw2.prepare("UPDATE operations SET state='succeeded' WHERE tenant='tenant-a'").run(); raw2.close(); f.reopen();
  assert.throws(() => f.store.getOperation('tenant-a', 'op-1'), { code: 'STORE_INTEGRITY_ERROR' });
});

test('past-expiry tampering fails authentication before reads or retention deletion', (t) => {
  const f = fixture(t);
  f.store.put('tenant-a', 'memory', 'valid-expired', { text: 'legitimately expired' }, { expiresAt: Date.now() - 1000 });
  f.store.put('tenant-a', 'memory', 'tampered', { text: 'still protected' }, { expiresAt: Date.now() + 60_000 });
  f.store.close(); const raw = new DatabaseSync(join(f.directory, 'runtime.db'));
  raw.prepare("UPDATE objects SET expires=? WHERE tenant='tenant-a' AND namespace='memory' AND id='tampered'").run(Date.now() - 500);
  raw.close(); f.reopen();
  assert.throws(() => f.store.get('tenant-a', 'memory', 'tampered'), { code: 'STORE_INTEGRITY_ERROR' });
  assert.throws(() => f.store.purgeExpired(), { code: 'STORE_INTEGRITY_ERROR' });
  f.store.close(); const check = new DatabaseSync(join(f.directory, 'runtime.db'));
  assert.equal(check.prepare("SELECT count(*) AS n FROM objects WHERE tenant='tenant-a' AND namespace='memory'").get().n, 2);
  check.close(); f.reopen();
});

test('document provider namespaces remain explicit and tenant scoped', (t) => {
  const { store } = fixture(t);
  for (const namespace of ['documents', 'deliveries', 'resource-operations']) {
    store.put('tenant-a', namespace, 'one', { value: namespace });
    assert.equal(store.get('tenant-a', namespace, 'one').value, namespace);
    assert.equal(store.get('tenant-b', namespace, 'one'), null);
  }
  assert.throws(() => store.put('tenant-a', 'arbitrary-provider-table', 'one', {}), { code: 'INVALID_STORE_INPUT' });
});
