import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { generateKeypair, verifyReceipt } from '@zanii/core';
import { Runtime } from '@zanii/runtime';
import { AppError } from '../src/protocol.mjs';
import { createProductFixture, seedProductFixture, resourceEffects } from '../scripts/product-fixture.mjs';
import { startLocalRuntimeLedgerFixture } from '../scripts/product-ledger-fixture.mjs';
import { createConfiguredZaniiLedger } from '../src/adapters/zanii.mjs';
import { openAsyncSqliteStore } from '../src/product/async-store.mjs';
import { RUNTIME_PREFLIGHT_TOOL } from '../src/adapters/zanii-runtime.mjs';
import { createRuntimePreflight } from '../src/adapters/zanii-runtime.mjs';
import { createProductExecutor } from '../src/product/executor.mjs';

const action = (id) => ({ taskId: 'runtime-task', action: { id, kind: 'read', documentId: 'guide' } });
async function fixture(t, options = {}) { const f = await createProductFixture({ featureProfile: 'runtime-preflight-local-ledger', ...options }); t.after(() => f.close()); await seedProductFixture(f, { taskId: 'runtime-task' }); return f; }

test('actual Runtime0.4 preflight accepts signed evidence before broker effect and cached reads reauthorize without replay', async (t) => {
  assert.equal(typeof Runtime.prototype.executeWithEvidence, 'function'); const f = await fixture(t);
  assert.equal(f.gateway.runtime.runtimePreflight.status().calls, 0); assert.equal(f.ledgerFixture.status().acceptedReceipts, 0);
  const result = await f.agent.call('/v1/actions', action('runtime-real')); assert.equal(result.status, 200, JSON.stringify(result.body));
  const status = f.gateway.runtime.runtimePreflight.status(); assert.equal(status.calls, 1); assert.equal(status.authorized, 1); assert.equal(status.businessExecution, false); assert.equal(status.liveCompanyValidated, false);
  const records = f.ledgerFixture.records(); assert.equal(records.length, 3); assert.ok(records.every((receipt) => verifyReceipt(receipt).ok));
  assert.deepEqual(records.slice(0, 2).map((receipt) => [receipt.target, receipt.action]), [[RUNTIME_PREFLIGHT_TOOL, 'action_intent'], [RUNTIME_PREFLIGHT_TOOL, 'action_result']]);
  assert.equal(records[2].target, 'broker.resource.post'); assert.equal((await resourceEffects(f.resourceStore)).length, 1);
  const cached = await f.agent.call('/v1/actions', action('runtime-real')); assert.equal(cached.status, 200, JSON.stringify(cached.body));
  assert.equal(f.gateway.runtime.runtimePreflight.status().calls, 2); assert.equal(f.ledgerFixture.status().runtimeIntentReceipts, 2); assert.equal(f.ledgerFixture.status().runtimeResultReceipts, 2);
  assert.equal((await resourceEffects(f.resourceStore)).length, 1);
  const foreign = await f.client('agent', { actorId: 'another-agent' }); assert.equal((await foreign.call('/v1/actions', action('runtime-other-actor'))).status, 403);
  assert.equal(f.gateway.runtime.runtimePreflight.status().calls, 2);
});

test('two concurrent real Runtime actions wait for local accepted evidence without bypassing raw pending health', async (t) => {
  const f = await fixture(t); let release; let started; const ack = new Promise((done) => { release = done; }); const received = new Promise((done) => { started = done; }); let paused = false;
  f.ledgerFixture.afterReceipt(async (receipts) => { if (!paused && receipts.some((receipt) => receipt.target === RUNTIME_PREFLIGHT_TOOL)) { paused = true; started(); await ack; } });
  const first = f.agent.call('/v1/actions', action('runtime-concurrent-1')); await received;
  const monitor = await f.client('operator', { tenantId: 'platform', roles: ['auditor'], scopes: 'runtime:health' });
  try { assert.equal((await monitor.call('/health/ready')).body.ready, false); const second = f.agent.call('/v1/actions', action('runtime-concurrent-2')); await sleep(30); release();
    const results = await Promise.all([first, second]); assert.deepEqual(results.map((result) => result.status), [200, 200], JSON.stringify(results.map((result) => result.body)));
    assert.equal(f.gateway.runtime.runtimePreflight.status().authorized, 2); assert.equal(f.ledgerFixture.status().acceptedReceipts, 6); assert.equal((await resourceEffects(f.resourceStore)).length, 2);
  } finally { release(); }
});

test('an expired authorization waiter does not advance the actual writer tail or overlap a later signed receipt', async (t) => {
  const f = await fixture(t); const ledger = await createConfiguredZaniiLedger({ store: f.gateway.store, config: f.ledgerFixture.config }); t.after(() => ledger.close());
  const identity = { tenantId: 'company', actorId: 'operator', roles: ['operator'], expiresAt: Date.now() + 60000 }; let release; let started; let paused = false;
  const ack = new Promise((done) => { release = done; }); const received = new Promise((done) => { started = done; });
  f.ledgerFixture.afterReceipt(async () => { if (!paused) { paused = true; started(); await ack; } });
  const first = ledger.record(identity, { target: 'broker.resource.post', payload: { sequence: 1 } }); await received;
  try {
    await assert.rejects(ledger.authorizationStatus({ deadlineAt: Date.now() + 30 }), { code: 'ZANII_WRITER_WAIT_DEADLINE' }); let completed = false;
    const second = ledger.record(identity, { target: 'broker.resource.post', payload: { sequence: 2 } }).then((value) => { completed = true; return { value }; }, (error) => { completed = true; return { error }; });
    await sleep(60); assert.equal(completed, false); assert.equal(f.ledgerFixture.status().acceptedReceipts, 1); assert.equal((await ledger.status()).blocked, true);
    release(); const one = await first; const two = await second; assert.equal(two.error, undefined); assert.equal(two.value.accepted, true);
    assert.equal(f.ledgerFixture.records()[1].prev, one.hash); assert.equal((await ledger.authorizationStatus({ deadlineAt: Date.now() + 500 })).blocked, false); assert.equal((await resourceEffects(f.resourceStore)).length, 0);
  } finally { release(); }
});

test('signed Runtime delegation revocation denies cached plaintext release while preserving completed effect journal', async (t) => {
  const f = await fixture(t); assert.equal((await f.agent.call('/v1/actions', action('runtime-cached'))).status, 200);
  await f.ledgerFixture.revokeDelegation(); const response = await f.agent.call('/v1/actions', action('runtime-cached'));
  assert.equal(response.status, 403); assert.equal(response.body.error.code, 'ZANII_RUNTIME_DELEGATION_DENIED');
  assert.equal((await f.gateway.store.getOperation('company', 'runtime-cached')).status, 'succeeded'); assert.equal((await resourceEffects(f.resourceStore)).length, 1);
  assert.equal(JSON.stringify(response.body).includes('Ignore prior instructions'), false);
  const monitor = await f.client('operator', { tenantId: 'platform', roles: ['auditor'], scopes: 'runtime:health' });
  assert.equal((await monitor.call('/health/ready')).body.ready, false);
});

test('an unknown business response never invokes Runtime or resource again until read-only reconciliation establishes the existing result', async (t) => {
  const f = await fixture(t, { uncertainOperation: 'runtime-unknown' });
  const first = await f.agent.call('/v1/actions', action('runtime-unknown')); assert.equal(first.status, 202, JSON.stringify(first.body)); assert.equal(first.body.state, 'unknown');
  const before = f.ledgerFixture.status(); assert.equal((await resourceEffects(f.resourceStore)).length, 1);
  assert.equal((await f.agent.call('/v1/actions', action('runtime-unknown'))).status, 202); assert.equal(f.gateway.runtime.runtimePreflight.status().calls, 1); assert.equal(f.ledgerFixture.status().acceptedReceipts, before.acceptedReceipts);
  const reconciled = await f.agent.call('/v1/operations/runtime-unknown/reconcile', {}); assert.equal(reconciled.status, 200, JSON.stringify(reconciled.body));
  assert.equal(f.gateway.runtime.runtimePreflight.status().calls, 2); assert.equal((await resourceEffects(f.resourceStore)).length, 1);
});

for (const event of ['action_intent', 'action_result']) test(`task revocation during actual accepted Runtime ${event} await stops all business effects`, async (t) => {
  const f = await fixture(t); let revoked = false;
  f.ledgerFixture.afterReceipt(async (receipts) => { if (!revoked && receipts.some((receipt) => receipt.target === RUNTIME_PREFLIGHT_TOOL && receipt.action === event)) { revoked = true; await f.gateway.runtime.policy.revoke({ actorId: 'operator', tenantId: 'company', roles: ['operator'] }, 'runtime-task'); } });
  const response = await f.agent.call('/v1/actions', action(`runtime-revoked-${event}`)); assert.equal(response.status, 403, JSON.stringify(response.body));
  assert.equal(revoked, true); assert.equal((await resourceEffects(f.resourceStore)).length, 0); assert.equal(f.ledgerFixture.status().acceptedReceipts, event === 'action_intent' ? 1 : 2);
});

test('delegation revoked during existing broker evidence await is checked again before resource dispatch', async (t) => {
  const f = await fixture(t); let revoked = false;
  f.ledgerFixture.afterReceipt(async (receipts) => { if (!revoked && receipts.some((receipt) => receipt.target === 'broker.resource.post')) { revoked = true; await f.ledgerFixture.revokeDelegation(); } });
  const response = await f.agent.call('/v1/actions', action('runtime-before-dispatch')); assert.equal(response.status, 403, JSON.stringify(response.body));
  assert.equal(response.body.error.code, 'ZANII_RUNTIME_DELEGATION_DENIED'); assert.equal((await resourceEffects(f.resourceStore)).length, 0); assert.equal((await f.gateway.store.getOperation('company', 'runtime-before-dispatch')).status, 'failed');
});

test('stale and rolled-back signed revocation snapshots cannot authorize another action', async (t) => {
  const f = await fixture(t); const path = f.ledgerFixture.config.runtime.revocationSnapshotFile; const old = await readFile(path);
  await f.ledgerFixture.refreshSnapshot(); assert.equal((await f.agent.call('/v1/actions', action('runtime-new-authority'))).status, 200);
  await writeFile(path, old, { mode: 0o600 }); const replay = await f.agent.call('/v1/actions', action('runtime-old-authority')); assert.equal(replay.status, 503); assert.equal(replay.body.error.code, 'ZANII_RUNTIME_REVOCATION_ROLLBACK');
  await f.ledgerFixture.refreshSnapshot({ issuedAt: Date.now() - 10000, expiresAt: Date.now() - 1 }); const stale = await f.agent.call('/v1/actions', action('runtime-stale'));
  assert.equal(stale.status, 503); assert.equal(stale.body.error.code, 'ZANII_RUNTIME_REVOCATION_STALE'); assert.equal((await resourceEffects(f.resourceStore)).length, 1);
});

test('lost accepted preflight acknowledgement keeps the per-DID durable outbox blocked until explicit duplicate recovery', async (t) => {
  const f = await fixture(t); let lost = false;
  f.ledgerFixture.afterReceipt(async (receipts) => { if (!lost && receipts.some((receipt) => receipt.target === RUNTIME_PREFLIGHT_TOOL && receipt.action === 'action_intent')) { lost = true; throw new AppError(503, 'FIXTURE_ACK_LOST'); } });
  assert.equal((await f.agent.call('/v1/actions', action('runtime-recover'))).status, 503); assert.equal((await resourceEffects(f.resourceStore)).length, 0);
  assert.equal((await f.agent.call('/v1/actions', action('runtime-recover'))).body.error.code, 'ZANII_RECOVERY_REQUIRED');
  const operator = await f.client('operator', { scopes: 'runtime:integrations' }); const recovered = await operator.call('/v1/zanii/recover', {}); assert.equal(recovered.status, 200, JSON.stringify(recovered.body));
  assert.equal(f.ledgerFixture.status().duplicateReceipts, 1); assert.equal((await f.agent.call('/v1/actions', action('runtime-recover'))).status, 200); assert.equal((await resourceEffects(f.resourceStore)).length, 1);
});

test('task expiry across an accepted evidence wait cannot be extended by Runtime or release cached data', async (t) => {
  const f = await fixture(t); const expiresAt = Date.now() + 200;
  const task = { id: 'runtime-short', actorId: 'agent', documentIds: ['guide'], recipients: ['team'], allowedActions: ['read'], expiresAt, maxActions: 5, profile: 'general', purpose: 'support' };
  assert.equal((await f.operator.call('/v1/tasks', task)).status, 201); let waited = false;
  f.ledgerFixture.afterReceipt(async (receipts) => { if (!waited && receipts.some((receipt) => receipt.target === RUNTIME_PREFLIGHT_TOOL)) { waited = true; await sleep(250); } });
  const response = await f.agent.call('/v1/actions', { taskId: task.id, action: { id: 'runtime-expired', kind: 'read', documentId: 'guide' } });
  assert.notEqual(response.status, 200); assert.equal(waited, true); assert.equal((await resourceEffects(f.resourceStore)).length, 0);
});

test('configured Runtime refuses a foreign owner, missing preflight scope and legacy-only configuration before startup', async (t) => {
  await mkdir('.test-data', { recursive: true }); const directory = await mkdtemp(resolve('.test-data/runtime-config-')); const store = openAsyncSqliteStore({ path: join(directory, 'db.sqlite'), encryptionKey: randomBytes(32), auditKey: randomBytes(32) }); let ledger;
  t.after(async () => { await ledger?.close(); await store.close(); await rm(directory, { recursive: true, force: true }); });
  ledger = await startLocalRuntimeLedgerFixture({ directory, scopes: ['broker.resource.post'] });
  await assert.rejects(createConfiguredZaniiLedger({ store, config: ledger.config }), { code: 'ZANII_RUNTIME_DELEGATION_DENIED' });
  await assert.rejects(createConfiguredZaniiLedger({ store, config: { ...ledger.config, runtime: { ...ledger.config.runtime, ownerDid: generateKeypair().did } } }), { code: 'ZANII_RUNTIME_REVOCATION_INVALID' });
  const legacy = { ...ledger.config }; delete legacy.runtime; await assert.rejects(createConfiguredZaniiLedger({ store, config: legacy }), { code: 'ZANII_RUNTIME_CONFIGURATION_REQUIRED' });
});

test('revocation during the final cached metadata await is checked after that await before plaintext release', async (t) => {
  const f = await fixture(t); assert.equal((await f.agent.call('/v1/actions', action('runtime-final-metadata'))).status, 200);
  const base = f.gateway.runtime.runtimePreflight; let prepared = false; let insideGuard = false; let revoked = false;
  const runtimePreflight = { ...base, async authorize(value) { const ticket = await base.authorize(value); prepared = true; return ticket; },
    async assertCurrent(ticket) { insideGuard = true; try { await base.assertCurrent(ticket); } finally { insideGuard = false; } } };
  const adapter = { ...f.gateway.runtime.adapter, async metadata(...args) { const value = await f.gateway.runtime.adapter.metadata(...args); if (prepared && !insideGuard && !revoked) { revoked = true; await f.ledgerFixture.revokeDelegation(); } return value; } };
  const executor = createProductExecutor({ store: f.gateway.store, policy: f.gateway.runtime.policy, adapter, coverage: f.gateway.runtime.coverage,
    zanii: { runtimePreflight }, operationalGate: f.gateway.runtime.operations.gate });
  await assert.rejects(executor.operation({ tenantId: 'company', actorId: 'agent', roles: ['agent'], scopes: ['runtime:invoke'], expiresAt: Date.now() + 60000 }, 'runtime-final-metadata'), { code: 'ZANII_RUNTIME_DELEGATION_DENIED' });
  assert.equal(revoked, true); assert.equal((await resourceEffects(f.resourceStore)).length, 1);
});

test('stalled authority and authorization awaits settle at their budget without invoking a late Runtime tool', async (t) => {
  const f = await fixture(t); const config = { ...f.ledgerFixture.config.runtime, timeoutMs: 100 };
  const loaded = { delegation: JSON.parse(await readFile(f.ledgerFixture.config.delegationFile, 'utf8')), revocations: JSON.parse(await readFile(config.revocationSnapshotFile, 'utf8')) };
  let recorded = 0; const options = { store: f.gateway.store, ledger: { async record() { recorded++; throw new Error('negative contract must never record'); } }, config, tenantId: 'company', agentDid: f.ledgerFixture.config.agentDid, loadAuthoritySync: () => structuredClone(loaded) };
  const stalled = createRuntimePreflight({ ...options, loadAuthority: () => new Promise(() => {}) }); t.after(() => stalled.close());
  let started = Date.now(); const health = await stalled.health(); assert.equal(health.ready, false); assert.equal(health.code, 'ZANII_RUNTIME_DEADLINE'); assert.ok(Date.now() - started < 600);
  started = Date.now(); await assert.rejects(stalled.initialize(), { code: 'ZANII_RUNTIME_DEADLINE' }); assert.ok(Date.now() - started < 600);
  const preflight = createRuntimePreflight({ ...options, loadAuthority: async () => structuredClone(loaded) }); t.after(() => preflight.close()); let release;
  const identity = { tenantId: 'company', actorId: 'agent', roles: ['agent'], scopes: ['runtime:invoke'], expiresAt: Date.now() + 60000 }; const value = action('runtime-stalled');
  const metadata = await f.gateway.runtime.adapter.metadata(identity, value.action); const decision = await f.gateway.runtime.policy.authorize(identity, value.taskId, value.action, metadata); const posture = await f.gateway.runtime.coverage.require();
  started = Date.now(); await assert.rejects(preflight.authorize({ identity, taskId: value.taskId, action: value.action, current: { metadata, decision, posture }, authorize: () => new Promise((done) => { release = done; }) }), { code: 'ZANII_RUNTIME_DEADLINE' });
  assert.ok(Date.now() - started < 600); assert.equal(preflight.status().active, 0); release?.({ metadata, decision, posture }); await sleep(20); assert.equal(recorded, 0); assert.equal((await resourceEffects(f.resourceStore)).length, 0);
});
