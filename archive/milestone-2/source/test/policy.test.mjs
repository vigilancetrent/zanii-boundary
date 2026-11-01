import test from 'node:test';
import assert from 'node:assert/strict';
import { authorizeAction, authorizeCoverage, createAdmission } from '../src/policy.mjs';

const now = 1_000_000;
const task = () => ({ id: 'task-1', actorId: 'agent-1', tenantId: 'tenant-a', documentIds: ['guide'], recipients: ['ops'], expiresAt: now + 10_000, maxActions: 2 });
const identity = { actorId: 'agent-1', tenantId: 'tenant-a' };
const action = (id = 'read-1') => ({ id, kind: 'read', documentId: 'guide' });
const code = (value) => (error) => error.code === value;

test('authorized reads and approved sharing succeed; actor and tenant cannot be changed', () => {
  assert.equal(authorizeAction(task(), action(), { ...identity, now }).kind, 'read');
  assert.equal(authorizeAction(task(), { ...action(), kind: 'share', recipient: 'ops' }, { ...identity, now }).kind, 'share');
  assert.throws(() => authorizeAction(task(), action(), { ...identity, actorId: 'attacker', now }), code('IDENTITY_DENIED'));
  assert.throws(() => authorizeAction(task(), action(), { ...identity, tenantId: 'tenant-b', now }), code('IDENTITY_DENIED'));
  assert.throws(() => authorizeAction(task(), { ...action(), tenantId: 'tenant-a' }, { ...identity, now }), code('INVALID_INPUT'));
});

test('foreign or out-of-mission documents and external recipients are denied', () => {
  assert.throws(() => authorizeAction(task(), { ...action(), documentId: 'tenant-b-secret' }, { ...identity, now }), code('DOCUMENT_DENIED'));
  assert.throws(() => authorizeAction(task(), { ...action(), documentId: 'tenant-a-secret' }, { ...identity, now }), code('DOCUMENT_DENIED'));
  assert.throws(() => authorizeAction(task(), { ...action(), kind: 'share', recipient: 'external' }, { ...identity, now }), code('RECIPIENT_DENIED'));
});

test('expiry and revocation apply at execution time', () => {
  assert.throws(() => authorizeAction({ ...task(), expiresAt: now }, action(), { ...identity, now }), code('TASK_EXPIRED'));
  assert.throws(() => authorizeAction({ ...task(), revoked: true }, action(), { ...identity, now }), code('TASK_REVOKED'));
  let clock = now;
  const admission = createAdmission(task(), identity, { now: () => clock });
  clock += 10_000;
  assert.throws(() => admission.reserve(action()), code('TASK_EXPIRED'));
});

test('synchronous admission consumes replay ID and quota before any provider await', async () => {
  const admission = createAdmission(task(), identity, { now: () => now });
  admission.reserve(action());
  assert.throws(() => admission.reserve(action()), code('REPLAY'));
  const outcomes = await Promise.allSettled(Array.from({ length: 10 }, (_, i) => Promise.resolve().then(() => admission.reserve(action(`parallel-${i}`)))));
  assert.equal(outcomes.filter((outcome) => outcome.status === 'fulfilled').length, 1);
  assert.equal(admission.snapshot().admitted, 2);
  assert.throws(() => admission.reserve(action('third')), code('TASK_QUOTA'));
});

test('caller mutation cannot widen admission authority; revoke blocks queued action', () => {
  const source = task();
  const who = { ...identity };
  const admission = createAdmission(source, who, { now: () => now });
  source.documentIds.push('secret'); source.maxActions = 1_000; who.actorId = 'attacker';
  assert.throws(() => admission.reserve({ ...action(), documentId: 'secret' }), code('DOCUMENT_DENIED'));
  admission.reserve(action()); admission.revoke();
  assert.throws(() => admission.reserve(action('queued')), code('TASK_REVOKED'));
});

test('coverage is fresh, correctly scoped and bound to current resource configuration', () => {
  const coverage = { version: 1, resourceId: 'resource-1', configurationVersion: 2, taskId: 'task-1', issuedAt: now, expiresAt: now + 1_000, checks: { authorizedRead: true, directDenied: true, wrongIdentityDenied: true } };
  const current = { taskId: 'task-1', resourceId: 'resource-1', configurationVersion: 2, now };
  assert.equal(authorizeCoverage(coverage, current).configurationVersion, 2);
  assert.throws(() => authorizeCoverage(coverage, { ...current, configurationVersion: 3 }), code('COVERAGE_STALE'));
  assert.throws(() => authorizeCoverage(coverage, { ...current, resourceId: 'new-process' }), code('COVERAGE_SCOPE'));
  assert.throws(() => authorizeCoverage(coverage, { ...current, taskId: 'other-task' }), code('COVERAGE_SCOPE'));
  assert.throws(() => authorizeCoverage(coverage, { ...current, now: now - 1 }), code('COVERAGE_EXPIRED'));
  assert.throws(() => authorizeCoverage(coverage, { ...current, now: now + 1_000 }), code('COVERAGE_EXPIRED'));
});
