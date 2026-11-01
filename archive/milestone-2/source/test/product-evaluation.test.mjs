import test from 'node:test';
import assert from 'node:assert/strict';
import { runProductEvaluation } from '../scripts/product-evaluate.mjs';
import { runProductLoad } from '../scripts/product-load.mjs';
import { implementationDigest, implementationManifest } from '../scripts/benchmark.mjs';
import { sha256 } from '../src/protocol.mjs';
import { signEnvelope } from '../src/protocol.mjs';
import { generateKeyPairSync } from 'node:crypto';
import { verifyProductEvaluation } from '../scripts/product-verify.mjs';
import { createProductFixture, taskSpec } from '../scripts/product-fixture.mjs';

test('operator task collection pages beyond 100 records with bounded tenant-scoped cursors', async () => {
  const fixture = await createProductFixture();
  try {
    for (let index = 0; index < 103; index++) {
      const result = await fixture.operator.call('/v1/tasks', taskSpec(`task-${String(index).padStart(3, '0')}`)); assert.equal(result.status, 201);
    }
    const first = await fixture.operator.call('/v1/tasks/list', { limit: 100 }); assert.equal(first.status, 200); assert.equal(first.body.items.length, 100); assert.ok(first.body.next);
    const second = await fixture.operator.call('/v1/tasks/list', { limit: 100, after: first.body.next }); assert.equal(second.status, 200); assert.equal(second.body.items.length, 3); assert.equal(second.body.next, null);
    assert.equal(new Set([...first.body.items, ...second.body.items].map((row) => row.id)).size, 103);
    assert.equal((await fixture.agent.call('/v1/tasks/list', {})).status, 403);
    assert.equal((await fixture.operator.call('/v1/tasks/list', { limit: 100000 })).status, 400);
    assert.equal((await fixture.operator.call('/v1/tasks/list', { unrecognized: true })).status, 400);
    const foreign = await fixture.client('operator', { tenantId: 'foreign' }); assert.equal((await foreign.call('/v1/tasks/list', {})).body.items.length, 0);
  } finally { await fixture.close(); }
});

test('actual product evaluation observes useful tasks, denied effects, durable restart and bounded learning claims', async () => {
  const report = await runProductEvaluation();
  assert.equal(report.summary.cases, 15); assert.equal(report.summary.observedNegativeEffects, 0);
  assert.equal(report.summary.duplicateEffects, 0); assert.equal(report.summary.observedEffects, 3);
  assert.equal(report.summary.completedAuthorizedPrimaryTasks, report.summary.authorizedPrimaryTasks);
  assert.equal(report.cases.find((item) => item.name === 'effect-then-response-loss').state, 'unknown');
  assert.equal(report.cases.find((item) => item.name === 'unknown-reconciles-after-restart').state, 'succeeded');
  assert.equal(report.learning.holdout.examples, 8); assert.equal(report.learning.authorityPolicyUnchanged, true);
  assert.equal(report.environment.transport, 'in-process-real-mtls');
  const keys = generateKeyPairSync('ed25519'); const envelope = signEnvelope(report, keys.privateKey, 'product-experiment');
  assert.equal(verifyProductEvaluation(envelope, keys.publicKey).negativeEffects, 0);
  assert.throws(() => verifyProductEvaluation(envelope, generateKeyPairSync('ed25519').publicKey));
  const altered = structuredClone(report); altered.summary.observedEffects++;
  assert.throws(() => verifyProductEvaluation(signEnvelope(altered, keys.privateKey, 'product-experiment'), keys.publicKey));
  const truncated = structuredClone(report); truncated.cases.pop();
  assert.throws(() => verifyProductEvaluation(signEnvelope(truncated, keys.privateKey, 'product-experiment'), keys.publicKey));
  for (const change of [(value) => { value.resourceObservations.pop(); }, (value) => { value.resourceObservations[0].actorId = 'foreign'; },
    (value) => { value.resourceObservations.find((row) => row.kind === 'share').recipient = 'outside'; },
    (value) => { value.resourceObservations.push(value.resourceObservations[0]); }, (value) => { value.summary.completedAuthorizedPrimaryTasks = 0; },
    (value) => { value.startedAt = 'not-a-time'; }, (value) => { value.finishedAt = -1; },
    (value) => { Object.assign(value.learning.holdout, { truePositive: -1, trueNegative: 9, falsePositive: 0, falseNegative: 0, attackCount: -1, benignCount: 9, precision: 1, recall: 1, falsePositiveRate: 0 }); },
    (value) => { value.learning.trainingExamples = -1; }, (value) => { value.learning.holdout.precision = 1.5; }]) {
    const invalid = structuredClone(report); change(invalid);
    assert.throws(() => verifyProductEvaluation(signEnvelope(invalid, keys.privateKey, 'product-experiment'), keys.publicKey));
  }
  assert.throws(() => verifyProductEvaluation(envelope, keys.publicKey, { expectedSourceDigest: '0'.repeat(64) }));
});

test('product load separately counts success, throttling, pending, denials and independently stored effects', async () => {
  const report = await runProductLoad({ requests: 8, concurrency: [1, 4] });
  for (const level of report.levels) {
    assert.equal(level.requested, level.successful + level.throttled + level.pending + level.denied + level.errors);
    assert.equal(level.observedEffects, level.successful); assert.equal(level.effectsWithoutSuccessfulResponse, 0);
    assert.equal(level.successful, 8); assert.ok(level.cpuMilliseconds.user >= 0);
  }
  assert.equal(report.hardwareBreakingPoint, null);
  for (const options of [{ requests: 0 }, { concurrency: [] }, { concurrency: [1, 1] }, { concurrency: [129] }, { silentFallback: true }]) {
    await assert.rejects(runProductLoad(options));
  }
});

test('implementation manifest covers nested runtime, SDK, fixtures and deployment files without generated secrets', async () => {
  const manifest = await implementationManifest(); const paths = manifest.map(([path]) => path);
  for (const path of ['src/product/server.mjs', 'src/adapters/zanii.mjs', 'scripts/product-evaluate.mjs', 'fixtures/product-attacks.json', 'deploy/compose.yaml']) assert.ok(paths.includes(path), path);
  assert.equal(paths.some((path) => /artifacts|node_modules|__pycache__|archive/.test(path)), false);
  assert.equal(await implementationDigest(), sha256(JSON.stringify(manifest)));
});
