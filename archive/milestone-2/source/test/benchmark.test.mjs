import test from 'node:test';
import assert from 'node:assert/strict';
import { runBenchmark } from '../scripts/benchmark.mjs';

test('fixed real-HTTP benchmark records useful work, stale dispatch and the known direct-access failure honestly', async () => {
  const payload = await runBenchmark({ transport: 'in-process' });
  assert.equal(payload.cases.length, 24);
  assert.equal(payload.environment.transport, 'in-process');
  assert.equal(payload.environment.model, 'none');
  for (const mode of ['broker-static', 'lease-only', 'coverage-bound']) {
    assert.equal(payload.summary[mode].healthyCompleted, 2);
    assert.equal(payload.summary[mode].forbiddenEffects, 1);
    assert.equal(payload.summary[mode].revokedEffects, 0);
    assert.equal(payload.summary[mode].uncertainResponses, 1);
    assert.equal(payload.summary[mode].effectsWithoutSuccessResponse, 1);
    const failedBoundary = payload.cases.find((item) => item.mode === mode && item.scenario === 'broken-resource');
    assert.ok(failedBoundary.events.some((event) => event.via === 'legacy' && event.documentId === 'tenant-a-secret'));
    const drift = payload.cases.find((item) => item.mode === mode && item.scenario === 'tool-drift');
    assert.equal(drift.attempts[0].status, mode === 'coverage-bound' ? 409 : 200);
    // Metadata drift remains a stale operational assumption, not a forbidden business read.
    assert.ok(drift.events.every((event) => event.documentId === 'tenant-a-guide'));
  }
  assert.equal(payload.summary['coverage-bound'].staleBrokerDispatches, 0);
  assert.ok(payload.summary['broker-static'].staleBrokerDispatches > 0);
  assert.ok(payload.summary['lease-only'].staleBrokerDispatches > 0);
  assert.equal(payload.summary['broker-static'].expiredCoverageDispatches, 1);
  assert.equal(payload.summary['lease-only'].expiredCoverageDispatches, 0);
  assert.equal(payload.summary['coverage-bound'].expiredCoverageDispatches, 0);
});

test('benchmark rejects unknown transport or options without silently changing execution mode', async () => {
  await assert.rejects(runBenchmark({ transport: 'automatic' }), { code: 'INVALID_CONFIGURATION' });
  await assert.rejects(runBenchmark({ transport: 'in-process', unapproved: true }), { code: 'INVALID_INPUT' });
});
