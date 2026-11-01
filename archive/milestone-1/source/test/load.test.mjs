import test from 'node:test';
import assert from 'node:assert/strict';
import { parseLoadArgs, runLoad } from '../scripts/load.mjs';

test('small real HTTP load pairs successful responses with independent resource effects', async () => {
  const report = await runLoad({ transport: 'in-process', concurrency: [1, 2], requests: 4 });
  assert.equal(report.environment.transport, 'in-process');
  for (const level of report.levels) {
    assert.equal(level.requested, 4);
    assert.equal(level.successful, 4);
    assert.equal(level.observedEffects, 4);
    assert.equal(level.effectsWithoutSuccessfulResponse, 0);
    assert.equal(level.denied, 0);
    assert.equal(level.errors, 0);
    assert.equal(level.statuses['200'], 4);
    assert.ok(level.successfulRequestsPerSecond > 0);
    assert.ok(level.latencyMs.p50 <= level.latencyMs.p95);
    assert.ok(level.latencyMs.p95 <= level.latencyMs.p99);
  }
  assert.equal(report.breakingPoint, null);
  assert.equal(report.firstBottleneck, 'not established');
});

test('load bounds reject invalid, duplicate and unknown settings before starting services', async () => {
  const sparse = Array(1); sparse.extra = 1;
  for (const options of [
    { requests: 0 }, { requests: 1_001 }, { concurrency: [0] }, { concurrency: [33] },
    { concurrency: [1, 1] }, { concurrency: [] }, { concurrency: sparse }, { transport: 'automatic' }, { other: true },
  ]) await assert.rejects(runLoad(options));
  assert.deepEqual(parseLoadArgs(['--transport=in-process', '--requests=4', '--concurrency=1,2']),
    { transport: 'in-process', requests: 4, concurrency: [1, 2] });
  for (const args of [['--requests=0'], ['--transport=automatic'], ['--requests=1', '--requests=2'],
    ['--unknown=1'], ['--requests=2,3'], ['--concurrency=0']]) assert.throws(() => parseLoadArgs(args));
});
