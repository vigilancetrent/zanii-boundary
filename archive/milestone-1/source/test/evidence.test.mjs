import test, { before } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { mkdtemp, writeFile, unlink, rmdir } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runBenchmark } from '../scripts/benchmark.mjs';
import { verifyFiles } from '../scripts/verify.mjs';
import { signEnvelope } from '../src/protocol.mjs';
import { summarizeExperiment, verifyEvidence } from '../src/evidence.mjs';

const keys = generateKeyPairSync('ed25519');
let payload;
before(async () => { payload = await runBenchmark({ transport: 'in-process' }); });
const signed = (value = payload) => signEnvelope(value, keys.privateKey, 'experiment');
const rejected = (value) => assert.throws(() => verifyEvidence(signed(value), keys.publicKey), { code: 'INVALID_EXPERIMENT_EVIDENCE' });

test('offline evidence uses an independently pinned evaluator key and never calls a network service', () => {
  const original = globalThis.fetch;
  globalThis.fetch = () => { throw new Error('Network not allowed'); };
  try {
    const result = verifyEvidence(signed(), keys.publicKey);
    assert.equal(result.ok, true);
    assert.deepEqual(result.summary, payload.summary);
    const wrong = generateKeyPairSync('ed25519').publicKey;
    assert.throws(() => verifyEvidence(signed(), wrong), { code: 'INVALID_EXPERIMENT_EVIDENCE' });
    assert.throws(() => verifyEvidence(signed(), undefined), { code: 'INVALID_EXPERIMENT_EVIDENCE' });
    assert.equal(JSON.stringify(signed()).includes('PRIVATE KEY'), false);
  } finally { globalThis.fetch = original; }
});

test('tampered bytes, substituted trust material and wrong signature purpose fail verification', () => {
  const envelope = signed();
  assert.throws(() => verifyEvidence({ ...envelope, payload: `${envelope.payload.slice(0, -1)}A` }, keys.publicKey), { code: 'INVALID_EXPERIMENT_EVIDENCE' });
  assert.throws(() => verifyEvidence({ ...envelope, publicKey: keys.publicKey.export({ type: 'spki', format: 'pem' }) }, keys.publicKey), { code: 'INVALID_EXPERIMENT_EVIDENCE' });
  assert.throws(() => verifyEvidence(signEnvelope(payload, keys.privateKey, 'coverage'), keys.publicKey), { code: 'INVALID_EXPERIMENT_EVIDENCE' });
});

test('even a trusted signature cannot make fabricated summary totals internally consistent', () => {
  const changed = structuredClone(payload);
  changed.summary['coverage-bound'].forbiddenEffects = 0;
  rejected(changed);
});

test('unsupported statuses cannot disappear from response totals, and wrong-actor effects are not legitimate completion', () => {
  const changedStatus = structuredClone(payload);
  changedStatus.cases[0].attempts[0].status = 201;
  changedStatus.cases[0].attempts[0].code = 'UNEXPECTED_STATUS';
  changedStatus.summary = summarizeExperiment(changedStatus);
  rejected(changedStatus);
  const wrongActor = structuredClone(payload);
  const healthy = wrongActor.cases.find((item) => item.mode === 'coverage-bound' && item.scenario === 'healthy');
  healthy.events.find((event) => !event.actionId.startsWith('admission-')).actorId = 'wrong-actor';
  wrongActor.summary = summarizeExperiment(wrongActor);
  const result = verifyEvidence(signed(wrongActor), keys.publicKey);
  assert.equal(result.summary['coverage-bound'].healthyCompleted, 1);
  assert.equal(result.summary['coverage-bound'].healthyNotCompleted, 1);
  assert.equal(result.summary['coverage-bound'].forbiddenEffects, 2);
});

test('missing effects, duplicated events and altered operations fail association checks', () => {
  const missing = structuredClone(payload);
  const healthy = missing.cases.find((item) => item.scenario === 'healthy');
  healthy.events.splice(healthy.events.findIndex((event) => !event.actionId.startsWith('admission-')), 1);
  healthy.observedTotal = healthy.events.length; missing.summary = summarizeExperiment(missing);
  rejected(missing);
  const duplicate = structuredClone(payload);
  duplicate.cases[0].events.push(structuredClone(duplicate.cases[0].events[0]));
  duplicate.cases[0].observedTotal += 1; duplicate.summary = summarizeExperiment(duplicate);
  rejected(duplicate);
  const changed = structuredClone(payload);
  changed.cases[0].attempts[0].action.documentId = 'tenant-a-secret';
  changed.summary = summarizeExperiment(changed); rejected(changed);
});

test('missing matrix cases, unapproved fields and implausible event epochs are rejected', () => {
  const missing = structuredClone(payload); missing.cases.pop(); missing.summary = summarizeExperiment(missing); rejected(missing);
  const unknown = structuredClone(payload); unknown.cases[0].clientToken = 'unapproved-field'; rejected(unknown);
  const epoch = structuredClone(payload); epoch.cases[0].events[0].configurationVersion = epoch.cases[0].configurationVersion + 1;
  rejected(epoch);
});

test('a historical run remains verifiable after task and coverage lifetimes have ended', () => {
  const old = structuredClone(payload); const shift = 7 * 24 * 60 * 60 * 1_000;
  old.startedAt -= shift; old.finishedAt -= shift;
  for (const item of old.cases) {
    item.task.expiresAt -= shift; item.coverage.issuedAt -= shift; item.coverage.expiresAt -= shift;
    for (const attempt of item.attempts) attempt.at -= shift;
    for (const event of item.events) event.at -= shift;
  }
  old.summary = summarizeExperiment(old);
  assert.ok(old.cases.every((item) => item.coverage.expiresAt < Date.now()));
  assert.equal(verifyEvidence(signed(old), keys.publicKey).ok, true);
});

test('file verification requires explicit trust and rejects oversized or malformed public artifacts', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'agent-runtime-evidence-'));
  const bundle = join(directory, 'evidence.json'); const key = join(directory, 'public.pem');
  const oversized = join(directory, 'oversized.json'); const malformed = join(directory, 'malformed.json');
  try {
    await writeFile(bundle, JSON.stringify(signed()));
    await writeFile(key, keys.publicKey.export({ type: 'spki', format: 'pem' }));
    await writeFile(oversized, 'x'.repeat(131_073)); await writeFile(malformed, '{broken');
    assert.equal((await verifyFiles(bundle, key)).ok, true);
    await assert.rejects(verifyFiles(bundle, ''), { code: 'TRUST_KEY_REQUIRED' });
    await assert.rejects(verifyFiles(oversized, key), { code: 'INVALID_FILE' });
    await assert.rejects(verifyFiles(malformed, key), { code: 'INVALID_EXPERIMENT_EVIDENCE' });
  } finally {
    for (const file of [bundle, key, oversized, malformed]) await unlink(file).catch((error) => { if (error.code !== 'ENOENT') throw error; });
    await rmdir(directory);
  }
});
