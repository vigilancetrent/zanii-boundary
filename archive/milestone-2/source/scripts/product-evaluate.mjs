import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { AppError, exactObject, signEnvelope } from '../src/protocol.mjs';
import { createLearningService, signDetectorUpdate } from '../src/product/learning.mjs';
import { createProductFixture, resourceEffects, seedProductFixture, taskSpec } from './product-fixture.mjs';
import { implementationDigest } from './benchmark.mjs';

/** Author-authored synthetic cases on the actual TLS service; no model or live company provider. */
export async function runProductEvaluation(options = {}) {
  exactObject(options, []); const sourceDigest = await implementationDigest(); const startedAt = Date.now();
  const f = await createProductFixture({ uncertainOperation: 'unknown-read' }); const cases = [];
  const attempt = async (name, client, path, body, expectedStatus, expectedEffectDelta) => {
    const before = resourceEffects(f.resourceStore).length; const begin = performance.now(); const response = await client.call(path, body);
    const delta = resourceEffects(f.resourceStore).length - before;
    assert.equal(response.status, expectedStatus, `${name}: ${JSON.stringify(response.body)}`); assert.equal(delta, expectedEffectDelta, name);
    cases.push({ name, status: response.status, code: response.body?.error?.code ?? null, state: response.body?.state ?? null,
      effectDelta: delta, durationMs: performance.now() - begin }); return response;
  };
  try {
    await seedProductFixture(f); const taskId = 'evaluation-task';
    const read = { taskId, action: { id: 'allowed-read', kind: 'read', documentId: 'guide' } };
    const allowed = await attempt('authorized-read', f.agent, '/v1/actions', read, 200, 1);
    assert.equal(allowed.body.warning.suspicious, true); assert.equal(allowed.body.warning.grantsAuthority, false);
    await attempt('idempotent-replay', f.agent, '/v1/actions', read, 200, 0);
    await attempt('out-of-task-document', f.agent, '/v1/actions', { taskId, action: { id: 'forbidden-document', kind: 'read', documentId: 'payroll' } }, 403, 0);
    await attempt('forbidden-recipient', f.agent, '/v1/actions', { taskId, action: { id: 'forbidden-share', kind: 'share', documentId: 'guide', recipient: 'outside' } }, 403, 0);
    await attempt('missing-exact-approval', f.agent, '/v1/actions', { taskId, action: { id: 'no-approval', kind: 'share', documentId: 'guide', recipient: 'team' } }, 403, 0);
    const share = { id: 'approved-share', kind: 'share', documentId: 'guide', recipient: 'team' };
    const approval = await f.operator.call('/v1/approvals', { taskId, action: share, expiresAt: Date.now() + 60000 }); assert.equal(approval.status, 201);
    await attempt('approved-internal-mailbox', f.agent, '/v1/actions', { taskId, action: { ...share, approvalId: approval.body.id } }, 200, 1);
    const delivery = await f.resourceOwner.call('/v1/resource/deliveries', { deliveryId: share.id });
    assert.equal(delivery.body.content, allowed.body.result.content);
    const foreign = await f.client('agent', { tenantId: 'foreign' });
    await attempt('cross-tenant-task', foreign, '/v1/actions', read, 403, 0);
    const restricted = await f.client('agent', { scopes: 'runtime:read' });
    await attempt('missing-invoke-scope', restricted, '/v1/actions', read, 403, 0);
    const direct = await f.client('agent', { target: 'resource' });
    await attempt('direct-resource-agent-identity', direct, '/v1/resource/execute', { action: read.action, operationId: read.action.id, expectedVersion: 3, deadlineAt: Date.now() + 1000 }, 401, 0);
    const unknown = { taskId, action: { id: 'unknown-read', kind: 'read', documentId: 'guide' } };
    await attempt('effect-then-response-loss', f.agent, '/v1/actions', unknown, 202, 1);
    await attempt('unknown-is-not-redispatched', f.agent, '/v1/actions', unknown, 202, 0);
    await f.restartGateway();
    await attempt('restart-retains-idempotency', f.agent, '/v1/actions', read, 200, 0);
    await attempt('unknown-reconciles-after-restart', f.agent, '/v1/operations/unknown-read/reconcile', {}, 200, 0);
    assert.equal((await f.operator.call('/v1/tasks/evaluation-task/revoke', {})).status, 200);
    await attempt('revoked-cached-read', f.agent, '/v1/actions', read, 403, 0);
    const short = { ...taskSpec('expired-task'), expiresAt: Date.now() + 75 };
    assert.equal((await f.operator.call('/v1/tasks', short)).status, 201); await new Promise((done) => setTimeout(done, 100));
    await attempt('expired-task', f.agent, '/v1/actions', { taskId: short.id, action: { id: 'expired-read', kind: 'read', documentId: 'guide' } }, 403, 0);
    const keys = generateKeyPairSync('ed25519');
    const learning = createLearningService({ store: f.gateway.store, trustKey: keys.publicKey, policyDigest: f.gateway.runtime.policy.authorityDigest });
    const agentIdentity = { actorId: 'agent', tenantId: 'company', roles: ['agent'] };
    const reviewer = { actorId: 'reviewer', tenantId: 'company', roles: ['operator', 'approver'] };
    const learner = { actorId: 'learner', tenantId: 'company', roles: ['learner'] };
    const corpus = [];
    for (const [file, label] of [['product-attacks.json', 'attack'], ['product-benign.json', 'benign']]) {
      corpus.push(...JSON.parse(await readFile(new URL(`../fixtures/${file}`, import.meta.url), 'utf8')).map((item) => ({ ...item, label })));
    }
    const beforePolicy = f.gateway.runtime.policy.authorityDigest();
    for (const item of corpus) { const saved = learning.quarantine(agentIdentity, { id: item.id, text: item.text, sourceId: item.id, sourceKind: 'document' });
      learning.review(reviewer, { id: saved.id, label: item.label, split: item.split }); }
    const candidate = learning.train(learner); learning.stage(learner, candidate.id);
    await learning.applyUpdate(reviewer, await signDetectorUpdate(learning.prepareUpdate(reviewer, candidate.id), keys.privateKey));
    assert.equal(f.gateway.runtime.policy.authorityDigest(), beforePolicy);
    const effects = resourceEffects(f.resourceStore); assert.equal(effects.length, 3); assert.equal(resourceEffects(f.resourceStore, 'foreign').length, 0);
    assert.equal(new Set(effects.map((effect) => effect.id)).size, effects.length);
    const payload = { version: 1, kind: 'product-evaluation', runId: randomUUID(), startedAt, finishedAt: Date.now(),
      environment: { node: process.version, platform: process.platform, arch: process.arch, transport: 'in-process-real-mtls', model: 'none', sourceDigest },
      cases, summary: { cases: cases.length, assertionsPassed: cases.length, authorizedPrimaryTasks: 2, completedAuthorizedPrimaryTasks: 2,
        observedEffects: effects.length, expectedNegativeEffects: 0, observedNegativeEffects: cases.filter((item) => item.status >= 400).reduce((sum, item) => sum + item.effectDelta, 0),
        duplicateEffects: effects.length - new Set(effects.map((effect) => effect.id)).size },
      learning: { corpusSize: corpus.length, trainingExamples: corpus.filter((item) => item.split === 'train').length,
        holdout: candidate.evaluation, signedPromotion: true, authorityPolicyUnchanged: true,
        scope: 'Author-authored synthetic corpus and preselected split; not production accuracy or adaptive adversary evaluation.' },
      resourceObservations: effects, limitations: ['One process with real TLS and encrypted SQLite; no process/kernel/network isolation demonstrated.',
        'The evaluator controls test identities and resource fixtures; signatures do not establish evaluator honesty.',
        'No paid model, live customer endpoint, live companion deployment, or external ledger was used.'] };
    if (await implementationDigest() !== sourceDigest) throw new AppError(409, 'IMPLEMENTATION_CHANGED');
    return payload;
  } finally { await f.close(); }
}

export async function writeProductEvaluation(payload) {
  const keys = generateKeyPairSync('ed25519'); const root = new URL('../artifacts/', import.meta.url); await mkdir(root, { recursive: true });
  await writeFile(new URL('product-evaluation.json', root), `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
  await writeFile(new URL('product-evaluation.signed.json', root), `${JSON.stringify(signEnvelope(payload, keys.privateKey, 'product-experiment'), null, 2)}\n`, { mode: 0o600 });
  await writeFile(new URL('product-evaluator-public.pem', root), keys.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  (async () => { if (process.argv.length !== 2) throw new AppError(400, 'INVALID_ARGUMENTS');
    const payload = await runProductEvaluation(); await writeProductEvaluation(payload);
    process.stdout.write(`${JSON.stringify({ runId: payload.runId, sourceDigest: payload.environment.sourceDigest, summary: payload.summary, learning: payload.learning.holdout })}\n`);
  })().catch((error) => { process.stderr.write(`${JSON.stringify({ code: error instanceof AppError ? error.code : 'PRODUCT_EVALUATION_FAILED' })}\n`); process.exitCode = 1; });
}
