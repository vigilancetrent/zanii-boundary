import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { startHarness } from '../src/harness.mjs';
import { listenLoopback, requestJson, requireBearer, sendJson } from '../src/http.mjs';
import { startBroker } from '../src/broker.mjs';
import { randomToken, signEnvelope } from '../src/protocol.mjs';

const action = (patch = {}) => ({ id: randomUUID(), kind: 'read', documentId: 'tenant-a-guide', ...patch });
async function fixture(t, options = {}) {
  const h = await startHarness({ transport: 'in-process', ...options });
  t.after(() => h.close()); return h;
}
const workload = (observation) => observation.events.filter((event) => !event.actionId.startsWith('admission-'));

test('real HTTP authorized read and internal sharing produce independently observed effects', async (t) => {
  const h = await fixture(t);
  const read = action(); const share = action({ kind: 'share', recipient: 'internal-team' });
  assert.equal((await h.client(read)).status, 200);
  assert.equal((await h.client(share)).status, 200);
  const events = workload(await h.observe());
  assert.deepEqual(events.map((event) => [event.actionId, event.result, event.via]), [[read.id, 'read', 'broker'], [share.id, 'shared', 'broker']]);
  assert.equal(h.transport, 'in-process');
});

test('cross-tenant, same-tenant out-of-task and forbidden recipient requests have no effect', async (t) => {
  const h = await fixture(t);
  for (const attempt of [action({ documentId: 'tenant-b-secret' }), action({ documentId: 'tenant-a-secret' }), action({ kind: 'share', recipient: 'external-recipient' })]) {
    assert.equal((await h.client(attempt)).status, 403);
  }
  assert.deepEqual(workload(await h.observe()), []);
});

test('raw clients cannot use observer/control endpoints or impersonate the resource broker', async (t) => {
  const h = await fixture(t);
  assert.equal((await h.direct(action())).status, 403);
  for (const [origin, path, method, body] of [
    [h.resourceOrigin, '/v1/observations', 'GET', undefined],
    [h.resourceOrigin, '/v1/status', 'GET', undefined],
    [h.resourceOrigin, '/v1/control', 'POST', { brokerOnly: false }],
    [h.brokerOrigin, '/v1/control/revoke', 'POST', {}],
  ]) assert.equal((await requestJson(origin, path, { method, body, token: h.clientToken })).status, 401);
  const forged = await requestJson(h.resourceOrigin, '/v1/actions', { method: 'POST', token: h.clientToken,
    body: { actorId: 'agent-a', tenantId: 'tenant-a', action: action() } });
  assert.equal(forged.status, 401);
  const unknown = await requestJson(h.brokerOrigin, '/v1/actions', { method: 'POST', token: h.clientToken,
    body: { ...action(), tenantId: 'tenant-b' } });
  assert.equal(unknown.status, 400);
  assert.deepEqual(workload(await h.observe()), []);
});

test('only coverage-bound mode stops admission after a changed tool/configuration epoch', async (t) => {
  for (const mode of ['broker-static', 'lease-only', 'coverage-bound']) {
    const h = await fixture(t, { mode });
    const before = await h.state(); const after = await h.mutate({ toolVersion: 2 });
    assert.equal(after.configurationVersion, before.configurationVersion + 1);
    const result = await h.client(action());
    assert.equal(result.status, mode === 'coverage-bound' ? 409 : 200);
    assert.equal(workload(await h.observe()).length, mode === 'coverage-bound' ? 0 : 1);
    assert.equal((await h.direct(action())).status, 403);
  }
});

test('expired coverage fails closed and fresh measured coverage restores action admission', async (t) => {
  const h = await fixture(t);
  await h.refreshCoverage({ issuedAt: Date.now() - 2_000, expiresAt: Date.now() - 1_000 });
  assert.equal((await h.client(action())).status, 403);
  await h.refreshCoverage();
  assert.equal((await h.client(action())).status, 200);
  assert.equal(workload(await h.observe()).length, 1);
});

test('revocation is rechecked for a queued client operation at actual dispatch', async (t) => {
  const h = await fixture(t);
  const queued = action(); const executeLater = () => h.client(queued);
  assert.equal((await h.revoke()).status, 200);
  assert.equal((await executeLater()).status, 403);
  assert.deepEqual(workload(await h.observe()), []);
});

test('parallel requests cannot exceed quota or repeat a successful action identifier', async (t) => {
  const h = await fixture(t, { maxActions: 2 });
  const attempts = Array.from({ length: 8 }, () => action());
  const results = await Promise.all(attempts.map((value) => h.client(value)));
  assert.equal(results.filter((result) => result.status === 200).length, 2);
  assert.equal(results.filter((result) => result.status === 429).length, 6);
  const events = workload(await h.observe());
  assert.equal(events.length, 2);
  const completed = attempts.find((value) => value.id === events[0].actionId);
  assert.equal((await h.client(completed)).status, 409);
  assert.equal(workload(await h.observe()).length, 2);
});

test('tampered coverage cannot replace the pinned trusted record', async (t) => {
  const h = await fixture(t);
  const envelope = h.coverage();
  assert.equal((await h.setCoverage({ ...envelope, signature: 'A'.repeat(86) })).status, 403);
  assert.equal((await h.client(action())).status, 200);
});

test('resource rechecks epoch after a delayed dispatch before creating any effect', async (t) => {
  const h = await fixture(t, { providerTimeoutMs: 500 });
  await h.mutate({ delayMs: 100 }); await h.refreshCoverage();
  const pending = h.client(action());
  await sleep(20); await h.mutate({ toolVersion: 2 });
  assert.equal((await pending).status, 409);
  assert.deepEqual(workload(await h.observe()), []);
});

test('post-effect response timeout remains uncertain and is never replayed automatically', async (t) => {
  const h = await fixture(t, { providerTimeoutMs: 40 });
  await h.mutate({ responseDelayMs: 120 }); await h.refreshCoverage();
  const operation = action({ kind: 'share', recipient: 'internal-team' });
  const result = await h.client(operation);
  assert.equal(result.status, 504); assert.equal(result.body.error.code, 'OUTCOME_UNCERTAIN');
  assert.equal(workload(await h.observe()).filter((event) => event.actionId === operation.id).length, 1);
  assert.equal((await h.client(operation)).status, 409);
});

test('provider dispatch deadline cannot outlive task authority', async (t) => {
  const h = await fixture(t, { mode: 'broker-static', taskLifetimeMs: 300, providerTimeoutMs: 1_000 });
  await h.mutate({ delayMs: 400 });
  const result = await h.client(action());
  assert.equal(result.status, 504); assert.equal(result.body.error.code, 'OUTCOME_UNCERTAIN');
  await sleep(150);
  assert.deepEqual(workload(await h.observe()), []);
});

test('provider dispatch deadline cannot outlive a signed lease', async (t) => {
  const h = await fixture(t, { mode: 'lease-only', coverageLifetimeMs: 300, providerTimeoutMs: 1_000 });
  await h.mutate({ delayMs: 400 });
  const result = await h.client(action());
  assert.equal(result.status, 504); assert.equal(result.body.error.code, 'OUTCOME_UNCERTAIN');
  await sleep(150);
  assert.deepEqual(workload(await h.observe()), []);
});

test('unavailable resource does not trigger direct-access fallback', async (t) => {
  const h = await fixture(t);
  await h.closeResource();
  assert.equal((await h.client(action())).status, 503);
  assert.equal((await requestJson(h.brokerOrigin, '/health/live')).status, 200);
  assert.equal((await requestJson(h.brokerOrigin, '/health/ready')).status, 503);
});

test('broker readiness authenticates the expected resource and rejects malformed status', async (t) => {
  const resourceToken = randomToken(); let malformed = false;
  const resourceId = 'readiness-resource';
  const resource = await listenLoopback((request, response, context) => {
    if (request.url === '/health/ready') { sendJson(response, 200, { ok: true }, context); return; }
    requireBearer(request, resourceToken);
    sendJson(response, 200, { resourceId, configurationVersion: 1, toolVersion: 1, brokerOnly: true,
      legacyEnabled: false, delayMs: 0, responseDelayMs: 0, changedAt: Date.now(), ...(malformed ? { extra: true } : {}) }, context);
  });
  t.after(() => resource.close());
  const keys = generateKeyPairSync('ed25519');
  const task = { id: 'readiness-task', actorId: 'agent-a', tenantId: 'tenant-a', documentIds: ['tenant-a-guide'],
    recipients: ['internal-team'], expiresAt: Date.now() + 60_000, maxActions: 10 };
  const coverage = signEnvelope({ version: 1, resourceId, configurationVersion: 1, taskId: task.id,
    issuedAt: Date.now(), expiresAt: Date.now() + 60_000,
    checks: { authorizedRead: true, directDenied: true, wrongIdentityDenied: true } }, keys.privateKey);
  const config = { version: 1, mode: 'coverage-bound', resourceOrigin: resource.origin, resourceId, resourceToken,
    clientToken: randomToken(), controlToken: randomToken(), task, publicKey: keys.publicKey.export({ type: 'spki', format: 'pem' }),
    coverage, providerTimeoutMs: 500 };
  for (const patch of [{ resourceToken: randomToken() }, { resourceId: 'unexpected-resource' }, {}]) {
    const broker = await startBroker({ ...config, ...patch });
    try {
      const expected = Object.keys(patch).length ? 503 : 200;
      assert.equal((await requestJson(broker.origin, '/health/ready')).status, expected);
      assert.equal((await requestJson(broker.origin, '/health/live')).status, 200);
      if (expected === 200) {
        malformed = true;
        const result = await requestJson(broker.origin, '/health/ready');
        assert.equal(result.status, 503); assert.deepEqual(result.body, { ok: false });
        malformed = false;
      }
    } finally { await broker.close(); }
  }
});

test('broken provider authorization causes an honestly observed direct forbidden effect', async (t) => {
  const h = await fixture(t);
  await h.mutate({ brokerOnly: false, legacyEnabled: true });
  assert.equal((await h.client(action())).status, 409);
  const forbidden = action({ documentId: 'tenant-a-secret' });
  assert.equal((await h.direct(forbidden)).status, 200);
  assert.equal((await h.direct(action({ documentId: 'tenant-b-secret' }))).status, 403);
  const effects = workload(await h.observe());
  assert.equal(effects.length, 1); assert.equal(effects[0].documentId, 'tenant-a-secret'); assert.equal(effects[0].via, 'legacy');
  await assert.rejects(h.refreshCoverage(), { code: 'ADMISSION_FAILED' });
});

test('startup rejects unknown configuration and never silently changes transport', async () => {
  await assert.rejects(startHarness({ transport: 'automatic' }), { code: 'INVALID_CONFIGURATION' });
  await assert.rejects(startHarness({ transport: 'in-process', extra: true }), { code: 'INVALID_INPUT' });
  let h;
  try { h = await startHarness({ transport: 'process' }); assert.equal(h.transport, 'process'); }
  catch (error) { assert.equal(error.code, 'PROCESS_TRANSPORT_UNAVAILABLE'); }
  finally { await h?.close(); }
});
