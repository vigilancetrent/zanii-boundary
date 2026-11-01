import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { readFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { resolve, join } from 'node:path';
import { openStore } from '../src/product/store.mjs';
import { asAsyncStore } from '../src/product/async-store.mjs';
import { createDocumentService } from '../src/adapters/documents.mjs';
import { createHttpsTransport } from '../src/adapters/transport.mjs';
import { createRestAdapter } from '../src/adapters/rest.mjs';
const operator = { actorId: 'operator', tenantId: 'company-a', roles: ['operator'] };
const agent = { actorId: 'agent', tenantId: 'company-a', roles: ['agent'] };

test('document database waits cannot extend a grant into a late read or mailbox commit', async (t) => {
    const base = resolve('.test-data'); mkdirSync(base, { recursive: true });
    const dir = mkdtempSync(join(base, 'document-expiry-'));
    const store = asAsyncStore(openStore({ path: join(dir, 'db.sqlite'), encryptionKey: randomBytes(32) }));
    t.after(async () => { await store.close(); assert.ok(resolve(dir).startsWith(base)); rmSync(dir, { recursive: true, force: true }); });
    let delayed = false;
    const delayedStore = { ...store, async get(...args) {
        const result = await store.get(...args);
        if (delayed && args[1] === 'documents') await new Promise((done) => setTimeout(done, 60));
        return result;
    } };
    const service = createDocumentService({ store: delayedStore, internalRecipients: ['reviewer'] });
    const uploaded = await service.putDocument(operator, { id: 'report', content: 'private', label: 'internal', allowedRecipients: ['reviewer'] });
    delayed = true;
    for (const kind of ['read', 'share']) {
        const action = { id: `expired-${kind}`, kind, documentId: 'report', ...(kind === 'share' ? { recipient: 'reviewer' } : {}) };
        await assert.rejects(service.execute(agent, action, { expectedVersion: uploaded.configurationVersion, deadlineAt: Date.now() + 30 }),
            (error) => ['DATABASE_TIMEOUT', 'DATABASE_ACQUIRE_TIMEOUT', 'TRANSPORT_DEADLINE', 'RESOURCE_GRANT_EXPIRED'].includes(error.code));
        await new Promise((done) => setTimeout(done, 70));
        assert.equal(await store.get(agent.tenantId, 'resource-operations', action.id), null);
        assert.equal(await store.get(agent.tenantId, 'deliveries', action.id), null);
    }
});
test('operator documents persist encrypted; real mailbox commit is atomic and restart-idempotent', async (t) => {
    const base = resolve('.test-data');
    mkdirSync(base, { recursive: true });
    const dir = mkdtempSync(join(base, 'documents-'));
    const key = randomBytes(32);
    const path = join(dir, 'db.sqlite');
    let store = openStore({ path, encryptionKey: key });
    t.after(async () => { (await store.close()); assert.ok(resolve(dir).startsWith(base)); rmSync(dir, { recursive: true, force: true }); });
    let service = createDocumentService({ store, internalRecipients: ['reviewer'] });
    (await assert.rejects(async () => (await service.putDocument(agent, { id: 'report', content: 'secret', label: 'restricted', allowedRecipients: ['reviewer'] })), { code: 'ROLE_REQUIRED' }));
    const uploaded = (await service.putDocument(operator, { id: 'report', content: 'live company document', label: 'confidential', allowedRecipients: ['reviewer'], allowedPurposes: ['audit'] }));
    const action = { id: 'share-one', kind: 'share', documentId: 'report', recipient: 'reviewer' };
    const context = { operationId: 'op-one', expectedVersion: uploaded.configurationVersion, deadlineAt: Date.now() + 10000 };
    assert.equal((await service.metadata(agent, action)).recipientIsInternal, true);
    (await assert.rejects(async () => (await service.execute(agent, action, { ...context, deadlineAt: 1 })), { code: 'RESOURCE_GRANT_EXPIRED' }));
    (await assert.rejects(async () => (await service.execute(agent, action, { ...context, expectedVersion: 999 })), { code: 'RESOURCE_VERSION_CHANGED' }));
    const result = (await service.execute(agent, action, context));
    assert.equal(result.channel, 'internal-mailbox');
    assert.equal((await service.delivery(operator, 'op-one')).content, 'live company document');
    (await assert.rejects(async () => (await service.metadata({ ...agent, tenantId: 'company-b' }, action)), { code: 'DOCUMENT_NOT_FOUND' }));
    (await store.close());
    store = openStore({ path, encryptionKey: key });
    service = createDocumentService({ store, internalRecipients: ['reviewer'] });
    assert.deepEqual((await service.execute(agent, action, context)), result);
    assert.equal((await store.list(operator.tenantId, 'deliveries')).items.length, 1);
    (await assert.rejects(async () => (await service.execute(agent, { ...action, recipient: 'attacker' }, context)), { code: 'OPERATION_CONFLICT' }));
    assert.equal((await service.observe(agent, 'op-one')).state, 'succeeded');
    const secondAction = { id: 'read-retain', kind: 'read', documentId: 'report' };
    (await service.execute(agent, secondAction, { ...context, operationId: 'op-read' }));
    const pruned = (await service.pruneResults(operator.tenantId, { before: Date.now(), now: Date.now() }));
    assert.equal(pruned.pruned, 2);
    assert.deepEqual((await service.observe(agent, 'op-read')), { operationId: 'op-read', state: 'succeeded', resultExpired: true });
    assert.deepEqual((await service.execute(agent, secondAction, { ...context, operationId: 'op-read' })), { operationId: 'op-read', state: 'succeeded', resultExpired: true });
    assert.equal((await store.list(operator.tenantId, 'deliveries')).items.length, 1);
    assert.equal((await store.get(operator.tenantId, 'resource-operations', 'op-read')).result, null);
    (await assert.rejects(async () => (await service.execute(agent, { ...secondAction, documentId: 'different' }, { ...context, operationId: 'op-read' })), { code: 'OPERATION_CONFLICT' }));
    assert.equal(readFileSync(path).includes(Buffer.from('live company document')), false);
});
test('shared document instances change configuration epochs atomically without reusing an older version', async (t) => {
    const base = resolve('.test-data'); mkdirSync(base, { recursive: true });
    const dir = mkdtempSync(join(base, 'document-epochs-'));
    const store = openStore({ path: join(dir, 'db.sqlite'), encryptionKey: randomBytes(32) });
    t.after(() => { store.close(); assert.ok(resolve(dir).startsWith(base)); rmSync(dir, { recursive: true, force: true }); });
    const first = createDocumentService({ store, toolVersion: 'documents-v1' });
    const second = createDocumentService({ store, toolVersion: 'documents-v2' });
    await first.putDocument(operator, { id: 'report', content: 'version-bound', label: 'internal', allowedRecipients: [] });
    const prior = await first.status(operator);
    const snapshots = await Promise.all(Array.from({ length: 12 }, (_, index) => (index % 2 ? first : second).status(operator)));
    const versions = snapshots.map((value) => value.configurationVersion);
    assert.ok(versions.every((value, index) => value > (index ? versions[index - 1] : prior.configurationVersion)));
    assert.equal(new Set(versions).size, versions.length);
    await assert.rejects(first.execute(agent, { id: 'stale', kind: 'read', documentId: 'report' }, {
        expectedVersion: prior.configurationVersion, deadlineAt: Date.now() + 5000,
    }), { code: 'RESOURCE_VERSION_CHANGED' });
    assert.equal((await store.list(operator.tenantId, 'resource-operations')).items.length, 0);
});
export async function localTls(t, handler) {
    const file = (name) => readFileSync(resolve('artifacts', `test-pki-${name}.pem`));
    const ca = file('ca');
    const server = https.createServer({ ca, cert: file('resource-cert'), key: file('resource-key'), requestCert: true, rejectUnauthorized: true }, handler);
    await new Promise((done) => server.listen(0, '127.0.0.1', done));
    t.after(() => new Promise((done) => { server.closeAllConnections(); server.close(done); }));
    const origin = `https://127.0.0.1:${server.address().port}`;
    return { origin, transport: createHttpsTransport({ origin, tls: { ca, cert: file('gateway-cert'), key: file('gateway-key') }, allowPrivateNetworks: true, timeoutMs: 1000, readTimeoutMs: 300 }) };
}
test('native HTTPS transport authenticates TLS, refuses redirect, overflow, foreign origin and private default', async (t) => {
    const { origin, transport } = await localTls(t, (req, res) => {
        if (req.url === '/redirect') {
            res.writeHead(302, { location: 'https://attacker.example' });
            res.end();
        }
        else if (req.url === '/large')
            res.end('x'.repeat(70000));
        else if (req.url === '/wait') { /* connection intentionally stalls */ }
        else {
            res.setHeader('content-type', 'application/json');
            res.end(JSON.stringify({ authorized: req.client.authorized }));
        }
    });
    assert.equal((await transport.request('/ok')).body.authorized, true);
    assert.throws(() => createHttpsTransport({ origin }), { code: 'NETWORK_DESTINATION_DENIED' });
    assert.throws(() => createHttpsTransport({ origin: 'https://[::ffff:169.254.169.254]', allowPrivateNetworks: true }), { code: 'NETWORK_DESTINATION_DENIED' });
    await assert.rejects(transport.request('/redirect'), { code: 'TRANSPORT_REDIRECT_DENIED' });
    await assert.rejects(transport.request('/large'), { code: 'RESPONSE_TOO_LARGE' });
    await assert.rejects(transport.request('/wait'), { code: 'TRANSPORT_READ_TIMEOUT' });
    await assert.rejects(transport.fetch('https://attacker.example/private'), { code: 'TRANSPORT_ROUTE_DENIED' });
    await assert.rejects(transport.request('/ok', { headers: { host: 'attacker.example' } }), { code: 'INVALID_TRANSPORT_HEADERS' });
});
test('REST connector uses only configured routes and fails closed on wrong resource scope', async () => {
    let called = 0;
    const adapter = createRestAdapter({ credentialProvider: async ({ scope }) => { assert.equal(scope, 'resource:metadata'); return 'scoped-resource-jwt'; },
        transport: { async request(path, options) {
                called++;
                assert.equal(path, '/v1/resource/metadata');
                assert.equal(options.headers.authorization, 'Bearer scoped-resource-jwt');
                return { status: 200, body: { tenantId: 'company-b', documentId: 'report', label: 'public', toolVersion: 'v1' } };
            } } });
    await assert.rejects(adapter.metadata(agent, { id: 'one', kind: 'read', documentId: 'report' }), { code: 'RESOURCE_SCOPE_MISMATCH' });
    assert.equal(called, 1);
});
