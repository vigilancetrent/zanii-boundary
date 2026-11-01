import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { readFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { resolve, join } from 'node:path';
import { openStore } from '../src/product/store.mjs';
import { createDocumentService } from '../src/adapters/documents.mjs';
import { createHttpsTransport } from '../src/adapters/transport.mjs';
import { createRestAdapter } from '../src/adapters/rest.mjs';

const operator = { actorId: 'operator', tenantId: 'company-a', roles: ['operator'] };
const agent = { actorId: 'agent', tenantId: 'company-a', roles: ['agent'] };
test('operator documents persist encrypted; real mailbox commit is atomic and restart-idempotent', (t) => {
  const base = resolve('.test-data'); mkdirSync(base, { recursive: true }); const dir = mkdtempSync(join(base, 'documents-'));
  const key = randomBytes(32); const path = join(dir, 'db.sqlite'); let store = openStore({ path, encryptionKey: key });
  t.after(() => { store.close(); assert.ok(resolve(dir).startsWith(base)); rmSync(dir, { recursive: true, force: true }); });
  let service = createDocumentService({ store, internalRecipients: ['reviewer'] });
  assert.throws(() => service.putDocument(agent, { id: 'report', content: 'secret', label: 'restricted', allowedRecipients: ['reviewer'] }), { code: 'ROLE_REQUIRED' });
  const uploaded = service.putDocument(operator, { id: 'report', content: 'live company document', label: 'confidential', allowedRecipients: ['reviewer'], allowedPurposes: ['audit'] });
  const action = { id: 'share-one', kind: 'share', documentId: 'report', recipient: 'reviewer' };
  const context = { operationId: 'op-one', expectedVersion: uploaded.configurationVersion, deadlineAt: Date.now() + 10000 };
  assert.equal(service.metadata(agent, action).recipientIsInternal, true);
  assert.throws(() => service.execute(agent, action, { ...context, deadlineAt: 1 }), { code: 'RESOURCE_GRANT_EXPIRED' });
  assert.throws(() => service.execute(agent, action, { ...context, expectedVersion: 999 }), { code: 'RESOURCE_VERSION_CHANGED' });
  const result = service.execute(agent, action, context);
  assert.equal(result.channel, 'internal-mailbox'); assert.equal(service.delivery(operator, 'op-one').content, 'live company document');
  assert.throws(() => service.metadata({ ...agent, tenantId: 'company-b' }, action), { code: 'DOCUMENT_NOT_FOUND' });
  store.close(); store = openStore({ path, encryptionKey: key }); service = createDocumentService({ store, internalRecipients: ['reviewer'] });
  assert.deepEqual(service.execute(agent, action, context), result);
  assert.equal(store.list(operator.tenantId, 'deliveries').items.length, 1);
  assert.throws(() => service.execute(agent, { ...action, recipient: 'attacker' }, context), { code: 'OPERATION_CONFLICT' });
  assert.equal(service.observe(agent, 'op-one').state, 'succeeded');
  const secondAction = { id: 'read-retain', kind: 'read', documentId: 'report' };
  service.execute(agent, secondAction, { ...context, operationId: 'op-read' });
  const pruned = service.pruneResults(operator.tenantId, { before: Date.now(), now: Date.now() });
  assert.equal(pruned.pruned, 2);
  assert.deepEqual(service.observe(agent, 'op-read'), { operationId: 'op-read', state: 'succeeded', resultExpired: true });
  assert.deepEqual(service.execute(agent, secondAction, { ...context, operationId: 'op-read' }), { operationId: 'op-read', state: 'succeeded', resultExpired: true });
  assert.equal(store.list(operator.tenantId, 'deliveries').items.length, 1);
  assert.equal(store.get(operator.tenantId, 'resource-operations', 'op-read').result, null);
  assert.throws(() => service.execute(agent, { ...secondAction, documentId: 'different' }, { ...context, operationId: 'op-read' }), { code: 'OPERATION_CONFLICT' });
  assert.equal(readFileSync(path).includes(Buffer.from('live company document')), false);
});

export async function localTls(t, handler) {
  const file = (name) => readFileSync(resolve('artifacts', `test-pki-${name}.pem`));
  const ca = file('ca'); const server = https.createServer({ ca, cert: file('resource-cert'), key: file('resource-key'), requestCert: true, rejectUnauthorized: true }, handler);
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  t.after(() => new Promise((done) => { server.closeAllConnections(); server.close(done); }));
  const origin = `https://127.0.0.1:${server.address().port}`;
  return { origin, transport: createHttpsTransport({ origin, tls: { ca, cert: file('gateway-cert'), key: file('gateway-key') }, allowPrivateNetworks: true, timeoutMs: 1000, readTimeoutMs: 300 }) };
}

test('native HTTPS transport authenticates TLS, refuses redirect, overflow, foreign origin and private default', async (t) => {
  const { origin, transport } = await localTls(t, (req, res) => {
    if (req.url === '/redirect') { res.writeHead(302, { location: 'https://attacker.example' }); res.end(); }
    else if (req.url === '/large') res.end('x'.repeat(70000));
    else if (req.url === '/wait') { /* connection intentionally stalls */ }
    else { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ authorized: req.client.authorized })); }
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
    transport: { async request(path, options) { called++; assert.equal(path, '/v1/resource/metadata'); assert.equal(options.headers.authorization, 'Bearer scoped-resource-jwt');
      return { status: 200, body: { tenantId: 'company-b', documentId: 'report', label: 'public', toolVersion: 'v1' } }; } } });
  await assert.rejects(adapter.metadata(agent, { id: 'one', kind: 'read', documentId: 'report' }), { code: 'RESOURCE_SCOPE_MISMATCH' });
  assert.equal(called, 1);
});
