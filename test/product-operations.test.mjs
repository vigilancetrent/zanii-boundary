import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { readFile, writeFile, mkdir, mkdtemp, rm } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createPrivateKey, createHash, X509Certificate, randomBytes, randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import { openAsyncSqliteStore } from '../src/product/async-store.mjs';
import { parseOperationsConfig, loadOperationsConfig } from '../src/product/operations-config.mjs';
import { createRuntimeOperations, createConfiguredOperations, createObjectCleanupHandler } from '../src/product/runtime-operations.mjs';
import { createJobService } from '../src/product/jobs.mjs';
import { createMaintenanceWorker } from '../src/product/worker.mjs';
import { createTelemetry, instrumentStore } from '../src/product/telemetry.mjs';
import { InMemorySpanExporter } from '@opentelemetry/sdk-trace';
import { createAlertEvent, createAlertDelivery, createAlertReceiver } from '../src/product/alerts.mjs';
import { createHttpsTransport } from '../src/adapters/transport.mjs';
import { startProductServer } from '../src/product/server.mjs';
import { routeTemplate } from '../src/product/observability.mjs';

const pem = (name) => readFile(resolve('artifacts', `test-pki-${name}.pem`), 'utf8');
const operator = { tenantId: 'company', actorId: 'operator', roles: ['operator'], scopes: ['runtime:operations', 'runtime:operations:retry', 'runtime:privacy', 'runtime:privacy:export', 'runtime:privacy:hold'] };
async function fixture(t) {
  await mkdir('.test-data', { recursive: true }); const directory = await mkdtemp(resolve('.test-data', 'ops-'));
  const store = openAsyncSqliteStore({ path: join(directory, 'state.sqlite'), encryptionKey: randomBytes(32), auditKey: randomBytes(32) });
  const cleanup = [];
  t.after(async () => { for (const close of cleanup.reverse()) await close(); await store.close(); await rm(directory, { force: true, recursive: true }); }); return { store, directory, cleanup };
}
const queued = () => ({ queued: 0, retry: 0, running: 0, dead: 0, done: 0, due: 0, oldestDueAt: null });

test('role-specific maintenance config needs no gateway JWT key and rejects archive decryption material', async (t) => {
  const { directory } = await fixture(t);
  const config = { version: 1, role: 'worker', realm: 'gateway', storage: { backend: 'sqlite', path: 'worker.sqlite', encryptionKeyFile: 'encryption', auditKeyFile: 'audit' }, worker: {} };
  await writeFile(join(directory, 'encryption'), randomBytes(32).toString('hex'), { mode: 0o600 });
  await writeFile(join(directory, 'audit'), randomBytes(32).toString('hex'), { mode: 0o600 });
  await writeFile(join(directory, 'worker.json'), JSON.stringify(config));
  const loaded = await loadOperationsConfig(join(directory, 'worker.json'));
  assert.equal(loaded.config.role, 'worker'); assert.equal(loaded.material.signingKey, undefined);
  assert.equal(loaded.material.encryptionKey.length, 32); assert.deepEqual(loaded.config.services, {});
  assert.throws(() => parseOperationsConfig({ ...config, services: { arbitraryHandler: 'https://attacker.invalid' } }), { code: 'INVALID_OPERATIONS_CONFIGURATION' });
  assert.throws(() => parseOperationsConfig({ ...config, role: 'archive' }), { code: 'INVALID_OPERATIONS_CONFIGURATION' });
  assert.throws(() => parseOperationsConfig({ ...config, worker: { timeoutMs: 5000, leaseMs: 1000 } }), { code: 'INVALID_OPERATIONS_CONFIGURATION' });
});

test('required dependency age, durable DLQ and key freeze gate admission while optional outages degrade their feature', async (t) => {
  const { store } = await fixture(t); let at = 100000; let heartbeat = { at, state: 'idle' }; let queue = queued();
  const ports = { store, now: () => at, workerStatus: async () => heartbeat, jobs: { status: async () => queue },
    archive: { status: async () => ({ at: 100000, healthy: true }) }, backup: { status: async () => { throw new Error('private provider URL'); } } };
  const optional = createRuntimeOperations({ ...ports, policy: { backup: { required: false } } });
  assert.equal((await optional.status(operator)).ready, true); await optional.gate(operator);
  const required = createRuntimeOperations({ ...ports, policy: { worker: { maxHeartbeatAgeMs: 1000 }, archive: { maxAgeMs: 1000 } } });
  assert.equal((await required.status(operator)).ready, true); queue = { ...queued(), dead: 1 };
  await assert.rejects(required.gate(operator), { code: 'REQUIRED_WORKER_UNAVAILABLE' });
  queue = queued(); heartbeat = { at: 100000, state: 'error' }; await assert.rejects(required.gate(operator), { code: 'REQUIRED_WORKER_UNAVAILABLE' });
  heartbeat = { at: 100000, state: 'idle' }; at += 2000;
  assert.deepEqual((await required.status(operator)).blockers, ['REQUIRED_WORKER_UNAVAILABLE', 'REQUIRED_ARCHIVE_UNAVAILABLE']);
  assert.equal(JSON.stringify(await optional.status(operator)).includes('private provider'), false);
  const frozen = createRuntimeOperations({ store: { async: true, get() {}, keyEpoch: async () => ({ version: 2, frozen: true }) } });
  await assert.rejects(frozen.gate(operator), { code: 'KEY_EPOCH_UNAVAILABLE' });
});
test('fresh verification of an old immutable snapshot cannot refresh required recovery point readiness', async (t) => {
  const { store } = await fixture(t); let capturedAt = 100000; const time = 1000000;
  const operations = createRuntimeOperations({ store, now: () => time, policy: { backup: { required: true, maxAgeMs: 1000 } },
    backup: { status: async () => ({ healthy: true, capturedAt, lastVerifiedAt: time }) } });
  const stale = await operations.status(operator); assert.equal(stale.ready, false); assert.equal(stale.backup.ageMs, 0); assert.equal(stale.backup.snapshotAgeMs, 900000);
  await assert.rejects(operations.gate(operator), { code: 'REQUIRED_BACKUP_UNAVAILABLE' });
  capturedAt = time; assert.equal((await operations.status(operator)).ready, true);
});

test('operations routes have independent operator scopes, bounded pages and static metric labels', async (t) => {
  const { store } = await fixture(t); let page;
  const operations = createRuntimeOperations({ store, jobs: { list: async (_identity, options) => { page = options; return { items: [], next: null }; } },
    privacy: { request: async (_identity, value) => ({ id: 'privacy-1', ...value }) } });
  await operations.route('/v1/ops/jobs/list', 'POST', operator, {}); assert.equal(page.limit, 25);
  await assert.rejects(operations.route('/v1/ops/jobs/list', 'POST', operator, { limit: 101 }));
  await assert.rejects(operations.route('/v1/ops/jobs/list', 'POST', { ...operator, roles: ['agent'] }, {}), { code: 'ROLE_REQUIRED' });
  await assert.rejects(operations.route('/v1/ops/jobs/retry', 'POST', { ...operator, scopes: ['runtime:operations'] }, { id: 'job-1' }), { code: 'OPERATOR_SCOPE_DENIED' });
  await assert.rejects(operations.route('/v1/ops/privacy/request', 'POST', operator, { kind: 'delete', subject: { kind: 'actor', id: 'one' } }), { code: 'OPERATOR_SCOPE_DENIED' });
  assert.equal(routeTemplate('/v1/ops/privacy/holds/release'), '/v1/ops/privacy/holds/release');
  assert.equal(routeTemplate('/v1/ops/private-customer-id'), 'unmatched');
});

test('controlled mTLS alert receiver durably deduplicates a lost acknowledgement and rejects tampering', async (t) => {
  const { store } = await fixture(t); const key = randomBytes(32); const receiver = createAlertReceiver({ store, key });
  t.after(() => receiver.close()); let received = 0;
  const server = createServer({ ca: await pem('ca'), cert: await pem('gateway-cert'), key: await pem('gateway-key'), requestCert: true, rejectUnauthorized: true }, async (req, res) => {
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      const result = await receiver.receive({ raw: Buffer.concat(chunks).toString(), timestamp: req.headers['x-runtime-alert-time'],
        signature: req.headers['x-runtime-alert-signature'], idempotencyKey: req.headers['idempotency-key'] });
      if (++received === 1) { req.socket.destroy(); return; }
      res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(result));
    } catch { res.writeHead(401); res.end('{}'); }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  const transport = createHttpsTransport({ origin: `https://127.0.0.1:${server.address().port}`, tls: { ca: await pem('ca'), cert: await pem('operator-cert'), key: await pem('operator-key') }, allowPrivateNetworks: true, timeoutMs: 1000 });
  const delivery = createAlertDelivery({ key, path: '/alerts', transport }); t.after(() => delivery.close());
  const event = createAlertEvent({ key, tenantId: 'company-private-name', kind: 'job-dead-letter', code: 'JOB_FAILED' });
  assert.equal(JSON.stringify(event).includes('company-private-name'), false);
  await assert.rejects(delivery.deliver(event)); assert.equal(received, 1);
  assert.deepEqual(await delivery.deliver(event), { id: event.id, delivered: true, duplicate: true }); assert.equal(received, 2);
  assert.equal((await store.list('system', 'incidents')).items.length, 1);
  const invalid = { raw: JSON.stringify(event), timestamp: String(Date.now()), signature: '0'.repeat(64), idempotencyKey: event.id };
  await assert.rejects(receiver.receive(invalid), { code: 'ALERT_AUTHENTICATION_FAILED' });
  await assert.rejects(receiver.receive({ ...invalid, timestamp: '1' }), { code: 'ALERT_AUTHENTICATION_FAILED' });
  assert.throws(() => createAlertEvent({ key, tenantId: 'company', kind: 'job-dead-letter', code: 'PRIVATE https://url' }), { code: 'INVALID_ALERT' });
});

test('real mTLS resource refuses protected admission on required operations outage and records typed security outcomes', async (t) => {
  const { store, directory } = await fixture(t); let blocked = true;
  const operations = createRuntimeOperations({ store, policy: { worker: {} }, jobs: { status: async () => queued() }, workerStatus: async () => ({ at: Date.now(), state: blocked ? 'error' : 'idle' }) });
  const ca = await pem('ca'); const cert = await pem('operator-cert'); const issuer = createPrivateKey(await pem('issuer-key'));
  const jwks = JSON.parse(await readFile(resolve('artifacts/test-pki-issuer-public.jwks.json'), 'utf8'));
  const service = await startProductServer({ store, operations, config: { version: 1, role: 'resource', profile: 'local-test', listen: { host: '127.0.0.1', port: 0 },
    auth: { issuer: 'https://issuer.company', audience: 'resource', algorithms: ['EdDSA'], maxLifetimeSeconds: 900, requireSenderBinding: true },
    limits: { bodyBytes: 65536, requestTimeoutMs: 3000, rateWindowMs: 1000, rateRequests: 500, maxConcurrency: 16 }, storage: { retentionMs: 60000 }, integrations: {}, protocols: {} },
    material: { baseDirectory: directory, tls: { ca, cert: await pem('resource-cert'), key: await pem('resource-key') }, jwks, encryptionKey: randomBytes(32), auditKey: randomBytes(32), signingKey: issuer }, logger() {} });
  t.after(() => service.close());
  const token = await new SignJWT({ tenant_id: 'company', roles: ['operator'], scope: 'resource:admin runtime:audit runtime:operations',
    cnf: { 'x5t#S256': createHash('sha256').update(new X509Certificate(cert).raw).digest('base64url') } }).setSubject('operator')
    .setProtectedHeader({ alg: 'EdDSA', kid: jwks.keys[0].kid }).setIssuer('https://issuer.company').setAudience('resource').setIssuedAt().setExpirationTime('5m').setJti(randomUUID()).sign(issuer);
  const transport = createHttpsTransport({ origin: service.origin, tls: { ca, cert, key: await pem('operator-key') }, allowPrivateNetworks: true });
  const call = (path, body, credential = token) => transport.request(path, { method: body ? 'POST' : 'GET', headers: { authorization: `Bearer ${credential}` }, ...(body ? { body } : {}) });
  assert.equal((await call('/health/live')).body.live, true);
  assert.equal((await call('/health/startup')).body.started, true);
  assert.equal((await call('/health/ready')).status, 503);
  assert.equal((await call('/v1/resource/documents', { id: 'doc', content: 'fixture', labels: ['public'] })).body.error.code, 'REQUIRED_WORKER_UNAVAILABLE');
  assert.equal((await store.list('company', 'documents')).items.length, 0);
  blocked = false; const ready = await call('/health/ready'); assert.equal(ready.status, 200, JSON.stringify(ready.body));
  assert.equal((await call('/v1/ops/status')).status, 200);
  assert.equal((await call('/v1/ops/status', undefined, 'invalid')).status, 401);
  const companyAudit = await store.queryAudit('company', { limit: 100 }); const systemAudit = await store.queryAudit('system', { limit: 100 });
  assert.ok(companyAudit.some((item) => item.event === 'authentication.succeeded'));
  assert.ok(companyAudit.some((item) => item.event === 'security.request.failed'));
  assert.ok(systemAudit.some((item) => item.event === 'authentication.failed'));
  assert.equal(JSON.stringify(companyAudit).includes(token), false); assert.equal(JSON.stringify(companyAudit).includes('127.0.0.1'), false);
});

test('configured worker joins durable DLQ, stable alert outbox, real mTLS dedupe, dormant retention and job traces', async (t) => {
  const { store: rawStore, directory, cleanup } = await fixture(t); const key = randomBytes(32); const receiver = createAlertReceiver({ store: rawStore, key });
  t.after(() => receiver.close()); let receives = 0;
  const server = createServer({ ca: await pem('ca'), cert: await pem('gateway-cert'), key: await pem('gateway-key'), requestCert: true, rejectUnauthorized: true }, async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    try {
      const ack = await receiver.receive({ raw: Buffer.concat(chunks).toString(), timestamp: req.headers['x-runtime-alert-time'], signature: req.headers['x-runtime-alert-signature'], idempotencyKey: req.headers['idempotency-key'] });
      if (++receives === 1) return req.socket.destroy();
      res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(ack));
    } catch { res.writeHead(401); res.end('{}'); }
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  const exporter = new InMemorySpanExporter(); const telemetry = createTelemetry({ exporter, samplingRatio: 1 });
  cleanup.push(() => telemetry.close()); const store = instrumentStore(rawStore, telemetry);
  const jobs = createJobService({ store, maxAttempts: 2, baseDelayMs: 1, maxDelayMs: 1, random: () => 0 });
  await writeFile(join(directory, 'alert-key'), key.toString('hex'), { mode: 0o600 });
  const services = { alerts: { origin: `https://127.0.0.1:${server.address().port}`, path: '/alerts', hmacKeyFile: 'alert-key',
    caFile: resolve('artifacts/test-pki-ca.pem'), certFile: resolve('artifacts/test-pki-operator-cert.pem'), keyFile: resolve('artifacts/test-pki-operator-key.pem'), allowPrivateNetworks: true } };
  const operations = await createConfiguredOperations({ config: { role: 'worker', storage: { retentionMs: 60000 }, worker: {}, services }, material: { baseDirectory: directory, auditKey: randomBytes(32) }, store, telemetry, ports: { jobs } });
  cleanup.push(() => operations.close());
  const traceparent = `00-${'3'.repeat(32)}-${'4'.repeat(16)}-01`;
  const bad = await jobs.enqueue(operator, { id: 'bad-retention', kind: 'retention', payload: { arbitrary: 'handler' }, trace: { requestId: 'original-http', traceparent } });
  await store.put('dormant-company', 'memory', 'expired', { text: 'synthetic dormant fixture' }, { expiresAt: Date.now() - 1 });
  const worker = createMaintenanceWorker({ store, jobs, handlers: operations.handlers, onAlert: operations.onAlert, schedule: operations.schedule, telemetry });
  cleanup.push(() => worker.close());
  await worker.tick(); assert.equal((await store.get('company', 'jobs', bad.id)).state, 'dead');
  const alarm = { tenantId: 'company', code: 'INVALID_OBJECT', idempotencyKey: 'stable-manual-alarm' };
  const first = await operations.onAlert(alarm); const second = await operations.onAlert(alarm); assert.equal(first.digest, second.digest);
  await worker.tick(); await worker.tick(); await worker.tick();
  assert.equal((await store.list('dormant-company', 'memory')).items.length, 0);
  assert.ok(receives >= 3); assert.equal((await store.list('system', 'incidents')).items.filter((row) => row.value.event).length, 2);
  const page = await jobs.list(operator, { limit: 100 }); const alertJobs = page.items.map((row) => row.value).filter((job) => job.kind === 'alert-delivery');
  assert.equal(alertJobs.length, 2); assert.ok(alertJobs.every((job) => job.state === 'done'));
  assert.equal((await store.workerStatus()).items[0].state, 'idle');
  await telemetry.flush(); const spans = exporter.getFinishedSpans();
  assert.ok(spans.some((span) => span.name === 'maintenance.job' && span.spanContext().traceId === '3'.repeat(32)));
  assert.ok(spans.some((span) => span.name === 'http.provider'));
  assert.equal(JSON.stringify(spans.map((span) => span.attributes)).includes('synthetic dormant fixture'), false);
});

test('object cleanup requires a durable abandoned intent and refuses live retained copies', async (t) => {
  const { store } = await fixture(t); let deletes = 0;
  const reference = { id: 'doc', purpose: 'document', bucket: 'fixture-bucket', key: 'opaque-key', versionId: 'version-one' };
  const handler = createObjectCleanupHandler({ store, objectStorage: { async remove() { deletes++; return { removed: true }; } }, privacy: { async canDeleteReference() { return true; } } });
  const job = { tenantId: 'company', payload: { reference, intentId: 'upload-intent' } };
  await assert.rejects(handler(job), { code: 'OBJECT_INTENT_NOT_ABANDONED' }); assert.equal(deletes, 0);
  await store.put('company', 'object-intents', 'upload-intent', { state: 'uploaded', reference });
  await store.put('company', 'deliveries', 'retained-copy', { result: { objectRef: reference } });
  await assert.rejects(handler(job), { code: 'OBJECT_REFERENCE_STILL_LIVE' }); assert.equal(deletes, 0);
  await store.delete('company', 'deliveries', 'retained-copy');
  assert.deepEqual(await handler(job), { removed: true }); assert.equal(deletes, 1);
  assert.equal((await store.get('company', 'object-intents', 'upload-intent')).state, 'deleted');
  assert.deepEqual(await handler(job), { removed: true }); assert.equal(deletes, 1);
});

test('prepared upload recovery never calls PUT or claims a 404 is a completed deletion', async (t) => {
  const { store } = await fixture(t); let found = false; let deletes = 0;
  const reference = { id: 'doc', purpose: 'document', bucket: 'fixture', key: 'opaque', versionId: 'verified-version' };
  const handler = createObjectCleanupHandler({ store, objectStorage: { async recoverUpload() { return found ? reference : null; }, async remove() { deletes++; return { removed: true }; } }, privacy: { async canDeleteReference() { return true; } } });
  await store.put('company', 'object-intents', 'prepared', { state: 'prepared', documentId: 'doc', upload: { id: 'doc', plaintextSha256: 'a'.repeat(64) } });
  const job = { tenantId: 'company', payload: { intentId: 'prepared' } };
  await assert.rejects(handler(job), { code: 'OBJECT_UPLOAD_RECOVERY_PENDING' }); assert.equal(deletes, 0);
  assert.equal((await store.get('company', 'object-intents', 'prepared')).state, 'prepared');
  found = true; assert.deepEqual(await handler(job), { removed: true }); assert.equal(deletes, 1);
  assert.equal((await store.get('company', 'object-intents', 'prepared')).state, 'deleted');
});
