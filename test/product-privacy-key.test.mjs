import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { mkdir, mkdtemp, rm, readFile, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { randomBytes, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import canonicalize from 'canonicalize';
import { openAsyncSqliteStore } from '../src/product/async-store.mjs';
import { createPrivacyService, privacySubjectId } from '../src/product/privacy.mjs';
import { createJobService } from '../src/product/jobs.mjs';
import { createKeyLifecycle, createRetainedKeyVerifier, createConfiguredSourceFenceVerifier, privacyInventoryDigest } from '../src/product/key-lifecycle.mjs';
import { createConfiguredOperations } from '../src/product/runtime-operations.mjs';
import { createMemoryService } from '../src/product/memory.mjs';
import { createLearningService } from '../src/product/learning.mjs';
import { createAuditArchive } from '../src/product/audit-archive.mjs';
import { openSqliteArchivePort } from '../src/product/store.mjs';
import { runOperations } from '../scripts/operations.mjs';
import { DatabaseSync } from 'node:sqlite';

const owner = { tenantId: 'company', actorId: 'operator', roles: ['operator'] };
const pem = (name) => readFile(resolve('artifacts', `test-pki-${name}.pem`), 'utf8');
async function fixture(t, rotator = false) {
  await mkdir('.test-data', { recursive: true }); const directory = await mkdtemp(resolve('.test-data', 'privacy-key-'));
  const options = { path: join(directory, 'state.sqlite'), encryptionKey: randomBytes(32), auditKey: randomBytes(32), ...(rotator ? { role: 'rotator', keyring: { activeKeyId: 'current', keys: { old: randomBytes(32), current: randomBytes(32) } } } : {}) };
  const store = openAsyncSqliteStore(options); t.after(async () => { await store.close(); await rm(directory, { force: true, recursive: true }); });
  const jobs = createJobService({ store }); const privacy = createPrivacyService({ store, jobs }); return { store, jobs, privacy, directory, options };
}
async function process(privacy, request, maximum = 40) {
  for (let batch = 0; batch < maximum; batch++) {
    const state = await privacy.status(owner, request.id); if (['done', 'held', 'cleanup-pending'].includes(state.state)) return state;
    await privacy.process({ tenantId: owner.tenantId, kind: `privacy-${request.kind}`, id: `batch-${batch}`, payload: { requestId: request.id } });
  } throw new Error('bounded fixture did not finish');
}

test('typed privacy IDs cannot overwrite tombstones, requests or a prior hold', async (t) => {
  const { store, privacy } = await fixture(t); const subject = { kind: 'document', id: 'private-doc' };
  const request = await privacy.request(owner, { id: 'delete', kind: 'delete', subject });
  await privacy.hold(owner, { id: privacySubjectId(subject), subject, reason: 'fixture legal hold' });
  await assert.rejects(privacy.assertAccessible('company', subject), { code: 'PRIVACY_SUBJECT_BLOCKED' });
  assert.equal((await privacy.status(owner, request.id)).type, 'request');
  assert.equal((await store.get('company', 'privacy', privacySubjectId(subject))).type, 'tombstone');
  await assert.rejects(privacy.hold(owner, { id: privacySubjectId(subject), subject, reason: 'changed reason' }), { code: 'PRIVACY_HOLD_CONFLICT' });
  assert.equal((await process(privacy, request)).state, 'held');
  await privacy.releaseHold(owner, privacySubjectId(subject));
  await privacy.process({ tenantId: 'company', kind: 'privacy-delete', id: 'resume', payload: { requestId: request.id } });
  await assert.rejects(privacy.hold(owner, { subject, reason: 'too late' }), { code: 'PRIVACY_DELETION_IN_PROGRESS' });
});

test('synthetic privacy deletion removes provenance copies and deduplicates physical cleanup receipts', async (t) => {
  const { store, privacy } = await fixture(t); const reference = { id: 'private-doc', purpose: 'document', bucket: 'fixture', key: 'opaque', versionId: 'v1' };
  await store.put('company', 'documents', 'private-doc', { id: 'private-doc', objectRef: reference });
  await store.put('company', 'deliveries', 'copy', { documentId: 'private-doc', objectRef: reference });
  await store.put('company', 'memory', 'derived', { sourceDocumentIds: ['private-doc'], text: 'synthetic copied data' });
  await store.put('company', 'learning-examples', 'example', { sourceId: 'private-doc', sourceKind: 'document', actorId: 'agent', text: 'synthetic data' });
  await store.put('company', 'learning-candidates', 'model', { model: { examples: ['synthetic mixed model'] } });
  await store.put('company', 'documents', 'unrelated', { id: 'unrelated', content: 'keep' });
  await store.put('other-company', 'documents', 'private-doc', { id: 'private-doc', content: 'other tenant' });
  const request = await privacy.request(owner, { id: 'delete-copy', kind: 'delete', subject: { kind: 'document', id: 'private-doc' } });
  const state = await process(privacy, request); assert.equal(state.state, 'cleanup-pending'); assert.equal(state.pendingCleanup, 1);
  for (const namespace of ['deliveries', 'memory', 'learning-examples', 'learning-candidates']) assert.equal((await store.list('company', namespace)).items.length, 0);
  assert.equal((await store.get('company', 'documents', 'unrelated')).content, 'keep');
  assert.equal((await store.get('other-company', 'documents', 'private-doc')).content, 'other tenant');
  assert.deepEqual(await privacy.completeReference('company', request.id, reference), { pendingCleanup: 0 });
  assert.deepEqual(await privacy.completeReference('company', request.id, reference), { duplicate: true });
  assert.equal((await privacy.status(owner, request.id)).state, 'done');
  assert.deepEqual(await privacy.resetLearning(owner), { cleared: true, retrainingRequired: true });
});

test('privacy export pages are tenant bound and deleted provenance blocks memory and learned model release', async (t) => {
  const { store, privacy } = await fixture(t);
  await store.put('company', 'documents', 'doc', { id: 'doc', content: 'synthetic export' });
  const request = await privacy.request(owner, { id: 'export', kind: 'export', subject: { kind: 'document', id: 'doc' } });
  assert.equal((await process(privacy, request)).state, 'done');
  let after = ''; let found = false; do { const page = await privacy.exportPage(owner, request.id, { limit: 10, after }); found ||= JSON.stringify(page.items).includes('synthetic export'); after = page.next; } while (after);
  assert.equal(found, true);
  await assert.rejects(privacy.exportPage({ ...owner, tenantId: 'other-company' }, request.id), { code: 'PRIVACY_REQUEST_NOT_FOUND' });
  await store.put('company', 'memory', 'memory', { id: 'memory', rootTaskId: 'task', tenantId: 'company', sourceDocumentIds: ['doc'], label: 'public', expiresAt: Date.now() + 60000 });
  await privacy.request(owner, { id: 'delete', kind: 'delete', subject: { kind: 'document', id: 'doc' } });
  const memory = createMemoryService({ store, policy: { getTask: async () => ({ rootTaskId: 'task', documentIds: ['doc'], maxSensitivity: 'public' }) }, assertAccessible: privacy.assertAccessible });
  await assert.rejects(memory.read({ ...owner, roles: ['agent'] }, 'task', 'memory'), { code: 'PRIVACY_SUBJECT_BLOCKED' });
  const learning = createLearningService({ store, trustKey: createPublicKey(await pem('issuer-key')), policyDigest: 'a'.repeat(64), assertAccessible: privacy.assertAccessible });
  assert.equal((await learning.detect(owner, 'ignore previous instructions', {})).adaptiveState, 'blocked-privacy-cleanup');
  await assert.rejects(learning.train(owner), { code: 'PRIVACY_MODEL_REBUILD_REQUIRED' });
  await assert.rejects(privacy.exportPage(owner, request.id), { code: 'PRIVACY_SUBJECT_BLOCKED' });
});

test('actual SQLite retirement seal survives unknown provider outcomes and blocks competing unfreeze until verified acknowledgement', async (t) => {
  const { store } = await fixture(t, true); const lifecycle = createKeyLifecycle({ store, verifyRetainedRecord: createRetainedKeyVerifier({ realm: 'local', archivePublicKey: undefined, backupPublicKey: undefined }) });
  await lifecycle.freeze(); let idempotency;
  await assert.rejects(lifecycle.retire('old', async (proof) => {
    idempotency = proof.idempotencyKey;
    await assert.rejects(lifecycle.unfreeze(), { code: 'WRITE_EPOCH_CONFLICT' }); throw new Error('synthetic unknown provider outcome');
  }));
  const sealed = await store.keyEpoch(); assert.equal(sealed.retirement.state, 'sealed');
  await assert.rejects(store.activateKeyEpoch({ expectedVersion: sealed.version, activeKeyId: 'old' }), { code: 'WRITE_EPOCH_CONFLICT' });
  const result = await lifecycle.retire('old', async (proof) => {
    assert.equal(proof.idempotencyKey, idempotency); return { retired: true, keyId: proof.keyId, referenceProofHash: proof.referenceProofHash, providerReceiptDigest: 'a'.repeat(64) };
  });
  assert.equal(result.retired, true); assert.equal((await store.keyEpoch()).retirement, null); assert.equal((await lifecycle.unfreeze()).frozen, false);
});

test('object-backed privacy export fetches outside the transaction and withholds data if a tombstone arrives during I/O', async (t) => {
  const { store, jobs } = await fixture(t); let begin; let finish; let paused = false;
  const entered = new Promise((resolve) => { begin = resolve; }); const wait = new Promise((resolve) => { finish = resolve; });
  const privacy = createPrivacyService({ store, jobs, realm: 'resource', readReference: async () => { if (paused) { begin(); await wait; } return Buffer.from('synthetic object bytes'); } });
  await store.put('company', 'documents', 'object-doc', { id: 'object-doc', objectRef: { id: 'object-doc', purpose: 'document', versionId: 'immutable-version' } });
  const request = await privacy.request(owner, { id: 'object-export', kind: 'export', subject: { kind: 'document', id: 'object-doc' } });
  await process(privacy, request); const page = await privacy.exportPage(owner, request.id);
  assert.equal(page.items[0].rows[0].value.content, 'synthetic object bytes'); assert.equal(page.items[0].rows[0].value.objectRef, undefined);
  paused = true; const releasing = privacy.exportPage(owner, request.id); await entered;
  await privacy.request(owner, { id: 'delete-during-fetch', kind: 'delete', subject: { kind: 'document', id: 'object-doc' } });
  finish(); await assert.rejects(releasing, { code: 'PRIVACY_SUBJECT_BLOCKED' });
});

test('configured source fence verifier uses real mTLS and rejects a correctly signed receipt bound to another restore', async (t) => {
  const { directory, store, privacy } = await fixture(t); const privateKey = createPrivateKey(await pem('issuer-key')); let mismatch = false; let privacyMismatch = false; let privacyMissing = false;
  await writeFile(join(directory, 'trust.pem'), createPublicKey(privateKey).export({ type: 'spki', format: 'pem' }));
  const server = createServer({ ca: await pem('ca'), cert: await pem('gateway-cert'), key: await pem('gateway-key'), requestCert: true, rejectUnauthorized: true }, async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk); const input = JSON.parse(Buffer.concat(chunks)); const time = Date.now();
    const manifest = { version: 1, purpose: 'agent-runtime-source-fence', realm: input.realm, restoreSha256: mismatch ? 'b'.repeat(64) : input.restoreSha256, epoch: input.epoch, sourceWritersFenced: true, providerCredentialsRevoked: true, privacyReconciled: true, targetPrivacyDigest: privacyMismatch ? 'b'.repeat(64) : input.targetPrivacyDigest, observedAt: time, expiresAt: time + 1000 };
    if (privacyMissing) delete manifest.targetPrivacyDigest;
    res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ manifest, signature: sign(null, Buffer.from(canonicalize(manifest)), privateKey).toString('base64url') }));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve)); t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  const verifier = await createConfiguredSourceFenceVerifier({ origin: `https://127.0.0.1:${server.address().port}`, path: '/v1/runtime/fencing/status', caFile: resolve('artifacts/test-pki-ca.pem'), certFile: resolve('artifacts/test-pki-operator-cert.pem'), keyFile: resolve('artifacts/test-pki-operator-key.pem'), trustKeyFile: 'trust.pem', allowPrivateNetworks: true, maxAgeMs: 2000 }, { baseDirectory: directory });
  const targetPrivacyDigest = await privacyInventoryDigest({ store, realm: 'gateway' });
  const request = { realm: 'gateway', restoreSha256: 'a'.repeat(64), epoch: 3, targetPrivacyDigest };
  assert.equal((await verifier(request)).verified, true); mismatch = true; await assert.rejects(verifier(request), { code: 'SOURCE_FENCE_UNVERIFIED' });
  mismatch = false; privacyMismatch = true; await assert.rejects(verifier(request), { code: 'SOURCE_FENCE_UNVERIFIED' });
  privacyMismatch = false; privacyMissing = true; await assert.rejects(verifier(request), { code: 'SOURCE_FENCE_UNVERIFIED' });
  await privacy.request(owner, { kind: 'delete', subject: { kind: 'document', id: 'doc' } });
  assert.notEqual(await privacyInventoryDigest({ store, realm: 'gateway' }), targetPrivacyDigest);
});

test('retention cannot expire permanent privacy authority and legal holds serialize with physical pruning', async (t) => {
  const { store, jobs } = await fixture(t); let time = Date.now();
  const privacy = createPrivacyService({ store, jobs, now: () => time, policy: { retentionMs: { privacy: 1 } } });
  const subject = { kind: 'document', id: 'deleted-doc' }; await privacy.request(owner, { id: 'durable', kind: 'delete', subject }); time += 10000;
  for (let batch = 0; batch < 15; batch++) await privacy.retain('company');
  await assert.rejects(privacy.assertAccessible('company', subject), { code: 'PRIVACY_SUBJECT_BLOCKED' });
  assert.equal((await privacy.status(owner, 'durable')).type, 'request');
  let entered; const start = new Promise((resolve) => { entered = resolve; }); const events = [];
  const hold = (async () => { await start; await privacy.hold(owner, { subject: { kind: 'document', id: 'hold-doc' }, reason: 'synthetic retention race' }); events.push('hold-ack'); })();
  const wrapped = { ...store, async purgeExpired(...args) { entered(); await new Promise((resolve) => setTimeout(resolve, 10)); const removed = await store.purgeExpired(...args); events.push('purged'); return removed; } };
  const operations = await createConfiguredOperations({ config: { role: 'worker', storage: { retentionMs: 60000 }, worker: {}, services: {} }, material: { auditKey: randomBytes(32) }, store: wrapped });
  await operations.handlers.retention({ tenantId: 'company', payload: {} }); await hold;
  assert.deepEqual(events, ['purged', 'hold-ack']); await operations.close();
});
test('a parent cannot release child-authored memory after the child actor is tombstoned', async (t) => {
  const { store, privacy } = await fixture(t);
  await store.put('company', 'memory', 'child-note', { id: 'child-note', actorId: 'child', rootTaskId: 'root', tenantId: 'company', sourceDocumentIds: [], label: 'internal', text: 'synthetic child data', expiresAt: Date.now() + 60000 });
  await privacy.request(owner, { kind: 'delete', subject: { kind: 'actor', id: 'child' } });
  const memory = createMemoryService({ store, policy: { getTask: async () => ({ rootTaskId: 'root', documentIds: [], maxSensitivity: 'internal' }) }, assertAccessible: privacy.assertAccessible });
  await assert.rejects(memory.read({ ...owner, actorId: 'parent', roles: ['agent'] }, 'parent-task', 'child-note'), { code: 'PRIVACY_SUBJECT_BLOCKED' });
});
test('ordinary memory overwrite/delete and learned-copy deletion cannot bypass an acknowledged legal hold', async (t) => {
  const { store, privacy } = await fixture(t); const agent = { ...owner, actorId: 'agent', roles: ['agent'] };
  await store.put('company', 'memory', 'held-note', { id: 'held-note', actorId: 'agent', rootTaskId: 'root', tenantId: 'company', sourceDocumentIds: ['doc'], label: 'internal', text: 'synthetic held data', expiresAt: Date.now() + 60000 });
  const memory = createMemoryService({ store, policy: { getTask: async () => ({ rootTaskId: 'root', documentIds: ['doc'], maxSensitivity: 'internal', expiresAt: Date.now() + 60000 }) }, assertAccessible: privacy.assertAccessible, assertUnheld: privacy.assertUnheld });
  const hold = await privacy.hold(owner, { subject: { kind: 'actor', id: 'agent' }, reason: 'synthetic hold' });
  await assert.rejects(memory.remove(agent, 'task', 'held-note'), { code: 'LEGAL_HOLD_ACTIVE' });
  await assert.rejects(memory.remember(agent, 'task', { id: 'held-note', text: 'overwrite', sourceId: 'doc', label: 'internal', expiresAt: Date.now() + 30000 }), { code: 'LEGAL_HOLD_ACTIVE' });
  assert.equal((await store.get('company', 'memory', 'held-note')).text, 'synthetic held data');
  await store.put('company', 'learning-examples', 'held-example', { actorId: 'agent', sourceKind: 'document', sourceId: 'doc', text: 'synthetic held training text' });
  const learning = createLearningService({ store, trustKey: createPublicKey(await pem('issuer-key')), policyDigest: 'a'.repeat(64), assertAccessible: privacy.assertAccessible, assertUnheld: privacy.assertUnheld });
  await assert.rejects(learning.discardExample(owner, 'held-example'), { code: 'LEGAL_HOLD_ACTIVE' });
  await privacy.releaseHold(owner, hold.id); assert.deepEqual(await memory.remove(agent, 'task', 'held-note'), { deleted: true });
  assert.deepEqual(await learning.discardExample(owner, 'held-example'), { deleted: true });
});

test('completed signed archive intents do not permanently prevent unrelated application-key proof', async (t) => {
  const { store, options } = await fixture(t, true); const privateKey = createPrivateKey(await pem('issuer-key')); const publicKey = createPublicKey(privateKey); const objects = new Map();
  await store.appendAudit({ tenantId: 'company', actorId: 'operator', event: 'archive.fixture' });
  const raw = openSqliteArchivePort({ path: options.path }); let result; let intent;
  try {
    const archive = createAuditArchive({ store: raw, signingKey: privateKey, publicKey, objectStorage: {
      status: () => ({ requireLock: true }), async put(input) { const reference = { id: input.id, key: input.id, versionId: 'fixture-version', purpose: 'audit' }; objects.set(input.id, input.bytes); return reference; },
      async get(reference) { return objects.get(reference.id); }, async verifyRetention() { return { verified: true, mode: 'COMPLIANCE' }; },
    } });
    result = await archive.archive('company'); intent = raw.readArchiveIntent('company', result.signedManifest.manifest.id);
  } finally { raw.close(); }
  assert.equal(intent.status, 'complete');
  const verify = createRetainedKeyVerifier({ archivePublicKey: publicKey, backupPublicKey: undefined, realm: 'local' });
  assert.deepEqual((await verify({ kind: 'archive-intent', tenantId: 'company', record: intent })).keyIds, ['current']);
  await assert.rejects(verify({ kind: 'archive-intent', tenantId: 'company', record: { ...intent, keyIds: ['old'] } }), { code: 'KEY_INVENTORY_INCOMPLETE' });
  await assert.rejects(verify({ kind: 'archive-intent', tenantId: 'company', record: { ...intent, status: 'pending' } }), { code: 'KEY_INVENTORY_INCOMPLETE' });
  const lifecycle = createKeyLifecycle({ store, verifyRetainedRecord: verify }); await lifecycle.freeze();
  assert.equal((await lifecycle.retirementProof('old')).keyDomain, 'application-realm-dek');
  await assert.rejects(lifecycle.retirementProof('current'), { code: 'KEY_STILL_REFERENCED' });
});
test('cross-subject legal holds preserve matching provenance rows and reject acknowledgement after related purge sealing', async (t) => {
  const { store, privacy } = await fixture(t);
  await store.put('company', 'memory', 'held-child-copy', { actorId: 'child', sourceDocumentIds: ['secret'], text: 'synthetic held copy' });
  const hold = await privacy.hold(owner, { subject: { kind: 'actor', id: 'child' }, reason: 'preserve child provenance' });
  const request = await privacy.request(owner, { id: 'cross-delete', kind: 'delete', subject: { kind: 'document', id: 'secret' } });
  assert.equal((await process(privacy, request)).state, 'held'); assert.ok(await store.get('company', 'memory', 'held-child-copy'));
  await privacy.releaseHold(owner, hold.id);
  await privacy.process({ tenantId: 'company', kind: 'privacy-delete', id: 'cross-resume', payload: { requestId: request.id } });
  assert.equal(await store.get('company', 'memory', 'held-child-copy'), null);
  await assert.rejects(privacy.hold(owner, { subject: { kind: 'actor', id: 'child' }, reason: 'arrived after seal' }), { code: 'PRIVACY_DELETION_IN_PROGRESS' });
  assert.equal((await process(privacy, request)).state, 'done');
});
test('source deletion immediately blocks and then removes previously exported mixed model text', async (t) => {
  const { store, privacy } = await fixture(t);
  await store.put('company', 'learning-candidates', 'mixed-model', { createdBy: 'trainer', model: { examples: [{ text: 'synthetic secret source model copy' }] }, exampleIds: ['source-example'] });
  const request = await privacy.request(owner, { id: 'trainer-export', kind: 'export', subject: { kind: 'actor', id: 'trainer' } });
  await process(privacy, request); assert.ok(JSON.stringify(await privacy.exportPage(owner, request.id)).includes('synthetic secret source model copy'));
  const deletion = await privacy.request(owner, { id: 'delete-source', kind: 'delete', subject: { kind: 'document', id: 'secret-source' } });
  await assert.rejects(privacy.exportPage(owner, request.id), { code: 'PRIVACY_MODEL_REBUILD_REQUIRED' });
  assert.equal((await process(privacy, deletion)).state, 'done'); await privacy.resetLearning(owner);
  let after = ''; let text = ''; do { const page = await privacy.exportPage(owner, request.id, { after }); text += JSON.stringify(page.items); after = page.next; } while (after);
  assert.equal(text.includes('synthetic secret source model copy'), false);
});
test('legacy maintenance CLI cannot purge another tenant or held data and cannot restore production outside quarantine', async (t) => {
  const { store, options, directory, privacy } = await fixture(t);
  await writeFile(join(directory, 'data.key'), options.encryptionKey.toString('hex'), { mode: 0o600 });
  await writeFile(join(directory, 'audit.key'), options.auditKey.toString('hex'), { mode: 0o600 });
  const pki = (name) => resolve('artifacts', `test-pki-${name}`);
  const config = { version: 1, role: 'gateway', profile: 'local-test', listen: { host: '127.0.0.1', port: 0 },
    tls: { certFile: pki('gateway-cert.pem'), keyFile: pki('gateway-key.pem'), caFile: pki('ca.pem'), requireClientCertificate: true },
    auth: { issuer: 'https://issuer.company', audience: 'gateway', jwksFile: pki('issuer-public.jwks.json'), algorithms: ['EdDSA'], maxLifetimeSeconds: 900, requireSenderBinding: true },
    storage: { backend: 'sqlite', path: options.path, encryptionKeyFile: 'data.key', auditKeyFile: 'audit.key', retentionMs: 60000 },
    signing: { privateKeyFile: pki('issuer-key.pem') }, limits: { bodyBytes: 1024, requestTimeoutMs: 3000, rateWindowMs: 1000, rateRequests: 10, maxConcurrency: 4 }, integrations: {}, protocols: {} };
  const configPath = join(directory, 'operator.json'); await writeFile(configPath, JSON.stringify(config));
  for (const tenant of ['company', 'other-company']) await store.put(tenant, 'memory', 'expired', { actorId: 'agent', text: 'synthetic expired fixture' }, { expiresAt: Date.now() - 1000 });
  const physical = (tenant) => { const db = new DatabaseSync(options.path, { readOnly: true }); try { return db.prepare("SELECT count(*) AS n FROM objects WHERE tenant=? AND namespace='memory' AND id='expired'").get(tenant).n; } finally { db.close(); } };
  const hold = await privacy.hold(owner, { subject: { kind: 'actor', id: 'agent' }, reason: 'CLI retention fixture' });
  const args = { config: configPath, tenant: 'company', before: String(Date.now() - 60000) };
  assert.equal((await runOperations({ command: 'retention', options: args })).held, true); assert.equal(physical('company'), 1); assert.equal(physical('other-company'), 1);
  await assert.rejects(runOperations({ command: 'retention', options: { config: configPath, before: args.before } }), /MISSING_OPERATIONS_ARGUMENT/);
  await privacy.releaseHold(owner, hold.id); await runOperations({ command: 'retention', options: args });
  assert.equal(physical('company'), 0); assert.equal(physical('other-company'), 1);
  const production = { ...config, profile: 'production', deployment: { receiptFile: 'missing-receipt', trustKeyFile: 'missing-trust', maxAgeMs: 1000, profileDigest: 'a'.repeat(64), imageRef: `company/runtime@sha256:${'b'.repeat(64)}` } };
  const productionPath = join(directory, 'production.json'); await writeFile(productionPath, JSON.stringify(production));
  await assert.rejects(runOperations({ command: 'restore', options: { config: productionPath } }), { code: 'PRODUCTION_RESTORE_REQUIRES_QUARANTINED_POSTGRES' });
});
