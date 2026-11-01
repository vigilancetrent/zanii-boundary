import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { createHash, createHmac, randomBytes, generateKeyPairSync } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync, rmSync, readdirSync } from 'node:fs';
import { resolve, join } from 'node:path';
import canonicalize from 'canonicalize';
import { createConfiguredObjectStorage } from '../src/adapters/object-storage.mjs';
import { createConfiguredKms } from '../src/adapters/kms.mjs';
import { createConfiguredSecretProvider } from '../src/product/secret-provider.mjs';
import { createDocumentService } from '../src/adapters/documents.mjs';
import { openStore } from '../src/product/store.mjs';
import { asAsyncStore } from '../src/product/async-store.mjs';
import { createAuditArchive, canonicalDigest } from '../src/product/audit-archive.mjs';
import { createBackupService, createSnapshotJournal } from '../src/product/backup.mjs';
import { createAuditEvidencePage, verifyAuditEvidence } from '../src/product/evidence.mjs';
import { AppError } from '../src/protocol.mjs';
import { PGlite } from '@electric-sql/pglite';
import { migratePostgres } from '../src/product/migrations.mjs';
import { openPostgresStore, openPostgresArchivePort, openPostgresBackupPort, restorePostgresSnapshot } from '../src/product/postgres-store.mjs';
import { createPrivacyService } from '../src/product/privacy.mjs';
import { createJobService } from '../src/product/jobs.mjs';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const hmac = (key, text) => createHmac('sha256', key).update(text).digest();
const awsSecret = 'contract-fixture-secret-no-provider-access';
const keyArn = 'arn:aws:kms:us-east-1:123456789012:key/11111111-1111-1111-1111-111111111111';
const secondArn = 'arn:aws:kms:us-east-1:123456789012:key/22222222-2222-2222-2222-222222222222';
const tenantId = 'company-a';
const keys = generateKeyPairSync('ed25519');

function verifySigV4(req, body) {
  const auth = /^AWS4-HMAC-SHA256 Credential=([^/]+)\/([^,]+), SignedHeaders=([^,]+), Signature=([a-f\d]{64})$/.exec(req.headers.authorization ?? '');
  assert.ok(auth, 'actual AWS SigV4 authorization'); assert.equal(auth[1], 'FIXTURE_ACCESS');
  const [date, region, service, terminator] = auth[2].split('/'); assert.equal(region, 'us-east-1'); assert.ok(['s3', 'kms'].includes(service)); assert.equal(terminator, 'aws4_request');
  const url = new URL(req.url, 'https://fixture'); const encode = (text) => encodeURIComponent(text).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  const query = [...url.searchParams].map(([k, v]) => [encode(k), encode(v)]).sort(([a, av], [b, bv]) => a.localeCompare(b) || av.localeCompare(bv)).map(([k, v]) => `${k}=${v}`).join('&');
  const headers = auth[3].split(';').map((name) => `${name}:${String(req.headers[name]).trim().replace(/\s+/g, ' ')}\n`).join('');
  const payloadHash = req.headers['x-amz-content-sha256'] ?? hash(body); if (payloadHash !== 'UNSIGNED-PAYLOAD') assert.equal(payloadHash, hash(body));
  const canonical = [req.method, url.pathname, query, headers, auth[3], payloadHash].join('\n');
  const stringToSign = ['AWS4-HMAC-SHA256', req.headers['x-amz-date'], auth[2], hash(canonical)].join('\n');
  const signing = hmac(hmac(hmac(hmac(`AWS4${awsSecret}`, date), region), service), 'aws4_request');
  assert.equal(hmac(signing, stringToSign).toString('hex'), auth[4], 'SigV4 signature and fixed signing scope');
}

async function fixture(t, { lock = false, maxBytes = 262144 } = {}) {
  const base = resolve('.test-data'); mkdirSync(base, { recursive: true }); const dir = mkdtempSync(join(base, 'storage-services-'));
  const file = (name) => resolve('artifacts', `test-pki-${name}.pem`);
  const write = (name, value) => { const path = join(dir, name); writeFileSync(path, value, { mode: 0o600 }); return path; };
  const credentialsFile = write('credentials.json', JSON.stringify({ accessKeyId: 'FIXTURE_ACCESS', secretAccessKey: awsSecret, expiresAt: Date.now() + 3600000 }));
  const indexKeyFile = write('index.key', randomBytes(32).toString('hex')); const encryptionKeyFile = write('encryption.key', randomBytes(32).toString('hex'));
  const contextKeyFile = write('context.key', randomBytes(32).toString('hex'));
  const objects = new Map(); const encryptedKeys = new Map(); const beforeCleanup = []; let next = 0;
  const state = { signatures: 0, wrongVersion: false, corrupt: false, wrongLock: false, slowBody: false, deny: false, destroyedSecret: false, redirect: false, overflow: false, policyInvalid: false, unavailable: false, losePutAck: false, policyDelayMs: 0, controlPlaneDelayMs: 0, requests: [] };
  const xml = (res, content, status = 200) => { res.writeHead(status, { 'content-type': 'application/xml' }); res.end(content); };
  const server = https.createServer({ ca: readFileSync(file('ca')), cert: readFileSync(file('resource-cert')), key: readFileSync(file('resource-key')), requestCert: true, rejectUnauthorized: true }, async (req, res) => {
    try {
      const chunks = []; for await (const chunk of req) chunks.push(chunk); const body = Buffer.concat(chunks);
      const url = new URL(req.url, 'https://fixture'); state.requests.push({ method: req.method, path: url.pathname, query: url.search });
      if (state.controlPlaneDelayMs && /^\/company-private\/?$/.test(url.pathname)) await new Promise((done) => setTimeout(done, state.controlPlaneDelayMs));
      if (url.pathname.startsWith('/v1/')) {
        assert.equal(req.headers['x-vault-token'], 'fixture-vault-token');
        res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ data: { data: { value: { private: 'secret' }, expiresAt: Date.now() + 10000 }, metadata: { version: 3, destroyed: state.destroyedSecret, deletion_time: '' } } })); return;
      }
      verifySigV4(req, body); state.signatures++;
      if (state.redirect) { res.writeHead(307, { location: 'https://169.254.169.254/latest/meta-data/' }); res.end(); return; }
      if (state.unavailable) { xml(res, '<Error><Code>ServiceUnavailable</Code></Error>', 503); return; }
      if (state.deny) { xml(res, '<Error><Code>AccessDenied</Code></Error>', 403); return; }
      if (req.headers['x-amz-target']) {
        const input = JSON.parse(body.toString()); const action = String(req.headers['x-amz-target']).split('.').at(-1); let output;
        if (action === 'GenerateDataKey') {
          const key = randomBytes(32); const wrapped = randomBytes(48); encryptedKeys.set(wrapped.toString('base64'), { key, context: input.EncryptionContext, keyId: input.KeyId });
          output = { Plaintext: key.toString('base64'), CiphertextBlob: wrapped.toString('base64'), KeyId: input.KeyId };
        } else {
          const saved = encryptedKeys.get(input.CiphertextBlob); assert.ok(saved);
          assert.deepEqual(saved.context, input.EncryptionContext ?? input.SourceEncryptionContext);
          if (action === 'Decrypt') output = { Plaintext: saved.key.toString('base64'), KeyId: saved.keyId };
          else { const wrapped = randomBytes(48); encryptedKeys.set(wrapped.toString('base64'), { ...saved, keyId: input.DestinationKeyId }); output = { CiphertextBlob: wrapped.toString('base64'), SourceKeyId: saved.keyId, KeyId: input.DestinationKeyId }; }
        }
        res.setHeader('content-type', 'application/x-amz-json-1.1'); res.end(JSON.stringify(output)); return;
      }
      if (url.searchParams.has('versioning')) { if (state.policyDelayMs) await new Promise((done) => setTimeout(done, state.policyDelayMs)); xml(res, `<VersioningConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>${state.policyInvalid ? 'Suspended' : 'Enabled'}</Status></VersioningConfiguration>`); return; }
      if (url.searchParams.has('encryption')) { xml(res, '<ServerSideEncryptionConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>'); return; }
      if (url.searchParams.has('publicAccessBlock')) { xml(res, '<PublicAccessBlockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">' + ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'].map((v) => `<${v}>true</${v}>`).join('') + '</PublicAccessBlockConfiguration>'); return; }
      if (url.searchParams.has('object-lock')) { xml(res, '<ObjectLockConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>'); return; }
      let object = objects.get(url.pathname);
      if (req.method === 'PUT') {
        if (object) { xml(res, '<Error><Code>PreconditionFailed</Code></Error>', 412); return; }
        assert.equal(req.headers['if-none-match'], '*'); assert.equal(req.headers['x-amz-server-side-encryption'], 'AES256');
        object = { bytes: body, version: `version-${++next}`, metadata: Object.fromEntries(Object.entries(req.headers).filter(([k]) => k.startsWith('x-amz-meta-'))), retention: req.headers['x-amz-object-lock-retain-until-date'], mode: req.headers['x-amz-object-lock-mode'] };
        objects.set(url.pathname, object); if (state.losePutAck) { state.losePutAck = false; res.destroy(); return; }
        res.writeHead(200, { 'x-amz-version-id': object.version, 'x-amz-server-side-encryption': 'AES256' }); res.end(); return;
      }
      if (!object || url.searchParams.has('versionId') && url.searchParams.get('versionId') !== object.version) { xml(res, '<Error><Code>NoSuchKey</Code></Error>', 404); return; }
      if (url.searchParams.has('retention')) { xml(res, `<Retention xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Mode>${state.wrongLock ? 'GOVERNANCE' : object.mode}</Mode><RetainUntilDate>${object.retention}</RetainUntilDate></Retention>`); return; }
      if (url.searchParams.has('legal-hold')) { xml(res, '<LegalHold xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Status>OFF</Status></LegalHold>'); return; }
      if (req.method === 'DELETE') { objects.delete(url.pathname); res.writeHead(204); res.end(); return; }
      const headers = { ...object.metadata, 'content-type': 'application/octet-stream', 'content-length': state.overflow ? maxBytes * 3 : object.bytes.length, 'x-amz-version-id': state.wrongVersion ? 'foreign-version' : object.version,
        'x-amz-server-side-encryption': 'AES256', ...(object.retention ? { 'x-amz-object-lock-mode': object.mode, 'x-amz-object-lock-retain-until-date': object.retention } : {}) };
      res.writeHead(200, headers); if (req.method === 'HEAD') { res.end(); return; }
      if (state.slowBody) { res.flushHeaders(); setTimeout(() => res.end(object.bytes), 250); return; }
      if (state.overflow) { res.end(Buffer.alloc(maxBytes * 3)); return; }
      const output = Buffer.from(object.bytes); if (state.corrupt) output[output.length - 2] ^= 1; res.end(output);
    } catch (error) { state.failure = error; res.writeHead(500); res.end(); }
  });
  await new Promise((done) => server.listen(0, '127.0.0.1', done));
  t.after(async () => { for (const close of beforeCleanup) await close(); server.closeAllConnections(); await new Promise((done) => server.close(done)); assert.ok(resolve(dir).startsWith(base)); rmSync(dir, { recursive: true, force: true }); if (state.failure) throw state.failure; });
  const connection = { endpoint: `https://127.0.0.1:${server.address().port}`, region: 'us-east-1', credentialsFile, caFile: file('ca'), certFile: file('broker-cert'), keyFile: file('broker-key'), allowPrivateNetworks: true, timeoutMs: 2000 };
  const config = { ...connection, bucket: 'company-private', indexKeyFile, encryptionKeyFile, serverEncryption: 'AES256', requireLock: lock, maxBytes };
  return { config, connection, contextKeyFile, state, objects, dir, write, beforeCleanup };
}

test('actual S3 SDK contract: SigV4, immutable version/scope/digest, idempotency and streaming deadline', async (t) => {
  const f = await fixture(t); const first = await createConfiguredObjectStorage({ ...f.config, resilience: { failureThreshold: 100, cooldownMs: 10 } }); const second = await createConfiguredObjectStorage(f.config);
  t.after(() => { first.close(); second.close(); });
  const bytes = randomBytes(150000); const ref = await first.put({ tenantId, id: 'document', bytes });
  assert.deepEqual(await second.get(ref, { tenantId }), bytes); assert.equal(f.state.signatures >= 8, true);
  assert.deepEqual(await first.put({ tenantId, id: 'document', bytes }), ref);
  await assert.rejects(first.get(ref, { tenantId: 'foreign' }), { code: 'OBJECT_SCOPE_MISMATCH' });
  await assert.rejects(first.get({ ...ref, versionId: 'foreign' }, { tenantId }), { code: 'STORAGE_NOT_FOUND' });
  f.state.wrongVersion = true; await assert.rejects(first.get(ref, { tenantId }), { code: 'OBJECT_VERSION_MISMATCH' }); f.state.wrongVersion = false;
  f.state.corrupt = true; await assert.rejects(first.get(ref, { tenantId }), { code: 'OBJECT_DIGEST_MISMATCH' }); f.state.corrupt = false;
  f.state.redirect = true; const beforeRedirect = f.state.requests.length; await assert.rejects(first.get(ref, { tenantId }), { code: 'STORAGE_PROVIDER_UNAVAILABLE' }); assert.equal(f.state.requests.length, beforeRedirect + 1); f.state.redirect = false;
  f.state.overflow = true; await assert.rejects(first.get(ref, { tenantId }), { code: 'OBJECT_TOO_LARGE' }); f.state.overflow = false;
  f.state.policyInvalid = true; await assert.rejects(first.verifyBucketPolicy(), { code: 'OBJECT_POLICY_UNVERIFIED' }); f.state.policyInvalid = false;
  f.state.slowBody = true; const started = Date.now(); await assert.rejects(first.get(ref, { tenantId, deadlineAt: started + 60 }), { code: 'STORAGE_DEADLINE' }); assert.ok(Date.now() - started < 200); f.state.slowBody = false;
  await assert.rejects(first.remove(ref, { tenantId }), { code: 'OBJECT_DELETE_NOT_AUTHORIZED' });
  assert.equal((await first.remove(ref, { tenantId, authorized: true })).removed, true);
  assert.equal((await first.remove(ref, { tenantId, authorized: true })).alreadyAbsent, true);
});

test('actual KMS SDK contract binds contexts, supports explicit rewrap and rejects foreign scope', async (t) => {
  const f = await fixture(t); const kms = await createConfiguredKms({ ...f.connection, contextKeyFile: f.contextKeyFile, keyId: keyArn, rotationKeyIds: [secondArn] }); t.after(() => kms.close());
  const context = { tenantId, id: 'doc', purpose: 'document' }; const generated = await kms.generateDataKey(context);
  assert.deepEqual(await kms.decryptDataKey(generated.envelope, context), generated.key);
  await assert.rejects(kms.decryptDataKey(generated.envelope, { ...context, tenantId: 'foreign' }), { code: 'KMS_SCOPE_MISMATCH' });
  const next = await kms.rewrapDataKey(generated.envelope, context, secondArn); assert.deepEqual(await kms.decryptDataKey(next, context), generated.key);
  await assert.rejects(kms.decryptDataKey({ ...generated.envelope, ciphertext: '#' }, context), { code: 'KMS_SCOPE_MISMATCH' });
  await assert.rejects(kms.rewrapDataKey(generated.envelope, context, keyArn), { code: 'KMS_ROTATION_KEY_DENIED' }); generated.key.fill(0);
  assert.equal(f.state.signatures, 4);
});

test('actual SDK dependency breaker opens, admits one half-open probe and cannot close from a late body', async (t) => {
  const f = await fixture(t); const objects = await createConfiguredObjectStorage({ ...f.config, resilience: { failureThreshold: 2, cooldownMs: 30 } }); t.after(() => objects.close());
  const reference = await objects.put({ tenantId, id: 'breaker', bytes: Buffer.from('private') });
  f.state.unavailable = true;
  for (let index = 0; index < 2; index++) await assert.rejects(objects.get(reference, { tenantId }), { code: 'STORAGE_PROVIDER_UNAVAILABLE' });
  assert.equal(objects.status().dependency.state, 'open'); const requests = f.state.requests.length;
  await assert.rejects(objects.get(reference, { tenantId }), { code: 'CIRCUIT_OPEN' }); assert.equal(f.state.requests.length, requests);
  await new Promise((done) => setTimeout(done, 40)); f.state.unavailable = false; f.state.slowBody = true;
  const probe = objects.get(reference, { tenantId, deadlineAt: Date.now() + 70 });
  await new Promise((done) => setTimeout(done, 15));
  await assert.rejects(objects.get(reference, { tenantId }), { code: 'CIRCUIT_OPEN' });
  await assert.rejects(probe, { code: 'STORAGE_DEADLINE' }); assert.equal(objects.status().dependency.state, 'open');
  await new Promise((done) => setTimeout(done, 270)); assert.equal(objects.status().dependency.state, 'open');
  f.state.slowBody = false; assert.equal((await objects.get(reference, { tenantId })).toString(), 'private'); assert.equal(objects.status().dependency.state, 'closed');
});

test('expired bucket policy refresh is shared while each waiter keeps its shorter deadline', async (t) => {
  const f = await fixture(t); const objects = await createConfiguredObjectStorage({ ...f.config, policyLifetimeMs: 1000 }); t.after(() => objects.close());
  const reference = await objects.put({ tenantId, id: 'cached-policy', bytes: Buffer.from('company content') });
  await new Promise((done) => setTimeout(done, 1010));
  const before = f.state.requests.filter((request) => request.query.includes('versioning')).length; f.state.policyDelayMs = 80;
  const long = objects.get(reference, { tenantId, deadlineAt: Date.now() + 700 });
  await new Promise((done) => setTimeout(done, 5)); const started = Date.now();
  const short = objects.get(reference, { tenantId, deadlineAt: started + 20 });
  const peers = Array.from({ length: 8 }, () => objects.get(reference, { tenantId, deadlineAt: Date.now() + 700 }));
  await assert.rejects(short, { code: 'STORAGE_DEADLINE' }); assert.ok(Date.now() - started < 70);
  const results = await Promise.all([long, ...peers]); assert.ok(results.every((bytes) => bytes.toString() === 'company content'));
  assert.equal(f.state.requests.filter((request) => request.query.includes('versioning')).length - before, 1);
});

test('standalone composite bucket checks share one total timeout across SDK requests', async (t) => {
  const f = await fixture(t); const objects = await createConfiguredObjectStorage({ ...f.config, timeoutMs: 100 }); t.after(() => objects.close());
  f.state.controlPlaneDelayMs = 60; const started = Date.now();
  await assert.rejects(objects.verifyBucketPolicy(), { code: 'STORAGE_DEADLINE' });
  assert.ok(Date.now() - started < 180);
});

test('S3 encrypted objects use actual KMS DEKs and a foreign context cannot decrypt them', async (t) => {
  const f = await fixture(t); const config = { ...f.config, kms: { ...f.connection, contextKeyFile: f.contextKeyFile, keyId: keyArn } }; delete config.encryptionKeyFile;
  const objects = await createConfiguredObjectStorage(config); t.after(() => objects.close());
  const bytes = randomBytes(90000); const reference = await objects.put({ tenantId, id: 'kms-document', bytes });
  assert.equal(reference.keyId, keyArn); assert.deepEqual(await objects.get(reference, { tenantId }), bytes);
  await assert.rejects(objects.get(reference, { tenantId: 'other-company' }), { code: 'OBJECT_SCOPE_MISMATCH' });
  assert.equal(f.state.requests.filter((request) => request.path === '/').length, 2);
});

test('file and actual Vault KV2 TLS secrets require named, live, non-deleted records', async (t) => {
  const f = await fixture(t); const secretFile = f.write('secret.json', JSON.stringify({ value: 'private', expiresAt: Date.now() + 10000 }));
  const files = await createConfiguredSecretProvider({ type: 'file', files: { company: secretFile } }); assert.equal((await files.get('company')).value, 'private');
  await assert.rejects(files.get('foreign'), { code: 'SECRET_NOT_CONFIGURED' });
  f.write('secret.json', JSON.stringify({ value: 'private', expiresAt: 1 })); await assert.rejects(files.get('company'), { code: 'SECRET_EXPIRED' });
  const vault = await createConfiguredSecretProvider({ type: 'vault-kv2', origin: f.connection.endpoint, mount: 'secret', paths: { company: 'company/token' },
    tokenFile: f.write('vault-token', 'fixture-vault-token'), caFile: f.connection.caFile, certFile: f.connection.certFile, keyFile: f.connection.keyFile, allowPrivateNetworks: true });
  assert.equal((await vault.get('company')).version, 3); f.state.destroyedSecret = true; await assert.rejects(vault.get('company'), { code: 'SECRET_PROVIDER_DENIED' });
});

test('two document instances share real encrypted objects and mailbox effects, with no content inside database metadata', async (t) => {
  const f = await fixture(t); const objects = await createConfiguredObjectStorage(f.config); t.after(() => objects.close());
  const store = asAsyncStore(openStore({ path: join(f.dir, 'documents.sqlite'), encryptionKey: randomBytes(32) })); f.beforeCleanup.push(() => store.close());
  const first = createDocumentService({ store, objectStorage: objects, internalRecipients: ['reviewer'] });
  const secondObjects = await createConfiguredObjectStorage(f.config); t.after(() => secondObjects.close());
  const second = createDocumentService({ store, objectStorage: secondObjects, internalRecipients: ['reviewer'] });
  const identity = { actorId: 'operator', tenantId, roles: ['operator'] };
  const uploaded = await first.putDocument(identity, { id: 'report', content: 'company confidential bytes', label: 'internal', allowedRecipients: ['reviewer'] });
  const context = { expectedVersion: uploaded.configurationVersion, deadlineAt: Date.now() + 5000 };
  const action = { id: 'read', kind: 'read', documentId: 'report' };
  assert.equal((await second.execute(identity, action, context)).content, 'company confidential bytes');
  assert.equal((await first.execute(identity, action, context)).content, 'company confidential bytes');
  assert.equal((await second.observe(identity, 'read')).result.content, 'company confidential bytes');
  await second.execute(identity, { id: 'share', kind: 'share', documentId: 'report', recipient: 'reviewer' }, context);
  assert.equal((await first.delivery({ actorId: 'reviewer', tenantId, roles: ['agent'] }, 'share')).content, 'company confidential bytes');
  for (const namespace of ['documents', 'deliveries', 'resource-operations']) assert.equal(JSON.stringify(await store.list(tenantId, namespace)).includes('company confidential bytes'), false);
  assert.equal((await store.list(tenantId, 'object-intents')).items.length, 0);
});

test('archive verifies actual remote COMPLIANCE lock before prefix commit; independent signer anchors evidence v2', async (t) => {
  const f = await fixture(t, { lock: true }); const objects = await createConfiguredObjectStorage(f.config);
  const row = { tenantId, sequence: 1, previous: '0'.repeat(64), encrypted: '{"v":2,"kid":"old-key"}', at: Date.now() }; row.hash = canonicalDigest(row);
  let committed; let sourcePage = { base: { sequence: 0, hash: row.previous }, rows: [row], checkpoint: { tenantId, sequence: 1, hash: row.hash } };
  const intents = new Map();
  const store = { prepareArchiveIntent: async (_tenant, value) => { if (!intents.has(value.id)) intents.set(value.id, value); return intents.get(value.id); }, readArchiveSegment: async () => structuredClone(sourcePage), commitArchivedPrefix: async (_tenant, value) => { committed = value; } };
  const archive = createAuditArchive({ store, objectStorage: objects, signingKey: keys.privateKey, publicKey: keys.publicKey }); t.after(() => archive.close());
  f.state.wrongLock = true; await assert.rejects(archive.archive(tenantId), { code: 'OBJECT_LOCK_UNVERIFIED' }); assert.equal(committed, undefined);
  f.state.wrongLock = false; const result = await archive.archive(tenantId); assert.equal(result.archived, 1); assert.equal(committed.checkpoint.sequence, 1);
  assert.equal(f.objects.size, 1, 'retry reuses first durable manifest and immutable object');
  const base = { sequence: 1, hash: row.hash, reference: result.reference, signedManifest: result.signedManifest };
  const page = await createAuditEvidencePage({ store: { exportAudit: async () => ({ base, checkpoint: { tenantId, sequence: 1, hash: row.hash }, after: 1, next: null, rows: [] }) }, tenantId, signingKey: keys.privateKey });
  assert.equal(verifyAuditEvidence([page], { publicKey: keys.publicKey, archivePublicKey: keys.publicKey, tenantId }).independentlySignedArchiveBase, true);
  assert.throws(() => verifyAuditEvidence([page], { publicKey: keys.publicKey, tenantId }));
  const tampered = structuredClone(page); tampered.manifest.base.hash = 'f'.repeat(64); assert.throws(() => verifyAuditEvidence([tampered], { publicKey: keys.publicKey, archivePublicKey: keys.publicKey, tenantId }));
  const second = { tenantId, sequence: 2, previous: row.hash, encrypted: '{"v":2,"kid":"new-key"}', at: Date.now() }; second.hash = canonicalDigest(second);
  sourcePage = { base, rows: [second], checkpoint: { tenantId, sequence: 2, hash: second.hash } };
  const next = await archive.archive(tenantId);
  assert.equal((await archive.verifyChain(next.reference, { tenantId, expectedCheckpoint: next.checkpoint })).segments, 2);
  await assert.rejects(archive.verifyChain(next.reference, { tenantId, expectedCheckpoint: { ...next.checkpoint, hash: 'f'.repeat(64) } }), { code: 'INVALID_ARCHIVE_EVIDENCE' });
  const bounded = createAuditArchive({ store, objectStorage: objects, signingKey: keys.privateKey, publicKey: keys.publicKey, verificationTimeoutMs: 60 });
  f.state.slowBody = true; const started = Date.now();
  await assert.rejects(bounded.verifyChain(next.reference, { tenantId, expectedCheckpoint: next.checkpoint }), { code: 'STORAGE_DEADLINE' });
  assert.ok(Date.now() - started < 200, 'chain derives one deadline even without a caller deadline'); f.state.slowBody = false;
});

test('document object waits recheck tombstones and concurrent versions before any effect', async (t) => {
  const f = await fixture(t); const remote = await createConfiguredObjectStorage(f.config); t.after(() => remote.close());
  const baseStore = asAsyncStore(openStore({ path: join(f.dir, 'race.sqlite'), encryptionKey: randomBytes(32) })); f.beforeCleanup.push(() => baseStore.close());
  let transactionDepth = 0; let blockAfterRead = false; let blocked = false; let raceAfterPut = false; const jobs = [];
  const store = { ...baseStore, async transaction(work, options) { return baseStore.transaction(async () => { transactionDepth++; try { return await work(); } finally { transactionDepth--; } }, options); } };
  const objectStorage = { ...remote,
    async get(...args) { assert.equal(transactionDepth, 0); const result = await remote.get(...args); if (blockAfterRead) blocked = true; return result; },
    async put(...args) { assert.equal(transactionDepth, 0); const result = await remote.put(...args); if (raceAfterPut) await store.put(tenantId, 'documents', 'report', { ...(await store.get(tenantId, 'documents', 'report')), label: 'confidential' }); return result; },
  };
  const service = createDocumentService({ store, objectStorage, enqueueMaintenance: async (_identity, value) => jobs.push(value),
    assertAccessible: async (_tenant, subject) => { if (blocked && subject.kind === 'document') throw new AppError(410, 'PRIVACY_SUBJECT_BLOCKED'); } });
  const identity = { actorId: 'operator', tenantId, roles: ['operator'] };
  const document = { id: 'report', content: 'private', label: 'internal', allowedRecipients: [] };
  const uploaded = await service.putDocument(identity, document); blockAfterRead = true;
  await assert.rejects(service.execute(identity, { id: 'late', kind: 'read', documentId: 'report' }, { expectedVersion: uploaded.configurationVersion, deadlineAt: Date.now() + 5000 }), { code: 'PRIVACY_SUBJECT_BLOCKED' });
  assert.equal(await store.get(tenantId, 'resource-operations', 'late'), null);
  blocked = false; blockAfterRead = false; raceAfterPut = true;
  await assert.rejects(service.putDocument(identity, { ...document, content: 'replacement' }), { code: 'DOCUMENT_VERSION_CHANGED' });
  assert.equal(jobs.length, 1); assert.equal(jobs[0].kind, 'object-cleanup');
  const intent = await store.get(tenantId, 'object-intents', jobs[0].payload.intentId);
  assert.equal(intent.state, 'uploaded'); assert.ok(intent.reference); assert.deepEqual(Object.keys(jobs[0].payload), ['intentId']);
});

test('lost S3 PUT acknowledgement retains a prepared intent and recovers only the digest-bound immutable version', async (t) => {
  const f = await fixture(t); const remote = await createConfiguredObjectStorage(f.config); t.after(() => remote.close());
  const store = asAsyncStore(openStore({ path: join(f.dir, 'uncertain.sqlite'), encryptionKey: randomBytes(32) })); f.beforeCleanup.push(() => store.close());
  const jobs = []; const service = createDocumentService({ store, objectStorage: remote, enqueueMaintenance: async (_identity, job) => jobs.push(job) });
  f.state.losePutAck = true;
  await assert.rejects(service.putDocument({ tenantId, actorId: 'operator', roles: ['operator'] }, { id: 'uncertain', content: 'private accepted upload', label: 'internal', allowedRecipients: [] }), { code: 'STORAGE_PROVIDER_UNAVAILABLE' });
  assert.equal(await store.get(tenantId, 'documents', 'uncertain'), null); assert.equal(f.objects.size, 1); assert.equal(jobs.length, 1);
  const intent = await store.get(tenantId, 'object-intents', jobs[0].payload.intentId); assert.equal(intent.state, 'prepared'); assert.equal(intent.reference, undefined);
  const reference = await remote.recoverUpload(intent.upload, { tenantId }); assert.ok(reference.versionId); assert.equal((await remote.get(reference, { tenantId })).toString(), 'private accepted upload');
  await assert.rejects(remote.recoverUpload({ ...intent.upload, bytes: 1 }, { tenantId }), { code: 'OBJECT_SCOPE_MISMATCH' });
  assert.equal(await remote.recoverUpload({ ...intent.upload, plaintextSha256: '0'.repeat(64) }, { tenantId }), null);
  assert.equal(f.state.requests.filter((request) => request.method === 'PUT').length, 1, 'uncertain PUT was not automatically retried');
  await remote.remove(reference, { tenantId, authorized: true }); assert.equal(f.objects.size, 0);
});

test('acknowledged document and prior-actor legal holds block direct inline and object-backed overwrites', async (t) => {
  const f = await fixture(t); const remote = await createConfiguredObjectStorage(f.config); t.after(() => remote.close());
  const store = asAsyncStore(openStore({ path: join(f.dir, 'held-documents.sqlite'), encryptionKey: randomBytes(32) })); f.beforeCleanup.push(() => store.close());
  const jobs = createJobService({ store }); const privacy = createPrivacyService({ store, jobs });
  const owner = { tenantId, actorId: 'original-author', roles: ['operator'] }; const replacement = { tenantId, actorId: 'replacement-author', roles: ['operator'] };
  for (const objectBacked of [false, true]) {
    const id = objectBacked ? 'object-held' : 'inline-held';
    const service = createDocumentService({ store, ...(objectBacked ? { objectStorage: remote, enqueueMaintenance: jobs.enqueue } : {}), assertAccessible: privacy.assertAccessible, assertUnheld: privacy.assertUnheld });
    const input = { id, content: 'original held evidence', label: 'internal', allowedRecipients: [] };
    await service.putDocument(owner, input); const original = await store.get(tenantId, 'documents', id);
    const docHold = await privacy.hold(owner, { subject: { kind: 'document', id }, reason: 'preserve company evidence' });
    await assert.rejects(service.putDocument(replacement, { ...input, content: 'destroy held evidence' }), { code: 'LEGAL_HOLD_ACTIVE' });
    assert.deepEqual(await store.get(tenantId, 'documents', id), original); await privacy.releaseHold(owner, docHold.id);
    const actorHold = await privacy.hold(owner, { subject: { kind: 'actor', id: owner.actorId }, reason: 'preserve original author evidence' });
    await assert.rejects(service.putDocument(replacement, { ...input, content: 'wash author provenance' }), { code: 'LEGAL_HOLD_ACTIVE' });
    assert.deepEqual(await store.get(tenantId, 'documents', id), original); await privacy.releaseHold(owner, actorHold.id);
    await service.putDocument(replacement, { ...input, content: 'permitted new version' });
    const updated = await store.get(tenantId, 'documents', id); assert.equal(updated.createdBy, owner.actorId); assert.equal(updated.actorId, replacement.actorId);
  }
});

test('encrypted offsite backup verifies pinned catalogue, ordered chunks and NEW target restore', async (t) => {
  const f = await fixture(t, { lock: true }); const objects = await createConfiguredObjectStorage(f.config);
  const snapshot = Buffer.from(canonicalize({ version: 1, kind: 'postgres-snapshot', tenantId, realm: 'resource', schemaVersion: 2, keyEpoch: { version: 1, activeKeyId: 'old-key', frozen: false }, tables: { objects: [{ encrypted: '{"v":2,"kid":"old-key"}' }] }, checkpoint: { tenantId, sequence: 0, hash: '0'.repeat(64) } }));
  const records = []; let restored; let exported = 0; let clock = Date.now();
  const backup = createBackupService({ store: { exportSnapshot: async () => { exported++; return snapshot; }, readBackupCatalogue: async (_tenant, id) => records.findLast((row) => row.id === id), writeBackupCatalogue: async (_tenant, value) => records.push(value) }, objectStorage: objects,
    signingKey: keys.privateKey, publicKey: keys.publicKey, now: () => clock, restoreSnapshot: async (options) => { restored = options; return { restored: true }; } }); t.after(() => backup.close());
  const output = await backup.backup(tenantId, { id: 'backup-one' }); const catalogue = { reference: output.reference, catalogueSha256: output.catalogueSha256 };
  assert.equal(records[0].status, 'pending'); assert.equal(records.at(-1).status, 'complete'); assert.equal(records.at(-1).keyIds.includes('old-key'), true);
  const capturedAt = backup.status().capturedAt; clock += 60000;
  await backup.verify(catalogue, { tenantId, expectedSha256: catalogue.catalogueSha256 });
  assert.equal(backup.status().capturedAt, capturedAt); assert.equal(backup.status().lastVerifiedAt, clock); assert.ok(backup.status().lastVerifiedAt > capturedAt);
  assert.equal((await backup.backup(tenantId, { id: 'backup-one' })).duplicate, true); assert.equal(exported, 1);
  records.push({ id: 'interrupted', status: 'pending', createdAt: Date.now(), retainUntil: Date.now() + 10000 });
  await assert.rejects(backup.backup(tenantId, { id: 'interrupted' }), { code: 'BACKUP_RECOVERY_REQUIRED' }); assert.equal(exported, 1);
  await assert.rejects(backup.verify(catalogue, { tenantId, expectedSha256: '0'.repeat(64) }), { code: 'BACKUP_PIN_REQUIRED' });
  await assert.rejects(backup.restore(catalogue, { tenantId, expectedSha256: output.catalogueSha256 }), { code: 'NEW_RESTORE_TARGET_REQUIRED' });
  assert.deepEqual(await backup.restore(catalogue, { tenantId, expectedSha256: output.catalogueSha256, allowNewTarget: true, target: { realm: 'resource' } }), { restored: true });
  assert.deepEqual(restored.snapshot, snapshot); assert.equal(restored.expectedSha256, hash(snapshot)); assert.equal(restored.allowNewTarget, true);
  f.state.corrupt = true; await assert.rejects(backup.verify(catalogue, { tenantId, expectedSha256: output.catalogueSha256 }), { code: 'OBJECT_DIGEST_MISMATCH' });
});

test('encrypted durable spool resumes an interrupted backup without resnapshotting or losing original chunk inventory', async (t) => {
  const f = await fixture(t, { lock: true, maxBytes: 131072 }); const key = randomBytes(32); const directory = join(f.dir, 'journal');
  const snapshot = Buffer.from(canonicalize({ version: 1, kind: 'postgres-snapshot', tenantId, realm: 'resource', schemaVersion: 2, keyEpoch: { version: 1, activeKeyId: 'old-key', frozen: false },
    tables: { objects: [{ encrypted: JSON.stringify({ v: 2, kid: 'old-key', data: 'unique-private-marker' + 'a'.repeat(240000) }) }] }, checkpoint: { tenantId, sequence: 0, hash: '0'.repeat(64) } }));
  const records = new Map(); let exported = 0; let uploads = 0;
  const store = { exportSnapshot: async () => { exported++; return snapshot; }, readBackupCatalogue: async (_tenant, id) => records.get(id), writeBackupCatalogue: async (_tenant, value) => records.set(value.id, value) };
  const remote = await createConfiguredObjectStorage(f.config); const journal = await createSnapshotJournal({ directory, key });
  const first = createBackupService({ store, objectStorage: { ...remote, async put(...args) { if (++uploads === 2) throw new AppError(503, 'CONTROLLED_PROVIDER_OUTAGE'); return remote.put(...args); } },
    snapshotJournal: journal, signingKey: keys.privateKey, publicKey: keys.publicKey });
  await assert.rejects(first.backup(tenantId, { id: 'resume' }), { code: 'CONTROLLED_PROVIDER_OUTAGE' }); first.close();
  assert.equal(records.get('resume').status, 'pending'); assert.equal(records.get('resume').snapshotSha256, hash(snapshot)); assert.equal(f.objects.size, 1);
  const spool = readFileSync(join(directory, readdirSync(directory)[0])); assert.equal(spool.includes(Buffer.from('unique-private-marker')), false);
  const secondRemote = await createConfiguredObjectStorage(f.config); const secondJournal = await createSnapshotJournal({ directory, key }); key.fill(0);
  const second = createBackupService({ store, objectStorage: secondRemote, snapshotJournal: secondJournal, signingKey: keys.privateKey, publicKey: keys.publicKey }); t.after(() => second.close());
  const recovered = await second.backup(tenantId, { id: 'resume' }); assert.equal(exported, 1); assert.equal(records.get('resume').status, 'complete');
  assert.equal(recovered.snapshotSha256, hash(snapshot)); assert.equal(f.objects.size, 3); assert.equal(readdirSync(directory).length, 0);
});

test('real PostgreSQL SQL ports join SDK offsite backup, ownership fencing, archive and quarantined NEW-target restore', async (t) => {
  const f = await fixture(t, { lock: true });
  async function database() {
    const db = new PGlite(); await db.waitReady; let tail = Promise.resolve();
    const pool = { async connect() { let release; const gate = new Promise((done) => { release = done; }); const prior = tail; tail = tail.then(() => gate); await prior;
      return { query(input, values) { if (typeof input === 'string' && values === undefined) return db.exec(input).then((rows) => rows.at(-1) ?? { rows: [] }); return db.query(typeof input === 'string' ? input : input.text, typeof input === 'string' ? values : input.values); }, release }; } };
    await migratePostgres({ pool, realm: 'resource' }); f.beforeCleanup.push(() => db.close()); return { db, pool };
  }
  const source = await database(); const dataKeys = { encryptionKey: randomBytes(32), auditKey: randomBytes(32) };
  const app = await openPostgresStore({ pool: source.pool, realm: 'resource', role: 'worker', ...dataKeys, sqlFixture: true }); f.beforeCleanup.push(() => app.close());
  await app.put(tenantId, 'memory', 'company', { text: 'retained company memory' }); await app.appendAudit({ tenantId, actorId: 'operator', event: 'company.created' });
  const backupPort = await openPostgresBackupPort({ pool: source.pool, realm: 'resource', sqlFixture: true }); f.beforeCleanup.push(() => backupPort.close()); assert.equal(backupPort.get, undefined);
  const remote = await createConfiguredObjectStorage(f.config); const journal = await createSnapshotJournal({ directory: join(f.dir, 'joined-journal'), key: randomBytes(32) });
  const backup = createBackupService({ store: backupPort, objectStorage: remote, snapshotJournal: journal, signingKey: keys.privateKey, publicKey: keys.publicKey, restoreSnapshot: restorePostgresSnapshot }); t.after(() => backup.close());
  const foreign = await backupPort.claimBackupLease(tenantId, 'busy-backup', { ownerId: 'other-worker', ttlMs: 10000 });
  await assert.rejects(backup.backup(tenantId, { id: 'busy-backup' }), { code: 'BACKUP_BUSY' }); await backupPort.releaseBackupLease(foreign);
  const output = await backup.backup(tenantId, { id: 'joined-backup' }); assert.equal((await backupPort.readBackupCatalogue(tenantId, 'joined-backup')).status, 'complete');
  assert.equal((await backup.backup(tenantId, { id: 'joined-backup' })).duplicate, true);
  const target = await database(); const restored = await backup.restore({ reference: output.reference, catalogueSha256: output.catalogueSha256 },
    { tenantId, expectedSha256: output.catalogueSha256, allowNewTarget: true, target: { pool: target.pool, realm: 'resource', ...dataKeys } });
  assert.equal(restored.quarantined, true);
  const opened = await openPostgresStore({ pool: target.pool, realm: 'resource', ...dataKeys, sqlFixture: true }); f.beforeCleanup.push(() => opened.close());
  assert.equal((await opened.get(tenantId, 'memory', 'company')).text, 'retained company memory'); assert.equal((await opened.restoreStatus()).quarantined, true);
  await assert.rejects(opened.put(tenantId, 'memory', 'unsafe-resume', { text: 'blocked' }), { code: 'WRITE_EPOCH_REJECTED' });
  const archivePort = await openPostgresArchivePort({ pool: source.pool, realm: 'resource', sqlFixture: true }); f.beforeCleanup.push(() => archivePort.close());
  const archiveRemote = await createConfiguredObjectStorage(f.config); const archive = createAuditArchive({ store: archivePort, objectStorage: archiveRemote, signingKey: keys.privateKey, publicKey: keys.publicKey }); t.after(() => archive.close());
  const archived = await archive.archive(tenantId); assert.equal(archived.archived, 1);
  await app.appendAudit({ tenantId, actorId: 'operator', event: 'company.after-archive' });
  const evidence = await createAuditEvidencePage({ store: app, tenantId, signingKey: keys.privateKey });
  assert.equal(verifyAuditEvidence([evidence], { tenantId, publicKey: keys.publicKey, archivePublicKey: keys.publicKey }).sequence, 2);
  assert.equal((await archive.verifyChain(archived.reference, { tenantId, expectedCheckpoint: archived.checkpoint })).fullPrefix, true);
});
