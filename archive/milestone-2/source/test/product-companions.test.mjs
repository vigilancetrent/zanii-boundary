import test from 'node:test';
import assert from 'node:assert/strict';
import https from 'node:https';
import { once } from 'node:events';
import { readFileSync } from 'node:fs';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { decodeProtectedHeader, importJWK, jwtVerify } from 'jose';
import { createRegisterClient, credentialFileProvider } from '../src/adapters/register.mjs';
import { createPassportClient } from '../src/adapters/passport.mjs';
import { createVaultClient } from '../src/adapters/vault.mjs';
import { createConfiguredCompanions } from '../src/adapters/companions.mjs';

const tenantId = '11111111-1111-4111-8111-111111111111';
const caseId = '22222222-2222-4222-8222-222222222222';
const uploadId = '33333333-3333-4333-8333-333333333333';
const evidenceId = '44444444-4444-4444-8444-444444444444';
const operationId = '55555555-5555-4555-8555-555555555555';
const expiresAt = () => Date.now() + 60000;
const credentials = () => ({ session: 'explicit-test-session', csrfToken: 'explicit-test-csrf', expiresAt: expiresAt() });
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
async function fixture(t, handler) {
  const key = readFileSync('artifacts/test-pki-gateway-key.pem'); const cert = readFileSync('artifacts/test-pki-gateway-cert.pem');
  const ca = readFileSync('artifacts/test-pki-ca.pem'); const errors = [];
  const server = https.createServer({ key, cert }, async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk); const bytes = Buffer.concat(chunks);
    try {
      const result = await handler({ path: req.url, method: req.method, headers: req.headers, bytes,
        body: req.headers['content-type']?.startsWith('application/json') && bytes.length ? JSON.parse(bytes) : null });
      res.writeHead(result.status ?? 200, { 'content-type': 'application/json' }); res.end(JSON.stringify(result.body));
    } catch (error) { errors.push(error); res.writeHead(500, { 'content-type': 'application/json' }); res.end('{}'); }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  t.after(async () => { await new Promise((done) => server.close(done)); assert.deepEqual(errors, []); });
  return { origin: `https://127.0.0.1:${server.address().port}`, tls: { ca }, allowPrivateNetworks: true, contractOnly: true };
}
function assurance() { return { schemaVersion: 1, asOf: new Date().toISOString(), refreshedAt: new Date().toISOString(), freshness: 'fresh',
  freshnessExpiresAt: new Date(Date.now() + 1000).toISOString(), status: 'verified', reason: 'current_public_projection_match', evidenceBasis: 'self_declared', wording: 'Self declared',
  registrationId: caseId, recordVersion: 1, canonicalRecordHash: 'a'.repeat(64), projectionHash: 'b'.repeat(64) }; }

test('Register HTTPS projection checks bind query and remain assurance without dispatch authority', async (t) => {
  const options = await fixture(t, ({ path, headers, method }) => {
    assert.equal(method, 'GET'); assert.equal(headers.authorization, undefined); assert.equal(headers.cookie, undefined);
    const url = new URL(path, 'https://test'); assert.equal(url.pathname, `/v1/public/registrations/${caseId}/verification`);
    assert.equal(url.searchParams.get('recordVersion'), '1'); assert.equal(url.searchParams.get('canonicalRecordHash'), 'a'.repeat(64));
    return { body: assurance() };
  });
  const client = createRegisterClient(options);
  assert.equal(client.capabilities().status, 'pending');
  const result = await client.verifyRegistration({ registrationId: caseId, recordVersion: 1, canonicalRecordHash: 'a'.repeat(64) });
  assert.equal(result.status, 'verified'); assert.equal(result.dispatchPermit, false); assert.equal(client.capabilities().status, 'contract-validated'); assert.equal(client.capabilities().liveValidated, false);
});

test('Register uses exact protected cookie and rejects expired session and injected URLs', async () => {
  let seen;
  const client = createRegisterClient({ origin: 'https://register.example', credentials, request: async (path, init) => { seen = { path, init }; return { status: 200, body: { id: caseId, tenant_id: tenantId, state: 'published', version: 1, display_name: 'Company agent', purpose: 'support' } }; } });
  await client.getRegistration(caseId);
  assert.equal(seen.init.headers.Cookie, 'register_access=explicit-test-session'); assert.equal(seen.init.headers.Authorization, undefined);
  await assert.rejects(() => client.getRegistration('https://evil.example'));
  const expired = createRegisterClient({ origin: 'https://register.example', request: async () => assert.fail('must not dispatch'), credentials: () => ({ ...credentials(), expiresAt: 1 }) });
  await assert.rejects(() => expired.getRegistration(caseId), { code: 'COMPANION_SESSION_EXPIRED' });
  assert.throws(() => credentialFileProvider({ path: 'agent/secrets.json', agentRoot: 'agent' }), { code: 'CREDENTIAL_INSIDE_AGENT_ROOT' });
});

test('Passport challenge uses viewer token, verification explicitly rejects dispatchPermit true', async (t) => {
  const requestDigest = `sha256:${'a'.repeat(43)}`; const challengeId = 'b'.repeat(43); let dispatchPermit = false;
  const options = await fixture(t, ({ path, headers, body }) => {
    if (path === '/v1/challenges') {
      assert.equal(headers.authorization, 'Bearer explicit-viewer-token'); assert.deepEqual(body, { audience: 'runtime', requestDigest });
      return { status: 201, body: { ...body, id: challengeId, tenantId, expiresAt: new Date(expiresAt()).toISOString(), presentationFormat: 'm2m', requestedClaims: {} } };
    }
    assert.equal(path, '/v1/verify'); assert.deepEqual(Object.keys(body).sort(), ['challengeId', 'passport', 'tenantId']);
    return { body: { resultVersion: '1.0.0', passportId: caseId, decision: 'verified', asOf: new Date().toISOString(), offline: false, dispatchPermit,
      outcomes: { organisation: 'pass', agent: 'pass', presentation: 'pass', mandateCredential: 'pass', mandateScope: 'not_requested', relyingPartyPolicy: 'not_requested', executionEvidence: 'not_requested' }, components: [], reasons: [] } };
  });
  const client = createPassportClient({ ...options, viewerCredentials: () => ({ accessToken: 'explicit-viewer-token', expiresAt: expiresAt() }) });
  const challenge = await client.challenge({ audience: 'runtime', requestDigest }); assert.equal(challenge.id, challengeId);
  const input = { tenantId, challengeId, passport: { credential: 'fixture' } };
  assert.equal((await client.verify(input)).dispatchPermit, false);
  dispatchPermit = true; await assert.rejects(() => client.verify(input), { code: 'INVALID_PASSPORT_VERIFICATION' });
});

test('Passport workload DPoP binds exact raw body, method, URL, holder and pending/committed semantics', async (t) => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519'); const publicJwk = publicKey.export({ format: 'jwk' }); let committed = false; let origin;
  const options = await fixture(t, async ({ path, method, headers, bytes, body }) => {
    assert.equal(method, 'POST'); assert.equal(path, `/v1/pep/${tenantId}/${caseId}/directory-entries/team%2Fguide`);
    const protectedHeader = decodeProtectedHeader(headers.dpop); assert.equal(protectedHeader.typ, 'dpop+jwt'); assert.deepEqual(protectedHeader.jwk, publicJwk);
    const { payload } = await jwtVerify(headers.dpop, await importJWK(publicJwk, 'EdDSA'), { algorithms: ['EdDSA'], maxTokenAge: 120 });
    assert.equal(payload.htm, 'POST'); assert.equal(payload.htu, origin + path); assert.equal(payload.passport_id, caseId);
    assert.equal(payload.request_digest, `sha256:${createHash('sha256').update(bytes).digest('base64url')}`); assert.equal(body.operationId, operationId);
    return { status: committed ? 200 : 202, body: { operationId, status: committed ? 'committed' : 'unknown', executorState: committed ? 'confirmed' : 'unknown', executionEvidenceVerified: committed, dispatchPermit: false, ...(committed ? { result: { entryId: 'team/guide' } } : {}) } };
  }); origin = options.origin;
  const client = createPassportClient({ ...options, workloadCredentials: () => ({ privateKey, publicJwk, expiresAt: expiresAt() }) });
  const input = { tenantId, passportId: caseId, entryId: 'team/guide', operationId, expiresAt: new Date(expiresAt()).toISOString() };
  assert.deepEqual(await client.executeDirectoryRead(input), { status: 202, state: 'unknown', operationId });
  committed = true; assert.equal((await client.executeDirectoryRead(input)).result.entryId, 'team/guide');
});

test('Vault HTTPS case/declaration/chunk/completion matches source workflow and hashes actual bytes', async (t) => {
  const content = Buffer.from('encrypted audit evidence fixture'); const calls = [];
  const options = await fixture(t, ({ path, method, headers, body, bytes }) => {
    calls.push(path); assert.equal(headers.cookie, 'vault_session=explicit-test-session'); assert.equal(headers['x-csrf-token'], 'explicit-test-csrf');
    assert.equal(headers.origin, options.origin);
    if (path === '/v1/vault/cases') return { body: { id: caseId, tenantId, state: 'open', version: 1 } };
    if (path === `/v1/vault/cases/${caseId}/uploads`) {
      assert.equal(body.expectedSize, content.length); assert.equal(body.chunkSize, 32768); assert.equal(headers['idempotency-key'], 'evidence-request-1');
      return { body: { uploadId, chunkSize: 32768, chunkCount: 1, receivedBytes: 0, state: 'created' } };
    }
    if (path === `/v1/vault/uploads/${uploadId}/chunks/0`) {
      assert.equal(method, 'PUT'); assert.equal(headers['content-type'], 'application/octet-stream'); assert.deepEqual(bytes, content); assert.equal(headers['x-chunk-sha256'], hash(content));
      return { body: { index: 0, digest: hash(bytes), received: true, duplicate: false } };
    }
    assert.equal(path, `/v1/vault/uploads/${uploadId}/complete`); assert.equal(body.finalSha256, hash(content));
    return { body: { schemaVersion: 'difc-evidence-vault/v1', evidenceId, tenantId, caseId, sha256: hash(content), byteLength: content.length, scanState: 'pending' } };
  });
  const client = createVaultClient({ ...options, tenantId, credentials });
  assert.equal((await client.createCase({ title: 'Runtime incident', incidentType: 'data_disclosure', severity: 'high', retentionClass: 'company-policy', confidentiality: 'confidential' })).caseId, caseId);
  const evidence = await client.uploadEvidence(caseId, { filename: 'audit.json', mediaType: 'application/json', provenance: 'gateway_observed', sourceId: 'runtime', sourceTime: { timestamp: new Date().toISOString(), clockQuality: 'synchronised' }, acquisition: { method: 'runtime-export', capturePath: 'gateway-audit' } }, content, 'evidence-request-1');
  assert.equal(evidence.sha256, hash(content)); assert.equal(evidence.scanState, 'pending'); assert.equal(calls.length, 4);
  assert.equal('headers' in evidence, false); assert.equal(client.capabilities().liveValidated, false);
});

test('Companion unconfigured/expired identities and malformed provider receipts deny dispatch', async () => {
  const passport = createPassportClient({ origin: 'https://passport.example', request: async () => assert.fail('no identity') });
  assert.equal((await passport.validateLive()).status, 'unconfigured');
  await assert.rejects(() => passport.executeDirectoryRead({ tenantId, passportId: caseId, entryId: 'guide', operationId, expiresAt: new Date(expiresAt()).toISOString() }), { code: 'PASSPORT_WORKLOAD_UNCONFIGURED' });
  const vault = createVaultClient({ origin: 'https://vault.example', credentials, request: async () => ({ status: 200, body: { index: 0, digest: '0'.repeat(64), received: true, duplicate: false } }) });
  await assert.rejects(() => vault.putChunk(uploadId, 0, Buffer.from('content')), { code: 'INVALID_VAULT_CHUNK_RECEIPT' });
  const noCsrf = createVaultClient({ origin: 'https://vault.example', credentials: () => ({ session: 'session', expiresAt: expiresAt() }), request: async () => assert.fail('no csrf') });
  await assert.rejects(() => noCsrf.completeUpload(uploadId, 'a'.repeat(64)), { code: 'INVALID_COMPANION_CREDENTIAL' });
});

test('Configured companions are real clients and required dependencies remain unready before live validation', () => {
  const bundle = createConfiguredCompanions({ agentRoot: 'agent-workspace', register: { origin: 'https://register.example', required: true }, vault: { origin: 'https://vault.example' } });
  assert.equal(typeof bundle.register.verifyRegistration, 'function'); assert.equal(typeof bundle.vault.uploadEvidence, 'function');
  assert.equal(bundle.status().ready, false); assert.equal(bundle.status().services[0].status, 'pending');
  assert.equal(bundle.status().services[1].status, 'unconfigured');
  assert.throws(() => createConfiguredCompanions({ agentRoot: 'agent-workspace', register: { origin: 'https://register.example', accessToken: 'not-allowed' } }));
  assert.throws(() => createConfiguredCompanions({ agentRoot: 'agent-workspace', passport: { origin: 'https://passport.example', certificateFile: 'missing.pem' } }), { code: 'COMPANION_TLS_IDENTITY_INCOMPLETE' });
});

test('Companion observations expire and schema/transport failures invalidate prior validation', async () => {
  let mode = 'good';
  const client = createRegisterClient({ origin: 'https://register.example', request: async () => {
    if (mode === 'offline') throw new Error('network unavailable');
    const body = assurance();
    if (mode === 'stale') body.freshnessExpiresAt = new Date(1).toISOString();
    if (mode === 'malformed') body.dispatchPermit = true;
    return { status: 200, body };
  } });
  const input = { registrationId: caseId, recordVersion: 1, canonicalRecordHash: 'a'.repeat(64) };
  await client.verifyRegistration(input); assert.equal(client.capabilities().status, 'contract-validated');
  mode = 'stale'; assert.equal((await client.verifyRegistration(input)).status, 'not_verified'); assert.equal(client.capabilities().status, 'pending');
  mode = 'malformed'; await assert.rejects(() => client.verifyRegistration(input), { code: 'INVALID_REGISTER_RESPONSE' }); assert.equal(client.capabilities().status, 'failed');
  mode = 'offline'; await assert.rejects(() => client.verifyRegistration(input), { code: 'COMPANION_TRANSPORT_FAILED' }); assert.equal(client.capabilities().status, 'failed');
  const passport = createPassportClient({ origin: 'https://passport.example', tenantId, request: async () => assert.fail('cross tenant request') });
  await assert.rejects(() => passport.verify({ tenantId: caseId, challengeId: 'a'.repeat(43), passport: {} }), { code: 'COMPANION_TENANT_DENIED' });
});
