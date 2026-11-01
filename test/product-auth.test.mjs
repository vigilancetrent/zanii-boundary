import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { SignJWT, exportJWK, generateKeyPair } from 'jose';
import { createAuthenticator, requireRole } from '../src/product/auth.mjs';
import { parseProductConfig } from '../src/product/config.mjs';

async function setup() {
  const keys = await generateKeyPair('EdDSA', { extractable: true }); const jwk = await exportJWK(keys.publicKey); jwk.kid = 'issuer-1';
  const thumb = randomBytes(32).toString('base64url');
  const auth = createAuthenticator({ issuer: 'https://issuer.invalid', audience: 'runtime', jwks: { keys: [jwk] } });
  const token = (changes = {}, header = {}) => new SignJWT({ tenant_id: 'tenant-a', roles: ['agent'], cnf: { 'x5t#S256': thumb }, ...changes })
    .setProtectedHeader({ alg: 'EdDSA', kid: 'issuer-1', ...header }).setSubject('agent-a').setIssuer('https://issuer.invalid')
    .setAudience('runtime').setIssuedAt().setJti(randomUUID()).setExpirationTime('5m').sign(keys.privateKey);
  return { auth, token, thumb, keys };
}

test('JOSE pins issuer audience key algorithm lifetime and mTLS sender identity', async () => {
  const { auth, token, thumb, keys } = await setup();
  const identity = await auth.authenticate(await token(), { certificateFingerprint: thumb });
  assert.equal(identity.actorId, 'agent-a'); assert.equal(identity.tenantId, 'tenant-a'); assert.deepEqual(identity.roles, ['agent']);
  assert.throws(() => requireRole(identity, 'operator'), { code: 'ROLE_DENIED' });
  await assert.rejects(auth.authenticate(await token(), { certificateFingerprint: randomBytes(32).toString('base64url') }), { code: 'INVALID_ACCESS_TOKEN' });
  await assert.rejects(auth.authenticate(await token()), { code: 'INVALID_ACCESS_TOKEN' });
  const wrongAudience = await new SignJWT({ tenant_id: 'tenant-a', roles: ['agent'], cnf: { 'x5t#S256': thumb } })
    .setProtectedHeader({ alg: 'EdDSA', kid: 'issuer-1' }).setIssuer('https://issuer.invalid').setAudience('other').setSubject('agent-a')
    .setIssuedAt().setJti(randomUUID()).setExpirationTime('5m').sign(keys.privateKey);
  await assert.rejects(auth.authenticate(wrongAudience, { certificateFingerprint: thumb }), { code: 'INVALID_ACCESS_TOKEN' });
});

test('expired, excessive-lifetime, unsigned and private-JWKS credentials are rejected', async () => {
  const { thumb, keys, auth } = await setup();
  for (const seconds of [-20, 1800]) {
    const jwt = await new SignJWT({ tenant_id: 'tenant-a', roles: ['agent'], cnf: { 'x5t#S256': thumb } })
      .setProtectedHeader({ alg: 'EdDSA', kid: 'issuer-1' }).setIssuer('https://issuer.invalid').setAudience('runtime').setSubject('agent-a')
      .setIssuedAt().setJti(randomUUID()).setExpirationTime(Math.floor(Date.now() / 1000) + seconds).sign(keys.privateKey);
    await assert.rejects(auth.authenticate(jwt, { certificateFingerprint: thumb }), { code: 'INVALID_ACCESS_TOKEN' });
  }
  await assert.rejects(auth.authenticate('eyJhbGciOiJub25lIn0.e30.', { certificateFingerprint: thumb }), { code: 'INVALID_ACCESS_TOKEN' });
  const privateJwk = await exportJWK(keys.privateKey);
  assert.throws(() => createAuthenticator({ issuer: 'https://issuer.invalid', audience: 'runtime', jwks: { keys: [privateJwk] } }), { code: 'INVALID_AUTH_CONFIGURATION' });
});

test('product configuration rejects silent public test profiles and incomplete production assurance', () => {
  assert.throws(() => parseProductConfig({}), { code: 'INVALID_PRODUCT_CONFIGURATION' });
  const config = { version: 1, role: 'gateway', profile: 'local-test', listen: { host: '127.0.0.1', port: 0 },
    tls: { certFile: 'cert.pem', keyFile: 'key.pem', caFile: 'ca.pem', requireClientCertificate: true },
    auth: { issuer: 'https://issuer.invalid', audience: 'runtime', jwksFile: 'jwks.json', algorithms: ['EdDSA'], requireSenderBinding: true, maxLifetimeSeconds: 900 },
    storage: { path: 'runtime.db', encryptionKeyFile: 'key.hex', auditKeyFile: 'audit.hex', retentionMs: 60_000 },
    signing: { privateKeyFile: 'signing.pem' }, limits: { bodyBytes: 65536, requestTimeoutMs: 2000, rateWindowMs: 1000, rateRequests: 20, maxConcurrency: 4 } };
  assert.equal(parseProductConfig(config).role, 'gateway');
  assert.throws(() => parseProductConfig({ ...config, listen: { host: '0.0.0.0', port: 80 } }), { code: 'INVALID_PRODUCT_CONFIGURATION' });
  assert.throws(() => parseProductConfig({ ...config, profile: 'production' }), { code: 'INVALID_PRODUCT_CONFIGURATION' });
  const deployment = { receiptFile: 'receipt.json', trustKeyFile: 'trust.pem', maxAgeMs: 60_000,
    profileDigest: 'a'.repeat(64), imageRef: `node:24@sha256:${'b'.repeat(64)}` };
  assert.equal(parseProductConfig({ ...config, profile: 'production', deployment }).deployment.profileDigest, deployment.profileDigest);
  assert.throws(() => parseProductConfig({ ...config, profile: 'production', deployment: { ...deployment, profileDigest: undefined } }), { code: 'INVALID_PRODUCT_CONFIGURATION' });
  assert.throws(() => parseProductConfig({ ...config, profile: 'production', deployment: { ...deployment, imageRef: 'node:latest' } }), { code: 'INVALID_PRODUCT_CONFIGURATION' });
  assert.throws(() => parseProductConfig({ ...config, profile: 'production', deployment: { ...deployment, maxAgeMs: 900_001 } }), { code: 'INVALID_PRODUCT_CONFIGURATION' });
  assert.throws(() => parseProductConfig({ ...config, surprise: true }), { code: 'INVALID_PRODUCT_CONFIGURATION' });
});
