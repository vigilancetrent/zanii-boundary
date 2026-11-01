import test from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { signEnvelope, sha256 } from '../src/protocol.mjs';
import { CONTAINMENT_CHECKS, deploymentDoctor, readDeploymentFiles, validateDeployment, validateImageReference, verifyDeploymentReceipt } from '../src/product/deployment.mjs';
import { validateAgentInspection, validateAuthorizedProbe, validateBackendInspection } from '../scripts/containment-check.mjs';

const fixture = await readDeploymentFiles();
const pinned = `registry.example.test/runtime@sha256:${'a'.repeat(64)}`;
const mutate = (fn) => { const value = structuredClone(fixture.compose); fn(value); return value; };

test('Linux containment template is statically verified without claiming live or image acceptance', async () => {
  const result = validateDeployment(fixture.profile, fixture.compose);
  assert.equal(result.status, 'static-verified'); assert.equal(result.liveVerified, false); assert.equal(result.imageVerified, false);
  assert.equal((await deploymentDoctor({ staticOnly: true })).liveVerified, false);
});

test('agent network, privilege, writable mounts, environment and host sockets cannot be weakened', () => {
  for (const change of [
    (v) => { v.services.agent.network_mode = 'host'; },
    (v) => { v.services.agent.stdin_open = false; },
    (v) => { v.services.agent.networks = ['backend']; },
    (v) => { v.services.agent.privileged = true; },
    (v) => { v.services.agent.user = '0:0'; },
    (v) => { v.services.agent.cap_drop = []; },
    (v) => { v.services.agent.security_opt = ['seccomp:unconfined']; },
    (v) => { v.services.agent.read_only = false; },
    (v) => { v.services.agent.volumes[0].read_only = false; },
    (v) => { v.services.agent.volumes.push({ type: 'bind', source: '/var/run/docker.sock', target: '/var/run/docker.sock' }); },
    (v) => { v.services.agent.environment.API_KEY = 'not-a-real-key'; },
    (v) => { v.services.agent.mem_limit = '0'; },
    (v) => { v.services.agent.cpus = NaN; },
  ]) assert.throws(() => validateDeployment(fixture.profile, mutate(change)));
});

test('resource and gateway secrets, config mounts and backend network are checked independently', () => {
  for (const change of [
    (v) => { v.networks.backend.internal = false; },
    (v) => { v.services.gateway.volumes[0].read_only = false; },
    (v) => { v.services.gateway.secrets.push('resource_tls_key'); },
    (v) => { v.services.resource.secrets = v.services.resource.secrets.filter((name) => name !== 'containment_receipt'); },
    (v) => { v.services.resource.volumes[4] = v.services.gateway.volumes[4]; },
    (v) => { v.secrets.gateway_tls_key.file = '${RUNTIME_PKI_DIR:?}/resource-key.pem'; },
    (v) => { v.services.resource.ports = ['8443:8443']; },
  ]) assert.throws(() => validateDeployment(fixture.profile, mutate(change)));
});

test('only full digest-pinned image references are accepted', () => {
  assert.equal(validateImageReference(pinned), pinned);
  for (const value of ['node:latest', 'node:24', `node@sha256:${'g'.repeat(64)}`, '', null]) assert.throws(() => validateImageReference(value));
});

test('containment receipts require trusted signature, all successful checks, current scope and bounded lifetime', () => {
  const keys = generateKeyPairSync('ed25519'); const wrong = generateKeyPairSync('ed25519'); const now = Date.now();
  const payload = { version: 1, profileDigest: fixture.profileDigest, runtimeDigest: 'e'.repeat(64), imageRef: pinned, imageId: `sha256:${'b'.repeat(64)}`,
    startedAt: now - 1000, completedAt: now - 100, expiresAt: now + 10000,
    engine: { serverVersion: 'test', kernel: 'test', osType: 'linux' }, checks: Object.fromEntries(CONTAINMENT_CHECKS.map((name) => [name, true])) };
  const good = signEnvelope(payload, keys.privateKey, 'containment');
  const options = { profileDigest: fixture.profileDigest, imageRef: pinned, now };
  assert.equal(verifyDeploymentReceipt(good, keys.publicKey, options).version, 1);
  assert.throws(() => verifyDeploymentReceipt(good, wrong.publicKey, options));
  assert.throws(() => verifyDeploymentReceipt(good, keys.publicKey, { ...options, profileDigest: 'c'.repeat(64) }));
  assert.throws(() => verifyDeploymentReceipt(good, keys.publicKey, { ...options, now: now + 10001 }));
  const failed = structuredClone(payload); failed.checks['external-network'] = false;
  assert.throws(() => verifyDeploymentReceipt(signEnvelope(failed, keys.privateKey, 'containment'), keys.publicKey, options));
  assert.throws(() => verifyDeploymentReceipt(signEnvelope(payload, keys.privateKey, 'experiment'), keys.publicKey, options));
});

test('live inspection parser rejects unconfined security options, host escape controls and mismatched image IDs', () => {
  const imageId = `sha256:${'b'.repeat(64)}`;
  const agent = { Image: imageId, Config: { User: '10003:2000', OpenStdin: true, Image: pinned, Env: ['NODE_ENV=production'] },
    HostConfig: { NetworkMode: 'none', Privileged: false, ReadonlyRootfs: true, CapAdd: [], CapDrop: ['ALL'],
      SecurityOpt: ['no-new-privileges:true'], PidsLimit: 64, Memory: 268435456, NanoCpus: 500000000 },
    Mounts: [{ Type: 'bind', Source: '/dedicated/socket', Destination: '/run/runtime', RW: false },
      { Type: 'bind', Source: '/dedicated/identity', Destination: '/run/identity', RW: false }] };
  assert.equal(validateAgentInspection(agent, pinned, imageId), true);
  for (const patch of [
    { SecurityOpt: ['no-new-privileges:true', 'seccomp:unconfined'] },
    { SecurityOpt: ['no-new-privileges:true', 'apparmor:unconfined'] },
    { IpcMode: 'host' }, { UsernsMode: 'host' }, { Devices: [{}] }, { DeviceRequests: [{}] }, { PortBindings: { '80/tcp': [{}] } },
  ]) assert.equal(validateAgentInspection({ ...agent, HostConfig: { ...agent.HostConfig, ...patch } }, pinned, imageId), false);
  assert.equal(validateAgentInspection({ ...agent, Image: `sha256:${'c'.repeat(64)}` }, pinned, imageId), false);
  const service = fixture.compose.services.resource;
  const backend = { ...agent, Config: { User: service.user, Image: pinned },
    HostConfig: { ...agent.HostConfig, NetworkMode: 'project_backend', Memory: 536870912, NanoCpus: 1000000000, PidsLimit: 128 },
    Mounts: [...service.volumes.map((m) => ({ Type: 'bind', Source: '/dedicated/resource', Destination: m.target, RW: m.read_only !== true })),
      ...service.secrets.map((name) => ({ Type: 'bind', Source: '/dedicated/key', Destination: `/run/secrets/${name}`, RW: false }))] };
  assert.equal(validateBackendInspection(backend, service, imageId), true);
  assert.equal(validateBackendInspection({ ...backend, HostConfig: { ...backend.HostConfig, SecurityOpt: ['no-new-privileges:true', 'seccomp:unconfined'] } }, service, imageId), false);
});

test('live doctor cannot turn a missing image into a verified deployment', async () => {
  const result = await deploymentDoctor({ imageRef: '' });
  assert.equal(result.status, 'blocked'); assert.equal(result.liveVerified, false); assert.equal(result.reason, 'PINNED_IMAGE_REQUIRED');
});

test('authorized live probe must be a bounded read with an exact response selector and digest', () => {
  const probe = { path: '/v1/actions', body: { taskId: 'diagnostic', action: { id: 'probe', kind: 'read', documentId: 'test-document' } }, selector: ['result', 'content'], sha256: 'd'.repeat(64) };
  assert.deepEqual(validateAuthorizedProbe(probe), probe);
  for (const change of [(v) => { v.body.action.kind = 'share'; }, (v) => { v.path = 'https://example.test'; }, (v) => { v.path = '/v1/execute'; },
    (v) => { v.selector = ['__proto__']; }, (v) => { v.sha256 = 'invalid'; }]) {
    const altered = structuredClone(probe); change(altered); assert.throws(() => validateAuthorizedProbe(altered));
  }
});

test('pre-receipt bootstrap accepts only the fixed public diagnostic canary', () => {
  const probe = { path: '/v1/diagnostic/read', body: {}, selector: ['canary'], sha256: sha256('agent-runtime-public-containment-canary-v1') };
  assert.deepEqual(validateAuthorizedProbe(probe), probe);
  for (const change of [(v) => { v.body.kind = 'read'; }, (v) => { v.selector = ['result', 'content']; },
    (v) => { v.sha256 = '0'.repeat(64); }, (v) => { v.path = '/v1/diagnostic/read?bypass=true'; },
    (v) => { v.path = '/v1/tasks/delete'; v.body = { taskId: 'probe', action: { id: 'one', kind: 'read', documentId: 'document' } }; }]) {
    const bad = structuredClone(probe); change(bad); assert.throws(() => validateAuthorizedProbe(bad));
  }
});

test('generated local test PKI has distinct role keys, correct CA and service host names', async () => {
  const root = new URL('../artifacts/', import.meta.url);
  const cert = (role) => readFile(new URL(`test-pki-${role}-cert.pem`, root)).then((bytes) => new X509Certificate(bytes));
  const ca = new X509Certificate(await readFile(new URL('test-pki-ca.pem', root)));
  const gateway = await cert('gateway'); const resource = await cert('resource'); const agent = await cert('agent');
  assert.equal(ca.ca, true); assert.equal(gateway.verify(ca.publicKey), true); assert.equal(resource.verify(ca.publicKey), true);
  assert.equal(agent.verify(ca.publicKey), true); assert.equal(gateway.checkHost('gateway'), 'gateway');
  assert.equal(resource.checkHost('resource'), 'resource'); assert.equal(gateway.checkIP('127.0.0.1'), '127.0.0.1');
  assert.notEqual(gateway.fingerprint256, resource.fingerprint256); assert.notEqual(agent.fingerprint256, gateway.fingerprint256);
  const broker = JSON.parse(await readFile(new URL('test-pki-broker-public.jwks.json', root), 'utf8'));
  const issuer = JSON.parse(await readFile(new URL('test-pki-issuer-public.jwks.json', root), 'utf8'));
  const gatewaySigning = createPublicKey(await readFile(new URL('test-pki-gateway-signing-public.pem', root))).export({ format: 'jwk' });
  assert.equal(broker.keys[0].kid, 'local-test-broker'); assert.equal(broker.keys[0].x, gatewaySigning.x);
  assert.notEqual(broker.keys[0].x, issuer.keys[0].x);
});
