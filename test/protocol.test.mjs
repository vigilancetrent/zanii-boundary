import { generateKeyPairSync } from 'node:crypto';
import { createServer } from 'node:http';
import test from 'node:test';
import assert from 'node:assert/strict';
import { AppError, MAX_JSON_BYTES, randomToken, signEnvelope, tokenMatches, validateAction, validateCoverage, validateTask, verifyEnvelope } from '../src/protocol.mjs';
import { listenLoopback, loopbackOrigin, readJson, requestJson, requireBearer, sendJson } from '../src/http.mjs';

const task = () => ({ id: 'task-1', actorId: 'agent-1', tenantId: 'tenant-a', documentIds: ['guide'], recipients: ['ops@company.invalid'], expiresAt: Date.now() + 60_000, maxActions: 3 });
const coverage = () => ({ version: 1, resourceId: 'resource-1', configurationVersion: 1, taskId: 'task-1', issuedAt: Date.now(), expiresAt: Date.now() + 60_000, checks: { authorizedRead: true, directDenied: true, wrongIdentityDenied: true } });
const rejects = (code) => (error) => error instanceof AppError && error.code === code;

test('action is exact, bounded and cloned; read cannot smuggle a recipient', () => {
  const input = { id: 'a1', kind: 'read', documentId: 'guide' };
  const parsed = validateAction(input);
  input.documentId = 'private';
  assert.equal(parsed.documentId, 'guide');
  assert.ok(Object.isFrozen(parsed));
  for (const bad of [{ ...input, url: 'http://example.invalid' }, { ...input, recipient: 'ops' }, { ...input, kind: 'delete' }, { ...input, id: 'x'.repeat(129) }, { ...input, documentId: null }, []]) {
    assert.throws(() => validateAction(bad), rejects('INVALID_INPUT'));
  }
  assert.throws(() => validateAction({ id: 'a1', kind: 'share', documentId: 'guide' }), rejects('INVALID_INPUT'));
});

test('task authority arrays are independently frozen and malformed arrays rejected', () => {
  const input = task();
  const parsed = validateTask(input);
  input.documentIds.push('payroll');
  assert.deepEqual(parsed.documentIds, ['guide']);
  assert.throws(() => parsed.documentIds.push('payroll'), TypeError);
  const sparse = new Array(1); sparse.extra = 'guide';
  const accessor = ['guide']; Object.defineProperty(accessor, '0', { get() { throw new Error('must not execute'); } });
  for (const documentIds of [[], ['guide', 'guide'], sparse, accessor, [...Array(65)].map((_, i) => `d${i}`)]) {
    assert.throws(() => validateTask({ ...task(), documentIds }), rejects('INVALID_INPUT'));
  }
  for (const maxActions of [0, -1, 1.5, NaN, Infinity, 10_001]) assert.throws(() => validateTask({ ...task(), maxActions }), rejects('INVALID_INPUT'));
  assert.throws(() => validateTask({ ...task(), revoked: 'false' }), rejects('INVALID_INPUT'));
});

test('coverage explicitly requires every declared check and bounds its validity', () => {
  const parsed = validateCoverage(coverage());
  assert.ok(Object.isFrozen(parsed.checks));
  assert.throws(() => validateCoverage({ ...coverage(), checks: { ...coverage().checks, directDenied: false } }), rejects('INVALID_INPUT'));
  assert.throws(() => validateCoverage({ ...coverage(), expiresAt: 1 }), rejects('INVALID_INPUT'));
  const value = coverage(); value.expiresAt = value.issuedAt + 900_001;
  assert.throws(() => validateCoverage(value), rejects('INVALID_INPUT'));
});

test('exact-byte envelopes require pinned Ed25519 key and correct purpose', () => {
  const keys = generateKeyPairSync('ed25519');
  const wrong = generateKeyPairSync('ed25519');
  const payload = coverage();
  const envelope = signEnvelope(payload, keys.privateKey);
  assert.deepEqual(verifyEnvelope(envelope, keys.publicKey), payload);
  assert.throws(() => verifyEnvelope(envelope, wrong.publicKey), rejects('INVALID_EVIDENCE'));
  assert.throws(() => verifyEnvelope(envelope, keys.publicKey, 'evidence'), rejects('INVALID_EVIDENCE'));
  assert.throws(() => verifyEnvelope({ ...envelope, publicKey: 'self-trust' }, keys.publicKey), rejects('INVALID_EVIDENCE'));
  const altered = Buffer.from(JSON.stringify({ ...payload, configurationVersion: 2 })).toString('base64url');
  assert.throws(() => verifyEnvelope({ ...envelope, payload: altered }, keys.publicKey), rejects('INVALID_EVIDENCE'));
  assert.throws(() => verifyEnvelope({ ...envelope, signature: envelope.signature + '=' }, keys.publicKey), rejects('INVALID_EVIDENCE'));
  assert.throws(() => verifyEnvelope(envelope, 'not-a-key'), rejects('INVALID_EVIDENCE'));
  assert.equal(JSON.stringify(envelope).includes('PRIVATE KEY'), false);
});

test('signer rejects undefined, nonfinite, sparse, cyclic and oversized payloads', () => {
  const { privateKey } = generateKeyPairSync('ed25519');
  const sparse = new Array(1); sparse.extra = 'value';
  const cyclic = {}; cyclic.self = cyclic;
  for (const payload of [{ a: undefined }, { a: NaN }, { a: sparse }, cyclic, { a: 'x'.repeat(MAX_JSON_BYTES) }]) {
    assert.throws(() => signEnvelope(payload, privateKey), rejects('INVALID_INPUT'));
  }
});

test('opaque credentials compare exactly and reject malformed or unbounded inputs', () => {
  const token = randomToken();
  assert.equal(tokenMatches(token, token), true);
  assert.equal(tokenMatches(randomToken(), token), false);
  for (const candidate of [undefined, null, '', 'x'.repeat(257), 123]) assert.equal(tokenMatches(candidate, token), false);
});

test('loopback origins reject arbitrary hosts, paths, credentials and redirects', async () => {
  assert.equal(loopbackOrigin('http://127.0.0.1:1234'), 'http://127.0.0.1:1234');
  for (const origin of ['https://127.0.0.1:1234', 'http://localhost:1234', 'http://127.0.0.1:1234/path', 'http://user@127.0.0.1:1234', 'http://127.0.0.1:1234?x=1']) assert.throws(() => loopbackOrigin(origin), rejects('INVALID_ORIGIN'));
  const server = await listenLoopback((_request, response) => { response.writeHead(302, { location: 'http://example.invalid' }); response.end(); });
  try { await assert.rejects(requestJson(server.origin, '/'), rejects('DOWNSTREAM_REDIRECT')); }
  finally { await server.close(); }
});

test('real HTTP validates JSON, authenticates, rejects oversized body and hides exceptions', async () => {
  const token = randomToken();
  const server = await listenLoopback(async (request, response, context) => {
    requireBearer(request, token);
    if (request.url === '/fail') throw new Error('private-credential-must-not-leak');
    sendJson(response, 200, validateAction(await readJson(request, { maxBytes: 256 })), context);
  });
  try {
    const body = { id: 'a1', kind: 'read', documentId: 'guide' };
    const good = await requestJson(server.origin, '/', { method: 'POST', token, body });
    assert.equal(good.status, 200); assert.deepEqual(good.body, body);
    assert.equal(good.headers.get('cache-control'), 'no-store');
    assert.equal((await requestJson(server.origin, '/', { method: 'POST', token: randomToken(), body })).status, 401);
    const oversized = await fetch(server.origin, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: JSON.stringify({ payload: 'x'.repeat(300) }) });
    assert.equal(oversized.status, 413);
    const malformed = await fetch(server.origin, { method: 'POST', headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' }, body: '{' });
    assert.equal(malformed.status, 400);
    const failure = await requestJson(server.origin, '/fail', { token });
    assert.equal(failure.status, 500);
    assert.equal(JSON.stringify(failure.body).includes('private-credential'), false);
    assert.ok(failure.body.error.requestId);
  } finally { await server.close(); }
});

test('downstream garbage, oversized responses and unresponsive dependency fail boundedly', async () => {
  const garbage = await listenLoopback((_request, response) => { response.writeHead(200, { 'content-type': 'application/json' }); response.end('not-json'); });
  const oversized = await listenLoopback((_request, response) => sendJson(response, 200, { data: 'x'.repeat(300) }));
  const hanging = createServer(() => {});
  await new Promise((resolve) => hanging.listen(0, '127.0.0.1', resolve));
  try {
    await assert.rejects(requestJson(garbage.origin, '/'), rejects('INVALID_DOWNSTREAM'));
    await assert.rejects(requestJson(oversized.origin, '/', { maxBytes: 100 }), rejects('DOWNSTREAM_TOO_LARGE'));
    const started = performance.now();
    await assert.rejects(requestJson(`http://127.0.0.1:${hanging.address().port}`, '/', { timeoutMs: 50 }), rejects('DEPENDENCY_UNAVAILABLE'));
    assert.ok(performance.now() - started < 2_000);
  } finally {
    await garbage.close(); await oversized.close(); hanging.closeAllConnections();
    await new Promise((resolve) => hanging.close(resolve));
  }
});
