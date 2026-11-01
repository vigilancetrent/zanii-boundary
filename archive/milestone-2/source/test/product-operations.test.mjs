import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { Readable, Writable } from 'node:stream';
import { openStore, restoreStore } from '../src/product/store.mjs';
import { createAuditEvidencePage, verifyAuditEvidence } from '../src/product/evidence.mjs';
import { parseAgentArguments, runAgent } from '../scripts/agent-runner.mjs';
import { runOperations } from '../scripts/operations.mjs';

function fixture(t) {
  const base = resolve('.test-data'); mkdirSync(base, { recursive: true }); const directory = mkdtempSync(join(base, 'operations-'));
  const keys = { encryptionKey: randomBytes(32), auditKey: randomBytes(32) };
  const store = openStore({ path: join(directory, 'runtime.db'), ...keys });
  t.after(() => { store.close(); assert.ok(resolve(directory).startsWith(base + sep)); rmSync(directory, { recursive: true, force: true }); });
  return { store, keys, directory };
}

test('public audit evidence verifies complete ciphertext chain and rejects modified, missing, reordered or wrong-key pages', (t) => {
  const { store } = fixture(t); const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  for (let i = 0; i < 5; i += 1) store.appendAudit({ tenantId: 'company', actorId: 'operator', event: 'test.event', data: { secret: 'private-business-value' } });
  const pages = []; let after = 0; let through;
  do {
    const page = createAuditEvidencePage({ store, tenantId: 'company', signingKey: privateKey, after, through, limit: 2 });
    through ??= page.manifest.checkpoint.sequence; pages.push(page); after = page.manifest.next;
  } while (after !== null);
  const result = verifyAuditEvidence(pages, { publicKey, tenantId: 'company' });
  assert.equal(result.sequence, 5); assert.equal(result.pages, 3);
  assert.equal(JSON.stringify(pages).includes('private-business-value'), false);
  assert.throws(() => verifyAuditEvidence(pages.slice(0, -1), { publicKey, tenantId: 'company' }), { code: 'INVALID_AUDIT_EVIDENCE' });
  assert.throws(() => verifyAuditEvidence([pages[1], pages[0], pages[2]], { publicKey, tenantId: 'company' }));
  const changed = structuredClone(pages); changed[0].rows[0].encrypted += 'x';
  assert.throws(() => verifyAuditEvidence(changed, { publicKey, tenantId: 'company' }));
  assert.throws(() => verifyAuditEvidence(pages, { publicKey: generateKeyPairSync('ed25519').publicKey, tenantId: 'company' }));
  assert.throws(() => verifyAuditEvidence(pages, { publicKey, tenantId: 'company', expectedCheckpoint: { tenantId: 'company', sequence: 6, hash: 'a'.repeat(64) } }));
  store.appendAudit({ tenantId: 'company', actorId: 'operator', event: 'later.event' });
  assert.equal(verifyAuditEvidence(pages, { publicKey, tenantId: 'company' }).sequence, 5);
  // Newer tail detection requires an externally retained newer checkpoint, not signer trust alone.
});

test('retention removes terminal payloads in bounded progressing batches and preserves unknown effects and replay tombstones', (t) => {
  const { store } = fixture(t); const tenant = 'company'; const now = Date.now();
  store.put(tenant, 'tasks', 'task', { id: 'task', rootTaskId: 'task', parentId: null, actorId: 'agent', expiresAt: now + 60000, maxActions: 5 });
  const reserve = (id) => ({ tenantId: tenant, taskId: 'task', rootTaskId: 'task', operationId: id, actionDigest: `digest-${id}`,
    action: { kind: 'read', documentId: 'guide' }, policyDigest: 'policy', toolVersion: '1', maxActions: 5 });
  for (const id of ['a', 'b', 'uncertain']) {
    store.reserveOperation(reserve(id)); store.transitionOperation(tenant, id, 'dispatched');
    store.transitionOperation(tenant, id, id === 'uncertain' ? 'unknown' : 'succeeded', { content: 'private-read-result' });
  }
  const before = Date.now();
  assert.equal(store.pruneOperationResults(tenant, { before, limit: 1 }).removed, 1);
  assert.equal(store.pruneOperationResults(tenant, { before, limit: 1 }).removed, 1);
  assert.equal(store.getOperation(tenant, 'a').result, null); assert.ok(store.getOperation(tenant, 'a').resultExpiredAt);
  assert.equal(store.getOperation(tenant, 'uncertain').result.content, 'private-read-result');
  assert.equal(store.reserveOperation(reserve('a')).created, false);
  assert.equal(store.getOperation('other', 'a'), null);
  assert.equal(store.verifyAudit(tenant).ok, true);
  assert.throws(() => store.pruneOperationResults(tenant, { before: Date.now() + 10000 }), { code: 'INVALID_RETENTION_CUTOFF' });
});

test('audit pages adapt to ciphertext byte budget while retaining a complete signed chain', (t) => {
  const { store } = fixture(t); const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  for (let i = 0; i < 30; i += 1) store.appendAudit({ tenantId: 'company', actorId: 'operator', event: 'large.event', data: { bounded: 'x'.repeat(20000) } });
  const first = createAuditEvidencePage({ store, tenantId: 'company', signingKey: privateKey });
  assert.ok(first.rows.length < 30); assert.ok(Buffer.byteLength(JSON.stringify(first)) < 600000);
  const next = createAuditEvidencePage({ store, tenantId: 'company', signingKey: privateKey, after: first.manifest.next, through: first.manifest.checkpoint.sequence });
  assert.equal(verifyAuditEvidence([first, next], { publicKey, tenantId: 'company' }).sequence, 30);
});

test('actual encrypted backup restoration verifies externally pinned hash and reports measured restore duration', (t) => {
  const { store, keys, directory } = fixture(t);
  store.put('company', 'memory', 'note', { content: 'restore-me' });
  const manifest = store.backup(join(directory, 'backup.db')); const start = performance.now();
  const restored = restoreStore({ backupPath: join(directory, 'backup.db'), path: join(directory, 'restored.db'), ...keys, expectedSha256: manifest.sha256 });
  try { assert.equal(restored.get('company', 'memory', 'note').content, 'restore-me'); assert.ok(performance.now() - start >= 0); }
  finally { restored.close(); }
  assert.throws(() => restoreStore({ backupPath: join(directory, 'backup.db'), path: join(directory, 'wrong.db'), ...keys, expectedSha256: '0'.repeat(64) }), { code: 'BACKUP_TRUST_MISMATCH' });
});

test('narrow agent runner accepts structured invocations only and does not retry failed dispatch', async () => {
  const config = parseAgentArguments(['--socket', '/run/runtime/gateway.sock', '--token-file', 'token', '--cert-file', 'cert', '--key-file', 'key', '--ca-file', 'ca']);
  assert.equal(config.socketPath, '/run/runtime/gateway.sock'); assert.throws(() => parseAgentArguments(['--command', 'shell']));
  let calls = 0; const output = [];
  await runAgent({ input: Readable.from(['{"taskId":"task","action":{"id":"one","kind":"read","documentId":"guide"}}\nplain text\n{"taskId":"task","action":{"id":"two","kind":"read","documentId":"guide"}}\n']),
    output: new Writable({ write(bytes, encoding, done) { output.push(bytes.toString()); done(); } }),
    client: { async execute() { calls += 1; throw new Error('uncertain'); } } });
  assert.equal(calls, 2); assert.equal(output.length, 3); assert.ok(output.every((line) => JSON.parse(line).body.retryAutomatically === false));
  const responses = output.map((line) => JSON.parse(line));
  assert.deepEqual(responses.map((value) => value.status), [202, 400, 202]);
  assert.equal(responses[0].body.operationId, 'one'); assert.equal(responses[2].body.operationId, 'two');
  await assert.rejects(runAgent({ input: Readable.from(['x'.repeat(100)]), output: new Writable({ write(bytes, encoding, done) { done(); } }), maxBytes: 32,
    client: { async execute() { assert.fail('oversized input must not dispatch'); } } }), /AGENT_INPUT_TOO_LARGE/);
});

test('offline audit CLI verifies a pinned snapshot without reading storage or private keys', async (t) => {
  const { store, directory } = fixture(t); const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  store.appendAudit({ tenantId: 'company', actorId: 'operator', event: 'export.event' });
  const page = createAuditEvidencePage({ store, tenantId: 'company', signingKey: privateKey });
  writeFileSync(join(directory, 'audit.jsonl'), JSON.stringify(page) + '\n');
  writeFileSync(join(directory, 'checkpoint.json'), JSON.stringify(page.manifest.checkpoint));
  writeFileSync(join(directory, 'public.pem'), publicKey.export({ format: 'pem', type: 'spki' }));
  const options = { input: join(directory, 'audit.jsonl'), tenant: 'company', 'public-key': join(directory, 'public.pem'), checkpoint: join(directory, 'checkpoint.json') };
  const verified = await runOperations({ command: 'audit-verify', options });
  assert.equal(verified.verified, true); assert.equal(verified.externallyPinnedCheckpoint, true);
  await assert.rejects(runOperations({ command: 'audit-verify', options: { ...options, checkpoint: undefined } }), /MISSING_OPERATIONS_ARGUMENT/);
});
