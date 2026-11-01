import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { openStore, restoreStore } from '../src/product/store.mjs';
import { createAuditEvidencePage, verifyAuditEvidence } from '../src/product/evidence.mjs';
const args = process.argv.slice(2);
if (args.length !== 2 || args[0] !== '--out')
    throw new Error('Usage: node scripts/operations-check.mjs --out <new-results.json>');
const base = resolve('.test-data');
mkdirSync(base, { recursive: true });
const directory = mkdtempSync(join(base, 'operations-check-'));
const keys = { encryptionKey: randomBytes(32), auditKey: randomBytes(32) };
const signing = generateKeyPairSync('ed25519');
const store = openStore({ path: join(directory, 'live.db'), ...keys });
let result;
try {
    const now = Date.now();
    const tenantId = 'synthetic-company';
    (await store.put(tenantId, 'tasks', 'task', { id: 'task', rootTaskId: 'task', parentId: null, actorId: 'agent', expiresAt: now + 60000, maxActions: 2 }));
    const reservation = { tenantId, taskId: 'task', operationId: 'op', actionDigest: 'synthetic-digest', policyDigest: 'synthetic-policy',
        toolVersion: '1', maxActions: 2, action: { kind: 'read', documentId: 'guide' } };
    (await store.reserveOperation(reservation));
    (await store.transitionOperation(tenantId, 'op', 'dispatched'));
    (await store.transitionOperation(tenantId, 'op', 'succeeded', { content: 'synthetic-read-result' }));
    const retention = (await store.pruneOperationResults(tenantId, { before: Date.now(), limit: 1 }));
    assert.equal(retention.removed, 1);
    assert.equal((await store.reserveOperation(reservation)).created, false);
    assert.equal((await store.getOperation(tenantId, 'op')).result, null);
    const page = (await createAuditEvidencePage({ store, tenantId, signingKey: signing.privateKey }));
    const verified = verifyAuditEvidence([page], { publicKey: signing.publicKey, tenantId, expectedCheckpoint: page.manifest.checkpoint });
    const tampered = structuredClone(page);
    tampered.rows[0].encrypted += 'changed';
    assert.throws(() => verifyAuditEvidence([tampered], { publicKey: signing.publicKey, tenantId }), { code: 'INVALID_AUDIT_EVIDENCE' });
    const backupStart = performance.now();
    const backup = (await store.backup(join(directory, 'snapshot.db')));
    const backupElapsedMs = performance.now() - backupStart;
    const restoreStart = performance.now();
    const restored = restoreStore({ backupPath: join(directory, 'snapshot.db'), path: join(directory, 'restored.db'), ...keys, expectedSha256: backup.sha256 });
    const restoreElapsedMs = performance.now() - restoreStart;
    try {
        assert.equal((await restored.getOperation(tenantId, 'op')).result, null);
        assert.equal((await restored.reserveOperation(reservation)).created, false);
        assert.equal((await restored.verifyAudit(tenantId)).hash, verified.hash);
    }
    finally {
        (await restored.close());
    }
    result = { version: 1, measuredAt: new Date().toISOString(), runtime: process.version, scope: 'single-host synthetic encrypted SQLite operations',
        backup: { bytes: backup.bytes, elapsedMs: backupElapsedMs }, restore: { elapsedMs: restoreElapsedMs, pinnedSha256Verified: true, payloadAndTombstoneVerified: true },
        audit: { sequence: verified.sequence, completeCiphertextChainVerified: true, pinnedSignerVerified: true, tamperRejected: true },
        retention: { examined: retention.examined, removed: retention.removed, replayPrevented: true },
        limitations: ['Local synthetic restore only; no remote off-site backup or disaster failover.', 'No live containment, WORM archive, or external timestamp/anchor verified.'] };
}
finally {
    (await store.close());
    keys.encryptionKey.fill(0);
    keys.auditKey.fill(0);
    assert.ok(resolve(directory).startsWith(base + sep));
    rmSync(directory, { recursive: true, force: true });
}
writeFileSync(resolve(args[1]), `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
process.stdout.write(`${JSON.stringify(result)}\n`);
