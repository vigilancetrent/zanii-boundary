import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import canonicalize from 'canonicalize';
import { AppError, exactObject, identifier, positiveInteger } from '../protocol.mjs';
import { readProtectedFile } from './secret-provider.mjs';
import { createConfiguredObjectStorage } from '../adapters/object-storage.mjs';
import { effectiveDeadline } from './context.mjs';

export const canonicalDigest = (value) => createHash('sha256').update(canonicalize(value)).digest('hex');
const hex = (value) => typeof value === 'string' && /^[a-f\d]{64}$/.test(value);
const fail = () => { throw new AppError(400, 'INVALID_ARCHIVE_EVIDENCE'); };
export function signingKeys(signingKey, publicKey) {
  const privateKey = signingKey?.type === 'private' ? signingKey : createPrivateKey(signingKey);
  const pinned = publicKey?.type === 'public' ? publicKey : createPublicKey(publicKey);
  if (privateKey.asymmetricKeyType !== 'ed25519' || pinned.asymmetricKeyType !== 'ed25519'
      || !createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).equals(pinned.export({ type: 'spki', format: 'der' }))) throw new AppError(400, 'INVALID_ARCHIVE_SIGNING_KEY');
  return { privateKey, publicKey: pinned };
}
export function signedValue(manifest, key) { return { manifest, signature: sign(null, Buffer.from(canonicalize(manifest)), key).toString('base64url') }; }
export function verifySignedValue(value, publicKey) {
  exactObject(value, ['manifest', 'signature']);
  const key = publicKey?.type === 'public' ? publicKey : createPublicKey(publicKey);
  if (key.asymmetricKeyType !== 'ed25519' || typeof value.signature !== 'string' || !/^[A-Za-z\d_-]{86}$/.test(value.signature)
      || !verify(null, Buffer.from(canonicalize(value.manifest)), key, Buffer.from(value.signature, 'base64url'))) fail();
  return value.manifest;
}
/** @param {any} signedManifest @param {any} options */
export function verifyArchiveManifest(signedManifest, { publicKey, tenantId, checkpoint } = {}) {
  const m = verifySignedValue(signedManifest, publicKey);
  exactObject(m, ['version', 'purpose', 'tenantId', 'id', 'base', 'checkpoint', 'rowsDigest', 'createdAt', 'retainUntil', 'keyIds'], ['previousReference']);
  exactObject(m.base, ['sequence', 'hash']); exactObject(m.checkpoint, ['tenantId', 'sequence', 'hash']);
  if (m.version !== 1 || m.purpose !== 'agent-runtime-audit-segment' || m.tenantId !== tenantId || m.checkpoint.tenantId !== tenantId
      || !Number.isSafeInteger(m.base.sequence) || m.base.sequence < 0 || !hex(m.base.hash) || !hex(m.checkpoint.hash)
      || !Number.isSafeInteger(m.checkpoint.sequence) || m.checkpoint.sequence <= m.base.sequence || !hex(m.rowsDigest)
      || !Number.isSafeInteger(m.createdAt) || m.createdAt <= 0 || !Number.isSafeInteger(m.retainUntil) || m.retainUntil <= m.createdAt
      || !Array.isArray(m.keyIds) || m.keyIds.length > 128 || m.keyIds.some((id) => typeof id !== 'string' || id.length > 2048)
      || checkpoint && canonicalize(checkpoint) !== canonicalize(m.checkpoint)) fail();
  identifier(m.id); return m;
}
export function verifyArchiveRows(rows, { tenantId, base, checkpoint }) {
  if (!Array.isArray(rows) || rows.length > 100 || Buffer.byteLength(canonicalize(rows)) > 1024 * 1024) fail();
  let sequence = base.sequence; let previous = base.hash;
  for (const row of rows) {
    exactObject(row, ['tenantId', 'sequence', 'previous', 'hash', 'encrypted', 'at']);
    if (row.tenantId !== tenantId || row.sequence !== sequence + 1 || row.previous !== previous || !hex(row.hash)
        || typeof row.encrypted !== 'string' || Buffer.byteLength(row.encrypted) > 100000 || !Number.isSafeInteger(row.at) || row.at <= 0
        || row.hash !== canonicalDigest({ tenantId, sequence: row.sequence, previous, encrypted: row.encrypted, at: row.at })) fail();
    sequence = row.sequence; previous = row.hash;
  }
  if (checkpoint.tenantId !== tenantId || checkpoint.sequence !== sequence || checkpoint.hash !== previous) fail();
  return { sequence, hash: previous };
}
export function encryptionKeyIds(rows) {
  return [...new Set(rows.map((row) => { try { const box = JSON.parse(row.encrypted); return box.kid ?? 'legacy-v1'; } catch { return 'legacy-v1'; } }))].sort();
}

/** The archive role reads ciphertext only. Its credential and signer must be outside the gateway role. */
export function createAuditArchive({ store, objectStorage, signingKey, publicKey, retentionMs = 31536000000, verificationTimeoutMs = 30000, now = Date.now }) {
  positiveInteger(retentionMs); positiveInteger(verificationTimeoutMs, 300000); const keys = signingKeys(signingKey, publicKey); let lastArchivedAt = null;
  if (typeof store.readArchiveSegment !== 'function' || typeof store.commitArchivedPrefix !== 'function' || !objectStorage.status().requireLock) throw new AppError(400, 'ARCHIVE_AUTHORITY_REQUIRED');
  /** @param {any} reference @param {any} options */
  async function verifyReference(reference, { tenantId, id = reference.id, deadlineAt } = {}) {
    deadlineAt = effectiveDeadline({ deadlineAt, timeoutMs: verificationTimeoutMs });
    const bytes = await objectStorage.get(reference, { tenantId, id, purpose: 'audit', deadlineAt });
    let segment; try { segment = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); } catch { fail(); }
    exactObject(segment, ['manifest', 'signature', 'rows']);
    const signedManifest = { manifest: segment.manifest, signature: segment.signature };
    const manifest = verifyArchiveManifest(signedManifest, { publicKey: keys.publicKey, tenantId });
    if (manifest.id !== id || canonicalDigest(segment.rows) !== manifest.rowsDigest || canonicalize(encryptionKeyIds(segment.rows)) !== canonicalize(manifest.keyIds)) fail();
    verifyArchiveRows(segment.rows, manifest);
    const retention = await objectStorage.verifyRetention(reference, { tenantId, id, minimumUntil: manifest.retainUntil, deadlineAt });
    if (Date.now() >= deadlineAt) throw new AppError(504, 'STORAGE_DEADLINE');
    return { verified: true, signedManifest, checkpoint: manifest.checkpoint, retention, reference };
  }
  return Object.freeze({
    /** @param {string} tenantId @param {any} options */
    async archive(tenantId, { limit = 100, through, deadlineAt } = {}) {
      identifier(tenantId); positiveInteger(limit, 100);
      deadlineAt = effectiveDeadline({ deadlineAt, timeoutMs: 300000 });
      const page = await store.readArchiveSegment(tenantId, { limit, ...(through ? { through } : {}) });
      if (!page.rows.length) return { archived: 0, checkpoint: page.checkpoint };
      while (Buffer.byteLength(canonicalize(page.rows)) > 512 * 1024 && page.rows.length > 1) page.rows.pop();
      const last = page.rows.at(-1); const base = { sequence: page.base.sequence, hash: page.base.hash };
      const checkpoint = { tenantId, sequence: last.sequence, hash: last.hash };
      verifyArchiveRows(page.rows, { tenantId, base, checkpoint });
      const createdAt = now(); const id = `audit-${base.sequence}-${checkpoint.sequence}-${checkpoint.hash.slice(0, 16)}`;
      const manifest = { version: 1, purpose: 'agent-runtime-audit-segment', tenantId, id, base, checkpoint, previousReference: page.base.reference ?? null,
        rowsDigest: canonicalDigest(page.rows), createdAt, retainUntil: createdAt + retentionMs, keyIds: encryptionKeyIds(page.rows) };
      let signedManifest = signedValue(manifest, keys.privateKey);
      if (typeof store.prepareArchiveIntent === 'function') {
        const intent = await store.prepareArchiveIntent(tenantId, { id, status: 'pending', createdAt, retainUntil: manifest.retainUntil, checkpoint, expectedBase: base, keyIds: manifest.keyIds, signedManifest });
        const retained = verifyArchiveManifest(intent.signedManifest, { publicKey: keys.publicKey, tenantId, checkpoint });
        if (canonicalize(retained.base) !== canonicalize(base) || retained.rowsDigest !== manifest.rowsDigest || canonicalize(retained.keyIds) !== canonicalize(manifest.keyIds)) fail();
        signedManifest = intent.signedManifest;
      }
      const reference = await objectStorage.put({ tenantId, id, purpose: 'audit', bytes: Buffer.from(canonicalize({ ...signedManifest, rows: page.rows })), retentionUntil: signedManifest.manifest.retainUntil }, { deadlineAt });
      // A successful PUT response is insufficient: read the pinned version, verify its signature,
      // digest and actual COMPLIANCE retention before permitting local prefix removal.
      await verifyReference(reference, { tenantId, id, deadlineAt });
      if (Date.now() >= deadlineAt) throw new AppError(504, 'STORAGE_DEADLINE');
      await store.commitArchivedPrefix(tenantId, { expectedBase: base, checkpoint, reference, signedManifest });
      lastArchivedAt = signedManifest.manifest.createdAt;
      return { archived: page.rows.length, checkpoint, reference, signedManifest };
    },
    verify: verifyReference,
    /** @param {any} reference @param {any} options */
    async verifyChain(reference, { tenantId, expectedCheckpoint, maxSegments = 10000, deadlineAt } = {}) {
      identifier(tenantId); positiveInteger(maxSegments, 10000);
      deadlineAt = effectiveDeadline({ deadlineAt, timeoutMs: verificationTimeoutMs });
      if (!expectedCheckpoint || expectedCheckpoint.tenantId !== tenantId) fail();
      let current = reference; let checkpoint = expectedCheckpoint; let segments = 0; const seen = new Set();
      while (current) {
        if (segments >= maxSegments || seen.has(current.versionId + ':' + current.key)) fail();
        seen.add(current.versionId + ':' + current.key);
        const result = await verifyReference(current, { tenantId, deadlineAt }); const manifest = result.signedManifest.manifest;
        if (canonicalize(checkpoint) !== canonicalize(manifest.checkpoint)) fail();
        checkpoint = { tenantId, sequence: manifest.base.sequence, hash: manifest.base.hash };
        current = manifest.previousReference; segments++;
      }
      if (checkpoint.sequence !== 0 || checkpoint.hash !== '0'.repeat(64)) fail();
      return { verified: true, tenantId, checkpoint: expectedCheckpoint, segments, fullPrefix: true, remoteRetentionChecked: true };
    },
    status: () => ({ ...objectStorage.status(), configured: true, kind: 'independent-signed-object-lock-archive', lastArchivedAt }),
    close: () => objectStorage.close(),
  });
}

/** @param {any} raw @param {any} options */
export async function createConfiguredAuditArchive(raw, { store, baseDirectory = process.cwd() }) {
  exactObject(raw, ['objectStorage', 'signingKeyFile', 'publicKeyFile'], ['retentionMs', 'verificationTimeoutMs']);
  if (typeof store.prepareArchiveIntent !== 'function') throw new AppError(400, 'ARCHIVE_INTENT_AUTHORITY_REQUIRED');
  const objectStorage = await createConfiguredObjectStorage(raw.objectStorage, { baseDirectory });
  try { return createAuditArchive({ store, objectStorage, signingKey: await readProtectedFile(raw.signingKeyFile, { baseDirectory, secret: true }),
    publicKey: await readProtectedFile(raw.publicKeyFile, { baseDirectory }), retentionMs: raw.retentionMs, verificationTimeoutMs: raw.verificationTimeoutMs }); }
  catch (error) { objectStorage.close(); throw error; }
}
