import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import canonicalize from 'canonicalize';
import { AppError, exactObject, identifier } from '../protocol.mjs';
import { verifyArchiveManifest } from './audit-archive.mjs';
const digest = (value) => createHash('sha256').update(canonicalize(value)).digest('hex');
const fail = () => { throw new AppError(400, 'INVALID_AUDIT_EVIDENCE'); };
const hex = (value) => typeof value === 'string' && /^[a-f\d]{64}$/.test(value);
/** @param {any} options */
export async function createAuditEvidencePage({ store, tenantId, signingKey, after = 0, limit = 100, through }) {
    const page = (await store.exportAudit(tenantId, { after, limit, through }));
    while (Buffer.byteLength(JSON.stringify(page.rows)) > 512 * 1024 && page.rows.length > 1)
        page.rows.pop();
    const last = page.rows.at(-1)?.sequence ?? page.after;
    page.next = last < page.checkpoint.sequence ? last : null;
    const base = page.base;
    const manifest = { version: base?.sequence > 0 ? 2 : 1, purpose: 'agent-runtime-encrypted-audit', tenantId, createdAt: Date.now(),
        checkpoint: page.checkpoint, after: page.after, next: page.next, rowsDigest: digest(page.rows) };
    if (base?.sequence > 0) manifest.base = base;
    const key = signingKey?.type === 'private' ? signingKey : createPrivateKey(signingKey);
    if (key.asymmetricKeyType !== 'ed25519')
        throw new AppError(400, 'INVALID_EVIDENCE_SIGNING_KEY');
    return { manifest, signature: sign(null, Buffer.from(canonicalize(manifest)), key).toString('base64url'), rows: page.rows };
}
/** Full prefix is mandatory. An externally pinned checkpoint additionally detects historical rollback.
 * @param {Iterable<any>} pages @param {any} options */
export function verifyAuditEvidence(pages, { publicKey, tenantId, expectedCheckpoint, archivePublicKey, expectedBase }) {
    identifier(tenantId);
    const key = publicKey?.type === 'public' ? publicKey : createPublicKey(publicKey);
    if (key.asymmetricKeyType !== 'ed25519')
        fail();
    let checkpoint;
    let sequence = 0;
    let previous = '0'.repeat(64);
    let complete = false;
    let count = 0;
    let verifiedBase;
    for (const page of pages) {
        if (complete)
            fail();
        exactObject(page, ['manifest', 'signature', 'rows']);
        const m = page.manifest;
        exactObject(m, ['version', 'purpose', 'tenantId', 'createdAt', 'checkpoint', 'after', 'next', 'rowsDigest'], m.version === 2 ? ['base'] : []);
        exactObject(m.checkpoint, ['tenantId', 'sequence', 'hash']);
        if (m.version === 2) {
            if (!archivePublicKey || !m.base) fail();
            exactObject(m.base, ['sequence', 'hash', 'reference', 'signedManifest']);
            if (!Number.isSafeInteger(m.base.sequence) || m.base.sequence < 1 || !hex(m.base.hash)) fail();
            verifyArchiveManifest(m.base.signedManifest, { publicKey: archivePublicKey, tenantId, checkpoint: { tenantId, sequence: m.base.sequence, hash: m.base.hash } });
            if (!m.base.reference || m.base.reference.purpose !== 'audit' || m.base.reference.id !== m.base.signedManifest.manifest.id) fail();
            if (count === 0) { sequence = m.base.sequence; previous = m.base.hash; verifiedBase = m.base; }
            else if (canonicalize(m.base) !== canonicalize(verifiedBase)) fail();
            if (expectedBase && canonicalize(expectedBase) !== canonicalize({ sequence: m.base.sequence, hash: m.base.hash })) fail();
        } else if (verifiedBase || expectedBase?.sequence > 0) fail();
        if (![1, 2].includes(m.version) || m.purpose !== 'agent-runtime-encrypted-audit' || m.tenantId !== tenantId || m.checkpoint.tenantId !== tenantId
            || !Number.isSafeInteger(m.createdAt) || m.createdAt <= 0 || !Number.isSafeInteger(m.checkpoint.sequence) || m.checkpoint.sequence < 0
            || !hex(m.checkpoint.hash) || !hex(m.rowsDigest) || m.after !== sequence || !Array.isArray(page.rows) || page.rows.length > 100
            || typeof page.signature !== 'string' || !/^[A-Za-z\d_-]{86}$/.test(page.signature))
            fail();
        if (!verify(null, Buffer.from(canonicalize(m)), key, Buffer.from(page.signature, 'base64url')) || digest(page.rows) !== m.rowsDigest)
            fail();
        checkpoint ??= m.checkpoint;
        if (canonicalize(checkpoint) !== canonicalize(m.checkpoint))
            fail();
        for (const row of page.rows) {
            exactObject(row, ['tenantId', 'sequence', 'previous', 'hash', 'encrypted', 'at']);
            if (row.tenantId !== tenantId || row.sequence !== sequence + 1 || row.previous !== previous || !hex(row.hash)
                || !Number.isSafeInteger(row.at) || row.at <= 0 || typeof row.encrypted !== 'string' || Buffer.byteLength(row.encrypted) > 100000)
                fail();
            const actual = digest({ tenantId, sequence: row.sequence, previous, encrypted: row.encrypted, at: row.at });
            if (actual !== row.hash)
                fail();
            sequence += 1;
            previous = actual;
        }
        if (sequence > checkpoint.sequence || m.next !== (sequence < checkpoint.sequence ? sequence : null) || m.next !== null && !page.rows.length)
            fail();
        complete = m.next === null;
        count += 1;
    }
    if (!count || !complete || sequence !== checkpoint.sequence || previous !== checkpoint.hash
        || expectedCheckpoint && canonicalize(expectedCheckpoint) !== canonicalize(checkpoint))
        fail();
    return { verified: true, tenantId, sequence, hash: previous, pages: count, encrypted: true, externallyPinnedCheckpoint: Boolean(expectedCheckpoint),
        ...(verifiedBase ? { archiveBase: { sequence: verifiedBase.sequence, hash: verifiedBase.hash }, independentlySignedArchiveBase: true, remoteRetentionChecked: false } : {}),
        claim: 'Authenticity and chain completeness relative to the pinned signer/checkpoint and independently signed archive base; remote archive availability requires separate verification.' };
}
