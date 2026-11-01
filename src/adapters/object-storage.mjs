import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes } from 'node:crypto';
import { S3Client, PutObjectCommand, GetObjectCommand, HeadObjectCommand, DeleteObjectCommand,
  GetBucketVersioningCommand, GetBucketEncryptionCommand, GetPublicAccessBlockCommand, GetObjectLockConfigurationCommand,
  GetObjectRetentionCommand, GetObjectLegalHoldCommand } from '@aws-sdk/client-s3';
import canonicalize from 'canonicalize';
import { z } from 'zod';
import { AppError, exactObject, identifier } from '../protocol.mjs';
import { createKeyring } from '../product/keyring.mjs';
import { effectiveDeadline } from '../product/context.mjs';
import { readKeyFile, readProtectedJson } from '../product/secret-provider.mjs';
import { awsConnectionSchema, configuredAwsConnection, awsSend, awsDependencyStatus, createConfiguredKms } from './kms.mjs';

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fail = (code, status = 503) => { throw new AppError(status, code); };
const purposes = ['document', 'audit', 'backup', 'export'];
const file = z.string().min(1).max(4096);
const refFields = ['kind', 'tenantHash', 'idHash', 'id', 'purpose', 'bucket', 'key', 'versionId', 'cipherSha256', 'plaintextSha256', 'bytes', 'contentType', 'keyId', 'serverKeyId'];

async function bodyBytes(body, maximum, deadlineAt) {
  if (!body || typeof body[Symbol.asyncIterator] !== 'function') fail('INVALID_OBJECT_BODY');
  const chunks = []; let size = 0; const timer = setTimeout(() => body.destroy?.(new AppError(504, 'STORAGE_DEADLINE')), Math.max(1, deadlineAt - Date.now())); timer.unref?.();
  try {
    for await (const chunk of body) {
      if (Date.now() >= deadlineAt) fail('STORAGE_DEADLINE', 504);
      size += chunk.length; if (size > maximum) { body.destroy?.(); fail('OBJECT_TOO_LARGE', 413); }
      chunks.push(Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
  } catch (error) { throw error instanceof AppError ? error : new AppError(Date.now() >= deadlineAt ? 504 : 503, Date.now() >= deadlineAt ? 'STORAGE_DEADLINE' : 'OBJECT_READ_FAILED'); }
  finally { clearTimeout(timer); }
}

/** Private versioned objects. Metadata is not trusted until its version and ciphertext hash match. */
export async function createConfiguredObjectStorage(raw, { baseDirectory = process.cwd() } = {}) {
  const schema = awsConnectionSchema.extend({ bucket: z.string().regex(/^(?!\d+\.\d+\.\d+\.\d+$)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/),
    prefix: z.string().regex(/^[a-z0-9][a-z0-9/-]{0,63}$/).default('runtime'), indexKeyFile: file,
    encryptionKeyFile: file.optional(), encryptionKeyId: z.string().default('objects-v1'), encryptionKeyringFile: file.optional(), kms: z.unknown().optional(),
    serverEncryption: z.enum(['aws:kms', 'AES256']).default('aws:kms'), sseKmsKeyId: z.string().min(1).max(2048).optional(),
    allowedServerKeyIds: z.array(z.string().min(1).max(2048)).max(16).default([]), requireLock: z.boolean().default(false),
    maxBytes: z.number().int().min(1).max(16 * 1024 * 1024).default(1024 * 1024), policyLifetimeMs: z.number().int().min(1000).max(60000).default(60000),
  }).strict();
  let config; try { config = schema.parse(raw); } catch { fail('INVALID_OBJECT_STORAGE_CONFIGURATION', 400); }
  if ([config.encryptionKeyFile, config.encryptionKeyringFile, config.kms].filter(Boolean).length !== 1
      || config.serverEncryption === 'aws:kms' && !config.sseKmsKeyId || config.bucket.includes('..') || config.prefix.endsWith('/')) fail('INVALID_OBJECT_STORAGE_CONFIGURATION', 400);
  const connection = await configuredAwsConnection(config, { baseDirectory });
  const client = new S3Client({ ...connection.options, forcePathStyle: true, followRegionRedirects: false,
    requestChecksumCalculation: 'WHEN_REQUIRED', responseChecksumValidation: 'WHEN_REQUIRED' });
  let indexKey;
  let keyring; let kms;
  try {
  indexKey = await readKeyFile(config.indexKeyFile, { baseDirectory });
  if (config.kms) kms = await createConfiguredKms(config.kms, { baseDirectory });
  else if (config.encryptionKeyringFile) keyring = createKeyring(await readProtectedJson(config.encryptionKeyringFile, { baseDirectory, secret: true }));
  else { const key = await readKeyFile(config.encryptionKeyFile, { baseDirectory }); keyring = createKeyring({ activeKeyId: identifier(config.encryptionKeyId), keys: { [config.encryptionKeyId]: key } }); key.fill(0); }
  } catch (error) { indexKey?.fill(0); keyring?.close(); kms?.close(); client.destroy(); connection.close(); throw error; }
  let policyExpiresAt = 0; let closed = false; let policyRefresh;
  const opaque = (value) => createHmac('sha256', indexKey).update(value).digest('hex');
  const send = (command, deadlineAt, consume = undefined) => { if (closed) fail('OBJECT_STORAGE_CLOSED'); return awsSend(client, command, { timeoutMs: config.timeoutMs, deadlineAt, dependency: 'objects', resilience: config.resilience, consume }); };
  const scope = (tenantId, id, purpose) => { identifier(tenantId); identifier(id); if (!purposes.includes(purpose)) fail('INVALID_OBJECT_PURPOSE', 400);
    return { tenantHash: opaque(`tenant:${tenantId}`), idHash: opaque(`id:${id}`), purpose }; };
  function validate(ref, { tenantId, id = ref?.id, purpose = ref?.purpose }) {
    exactObject(ref, refFields); const expected = scope(tenantId, id, purpose);
    if (ref.kind !== 'encrypted-s3-v1' || ref.bucket !== config.bucket || ref.id !== id || ref.tenantHash !== expected.tenantHash || ref.idHash !== expected.idHash
        || ref.purpose !== purpose || ref.key !== `${config.prefix}/${expected.tenantHash}/${purpose}/${opaque(`${id}:${ref.plaintextSha256}`)}`
        || !/^[a-f\d]{64}$/.test(ref.cipherSha256) || !/^[a-f\d]{64}$/.test(ref.plaintextSha256)
        || typeof ref.versionId !== 'string' || !ref.versionId || ref.versionId === 'null' || ref.versionId.length > 1024
        || !Number.isSafeInteger(ref.bytes) || ref.bytes < 0 || ref.bytes > config.maxBytes || typeof ref.contentType !== 'string' || ref.contentType.length > 128
        || typeof ref.keyId !== 'string' || typeof ref.serverKeyId !== 'string'
        || config.serverEncryption === 'aws:kms' && ![config.sseKmsKeyId, ...config.allowedServerKeyIds].includes(ref.serverKeyId)
        || config.serverEncryption === 'AES256' && ref.serverKeyId !== 'AES256') fail('OBJECT_SCOPE_MISMATCH', 403);
    return expected;
  }
  /** @param {any} options */
  async function verifyBucketPolicy({ deadlineAt } = {}) {
    deadlineAt = effectiveDeadline({ timeoutMs: config.timeoutMs, deadlineAt });
    const versioning = await send(new GetBucketVersioningCommand({ Bucket: config.bucket }), deadlineAt);
    const encryption = await send(new GetBucketEncryptionCommand({ Bucket: config.bucket }), deadlineAt);
    const access = await send(new GetPublicAccessBlockCommand({ Bucket: config.bucket }), deadlineAt);
    const rules = encryption.ServerSideEncryptionConfiguration?.Rules;
    if (versioning.Status !== 'Enabled' || !Array.isArray(rules) || !rules.some((rule) => {
      const applied = rule.ApplyServerSideEncryptionByDefault;
      return applied?.SSEAlgorithm === config.serverEncryption && (config.serverEncryption !== 'aws:kms' || applied.KMSMasterKeyID === config.sseKmsKeyId);
    }) || ['BlockPublicAcls', 'IgnorePublicAcls', 'BlockPublicPolicy', 'RestrictPublicBuckets'].some((name) => access.PublicAccessBlockConfiguration?.[name] !== true)) fail('OBJECT_POLICY_UNVERIFIED');
    if (config.requireLock) {
      const lock = await send(new GetObjectLockConfigurationCommand({ Bucket: config.bucket }), deadlineAt);
      if (lock.ObjectLockConfiguration?.ObjectLockEnabled !== 'Enabled') fail('OBJECT_LOCK_UNVERIFIED');
    }
    policyExpiresAt = Date.now() + config.policyLifetimeMs;
    return { verified: true, versioning: true, private: true, encryption: config.serverEncryption, objectLock: config.requireLock };
  }
  const ready = async (deadlineAt) => {
    if (Date.now() < policyExpiresAt) return;
    if (!policyRefresh) {
      const refresh = verifyBucketPolicy({ deadlineAt }); policyRefresh = refresh;
      refresh.finally(() => { if (policyRefresh === refresh) policyRefresh = undefined; }).catch(() => {});
    }
    let timer;
    try {
      if (Date.now() >= deadlineAt) fail('STORAGE_DEADLINE', 504);
      await Promise.race([policyRefresh, new Promise((_, reject) => { timer = setTimeout(() => reject(new AppError(504, 'STORAGE_DEADLINE')), Math.max(1, deadlineAt - Date.now())); })]);
    } finally { clearTimeout(timer); }
  };
  async function inspect(ref, context) {
    validate(ref, context);
    const result = await send(new HeadObjectCommand({ Bucket: config.bucket, Key: ref.key, VersionId: ref.versionId }), context?.deadlineAt);
    if (result.VersionId !== ref.versionId || result.Metadata?.['runtime-cipher-sha256'] !== ref.cipherSha256
        || result.Metadata?.['runtime-tenant'] !== ref.tenantHash || result.Metadata?.['runtime-id'] !== ref.idHash
        || result.ServerSideEncryption !== config.serverEncryption || config.serverEncryption === 'aws:kms' && result.SSEKMSKeyId !== ref.serverKeyId
        || config.serverEncryption === 'aws:kms' && ![config.sseKmsKeyId, ...config.allowedServerKeyIds].includes(ref.serverKeyId)) fail('OBJECT_VERSION_MISMATCH');
    return { versionId: result.VersionId, bytes: result.ContentLength, cipherSha256: ref.cipherSha256,
      retentionMode: result.ObjectLockMode ?? null, retainUntil: result.ObjectLockRetainUntilDate?.getTime?.() ?? null, legalHold: result.ObjectLockLegalHoldStatus ?? null };
  }
  async function get(ref, context) {
    validate(ref, context); const deadlineAt = effectiveDeadline({ timeoutMs: config.timeoutMs, deadlineAt: context?.deadlineAt }); await ready(deadlineAt);
    return send(new GetObjectCommand({ Bucket: config.bucket, Key: ref.key, VersionId: ref.versionId }), deadlineAt, async (result) => {
    if (result.VersionId !== ref.versionId || result.ContentEncoding || result.ContentType !== 'application/octet-stream'
        || result.Metadata?.['runtime-cipher-sha256'] !== ref.cipherSha256 || result.Metadata?.['runtime-tenant'] !== ref.tenantHash
        || result.Metadata?.['runtime-id'] !== ref.idHash || result.ServerSideEncryption !== config.serverEncryption
        || config.serverEncryption === 'aws:kms' && result.SSEKMSKeyId !== ref.serverKeyId) { result.Body?.destroy?.(); fail('OBJECT_VERSION_MISMATCH'); }
    const bytes = await bodyBytes(result.Body, config.maxBytes * 2 + 65536, deadlineAt);
    if (sha(bytes) !== ref.cipherSha256) fail('OBJECT_DIGEST_MISMATCH');
    let value; let plain;
    try {
      value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); exactObject(value, ['header', 'ciphertext']);
      exactObject(value.header, ['version', 'tenantHash', 'idHash', 'purpose', 'bytes', 'contentType', 'keyId', 'encryption']);
      const h = value.header;
      if (h.version !== 1 || h.tenantHash !== ref.tenantHash || h.idHash !== ref.idHash || h.purpose !== ref.purpose || h.bytes !== ref.bytes
          || h.contentType !== ref.contentType || h.keyId !== ref.keyId) fail('OBJECT_SCOPE_MISMATCH', 403);
      const aad = canonicalize(h);
      if (h.encryption === 'keyring' && keyring) {
        exactObject(value.ciphertext, ['chunks']);
        const parts = value.ciphertext.chunks;
        if (!Array.isArray(parts) || parts.length !== Math.max(1, Math.ceil(ref.bytes / 32768))) fail('OBJECT_CIPHERTEXT_INVALID');
        plain = Buffer.concat(parts.map((part, index) => Buffer.from(keyring.decrypt(part, canonicalize([aad, index, parts.length])), 'base64')));
      }
      else if (h.encryption === 'kms' && kms) {
        exactObject(value.ciphertext, ['iv', 'data', 'tag', 'envelope']);
        const key = await kms.decryptDataKey(value.ciphertext.envelope, { tenantId: context.tenantId, id: ref.id, purpose: ref.purpose }, { deadlineAt });
        try {
          const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(value.ciphertext.iv, 'base64url')); decipher.setAAD(Buffer.from(aad));
          decipher.setAuthTag(Buffer.from(value.ciphertext.tag, 'base64url'));
          plain = Buffer.concat([decipher.update(Buffer.from(value.ciphertext.data, 'base64url')), decipher.final()]);
        } finally { key.fill(0); }
      } else fail('OBJECT_KEY_UNAVAILABLE');
    } catch (error) { throw error instanceof AppError ? error : new AppError(503, 'OBJECT_CIPHERTEXT_INVALID'); }
    if (plain.length !== ref.bytes || sha(plain) !== ref.plaintextSha256) fail('OBJECT_DIGEST_MISMATCH');
    if (Date.now() >= deadlineAt) { plain.fill(0); fail('STORAGE_DEADLINE', 504); }
    return plain;
    });
  }
  /** @param {any} input @param {any} options */
  async function put({ tenantId, id, bytes, purpose = 'document', contentType = 'application/octet-stream', retentionUntil }, { deadlineAt } = {}) {
    if (!(bytes instanceof Uint8Array) || bytes.length > config.maxBytes || !/^[a-z0-9.+-]+\/[a-z0-9.+-]+(?:;charset=utf-8)?$/i.test(contentType)) fail('INVALID_OBJECT_INPUT', 400);
    const expected = scope(tenantId, id, purpose); const deadline = effectiveDeadline({ timeoutMs: config.timeoutMs, deadlineAt }); await ready(deadline);
    if ((config.requireLock || retentionUntil !== undefined) && (!Number.isSafeInteger(retentionUntil) || retentionUntil <= Date.now())) fail('OBJECT_RETENTION_REQUIRED', 400);
    const plainDigest = sha(bytes); const key = `${config.prefix}/${expected.tenantHash}/${purpose}/${opaque(`${id}:${plainDigest}`)}`;
    const keyId = kms ? kms.status().keyId : keyring.activeKeyId;
    const header = { version: 1, ...expected, bytes: bytes.length, contentType, keyId, encryption: kms ? 'kms' : 'keyring' };
    let ciphertext;
    if (kms) {
      const generated = await kms.generateDataKey({ tenantId, id, purpose }, { deadlineAt: deadline }); const iv = randomBytes(12);
      try { const cipher = createCipheriv('aes-256-gcm', generated.key, iv); cipher.setAAD(Buffer.from(canonicalize(header)));
        ciphertext = { iv: iv.toString('base64url'), data: Buffer.concat([cipher.update(bytes), cipher.final()]).toString('base64url'), tag: cipher.getAuthTag().toString('base64url'), envelope: generated.envelope };
      } finally { generated.key.fill(0); }
    } else {
      const count = Math.max(1, Math.ceil(bytes.length / 32768)); const chunks = [];
      for (let index = 0; index < count; index++) chunks.push(keyring.encrypt(Buffer.from(bytes.subarray(index * 32768, (index + 1) * 32768)).toString('base64'), canonicalize([canonicalize(header), index, count])));
      ciphertext = { chunks };
    }
    const encrypted = Buffer.from(canonicalize({ header, ciphertext })); const cipherDigest = sha(encrypted);
    let result;
    try {
      result = await send(new PutObjectCommand({ Bucket: config.bucket, Key: key, Body: encrypted, ContentLength: encrypted.length,
        ContentType: 'application/octet-stream', ContentMD5: createHash('md5').update(encrypted).digest('base64'), IfNoneMatch: '*',
        Metadata: { 'runtime-cipher-sha256': cipherDigest, 'runtime-tenant': expected.tenantHash, 'runtime-id': expected.idHash, 'runtime-key-id': keyId },
        ServerSideEncryption: config.serverEncryption, ...(config.sseKmsKeyId ? { SSEKMSKeyId: config.sseKmsKeyId } : {}),
        ...(retentionUntil ? { ObjectLockMode: 'COMPLIANCE', ObjectLockRetainUntilDate: new Date(retentionUntil) } : {}) }), deadline);
    } catch (error) {
      if (!(error instanceof AppError && error.code === 'STORAGE_ALREADY_EXISTS')) throw error;
      const existing = await send(new HeadObjectCommand({ Bucket: config.bucket, Key: key }), deadline);
      const ref = { kind: 'encrypted-s3-v1', ...expected, id, bucket: config.bucket, key, versionId: existing.VersionId,
        cipherSha256: existing.Metadata?.['runtime-cipher-sha256'], plaintextSha256: plainDigest, bytes: bytes.length, contentType,
        keyId: existing.Metadata?.['runtime-key-id'] ?? keyId, serverKeyId: existing.SSEKMSKeyId ?? 'AES256' };
      if (!Buffer.from(bytes).equals(await get(ref, { tenantId, id, purpose, deadlineAt: deadline }))) fail('OBJECT_IDEMPOTENCY_CONFLICT', 409);
      return ref;
    }
    const ref = { kind: 'encrypted-s3-v1', ...expected, id, bucket: config.bucket, key, versionId: result.VersionId,
      cipherSha256: cipherDigest, plaintextSha256: plainDigest, bytes: bytes.length, contentType, keyId, serverKeyId: result.SSEKMSKeyId ?? 'AES256' };
    validate(ref, { tenantId, id, purpose }); await inspect(ref, { tenantId, id, purpose, deadlineAt: deadline }); return ref;
  }
  return Object.freeze({ put, get, inspect, verifyBucketPolicy,
    /** Trusted prepared-intent recovery: discover once, then pin and verify the exact returned version.
     * @param {any} upload @param {any} options */
    async recoverUpload(upload, { tenantId, deadlineAt } = {}) {
      exactObject(upload, ['id', 'purpose', 'bytes', 'plaintextSha256', 'contentType']);
      const expected = scope(tenantId, upload.id, upload.purpose);
      if (!Number.isSafeInteger(upload.bytes) || upload.bytes < 0 || upload.bytes > config.maxBytes || !/^[a-f\d]{64}$/.test(upload.plaintextSha256)
          || typeof upload.contentType !== 'string' || upload.contentType.length > 128) fail('INVALID_UPLOAD_INTENT', 400);
      const deadline = effectiveDeadline({ timeoutMs: config.timeoutMs, deadlineAt }); await ready(deadline);
      const key = `${config.prefix}/${expected.tenantHash}/${upload.purpose}/${opaque(`${upload.id}:${upload.plaintextSha256}`)}`;
      let result; try { result = await send(new HeadObjectCommand({ Bucket: config.bucket, Key: key }), deadline); }
      catch (error) { if (error instanceof AppError && error.code === 'STORAGE_NOT_FOUND') return null; throw error; }
      const ref = { kind: 'encrypted-s3-v1', ...expected, id: upload.id, bucket: config.bucket, key, versionId: result.VersionId,
        cipherSha256: result.Metadata?.['runtime-cipher-sha256'], plaintextSha256: upload.plaintextSha256, bytes: upload.bytes, contentType: upload.contentType,
        keyId: result.Metadata?.['runtime-key-id'], serverKeyId: result.SSEKMSKeyId ?? 'AES256' };
      const bytes = await get(ref, { tenantId, id: upload.id, purpose: upload.purpose, deadlineAt: deadline }); bytes.fill(0); return ref;
    },
    /** @param {any} ref @param {any} options */
    async verifyRetention(ref, { tenantId, id = ref.id, minimumUntil, deadlineAt } = {}) {
      if (!Number.isSafeInteger(minimumUntil) || minimumUntil <= 0) fail('INVALID_OBJECT_RETENTION', 400);
      deadlineAt = effectiveDeadline({ timeoutMs: config.timeoutMs, deadlineAt });
      validate(ref, { tenantId, id });
      const retention = await send(new GetObjectRetentionCommand({ Bucket: config.bucket, Key: ref.key, VersionId: ref.versionId }), deadlineAt);
      const hold = await send(new GetObjectLegalHoldCommand({ Bucket: config.bucket, Key: ref.key, VersionId: ref.versionId }), deadlineAt);
      if (retention.Retention?.Mode !== 'COMPLIANCE' || !(retention.Retention.RetainUntilDate instanceof Date)
          || retention.Retention.RetainUntilDate.getTime() < minimumUntil || !['ON', 'OFF'].includes(hold.LegalHold?.Status)) fail('OBJECT_LOCK_UNVERIFIED');
      return { verified: true, mode: 'COMPLIANCE', retainUntil: retention.Retention.RetainUntilDate.getTime(), legalHold: hold.LegalHold.Status };
    },
    /** @param {any} ref @param {any} options */
    async remove(ref, { tenantId, id = ref.id, deadlineAt, authorized = false } = {}) {
      if (!authorized) fail('OBJECT_DELETE_NOT_AUTHORIZED', 403); validate(ref, { tenantId, id });
      deadlineAt = effectiveDeadline({ timeoutMs: config.timeoutMs, deadlineAt });
      let info;
      try { info = await inspect(ref, { tenantId, id, deadlineAt }); }
      catch (error) { if (error instanceof AppError && error.code === 'STORAGE_NOT_FOUND') return { removed: true, versionId: ref.versionId, alreadyAbsent: true }; throw error; }
      if (info.legalHold === 'ON' || info.retainUntil && info.retainUntil > Date.now()) fail('OBJECT_RETENTION_ACTIVE', 409);
      await send(new DeleteObjectCommand({ Bucket: config.bucket, Key: ref.key, VersionId: ref.versionId }), deadlineAt);
      try { await inspect(ref, { tenantId, id, deadlineAt }); }
      catch (error) { if (error instanceof AppError && error.code === 'STORAGE_NOT_FOUND') return { removed: true, versionId: ref.versionId }; throw error; }
      fail('OBJECT_DELETE_UNCONFIRMED');
    },
    status: () => ({ configured: true, kind: 'encrypted-s3', ready: !closed && policyExpiresAt > Date.now() && awsDependencyStatus(client).state === 'closed', policyExpiresAt,
      versioned: true, immutableReferences: true, requireLock: config.requireLock, ambientCredentials: false, maxBytes: config.maxBytes, dependency: awsDependencyStatus(client) }),
    close() { if (!closed) { closed = true; client.destroy(); connection.close(); indexKey.fill(0); keyring?.close(); kms?.close(); } },
  });
}
