import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import canonicalize from 'canonicalize';
import { AppError, identifier } from '../protocol.mjs';
import { createKeyring, storageKey } from './keyring.mjs';

export const STORE_NAMESPACES = new Set(['tasks', 'approvals', 'flows', 'memory', 'incidents', 'learning-examples', 'learning-candidates',
  'learning-active', 'learning-promotions', 'operations', 'a2a', 'coverage', 'outbox', 'metadata', 'documents', 'deliveries', 'resource-operations',
  'jobs', 'leases', 'rate', 'sessions', 'privacy', 'archive', 'backups', 'secrets', 'protocol-sessions', 'rate-limits', 'object-intents', 'backup-catalogues']);
export const storeFailure = (code = 'INVALID_STORE_INPUT', status = 400) => { throw new AppError(status, code); };
export function leaseResource(value) { if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,255}$/.test(value)) storeFailure(); return value; }
export function storeScope(tenant, namespace, id) {
  identifier(tenant); identifier(namespace); if (!STORE_NAMESPACES.has(namespace)) storeFailure(); if (id !== undefined) identifier(id);
}
export function storeJson(value, maxBytes = 65536) {
  let result; try { result = canonicalize(value); } catch { storeFailure(); }
  if (typeof result !== 'string' || Buffer.byteLength(result) > maxBytes) storeFailure('STORE_VALUE_TOO_LARGE'); return result;
}
export const storeHash = (bytes) => createHash('sha256').update(bytes).digest('hex');
export function constantEqual(a, b) { const x = Buffer.from(a ?? ''); const y = Buffer.from(b ?? ''); return x.length === y.length && timingSafeEqual(x, y); }
export const objectAAD = (tenant, namespace, id, expires) => JSON.stringify(['object', tenant, namespace, id, expires]);
export const operationAAD = (tenant, id) => JSON.stringify(['operation', tenant, id]);
export const auditAAD = (tenant, sequence) => JSON.stringify(['audit', tenant, sequence]);

export function createStorageCodec({ encryptionKey, auditKey = encryptionKey, keyring }) {
  const key = storageKey(encryptionKey); const chainKey = storageKey(auditKey); const ring = keyring ? createKeyring(keyring) : null;
  return Object.freeze({
    encrypt(value, aad) {
      const text = storeJson(value); if (ring) return ring.encrypt(text, aad);
      const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', key, iv); cipher.setAAD(Buffer.from(aad));
      const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
      return JSON.stringify({ v: 1, iv: iv.toString('base64url'), data: data.toString('base64url'), tag: cipher.getAuthTag().toString('base64url') });
    },
    decrypt(value, aad) {
      if (ring) return JSON.parse(ring.decrypt(value, aad));
      try {
        const box = JSON.parse(value); if (box.v !== 1) throw new Error('version');
        const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(box.iv, 'base64url')); decipher.setAAD(Buffer.from(aad));
        decipher.setAuthTag(Buffer.from(box.tag, 'base64url'));
        return JSON.parse(Buffer.concat([decipher.update(Buffer.from(box.data, 'base64url')), decipher.final()]).toString('utf8'));
      } catch { storeFailure('STORE_INTEGRITY_ERROR', 500); }
    },
    mac: (text) => createHmac('sha256', chainKey).update(text).digest('hex'),
    usageMac: (tenant, root, count) => createHmac('sha256', chainKey).update(JSON.stringify(['usage', tenant, root, count])).digest('hex'),
    keyId: (text) => ring ? ring.keyId(text) : 'legacy', activeKeyId: ring?.activeKeyId ?? 'legacy',
    assertRetirable: (id, count) => ring ? ring.assertRetirable(id, count) : storeFailure('KEY_STILL_REFERENCED', 409),
    close() { key.fill(0); chainKey.fill(0); ring?.close(); },
  });
}
