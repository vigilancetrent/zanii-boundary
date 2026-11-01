import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { AppError, exactObject, identifier } from '../protocol.mjs';

export function storageKey(value) {
  const bytes = typeof value === 'string' && /^[a-f\d]{64}$/i.test(value) ? Buffer.from(value, 'hex') : value;
  if (!(bytes instanceof Uint8Array) || bytes.length !== 32) throw new AppError(400, 'INVALID_ENCRYPTION_KEY');
  return Buffer.from(bytes);
}

/** Rotation changes future ciphertext; existing audit bytes and their hashes stay untouched. */
export function createKeyring(spec) {
  exactObject(spec, ['activeKeyId', 'keys'], ['legacyKeyId']); identifier(spec.activeKeyId);
  if (!spec.keys || typeof spec.keys !== 'object' || Array.isArray(spec.keys) || Object.keys(spec.keys).length > 16) throw new AppError(400, 'INVALID_KEYRING');
  const keys = new Map(Object.entries(spec.keys).map(([id, value]) => [identifier(id), storageKey(value)]));
  const activeKeyId = spec.activeKeyId;
  const legacyKeyId = spec.legacyKeyId ?? activeKeyId;
  if (!keys.has(activeKeyId) || !keys.has(legacyKeyId)) throw new AppError(400, 'INVALID_KEYRING');
  let closed = false;
  const check = () => { if (closed) throw new AppError(503, 'KEYRING_CLOSED'); };
  return Object.freeze({
    activeKeyId, legacyKeyId,
    encrypt(text, aad) {
      check(); const iv = randomBytes(12); const cipher = createCipheriv('aes-256-gcm', keys.get(activeKeyId), iv);
      cipher.setAAD(Buffer.from(JSON.stringify(['keyring-v2', activeKeyId, aad])));
      const data = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
      return JSON.stringify({ v: 2, kid: activeKeyId, iv: iv.toString('base64url'), data: data.toString('base64url'), tag: cipher.getAuthTag().toString('base64url') });
    },
    decrypt(text, aad) {
      check();
      try {
        const box = JSON.parse(text);
        if (box.v === 1) exactObject(box, ['v', 'iv', 'data', 'tag']);
        else if (box.v === 2) exactObject(box, ['v', 'kid', 'iv', 'data', 'tag']);
        else throw new Error('version');
        const id = box.v === 1 ? legacyKeyId : box.kid;
        const key = keys.get(id); if (!key) throw new Error('key');
        const iv = Buffer.from(box.iv, 'base64url'); const tag = Buffer.from(box.tag, 'base64url');
        if (iv.length !== 12 || tag.length !== 16 || typeof box.data !== 'string' || box.data.length > 100000) throw new Error('box');
        const decipher = createDecipheriv('aes-256-gcm', key, iv);
        decipher.setAAD(Buffer.from(box.v === 1 ? aad : JSON.stringify(['keyring-v2', id, aad]))); decipher.setAuthTag(tag);
        return Buffer.concat([decipher.update(Buffer.from(box.data, 'base64url')), decipher.final()]).toString('utf8');
      } catch { throw new AppError(500, 'STORE_INTEGRITY_ERROR'); }
    },
    keyId(text) { const box = JSON.parse(text); return box.v === 1 ? legacyKeyId : box.kid; },
    assertRetirable(keyId, references) {
      identifier(keyId);
      if (keyId === activeKeyId || !keys.has(keyId) || !Number.isSafeInteger(references) || references !== 0) throw new AppError(409, 'KEY_STILL_REFERENCED');
      return true;
    },
    close() { if (!closed) { for (const key of keys.values()) key.fill(0); closed = true; } },
  });
}
