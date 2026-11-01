import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, timingSafeEqual, verify } from 'node:crypto';

export const MAX_JSON_BYTES = 65_536;
export const MAX_COVERAGE_LIFETIME_MS = 900_000;

export class AppError extends Error {
  constructor(status, code) {
    super(code);
    this.name = 'AppError';
    this.status = status;
    this.code = code;
  }
}

/** Validate a plain object with an exact allowlist of own data properties. */
export function exactObject(value, required, optional = []) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
      || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const allowed = new Set([...required, ...optional]);
  if (Reflect.ownKeys(descriptors).some((key) => typeof key !== 'string' || !allowed.has(key) || !('value' in descriptors[key]))
      || required.some((key) => !Object.hasOwn(value, key))) fail();
  return value;
}

export function identifier(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(value)) fail();
  return value;
}

export function positiveInteger(value, ceiling = Number.MAX_SAFE_INTEGER) {
  if (!Number.isSafeInteger(value) || value < 1 || value > ceiling) fail();
  return value;
}

function fail() { throw new AppError(400, 'INVALID_INPUT'); }

function denseArray(value) {
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1 || keys.some((key) => key !== 'length'
      && (typeof key !== 'string' || !/^(0|[1-9]\d*)$/.test(key) || Number(key) >= value.length
        || !('value' in Object.getOwnPropertyDescriptor(value, key))))) fail();
}

function identifierList(value, minimum = 0) {
  if (!Array.isArray(value) || value.length < minimum || value.length > 64) fail();
  denseArray(value);
  const items = value.map(identifier);
  if (new Set(items).size !== items.length) fail();
  return Object.freeze(items);
}

/** @returns {{id:string,kind:'read'|'share',documentId:string,recipient?:string}} */
export function validateAction(value) {
  exactObject(value, ['id', 'kind', 'documentId'], ['recipient']);
  if (!['read', 'share'].includes(value.kind)
      || (value.kind === 'read' && Object.hasOwn(value, 'recipient'))
      || (value.kind === 'share' && !Object.hasOwn(value, 'recipient'))) fail();
  return Object.freeze({
    id: identifier(value.id), kind: value.kind, documentId: identifier(value.documentId),
    ...(value.kind === 'share' ? { recipient: identifier(value.recipient) } : {}),
  });
}

/** Clone and freeze task authority, including its arrays. Times are Unix milliseconds. */
export function validateTask(value) {
  exactObject(value, ['id', 'actorId', 'tenantId', 'documentIds', 'recipients', 'expiresAt', 'maxActions'], ['revoked']);
  if (Object.hasOwn(value, 'revoked') && typeof value.revoked !== 'boolean') fail();
  return Object.freeze({
    id: identifier(value.id), actorId: identifier(value.actorId), tenantId: identifier(value.tenantId),
    documentIds: identifierList(value.documentIds, 1), recipients: identifierList(value.recipients),
    expiresAt: positiveInteger(value.expiresAt), maxActions: positiveInteger(value.maxActions, 10_000),
    revoked: value.revoked ?? false,
  });
}

export function validateCoverage(value) {
  exactObject(value, ['version', 'resourceId', 'configurationVersion', 'taskId', 'issuedAt', 'expiresAt', 'checks']);
  if (value.version !== 1) fail();
  exactObject(value.checks, ['authorizedRead', 'directDenied', 'wrongIdentityDenied']);
  if (Object.values(value.checks).some((item) => item !== true)) fail();
  const issuedAt = positiveInteger(value.issuedAt);
  const expiresAt = positiveInteger(value.expiresAt);
  if (expiresAt <= issuedAt || expiresAt - issuedAt > MAX_COVERAGE_LIFETIME_MS) fail();
  return Object.freeze({
    version: 1, resourceId: identifier(value.resourceId),
    configurationVersion: positiveInteger(value.configurationVersion), taskId: identifier(value.taskId),
    issuedAt, expiresAt,
    checks: Object.freeze({ authorizedRead: true, directDenied: true, wrongIdentityDenied: true }),
  });
}

export function randomToken() { return randomBytes(32).toString('base64url'); }

/** Hash both bounded inputs before timing-safe comparison; callers never log them. */
export function tokenMatches(candidate, expected) {
  if (typeof candidate !== 'string' || typeof expected !== 'string'
      || candidate.length < 16 || expected.length < 16 || candidate.length > 256 || expected.length > 256) return false;
  return timingSafeEqual(createHash('sha256').update(candidate).digest(), createHash('sha256').update(expected).digest());
}

/** @param {string | Uint8Array} bytes */
export function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function purposeName(value) {
  if (typeof value !== 'string' || !/^[a-z][a-z0-9-]{0,31}$/.test(value)) fail();
  return value;
}

function signedBytes(purpose, payload) {
  return Buffer.concat([Buffer.from(`agent-runtime-research/v1\0${purpose}\0`, 'utf8'), payload]);
}

function publicKey(key) {
  const parsed = key?.type === 'public' ? key : createPublicKey(key);
  if (parsed.asymmetricKeyType !== 'ed25519') throw new Error('Expected Ed25519');
  return parsed;
}

function jsonValue(value, depth = 0, seen = new Set()) {
  if (depth > 32) fail();
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return;
  if (typeof value === 'number') { if (!Number.isFinite(value)) fail(); return; }
  if (!value || typeof value !== 'object' || seen.has(value)) fail();
  seen.add(value);
  if (Array.isArray(value)) {
    denseArray(value);
  } else {
    if (![Object.prototype, null].includes(Object.getPrototypeOf(value))) fail();
    if (Object.getOwnPropertySymbols(value).length || Object.values(Object.getOwnPropertyDescriptors(value)).some((entry) => !('value' in entry))) fail();
  }
  for (const item of Object.values(value)) jsonValue(item, depth + 1, seen);
  seen.delete(value);
}

/** Sign exact UTF-8 JSON bytes, not a custom canonicalization or ledger receipt. */
export function signEnvelope(payload, privateKey, purpose = 'coverage') {
  purposeName(purpose);
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) fail();
  jsonValue(payload);
  const bytes = Buffer.from(JSON.stringify(payload), 'utf8');
  if (bytes.length > MAX_JSON_BYTES) fail();
  const key = privateKey?.type === 'private' ? privateKey : createPrivateKey(privateKey);
  if (key.asymmetricKeyType !== 'ed25519') fail();
  return Object.freeze({ version: 1, purpose, payload: bytes.toString('base64url'), signature: sign(null, signedBytes(purpose, bytes), key).toString('base64url') });
}

/** Verify against an independently supplied trust key; payload schema/freshness remain caller checks. */
export function verifyEnvelope(envelope, pinnedPublicKey, expectedPurpose = 'coverage') {
  try {
    purposeName(expectedPurpose);
    exactObject(envelope, ['version', 'purpose', 'payload', 'signature']);
    if (envelope.version !== 1 || envelope.purpose !== expectedPurpose
        || typeof envelope.payload !== 'string' || envelope.payload.length > Math.ceil(MAX_JSON_BYTES * 4 / 3)
        || !/^[A-Za-z0-9_-]+$/.test(envelope.payload)
        || typeof envelope.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature)) throw new Error('Envelope');
    const bytes = Buffer.from(envelope.payload, 'base64url');
    const signature = Buffer.from(envelope.signature, 'base64url');
    if (bytes.length > MAX_JSON_BYTES || bytes.toString('base64url') !== envelope.payload
        || signature.length !== 64 || signature.toString('base64url') !== envelope.signature
        || !verify(null, signedBytes(expectedPurpose, bytes), publicKey(pinnedPublicKey), signature)) throw new Error('Signature');
    const parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Payload');
    jsonValue(parsed);
    return parsed;
  } catch {
    throw new AppError(403, 'INVALID_EVIDENCE');
  }
}
