import { readFile, lstat } from 'node:fs/promises';
import { createPrivateKey } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { z } from 'zod';
import { AppError } from '../protocol.mjs';

const path = z.string().min(1).max(4096);
const dictionary = z.record(z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/), z.unknown());
const schema = z.object({
  version: z.literal(1), role: z.enum(['gateway', 'resource']), profile: z.enum(['production', 'local-test']),
  listen: z.object({ host: z.string().min(1).max(253), port: z.number().int().min(0).max(65535), socketPath: path.optional() }).strict(),
  tls: z.object({ certFile: path, keyFile: path, caFile: path, requireClientCertificate: z.literal(true) }).strict(),
  auth: z.object({ issuer: z.string().url(), audience: z.string().min(1).max(512), jwksFile: path,
    algorithms: z.array(z.enum(['EdDSA', 'ES256'])).min(1).max(2), requireSenderBinding: z.boolean(),
    maxLifetimeSeconds: z.number().int().min(1).max(3600) }).strict(),
  storage: z.object({ path, encryptionKeyFile: path, auditKeyFile: path,
    retentionMs: z.number().int().min(60_000).max(365 * 86_400_000) }).strict(),
  signing: z.object({ privateKeyFile: path, publicKeyFile: path.optional() }).strict(),
  limits: z.object({ bodyBytes: z.number().int().min(1024).max(1_048_576), requestTimeoutMs: z.number().int().min(100).max(60_000),
    rateWindowMs: z.number().int().min(100).max(3_600_000), rateRequests: z.number().int().min(1).max(100_000),
    maxConcurrency: z.number().int().min(1).max(1024) }).strict(),
  deployment: z.object({ receiptFile: path, trustKeyFile: path, maxAgeMs: z.number().int().min(1000).max(900_000),
    profileDigest: z.string().regex(/^[a-f\d]{64}$/),
    imageRef: z.string().max(512).regex(/^[A-Za-z0-9][A-Za-z0-9._:/+-]*@sha256:[a-f\d]{64}$/).refine((value) => !value.includes('://')) }).strict().optional(),
  integrations: dictionary.default({}), protocols: dictionary.default({}),
}).strict();

function freeze(value) {
  if (value && typeof value === 'object') {
    for (const item of Object.values(value)) freeze(item);
    Object.freeze(value);
  }
  return value;
}

/** Integration dictionaries are validated by their selected adapter before they may be used. */
export function parseProductConfig(raw) {
  try {
    const value = schema.parse(raw);
    if (value.profile === 'local-test' && value.listen.host !== '127.0.0.1') throw new Error('Local binding');
    if (value.profile === 'production' && (!value.auth.requireSenderBinding || !value.deployment
        || value.auth.issuer.startsWith('http:'))) throw new Error('Production assurance');
    return freeze(value);
  } catch { throw new AppError(400, 'INVALID_PRODUCT_CONFIGURATION'); }
}

async function file(pathValue, base, secret = false) {
  const full = resolve(base, pathValue); const stat = await lstat(full);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 1_048_576
      || (secret && process.platform !== 'win32' && (stat.mode & 0o077) !== 0)) throw new AppError(400, 'INVALID_SECRET_FILE');
  return readFile(full, 'utf8');
}
function decodeKey(text) {
  if (!/^[a-f\d]{64}$/i.test(text.trim())) throw new AppError(400, 'INVALID_ENCRYPTION_KEY');
  return Buffer.from(text.trim(), 'hex');
}

/** Never log or serialize material: it includes private keys and decryption keys. */
export async function loadProductConfig(configPath) {
  try {
    const base = dirname(resolve(configPath));
    const config = parseProductConfig(JSON.parse(await file(configPath, process.cwd())));
    const [cert, key, ca, jwksText, encryption, audit, signing] = await Promise.all([
      file(config.tls.certFile, base), file(config.tls.keyFile, base, true), file(config.tls.caFile, base),
      file(config.auth.jwksFile, base), file(config.storage.encryptionKeyFile, base, true),
      file(config.storage.auditKeyFile, base, true), file(config.signing.privateKeyFile, base, true),
    ]);
    const jwks = JSON.parse(jwksText); if (!Array.isArray(jwks.keys) || !jwks.keys.length) throw new Error('JWKS');
    const signingKey = createPrivateKey(signing); if (signingKey.asymmetricKeyType !== 'ed25519') throw new Error('Signing key');
    const absolute = { ...config, storage: { ...config.storage, path: resolve(base, config.storage.path) },
      listen: { ...config.listen, ...(config.listen.socketPath ? { socketPath: resolve(base, config.listen.socketPath) } : {}) },
      ...(config.deployment ? { deployment: { ...config.deployment, receiptFile: resolve(base, config.deployment.receiptFile), trustKeyFile: resolve(base, config.deployment.trustKeyFile) } } : {}) };
    return { config: freeze(absolute), material: { baseDirectory: base, tls: { cert, key, ca }, jwks: freeze(jwks),
      encryptionKey: decodeKey(encryption), auditKey: decodeKey(audit), signingKey } };
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError(400, 'PRODUCT_CONFIGURATION_UNAVAILABLE');
  }
}
