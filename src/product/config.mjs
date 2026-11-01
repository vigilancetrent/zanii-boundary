import { readFile, lstat } from 'node:fs/promises';
import { createPrivateKey } from 'node:crypto';
import { resolve, dirname } from 'node:path';
import { z } from 'zod';
import { AppError } from '../protocol.mjs';
import { createKeyring } from './keyring.mjs';
import { productOperationsSchema } from './operations-config.mjs';
import { loggingSchema } from './logging.mjs';
import { monitoringSourcesSchema } from './metrics-sources.mjs';

const path = z.string().min(1).max(4096);
const dictionary = z.record(z.string().regex(/^[A-Za-z][A-Za-z0-9_-]{0,63}$/), z.unknown());
const schema = z.object({
  version: z.literal(1), role: z.enum(['gateway', 'resource']), profile: z.enum(['production', 'local-test']),
  listen: z.object({ host: z.string().min(1).max(253), port: z.number().int().min(0).max(65535), socketPath: path.optional() }).strict(),
  tls: z.object({ certFile: path, keyFile: path, caFile: path, requireClientCertificate: z.literal(true) }).strict(),
  auth: z.object({ issuer: z.string().url(), audience: z.string().min(1).max(512), jwksFile: path,
    algorithms: z.array(z.enum(['EdDSA', 'ES256'])).min(1).max(2), requireSenderBinding: z.boolean(),
    maxLifetimeSeconds: z.number().int().min(1).max(3600) }).strict(),
  storage: z.object({ backend: z.enum(['sqlite', 'postgres']).default('sqlite'), path: path.optional(), encryptionKeyFile: path, auditKeyFile: path,
    keyringFile: path.optional(), retentionMs: z.number().int().min(60_000).max(365 * 86_400_000),
    postgres: z.object({ credentialsFile: path, caFile: path, role: z.enum(['app', 'worker']).default('app'),
      maxConnections: z.number().int().min(1).max(100).default(10), acquireTimeoutMs: z.number().int().min(10).max(10000).default(1000),
      queryTimeoutMs: z.number().int().min(10).max(30000).default(2000), statementTimeoutMs: z.number().int().min(10).max(30000).default(1500),
      lockTimeoutMs: z.number().int().min(1).max(10000).default(500) }).strict().optional(),
  }).strict(),
  signing: z.object({ privateKeyFile: path, publicKeyFile: path.optional() }).strict(),
  limits: z.object({ bodyBytes: z.number().int().min(1024).max(1_048_576), requestTimeoutMs: z.number().int().min(100).max(60_000),
    rateWindowMs: z.number().int().min(100).max(3_600_000), rateRequests: z.number().int().min(1).max(100_000),
    maxConcurrency: z.number().int().min(1).max(1024) }).strict(),
  deployment: z.object({ receiptFile: path, trustKeyFile: path, maxAgeMs: z.number().int().min(1000).max(900_000),
    kind: z.enum(['linux-no-network-v1', 'linux-distributed-v2']).default('linux-no-network-v1'),
    profileDigest: z.string().regex(/^[a-f\d]{64}$/),
    imageRef: z.string().max(512).regex(/^[A-Za-z0-9][A-Za-z0-9._:/+-]*@sha256:[a-f\d]{64}$/).refine((value) => !value.includes('://')) }).strict().optional(),
  integrations: dictionary.default({}), protocols: dictionary.default({}), telemetry: dictionary.optional(), operations: productOperationsSchema.optional(), logging: loggingSchema.optional(), monitoring: monitoringSourcesSchema.optional(),
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
    if (value.storage.backend === 'sqlite' ? !value.storage.path || value.storage.postgres : !value.storage.postgres) throw new Error('Storage backend');
    if (value.storage.postgres && value.storage.postgres.acquireTimeoutMs + value.storage.postgres.queryTimeoutMs > value.limits.requestTimeoutMs) throw new Error('Database budget');
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
    let keyring; let postgres;
    if (config.storage.keyringFile) {
      keyring = JSON.parse(await file(config.storage.keyringFile, base, true)); const checked = createKeyring(keyring); checked.close();
    }
    if (config.storage.postgres) {
      const connection = z.object({ host: z.string().min(1).max(253), port: z.number().int().min(1).max(65535),
        database: z.string().min(1).max(128), user: z.string().min(1).max(128), password: z.string().min(1).max(4096) }).strict()
        .parse(JSON.parse(await file(config.storage.postgres.credentialsFile, base, true)));
      postgres = { connection, ca: await file(config.storage.postgres.caFile, base) };
    }
    const absolute = { ...config, storage: { ...config.storage, ...(config.storage.path ? { path: resolve(base, config.storage.path) } : {}) },
      listen: { ...config.listen, ...(config.listen.socketPath ? { socketPath: resolve(base, config.listen.socketPath) } : {}) },
      ...(config.deployment ? { deployment: { ...config.deployment, receiptFile: resolve(base, config.deployment.receiptFile), trustKeyFile: resolve(base, config.deployment.trustKeyFile) } } : {}) };
    return { config: freeze(absolute), material: { baseDirectory: base, tls: { cert, key, ca }, jwks: freeze(jwks),
      encryptionKey: decodeKey(encryption), auditKey: decodeKey(audit), signingKey, ...(keyring ? { keyring } : {}), ...(postgres ? { postgres } : {}) } };
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError(400, 'PRODUCT_CONFIGURATION_UNAVAILABLE');
  }
}
