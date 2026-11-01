import https from 'node:https';
import { isIP } from 'node:net';
import { createHmac } from 'node:crypto';
import { createSecureContext } from 'node:tls';
import { NodeHttpHandler } from '@smithy/node-http-handler';
import { KMSClient, GenerateDataKeyCommand, DecryptCommand, ReEncryptCommand } from '@aws-sdk/client-kms';
import { z } from 'zod';
import canonicalize from 'canonicalize';
import { AppError, exactObject, identifier } from '../protocol.mjs';
import { createPinnedLookup, assertNetworkDestination } from './transport.mjs';
import { effectiveDeadline, withSpan } from '../product/context.mjs';
import { createDependencyPolicy } from '../product/resilience.mjs';
import { readProtectedFile, readProtectedJson, readKeyFile } from '../product/secret-provider.mjs';

const filePath = z.string().min(1).max(4096);
export const awsConnectionSchema = z.object({ endpoint: z.string().url(), region: z.string().regex(/^[a-z0-9-]{1,64}$/),
  credentialsFile: filePath, caFile: filePath, certFile: filePath.optional(), keyFile: filePath.optional(),
  allowPrivateNetworks: z.boolean().default(false), timeoutMs: z.number().int().min(100).max(300000).default(10000),
  resilience: z.object({ failureThreshold: z.number().int().min(1).max(100).default(3), cooldownMs: z.number().int().min(10).max(300000).default(10000) }).strict().default({ failureThreshold: 3, cooldownMs: 10000 }),
});
const policies = new WeakMap();
export const awsDependencyStatus = (client) => policies.get(client)?.status() ?? { state: 'closed', failures: 0, attempts: 0 };

/** Explicit fixed endpoint + SigV4 identity; never invoke the SDK's ambient credential chain. */
export async function configuredAwsConnection(config, { baseDirectory = process.cwd() } = {}) {
  let endpoint; try { endpoint = new URL(config.endpoint); } catch { throw new AppError(400, 'INVALID_STORAGE_ENDPOINT'); }
  if (endpoint.protocol !== 'https:' || endpoint.username || endpoint.password || endpoint.pathname !== '/' || endpoint.search || endpoint.hash
      || /metadata|instance-data/i.test(endpoint.hostname) || Boolean(config.certFile) !== Boolean(config.keyFile)) throw new AppError(400, 'INVALID_STORAGE_ENDPOINT');
  const host = endpoint.hostname.replace(/^\[|\]$/g, '');
  if (isIP(host)) assertNetworkDestination(host, { allowPrivateNetworks: config.allowPrivateNetworks });
  const tls = { ca: await readProtectedFile(config.caFile, { baseDirectory }),
    ...(config.certFile ? { cert: await readProtectedFile(config.certFile, { baseDirectory }), key: await readProtectedFile(config.keyFile, { baseDirectory, secret: true }) } : {}) };
  try { createSecureContext(tls); } catch { throw new AppError(400, 'INVALID_STORAGE_TLS'); }
  const agent = new https.Agent({ ...tls, rejectUnauthorized: true, keepAlive: false,
    lookup: createPinnedLookup({ allowPrivateNetworks: config.allowPrivateNetworks }), maxSockets: 8, timeout: config.timeoutMs });
  const requestHandler = new NodeHttpHandler({ httpsAgent: agent, connectionTimeout: Math.min(3000, config.timeoutMs),
    requestTimeout: config.timeoutMs, socketTimeout: config.timeoutMs, throwOnRequestTimeout: true });
  const credentials = async () => {
    const raw = await readProtectedJson(config.credentialsFile, { baseDirectory, secret: true, maxBytes: 16384 });
    exactObject(raw, ['accessKeyId', 'secretAccessKey', 'expiresAt'], ['sessionToken']);
    for (const key of ['accessKeyId', 'secretAccessKey', ...(raw.sessionToken === undefined ? [] : ['sessionToken'])]) {
      if (typeof raw[key] !== 'string' || !raw[key] || raw[key].length > 8192 || /[\r\n\0]/.test(raw[key])) throw new AppError(400, 'INVALID_STORAGE_CREDENTIAL');
    }
    if (!Number.isSafeInteger(raw.expiresAt) || raw.expiresAt <= Date.now()) throw new AppError(503, 'STORAGE_CREDENTIAL_EXPIRED');
    return { accessKeyId: raw.accessKeyId, secretAccessKey: raw.secretAccessKey, ...(raw.sessionToken ? { sessionToken: raw.sessionToken } : {}), expiration: new Date(raw.expiresAt) };
  };
  try { await credentials(); }
  catch (error) { requestHandler.destroy(); agent.destroy(); tls.key?.fill(0); throw error; }
  return { options: { endpoint: endpoint.origin, region: config.region, credentials, requestHandler, maxAttempts: 1 },
    close() { requestHandler.destroy(); agent.destroy(); tls.key?.fill(0); } };
}

/** @param {any} client @param {any} command @param {any} options */
export async function awsSend(client, command, { timeoutMs = 10000, deadlineAt, dependency = 'storage', resilience = {}, consume } = {}) {
  const deadline = effectiveDeadline({ timeoutMs, deadlineAt }); const abort = new AbortController();
  let policy = policies.get(client);
  if (!policy) { policy = createDependencyPolicy({ ...resilience, name: dependency, timeoutMs, maxAttempts: 1 }); policies.set(client, policy); }
  try { return await policy.execute(async () => {
  const timer = setTimeout(() => abort.abort(), Math.max(1, deadline - Date.now())); timer.unref?.();
  try {
    const result = await withSpan('storage.provider', { 'runtime.dependency': dependency, 'runtime.operation': command.constructor.name },
      () => client.send(command, { abortSignal: abort.signal }));
    if (Date.now() >= deadline) throw new AppError(504, 'STORAGE_DEADLINE');
    const value = consume ? await consume(result, deadline) : result;
    if (Date.now() >= deadline) throw new AppError(504, 'STORAGE_DEADLINE');
    return value;
  } catch (error) {
    if (error instanceof AppError) throw error;
    if (abort.signal.aborted) throw new AppError(504, 'STORAGE_DEADLINE');
    const status = /** @type {any} */ (error)?.$metadata?.httpStatusCode;
    throw new AppError(status === 404 ? 404 : status === 412 ? 409 : status === 403 ? 403 : 503,
      status === 404 ? 'STORAGE_NOT_FOUND' : status === 412 ? 'STORAGE_ALREADY_EXISTS' : status === 403 ? 'STORAGE_ACCESS_DENIED' : 'STORAGE_PROVIDER_UNAVAILABLE');
  } finally { clearTimeout(timer); }
  }, { deadlineAt: deadline, retrySafe: false }); }
  catch (error) { if (error instanceof AppError && error.code === 'TRANSPORT_DEADLINE') { abort.abort(); throw new AppError(504, 'STORAGE_DEADLINE'); } throw error; }
}

/** KMS symmetric DEKs are bound to opaque tenant/object context, not raw business identifiers. */
export async function createConfiguredKms(raw, { baseDirectory = process.cwd() } = {}) {
  const keyArn = z.string().regex(/^arn:aws(?:-[a-z]+)?:kms:[a-z0-9-]+:\d{12}:key\/[A-Za-z0-9-]+$/);
  const schema = awsConnectionSchema.extend({ keyId: keyArn, contextKeyFile: filePath,
    rotationKeyIds: z.array(keyArn).max(16).default([]) }).strict();
  let config; try { config = schema.parse(raw); } catch { throw new AppError(400, 'INVALID_KMS_CONFIGURATION'); }
  const connection = await configuredAwsConnection(config, { baseDirectory }); const client = new KMSClient(connection.options);
  let contextKey; try { contextKey = await readKeyFile(config.contextKeyFile, { baseDirectory }); }
  catch (error) { client.destroy(); connection.close(); throw error; }
  let closed = false;
  const scope = ({ tenantId, id, purpose }) => {
    identifier(tenantId); identifier(id); identifier(purpose);
    const opaque = (value) => createHmac('sha256', contextKey).update(value).digest('hex');
    return { runtime: 'company-agent-runtime-v1', tenant: opaque(`tenant:${tenantId}`), object: opaque(`object:${id}`), purpose };
  };
  const send = (command, deadlineAt) => { if (closed) throw new AppError(503, 'KMS_CLOSED'); return awsSend(client, command, { timeoutMs: config.timeoutMs, deadlineAt, dependency: 'kms', resilience: config.resilience }); };
  const validateEnvelope = (envelope, context) => {
    exactObject(envelope, ['keyId', 'ciphertext', 'context']);
    if (![config.keyId, ...config.rotationKeyIds].includes(envelope.keyId) || typeof envelope.ciphertext !== 'string' || !/^[A-Za-z\d_-]{1,21846}$/.test(envelope.ciphertext)
        || canonicalize(envelope.context) !== canonicalize(scope(context))) throw new AppError(403, 'KMS_SCOPE_MISMATCH');
  };
  return Object.freeze({
    /** @param {any} context @param {any} options */
    async generateDataKey(context, { deadlineAt } = {}) {
      const encryptionContext = scope(context); const result = await send(new GenerateDataKeyCommand({ KeyId: config.keyId, KeySpec: 'AES_256', EncryptionContext: encryptionContext }), deadlineAt);
      if (!(result.Plaintext instanceof Uint8Array) || result.Plaintext.length !== 32 || !(result.CiphertextBlob instanceof Uint8Array)
          || !result.CiphertextBlob.length || result.CiphertextBlob.length > 16384 || result.KeyId !== config.keyId) { result.Plaintext?.fill?.(0); throw new AppError(503, 'INVALID_KMS_RESPONSE'); }
      const key = Buffer.from(result.Plaintext); result.Plaintext.fill(0);
      return { key, envelope: { keyId: result.KeyId, ciphertext: Buffer.from(result.CiphertextBlob).toString('base64url'), context: encryptionContext } };
    },
    /** @param {any} envelope @param {any} context @param {any} options */
    async decryptDataKey(envelope, context, { deadlineAt } = {}) {
      validateEnvelope(envelope, context);
      const result = await send(new DecryptCommand({ KeyId: envelope.keyId, CiphertextBlob: Buffer.from(envelope.ciphertext, 'base64url'), EncryptionContext: scope(context) }), deadlineAt);
      if (!(result.Plaintext instanceof Uint8Array) || result.Plaintext.length !== 32 || result.KeyId !== envelope.keyId) { result.Plaintext?.fill?.(0); throw new AppError(503, 'INVALID_KMS_RESPONSE'); }
      const key = Buffer.from(result.Plaintext); result.Plaintext.fill(0); return key;
    },
    /** @param {any} envelope @param {any} context @param {any} destinationKeyId @param {any} options */
    async rewrapDataKey(envelope, context, destinationKeyId, { deadlineAt } = {}) {
      if (!config.rotationKeyIds.includes(destinationKeyId)) throw new AppError(403, 'KMS_ROTATION_KEY_DENIED');
      validateEnvelope(envelope, context); const expected = scope(context);
      const result = await send(new ReEncryptCommand({ SourceKeyId: envelope.keyId, DestinationKeyId: destinationKeyId,
        CiphertextBlob: Buffer.from(envelope.ciphertext, 'base64url'), SourceEncryptionContext: expected, DestinationEncryptionContext: expected }), deadlineAt);
      if (result.SourceKeyId !== envelope.keyId || result.KeyId !== destinationKeyId || !(result.CiphertextBlob instanceof Uint8Array) || !result.CiphertextBlob.length) throw new AppError(503, 'INVALID_KMS_RESPONSE');
      return { keyId: result.KeyId, ciphertext: Buffer.from(result.CiphertextBlob).toString('base64url'), context: expected };
    },
    status: () => ({ configured: true, kind: 'kms', keyId: config.keyId, ambientCredentials: false, closed, dependency: awsDependencyStatus(client) }),
    close() { if (!closed) { closed = true; contextKey.fill(0); client.destroy(); connection.close(); } },
  });
}
