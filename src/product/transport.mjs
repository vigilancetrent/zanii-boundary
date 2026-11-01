import { AsyncLocalStorage } from 'node:async_hooks';
import { readFile, lstat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createPrivateKey, createHash, X509Certificate, randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import { z } from 'zod';
import { createHttpsTransport } from '../adapters/transport.mjs';
import { createRestAdapter } from '../adapters/rest.mjs';
import { createZaniiBroker } from '../adapters/zanii.mjs';
import { AppError } from '../protocol.mjs';

import { requestContext } from './context.mjs';
export { requestContext };
const schema = z.object({
  origin: z.string().url(), caFile: z.string(), certFile: z.string(), keyFile: z.string(),
  issuer: z.string().url(), audience: z.string().min(1), signingKeyFile: z.string(), kid: z.string().min(1),
  allowPrivateNetworks: z.boolean().default(false), required: z.literal(true).default(true),
}).strict();

/** Resource credentials belong only to the gateway; agent JWTs are never forwarded.
 * @param {any} value
 * @param {{requestTimeoutMs?:number,baseDirectory?:string,ledger?:any}} options
 */
export async function createConfiguredResourceAdapter(value, { requestTimeoutMs = 5000, baseDirectory = process.cwd(), ledger } = {}) {
  let config; try { config = schema.parse(value); } catch { throw new AppError(400, 'INVALID_RESOURCE_INTEGRATION'); }
  const [ca, cert, key, signing] = await Promise.all([config.caFile, config.certFile, config.keyFile, config.signingKeyFile].map(async (path, index) => {
    const full = resolve(baseDirectory, path); const stat = await lstat(full);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536 || index >= 2 && process.platform !== 'win32' && (stat.mode & 0o077)) throw new AppError(400, 'UNSAFE_RESOURCE_KEY_FILE');
    return readFile(full, 'utf8');
  }));
  const privateKey = createPrivateKey(signing);
  if (privateKey.asymmetricKeyType !== 'ed25519') throw new AppError(400, 'INVALID_RESOURCE_SIGNING_KEY');
  const fingerprint = createHash('sha256').update(new X509Certificate(cert).raw).digest('base64url');
  const rawTransport = createHttpsTransport({ origin: config.origin, tls: { ca, cert, key }, allowPrivateNetworks: config.allowPrivateNetworks,
    timeoutMs: requestTimeoutMs, maxBytes: 65536, dependencyName: 'resource',
    allowedPaths: ['/v1/resource/metadata', '/v1/resource/status', '/v1/resource/execute', '/v1/resource/observe', '/v1/resource/diagnostic'] });
  const executionContext = new AsyncLocalStorage();
  const transport = { async request(path, options = {}) {
    const context = requestContext.getStore();
    const deadlineAt = Math.min(options.deadlineAt ?? Infinity, context?.deadlineAt ?? Date.now() + requestTimeoutMs);
    const headers = { ...options.headers, ...(context?.traceparent ? { traceparent: context.traceparent } : {}) };
    const execution = executionContext.getStore();
    if (path !== '/v1/resource/execute' || !ledger) return rawTransport.request(path, { ...options, deadlineAt, headers });
    if (!execution || typeof execution.beforeDispatch !== 'function') throw new AppError(503, 'BROKER_DISPATCH_BARRIER_REQUIRED');
    const authorization = headers.authorization; delete headers.authorization;
    if (typeof authorization !== 'string' || !authorization.startsWith('Bearer ')) throw new AppError(503, 'RESOURCE_CREDENTIAL_UNAVAILABLE');
    const url = `${config.origin}/v1/resource/execute`;
    const broker = createZaniiBroker({ credentials: { resource: { inject: 'bearer', secret: authorization.slice(7), allow: [url] } },
      ledger, identity: execution.identity, gate: () => Date.now() < deadlineAt,
      transport: { async fetch(input, init) {
        // Installed broker's gate precedes its record await. Repeat authority/deadline at actual I/O.
        if (input !== url || init.method !== 'POST' || Date.now() >= deadlineAt) throw new AppError(403, 'ACTION_EXPIRED');
        await execution.beforeDispatch();
        if (Date.now() >= deadlineAt) throw new AppError(403, 'ACTION_EXPIRED');
        const response = await rawTransport.request('/v1/resource/execute', { method: 'POST', headers: init.headers, body: init.body, deadlineAt });
        return new Response(JSON.stringify(response.body), { status: response.status, headers: { 'content-type': 'application/json' } });
      } } });
    const result = await broker.execute({ credential: 'resource', method: 'POST', url, headers, body: JSON.stringify(options.body) });
    let body; try { body = JSON.parse(result.body); } catch { throw new AppError(502, 'INVALID_PROVIDER_JSON'); }
    return { status: result.status, headers: result.headers, body };
  } };
  /** @param {any} context */
  async function credentialProvider({ identity, action, operationId, expectedVersion, deadlineAt, grant, scope }) {
    const now = Date.now(); const expiry = Math.min(now + 30000, identity.expiresAt ?? Infinity, deadlineAt ?? Infinity);
    if (expiry < now + 1000) throw new AppError(403, 'RESOURCE_GRANT_EXPIRED');
    const claims = { tenant_id: identity.tenantId, roles: identity.roles, scope, cnf: { 'x5t#S256': fingerprint },
      ...(action && scope === 'resource:execute' ? { task_id: grant?.taskId, policy_digest: grant?.policyDigest, action_digest: grant?.actionDigest,
        operation_id: operationId, resource_version: expectedVersion, deadline_at: deadlineAt, ...(grant?.lease ? { lease_owner: grant.lease.ownerId, lease_fence: grant.lease.fence, lease_expires_at: grant.lease.expiresAt } : {}) } : {}) };
    return new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA', kid: config.kid }).setIssuer(config.issuer).setAudience(config.audience)
      .setSubject(identity.actorId).setJti(randomUUID()).setIssuedAt(Math.floor(now / 1000)).setExpirationTime(Math.ceil(expiry / 1000)).sign(privateKey);
  }
  const adapter = createRestAdapter({ transport, credentialProvider });
  return Object.freeze({ ...adapter,
    recordsBeforeDispatch: Boolean(ledger), managesDispatchBarrier: Boolean(ledger),
    execute(identity, action, context) { return executionContext.run({ identity, beforeDispatch: context.beforeDispatch }, () => adapter.execute(identity, action, context)); },
    async diagnostic(identity) {
      const token = await credentialProvider({ identity, scope: 'resource:diagnostic' });
      const response = await transport.request('/v1/resource/diagnostic', { method: 'POST', headers: { authorization: `Bearer ${token}` }, body: {} });
      if (response.status !== 200 || response.body?.canary !== 'agent-runtime-public-containment-canary-v1') throw new AppError(503, 'DIAGNOSTIC_FAILED');
      return response.body;
    },
  });
}
