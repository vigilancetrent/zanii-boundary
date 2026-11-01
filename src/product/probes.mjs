import { dirname, resolve } from 'node:path';
import { createHash, X509Certificate } from 'node:crypto';
import { decodeJwt } from 'jose';
import { z } from 'zod';
import { AppError } from '../protocol.mjs';
import { createHttpsTransport } from '../adapters/transport.mjs';
import { readOperationsFile } from './operations-config.mjs';

export const PROBE_PATHS = Object.freeze({ live: '/health/live', startup: '/health/startup', ready: '/health/ready', metrics: '/metrics' });
const path = z.string().min(1).max(4096);
export const probeSchema = z.object({ version: z.literal(1), origin: z.string().url(), servername: z.string().min(1).max(253).optional(), socketPath: path.optional(),
  caFile: path, certFile: path, keyFile: path, tokenFile: path.optional(), audience: z.string().min(1).max(512),
  maxLifetimeSeconds: z.number().int().min(1).max(900).default(300), allowPrivateNetworks: z.boolean().default(false),
  timeoutMs: z.number().int().min(100).max(30000).default(5000), maxBytes: z.number().int().min(1024).max(1048576).default(1048576) }).strict();

/** Local claim inspection prevents accidentally mounting a broad operator credential; the runtime still verifies the signature. */
export function assertNarrowMonitorToken(token, { audience, fingerprint, maxLifetimeSeconds = 300, now = Date.now() }) {
  let claims; try { claims = decodeJwt(token); } catch { throw new AppError(401, 'INVALID_MONITOR_IDENTITY'); }
  const scopes = typeof claims.scope === 'string' ? claims.scope.split(/\s+/).filter(Boolean) : [];
  if (claims.aud !== audience || !Array.isArray(claims.roles) || !claims.roles.length || !claims.roles.every((role) => ['auditor', 'operator'].includes(role))
      || !scopes.length || scopes.some((scope) => !['runtime:health', 'runtime:metrics'].includes(scope))
      || claims.tenant_id !== 'platform' || claims.cnf?.['x5t#S256'] !== fingerprint
      || !Number.isSafeInteger(claims.iat) || !Number.isSafeInteger(claims.exp) || claims.exp * 1000 <= now
      || claims.iat * 1000 > now + 1000 || claims.exp - claims.iat > maxLifetimeSeconds) throw new AppError(401, 'NARROW_MONITOR_IDENTITY_REQUIRED');
  return { expiresAt: claims.exp * 1000, scopes };
}

/** @param {any} raw @param {any} options */
export async function createConfiguredProbe(raw, { baseDirectory = process.cwd() } = {}) {
  const parsed = probeSchema.safeParse(raw); if (!parsed.success) throw new AppError(400, 'INVALID_PROBE_CONFIGURATION'); const config = parsed.data;
  const tls = { ca: await readOperationsFile(config.caFile, { baseDirectory }), cert: await readOperationsFile(config.certFile, { baseDirectory }),
    key: await readOperationsFile(config.keyFile, { baseDirectory, secret: true }), ...(config.servername ? { servername: config.servername } : {}) };
  const fingerprint = createHash('sha256').update(new X509Certificate(tls.cert).raw).digest('base64url');
  const transport = createHttpsTransport({ origin: config.origin, tls, ...(config.socketPath ? { socketPath: resolve(baseDirectory, config.socketPath) } : {}),
    allowPrivateNetworks: config.allowPrivateNetworks, timeoutMs: config.timeoutMs, maxBytes: config.maxBytes, allowedMethods: ['GET'], allowedPaths: Object.values(PROBE_PATHS), dependencyName: 'probe' });
  return Object.freeze({
    async run(mode, { traceparent = undefined } = {}) {
      if (!Object.hasOwn(PROBE_PATHS, mode)) throw new AppError(400, 'INVALID_PROBE_MODE');
      /** @type {Record<string,string>} */ const headers = {};
      if (!['live', 'startup'].includes(mode)) {
        if (!config.tokenFile) throw new AppError(401, 'MONITOR_TOKEN_REQUIRED');
        const token = (await readOperationsFile(config.tokenFile, { baseDirectory, secret: true, maxBytes: 16384 })).trim();
        assertNarrowMonitorToken(token, { audience: config.audience, fingerprint, maxLifetimeSeconds: config.maxLifetimeSeconds }); headers.authorization = `Bearer ${token}`;
      }
      if (traceparent !== undefined) { if (!/^00-[a-f0-9]{32}-[a-f0-9]{16}-01$/.test(traceparent)) throw new AppError(400, 'INVALID_PROBE_TRACE'); headers.traceparent = traceparent; }
      if (mode === 'metrics') {
        const response = await transport.fetch(`${transport.origin}${PROBE_PATHS.metrics}`, { method: 'GET', headers }); const text = await response.text();
        if (response.status !== 200 || !/^text\/plain(?:;|$)/i.test(response.headers.get('content-type') ?? '')
            || !/^runtime_requests_total\s+/m.test(text) || !/^runtime_http_requests_total(?:\{|\s)/m.test(text)) throw new AppError(503, 'METRICS_PROBE_FAILED');
        return { healthy: true, mode, metrics: text, requestId: response.headers.get('x-request-id') ?? undefined };
      }
      const result = await transport.request(PROBE_PATHS[mode], { headers }); const field = { live: 'live', startup: 'started', ready: 'ready' }[mode];
      if (result.status !== 200 || result.body?.[field] !== true) throw new AppError(503, `${mode.toUpperCase()}_PROBE_FAILED`);
      const identity = result.body?.containment;
      const containment = identity && /^[a-f0-9]{64}$/.test(identity.profileDigest ?? '') && /^[A-Za-z0-9][A-Za-z0-9._:/+-]*@sha256:[a-f0-9]{64}$/.test(identity.imageRef ?? '')
        ? { imageRef: identity.imageRef, profileDigest: identity.profileDigest } : undefined;
      return { healthy: true, mode, requestId: result.headers['x-request-id'], ...(mode === 'ready' ? { role: result.body.role, ...(containment ? { containment } : {}) } : {}) };
    },
  });
}

export async function loadProbe(path) {
  let value; try { value = JSON.parse(await readOperationsFile(path)); } catch { throw new AppError(400, 'PROBE_CONFIGURATION_UNAVAILABLE'); }
  return createConfiguredProbe(value, { baseDirectory: dirname(resolve(path)) });
}
