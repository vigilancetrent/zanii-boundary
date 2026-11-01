import { createHmac, timingSafeEqual, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { AppError } from '../protocol.mjs';
import { asAsyncStore } from './async-store.mjs';
import { createHttpsTransport } from '../adapters/transport.mjs';
import { readOperationsFile } from './operations-config.mjs';

const id = z.string().regex(/^[A-Za-z0-9._:@-]{1,128}$/);
export const alertSchema = z.object({ version: z.literal(1), id, occurredAt: z.number().int().positive(),
  kind: z.enum(['job-dead-letter', 'worker-stale', 'archive-stale', 'backup-stale', 'dependency-unavailable', 'audit-unavailable', 'key-epoch-frozen']),
  severity: z.enum(['warning', 'critical']), tenant: z.string().regex(/^[a-f0-9]{24}$/),
  code: z.string().regex(/^[A-Z][A-Z0-9_]{0,63}$/), count: z.number().int().min(0).max(1000000000).optional() }).strict();
const configuration = z.object({ origin: z.string().url(), path: z.string().regex(/^\/[A-Za-z0-9/_-]{1,128}$/),
  caFile: z.string().min(1), certFile: z.string().min(1).optional(), keyFile: z.string().min(1).optional(),
  hmacKeyFile: z.string().min(1), allowPrivateNetworks: z.boolean().default(false),
  timeoutMs: z.number().int().min(100).max(30000).default(5000) }).strict();
const signature = (key, timestamp, eventId, raw) => createHmac('sha256', key).update(`${timestamp}.${eventId}.`).update(raw).digest('hex');
const parseAlert = (value) => { const parsed = alertSchema.safeParse(value); if (!parsed.success) throw new AppError(400, 'INVALID_ALERT'); return parsed.data; };

/** Event payloads have no text/body/URL fields: provider errors cannot enter an alert. */
export function createAlertEvent({ key, tenantId, kind, severity = 'critical', code, count = undefined, id: eventId = randomUUID(), now = Date.now }) {
  if (!(key instanceof Uint8Array) || key.length !== 32 || typeof tenantId !== 'string' || !tenantId || tenantId.length > 128) throw new AppError(400, 'INVALID_ALERT_KEY');
  return parseAlert({ version: 1, id: eventId, occurredAt: now(), kind, severity, code,
    tenant: createHmac('sha256', key).update(tenantId).digest('hex').slice(0, 24), ...(count === undefined ? {} : { count }) });
}

/** A retry sends the same event ID; no business operation is retried by this transport. */
export function createAlertDelivery({ transport, path, key, now = Date.now }) {
  if (!(key instanceof Uint8Array) || key.length !== 32 || typeof transport?.request !== 'function'
      || !/^\/[A-Za-z0-9/_-]{1,128}$/.test(path)) throw new AppError(400, 'INVALID_ALERT_CONFIGURATION');
  const secret = Buffer.from(key); let closed = false;
  return Object.freeze({
    async deliver(value) {
      if (closed) throw new AppError(503, 'ALERT_DELIVERY_CLOSED');
      const event = parseAlert(value); const raw = JSON.stringify(event); const timestamp = String(now());
      const response = await transport.request(path, { method: 'POST', body: raw, headers: {
        'content-type': 'application/json', 'idempotency-key': event.id,
        'x-runtime-alert-time': timestamp, 'x-runtime-alert-signature': signature(secret, timestamp, event.id, raw),
      } });
      if (response.status !== 200 || response.body?.received !== true || response.body?.id !== event.id
          || Object.keys(response.body).some((field) => !['received', 'id', 'duplicate'].includes(field))) throw new AppError(502, 'ALERT_ACKNOWLEDGEMENT_INVALID');
      return { id: event.id, delivered: true, duplicate: response.body.duplicate === true };
    },
    status() { return { configured: true, healthy: !closed, dependency: transport.dependencyStatus?.() }; },
    async close() { closed = true; secret.fill(0); await transport.close?.(); },
  });
}

export async function createConfiguredAlertDelivery(raw, { baseDirectory = process.cwd() } = {}) {
  const parsed = configuration.safeParse(raw);
  if (!parsed.success || Boolean(parsed.data.certFile) !== Boolean(parsed.data.keyFile)) throw new AppError(400, 'INVALID_ALERT_CONFIGURATION');
  const config = parsed.data;
  const keyText = (await readOperationsFile(config.hmacKeyFile, { baseDirectory, secret: true, maxBytes: 128 })).trim();
  if (!/^[a-f0-9]{64}$/i.test(keyText)) throw new AppError(400, 'INVALID_ALERT_KEY');
  const key = Buffer.from(keyText, 'hex');
  try {
    const ca = await readOperationsFile(config.caFile, { baseDirectory });
    const tls = { ca, ...(config.certFile ? { cert: await readOperationsFile(config.certFile, { baseDirectory }),
      key: await readOperationsFile(config.keyFile, { baseDirectory, secret: true }) } : {}) };
    return createAlertDelivery({ key, path: config.path, transport: createHttpsTransport({ origin: config.origin, tls,
      timeoutMs: config.timeoutMs, maxBytes: 4096, allowedPaths: [config.path], allowPrivateNetworks: config.allowPrivateNetworks,
      dependencyName: 'alerts' }) });
  } finally { key.fill(0); }
}

/** Controlled receiver helper. The HMAC and durable dedupe precede acknowledgement. */
export function createAlertReceiver({ store, key, now = Date.now, maxSkewMs = 300000 }) {
  store = asAsyncStore(store);
  if (!(key instanceof Uint8Array) || key.length !== 32 || !Number.isSafeInteger(maxSkewMs) || maxSkewMs < 100 || maxSkewMs > 3600000)
    throw new AppError(400, 'INVALID_ALERT_CONFIGURATION');
  const secret = Buffer.from(key);
  return Object.freeze({
    async receive({ raw, timestamp, signature: supplied, idempotencyKey }) {
      if (typeof raw !== 'string' || Buffer.byteLength(raw) > 4096 || !/^[0-9]{1,16}$/.test(timestamp ?? '')
          || !/^[a-f0-9]{64}$/.test(supplied ?? '') || typeof idempotencyKey !== 'string') throw new AppError(401, 'ALERT_AUTHENTICATION_FAILED');
      const time = Number(timestamp);
      if (!Number.isSafeInteger(time) || Math.abs(now() - time) > maxSkewMs
          || !timingSafeEqual(Buffer.from(supplied, 'hex'), Buffer.from(signature(secret, timestamp, idempotencyKey, raw), 'hex')))
        throw new AppError(401, 'ALERT_AUTHENTICATION_FAILED');
      let event; try { event = parseAlert(JSON.parse(raw)); } catch { throw new AppError(400, 'INVALID_ALERT'); }
      if (event.id !== idempotencyKey) throw new AppError(409, 'ALERT_ID_CONFLICT');
      const digest = createHmac('sha256', secret).update(raw).digest('hex');
      return store.transaction(async () => {
        const previous = await store.get('system', 'incidents', event.id);
        if (previous && previous.digest !== digest) throw new AppError(409, 'ALERT_ID_CONFLICT');
        if (!previous) {
          await store.put('system', 'incidents', event.id, { digest, event, receivedAt: now() });
          await store.appendAudit({ tenantId: 'system', actorId: 'alert-receiver', event: 'alert.received', target: event.id,
            data: { kind: event.kind, code: event.code, severity: event.severity } });
        }
        return { received: true, id: event.id, duplicate: Boolean(previous) };
      }, { tenantId: 'system' });
    },
    close() { secret.fill(0); },
  });
}
