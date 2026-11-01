import { createServer } from 'node:https';
import { createHash, createPrivateKey, createPublicKey, timingSafeEqual, randomUUID } from 'node:crypto';
import { dirname, resolve } from 'node:path';
import { z } from 'zod';
import canonicalize from 'canonicalize';
import { AppError, identifier, signEnvelope, verifyEnvelope } from '../protocol.mjs';
import { readJson, sendJson, sendError } from '../http.mjs';
import { openAsyncSqliteStore } from './async-store.mjs';
import { readOperationsFile } from './operations-config.mjs';
import { createAlertReceiver } from './alerts.mjs';
import { routeTemplate } from './observability.mjs';

const hex = z.string().regex(/^[a-f0-9]{64}$/); const file = z.string().min(1).max(4096);
const image = z.string().max(512).regex(/^[A-Za-z0-9][A-Za-z0-9._:/+-]*@sha256:[a-f0-9]{64}$/).refine((value) => !value.includes('://'));
const role = z.enum(['gateway', 'resource', 'worker', 'archive', 'backup']);
const deployment = z.object({ mode: z.enum(['local-contract', 'deployment']), profileDigest: hex, runtimeImage: image, collectorImage: image }).strict();
const peerList = z.array(hex).min(1).max(16);
const schema = z.object({ version: z.literal(1), listen: z.object({ host: z.enum(['127.0.0.1', '0.0.0.0']), port: z.number().int().min(0).max(65535) }).strict(),
  tls: z.object({ caFile: file, certFile: file, keyFile: file }).strict(),
  peers: z.object({ alertmanager: peerList, collector: peerList, reader: peerList, runtime: peerList.optional() }).strict(),
  auth: z.object({ alertmanagerTokenFile: file, readTokenFile: file, runtimeHmacKeyFile: file.optional() }).strict(),
  storage: z.object({ path: file, encryptionKeyFile: file, auditKeyFile: file, retentionMs: z.number().int().min(60000).max(604800000).default(86400000) }).strict(),
  signing: z.object({ privateKeyFile: file, publicKeyFile: file }).strict(), deployment,
  serviceRoles: z.record(z.string().regex(/^[A-Za-z][A-Za-z0-9._-]{0,63}$/), role),
  alertNames: z.array(z.string().regex(/^[A-Z][A-Za-z0-9]{0,63}$/)).min(1).max(100),
}).strict();
const spanNames = ['http.server', 'db.operation', 'http.provider', 'storage.provider', 'maintenance.job'];
const span = z.object({ id: z.string().regex(/^[a-f0-9]{16}$/), parentId: z.string().regex(/^(?:[a-f0-9]{16})?$/), name: z.enum(spanNames), role }).strict();
const logEntry = z.object({ role, event: z.enum(['http.request', 'http.security', 'maintenance.job', 'maintenance.worker']), level: z.enum(['info', 'warn', 'error']), route: z.string().max(128).refine((value) => routeTemplate(value) === value).optional(), status: z.number().int().min(100).max(599).optional() }).strict();
const logSummary = z.object({ entries: z.array(logEntry).min(1).max(64), truncated: z.boolean() }).strict();
const payloadSchema = z.object({ version: z.literal(1), kind: z.enum(['alert', 'trace', 'log']), id: z.string().regex(/^[A-Za-z0-9._:@-]{1,128}$/),
  firstObservedAt: z.number().int().positive(), lastObservedAt: z.number().int().positive(), sourceDigest: hex,
  deployment, summary: z.unknown() }).strict();
const hash = (value) => createHash('sha256').update(typeof value === 'string' ? value : canonicalize(value)).digest('hex');
const same = (a, b) => typeof a === 'string' && typeof b === 'string' && a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
const attribute = (items, key) => items?.find((item) => item.key === key)?.value?.stringValue;

/** A receipt proves what this pinned receiver observed, not human acknowledgement or kernel integrity.
 * @param {any} envelope @param {any} publicKey @param {any} options
 * @returns {any} */
export function verifyMonitoringReceipt(envelope, publicKey, { kind, id, expectedDeployment, after = 0, now = Date.now(), maxAgeMs = 300000 } = {}) {
  const parsed = payloadSchema.safeParse(verifyEnvelope(envelope, publicKey, 'monitoring-receipt'));
  if (!parsed.success) throw new AppError(403, 'INVALID_MONITORING_RECEIPT'); const value = parsed.data;
  if (value.kind !== kind || id !== undefined && value.id !== id || value.lastObservedAt < after || value.lastObservedAt > now
      || now - value.lastObservedAt > maxAgeMs || value.firstObservedAt > value.lastObservedAt
      || canonicalize(value.deployment) !== canonicalize(deployment.parse(expectedDeployment))) throw new AppError(403, 'MONITORING_RECEIPT_BINDING_FAILED');
  if (kind === 'trace') z.object({ spans: z.array(span).max(128), truncated: z.boolean() }).strict().parse(value.summary);
  else if (kind === 'alert') z.object({ names: z.array(z.string()).min(1).max(64), count: z.number().int().min(1).max(64), state: z.enum(['firing', 'resolved']), identityDigest: hex }).strict().parse(value.summary);
  else logSummary.parse(value.summary);
  return value;
}

/** mTLS role separation and durable bounded receipts. The receiver has its own metadata keys, never application data keys.
 * @param {any} raw @param {any} options */
export async function startMonitoringReceiver(raw, { baseDirectory = process.cwd(), now = Date.now } = {}) {
  const parsed = schema.safeParse(raw); if (!parsed.success) throw new AppError(400, 'INVALID_MONITOR_RECEIVER_CONFIGURATION'); const config = parsed.data;
  if (Object.keys(config.serviceRoles).length > 16 || Boolean(config.auth.runtimeHmacKeyFile) !== Boolean(config.peers.runtime)) throw new AppError(400, 'INVALID_MONITOR_RECEIVER_CONFIGURATION');
  const read = (path, secret = false) => readOperationsFile(path, { baseDirectory, secret });
  const key = async (path) => { const text = (await read(path, true)).trim(); if (!/^[a-f0-9]{64}$/i.test(text)) throw new AppError(400, 'INVALID_MONITOR_RECEIVER_KEY'); return Buffer.from(text, 'hex'); };
  const tls = { ca: await read(config.tls.caFile), cert: await read(config.tls.certFile), key: await read(config.tls.keyFile, true) };
  const privateKey = createPrivateKey(await read(config.signing.privateKeyFile, true)); const publicKey = createPublicKey(await read(config.signing.publicKeyFile));
  if (privateKey.asymmetricKeyType !== 'ed25519' || !createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).equals(publicKey.export({ format: 'der', type: 'spki' }))) throw new AppError(400, 'INVALID_MONITOR_RECEIPT_SIGNER');
  const encryptionKey = await key(config.storage.encryptionKeyFile); const auditKey = await key(config.storage.auditKeyFile);
  const store = openAsyncSqliteStore({ path: resolve(baseDirectory, config.storage.path), encryptionKey, auditKey, maxBytes: 67108864 }); encryptionKey.fill(0); auditKey.fill(0);
  let runtime; if (config.auth.runtimeHmacKeyFile) { const secret = await key(config.auth.runtimeHmacKeyFile); try { runtime = createAlertReceiver({ store, key: secret, now }); } finally { secret.fill(0); } }
  let inflight = 0; let closed = false; let purgeRun; const counters = { alerts: 0, traces: 0, logs: 0, denied: 0 };
  const receiptKey = (kind, id) => `${kind}-${hash(identifier(id))}`;
  async function put(kind, id, sourceDigest, summary) {
    identifier(id); return store.transaction(async () => {
      const key = receiptKey(kind, id); const old = await store.get('monitoring', 'incidents', key); let merged = summary; let changed = !old || old.sourceDigest !== sourceDigest;
      if (kind === 'trace' && old) {
        const spans = new Map(old.summary.spans.map((item) => [item.id, item])); let truncated = old.summary.truncated;
        for (const item of summary.spans) { const existing = spans.get(item.id); if (existing && canonicalize(existing) !== canonicalize(item)) throw new AppError(409, 'TRACE_SPAN_CONFLICT'); if (!existing && spans.size >= 128) truncated = true; else spans.set(item.id, item); }
        merged = { spans: [...spans.values()].sort((a, b) => a.id.localeCompare(b.id)), truncated }; sourceDigest = hash(merged); changed = old.sourceDigest !== sourceDigest;
      } else if (kind === 'log' && old) {
        const entries = new Map((old.summary.entries ?? [logEntry.parse(old.summary)]).map((item) => [hash(item), item])); let truncated = old.summary.truncated ?? false;
        for (const item of summary.entries) { const key = hash(item); if (!entries.has(key) && entries.size >= 64) truncated = true; else entries.set(key, item); }
        merged = { entries: [...entries].sort(([a], [b]) => a.localeCompare(b)).map(([, item]) => item), truncated }; sourceDigest = hash(merged); changed = old.sourceDigest !== sourceDigest;
      } else if (old && old.sourceDigest !== sourceDigest && !(kind === 'alert' && old.summary.state === 'firing' && summary.state === 'resolved' && old.summary.identityDigest === summary.identityDigest)) throw new AppError(409, 'RECEIPT_ID_CONFLICT');
      const value = old && !changed ? old : { version: 1, kind, id, firstObservedAt: old?.firstObservedAt ?? now(), lastObservedAt: now(), sourceDigest, deployment: config.deployment, summary: merged };
      if (changed) {
        await store.put('monitoring', 'incidents', key, value, { expiresAt: now() + config.storage.retentionMs });
        const index = await store.get('monitoring', 'metadata', `recent-${kind}`) ?? [];
        const recent = [{ id, at: value.lastObservedAt }, ...index.filter((item) => item.id !== id)];
        for (const retired of recent.slice(128)) await store.delete('monitoring', 'incidents', receiptKey(kind, retired.id));
        await store.put('monitoring', 'metadata', `recent-${kind}`, recent.slice(0, 128));
      }
      return { duplicate: Boolean(old) && !changed, receipt: signEnvelope(value, privateKey, 'monitoring-receipt') };
    }, { tenantId: 'monitoring' });
  }
  const authorize = async (req, purpose) => {
    const socket = /** @type {import('node:tls').TLSSocket} */ (req.socket); const peer = socket.getPeerCertificate();
    const fingerprint = peer.raw && createHash('sha256').update(peer.raw).digest('hex');
    if (!socket.authorized || !config.peers[purpose]?.includes(fingerprint)) throw new AppError(403, 'MONITOR_PEER_DENIED');
    const file = purpose === 'reader' ? config.auth.readTokenFile : purpose === 'alertmanager' ? config.auth.alertmanagerTokenFile : null;
    if (file) { const token = (await read(file, true)).trim(); if (token.length < 32 || token.length > 4096 || !same(req.headers.authorization, `Bearer ${token}`)) throw new AppError(401, 'MONITOR_AUTHENTICATION_REQUIRED'); }
  };
  async function otlp(body, kind) {
    const resources = kind === 'trace' ? body.resourceSpans : body.resourceLogs;
    if (!Array.isArray(resources) || resources.length > 64) throw new AppError(400, 'INVALID_OTLP_BATCH'); let accepted = 0; let seen = 0;
    for (const resource of resources) {
      const serviceName = attribute(resource.resource?.attributes, 'service.name'); const sourceRole = config.serviceRoles[serviceName];
      if (!sourceRole) continue; const scopes = kind === 'trace' ? resource.scopeSpans : resource.scopeLogs;
      if (!Array.isArray(scopes) || scopes.length > 64) throw new AppError(400, 'INVALID_OTLP_BATCH');
      for (const scope of scopes) {
        const items = kind === 'trace' ? scope.spans : scope.logRecords;
        if (!Array.isArray(items) || items.length > 256) throw new AppError(400, 'INVALID_OTLP_BATCH');
        const traces = new Map();
        for (const item of items) {
          if (++seen > 2048) throw new AppError(413, 'OTLP_BATCH_TOO_LARGE');
          if (kind === 'trace') {
            if (!/^[a-f0-9]{32}$/.test(item.traceId ?? '') || !spanNames.includes(item.name)) continue;
            const clean = span.parse({ id: item.spanId, parentId: item.parentSpanId ?? '', name: item.name, role: sourceRole });
            if (!traces.has(item.traceId)) traces.set(item.traceId, []); traces.get(item.traceId).push(clean);
          } else {
            let entry;
            try {
              if (typeof item.body?.stringValue === 'string') entry = JSON.parse(item.body.stringValue);
              else {
                const values = item.body?.kvlistValue?.values;
                if (!Array.isArray(values) || values.length > 16 || new Set(values.map((pair) => pair.key)).size !== values.length) continue;
                entry = Object.fromEntries(values.map((pair) => [pair.key, pair.value?.stringValue ?? pair.value?.intValue ?? pair.value?.doubleValue]));
                if (typeof entry.status === 'string' && /^\d{3}$/.test(entry.status)) entry.status = Number(entry.status);
              }
            } catch { continue; }
            if (!/^[A-Za-z0-9._:@-]{1,128}$/.test(entry.requestId ?? '') || !['http.request', 'http.security', 'maintenance.job', 'maintenance.worker'].includes(entry.event)
                || !['info', 'warn', 'error'].includes(entry.level) || entry.route && routeTemplate(entry.route) !== entry.route) continue;
            const clean = logEntry.safeParse({ role: sourceRole, event: entry.event, level: entry.level, ...(entry.route ? { route: entry.route } : {}), ...(entry.status !== undefined ? { status: entry.status } : {}) }); if (!clean.success) continue;
            const summary = { entries: [clean.data], truncated: false };
            await put('log', entry.requestId, hash(summary), summary); accepted++;
          }
        }
        for (const [id, spans] of traces) { const summary = { spans: spans.sort((a, b) => a.id.localeCompare(b.id)), truncated: false }; await put('trace', id, hash(summary), summary); accepted += spans.length; }
      }
    }
    counters[kind === 'trace' ? 'traces' : 'logs'] += accepted; return {};
  }
  async function route(path, req, body, raw) {
    if (path === '/v1/alerts/alertmanager') {
      await authorize(req, 'alertmanager');
      const alert = z.object({ status: z.enum(['firing', 'resolved']), labels: z.record(z.string().max(64), z.string().max(512)), annotations: z.record(z.string().max(64), z.string().max(2048)), startsAt: z.string().datetime(), endsAt: z.string().datetime(), generatorURL: z.string().max(2048), fingerprint: z.string().regex(/^[a-f0-9]{16,64}$/) }).strict();
      const batch = z.object({ version: z.literal('4'), groupKey: z.string().max(4096), truncatedAlerts: z.number().int().min(0).max(1000000).optional(), status: z.enum(['firing', 'resolved']), receiver: z.string().max(128), groupLabels: z.record(z.string(), z.string()), commonLabels: z.record(z.string(), z.string()), commonAnnotations: z.record(z.string(), z.string()), externalURL: z.string().max(2048), alerts: z.array(alert).min(1).max(64) }).strict().parse(body);
      if (batch.alerts.some((item) => !config.alertNames.includes(item.labels.alertname) || Object.keys(item.labels).length > 16 || Object.keys(item.annotations).length > 8)) throw new AppError(400, 'MONITOR_ALERT_DENIED');
      const nonces = [...new Set(batch.alerts.map((item) => item.annotations.acceptance_nonce).filter(Boolean))];
      if (nonces.length > 1 || nonces.some((nonce) => !/^[a-f0-9]{64}$/.test(nonce))) throw new AppError(400, 'INVALID_ALERT_NONCE');
      if (nonces.length && batch.alerts.some((item) => item.labels.alertname !== 'RuntimeMonitoringAcceptance')) throw new AppError(400, 'MONITOR_ALERT_DENIED');
      const summary = { names: [...new Set(batch.alerts.map((item) => item.labels.alertname))].sort(), count: batch.alerts.length, state: batch.status,
        identityDigest: hash(batch.alerts.map((item) => ({ fingerprint: item.fingerprint, startsAt: item.startsAt })).sort((a, b) => a.fingerprint.localeCompare(b.fingerprint))) };
      const digest = hash(batch.alerts.map((item) => ({ fingerprint: item.fingerprint, startsAt: item.startsAt, status: item.status })).sort((a, b) => a.fingerprint.localeCompare(b.fingerprint)));
      counters.alerts++; return { received: true, ...await put('alert', nonces[0] ?? digest, digest, summary) };
    }
    if (path === '/v1/alerts/runtime') {
      await authorize(req, 'runtime'); if (!runtime) throw new AppError(404, 'RUNTIME_ALERTS_UNCONFIGURED');
      const ack = await runtime.receive({ raw, timestamp: req.headers['x-runtime-alert-time'], signature: req.headers['x-runtime-alert-signature'], idempotencyKey: req.headers['idempotency-key'] });
      await put('alert', body.id, hash(body), { names: [body.code], count: 1, state: 'firing', identityDigest: hash(body.id) }); counters.alerts++; return ack;
    }
    if (path === '/v1/traces' || path === '/v1/logs') { await authorize(req, 'collector'); return otlp(body, path === '/v1/traces' ? 'trace' : 'log'); }
    if (path === '/v1/receipts/query') {
      await authorize(req, 'reader'); const input = z.object({ kind: z.enum(['alert', 'trace', 'log']), id: z.string().regex(/^[A-Za-z0-9._:@-]{1,128}$/).optional(), span: z.enum(spanNames).optional(), after: z.number().int().min(0).default(0), limit: z.number().int().min(1).max(10).default(1) }).strict().parse(body);
      const ids = input.id ? [input.id] : (await store.get('monitoring', 'metadata', `recent-${input.kind}`) ?? []).map((item) => item.id); const receipts = [];
      for (const id of ids) { const value = await store.get('monitoring', 'incidents', receiptKey(input.kind, id)); if (value && value.lastObservedAt >= input.after && (!input.span || value.summary.spans?.some((item) => item.name === input.span))) { const receipt = signEnvelope(value, privateKey, 'monitoring-receipt'); if (Buffer.byteLength(JSON.stringify([...receipts, receipt])) > 60000) break; receipts.push(receipt); } if (receipts.length >= input.limit) break; }
      return { receipts };
    }
    throw new AppError(404, 'ROUTE_NOT_FOUND');
  }
  const server = createServer({ ...tls, minVersion: 'TLSv1.3', requestCert: true, rejectUnauthorized: true, maxHeaderSize: 16384 }, (req, res) => {
    const requestId = randomUUID(); let admitted = false;
    Promise.resolve().then(async () => {
      if (closed || inflight >= 16) throw new AppError(503, 'MONITOR_RECEIVER_BUSY'); inflight++; admitted = true;
      if (req.method === 'GET' && req.url === '/health/live') { await authorize(req, 'reader'); return sendJson(res, 200, { live: true }, { requestId }); }
      if (req.method === 'GET' && req.url === '/metrics') { await authorize(req, 'reader'); res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4', 'cache-control': 'no-store' }); res.end(Object.entries(counters).map(([kind, count]) => `monitoring_receiver_${kind}_total ${count}\n`).join('')); return; }
      if (req.method !== 'POST' || !['/v1/alerts/alertmanager', '/v1/alerts/runtime', '/v1/traces', '/v1/logs', '/v1/receipts/query'].includes(req.url)) throw new AppError(404, 'ROUTE_NOT_FOUND');
      const chunks = []; let bytes = 0; const capture = (chunk) => { bytes += chunk.length; if (bytes <= 65536) chunks.push(Buffer.from(chunk)); }; req.on('data', capture);
      let body; try { body = await readJson(req, { maxBytes: 65536, timeoutMs: 5000 }); } finally { req.off('data', capture); }
      sendJson(res, 200, await route(req.url, req, body, Buffer.concat(chunks).toString('utf8')), { requestId });
    }).catch((error) => { counters.denied++; sendError(res, error instanceof z.ZodError ? new AppError(400, 'INVALID_MONITORING_INPUT') : error, requestId); }).finally(() => { if (admitted) inflight--; });
  });
  server.maxConnections = 32; server.maxHeadersCount = 32; server.requestTimeout = 5000; server.headersTimeout = 5000; server.timeout = 5000; server.keepAliveTimeout = 1000; server.on('timeout', (socket) => socket.destroy());
  try { await new Promise((done, reject) => { server.once('error', reject); server.listen(config.listen.port, config.listen.host, () => { server.off('error', reject); done(); }); }); }
  catch (error) { runtime?.close(); await store.close(); throw error; }
  const timer = setInterval(() => { if (!purgeRun) purgeRun = store.purgeExpired(now(), { tenantId: 'monitoring', limit: 100 }).catch(() => {}).finally(() => { purgeRun = null; }); }, 60000); timer.unref();
  return { origin: `https://${config.listen.host}:${/** @type {import('node:net').AddressInfo} */ (server.address()).port}`, store, publicKey, async close() {
    if (closed) return; closed = true; clearInterval(timer); await new Promise((done) => { const timeout = setTimeout(() => { server.closeAllConnections(); done(); }, 5000); timeout.unref(); server.close(() => { clearTimeout(timeout); done(); }); server.closeIdleConnections(); }); await purgeRun; runtime?.close(); await store.close();
  } };
}

export async function loadMonitoringReceiver(path) { let config; try { config = JSON.parse(await readOperationsFile(path)); } catch { throw new AppError(400, 'MONITOR_RECEIVER_CONFIGURATION_UNAVAILABLE'); } return startMonitoringReceiver(config, { baseDirectory: dirname(resolve(path)) }); }
