import { isIP } from 'node:net';
import { open, lstat } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createSecureContext } from 'node:tls';
import { z } from 'zod';
import { ROOT_CONTEXT, SpanKind, SpanStatusCode, trace } from '@opentelemetry/api';
import { BatchSpanProcessor, TracerProvider, TraceIdRatioBasedSampler } from '@opentelemetry/sdk-trace';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { AppError, positiveInteger } from '../protocol.mjs';
import { assertNetworkDestination, createPinnedLookup } from '../adapters/transport.mjs';
import { formatTraceparent, parseTraceparent, requestContext } from './context.mjs';

const ATTRIBUTE_NAMES = new Set(['http.route', 'http.request.method', 'http.response.status_code', 'db.system', 'db.operation.name',
  'runtime.dependency', 'runtime.operation', 'runtime.job.kind', 'runtime.job.attempt', 'error.type']);

function attributes(input = {}) {
  /** @type {import('@opentelemetry/api').Attributes} */
  const clean = {};
  for (const [name, value] of Object.entries(input)) {
    if (!ATTRIBUTE_NAMES.has(name)) continue;
    if (typeof value === 'string' && value.length <= 128 && /^[A-Za-z0-9_.:/{} -]+$/.test(value)) clean[name] = value;
    else if (typeof value === 'number' && Number.isFinite(value)) clean[name] = value;
    else if (typeof value === 'boolean') clean[name] = value;
  }
  return clean;
}

export async function createConfiguredTelemetry(value, { baseDirectory = process.cwd() } = {}) {
  const boundedPath = z.string().min(1).max(4096);
  const schema = z.object({ serviceName: z.string().optional(), samplingRatio: z.number().min(0).max(1).default(0.1),
    maxQueueSize: z.number().int().min(1).max(4096).default(512), maxExportBatchSize: z.number().int().min(1).max(1024).default(64),
    exportTimeoutMs: z.number().int().min(1).max(30000).default(3000), scheduledDelayMs: z.number().int().min(1).max(60000).default(1000),
    collector: z.object({ url: z.string().url(), caFile: boundedPath, certFile: boundedPath.optional(), keyFile: boundedPath.optional(),
      allowPrivateNetworks: z.boolean().default(false) }).strict(),
  }).strict();
  let config; try { config = schema.parse(value); } catch { throw new AppError(400, 'INVALID_TELEMETRY_CONFIGURATION'); }
  async function file(path, secret = false) {
    const full = resolve(baseDirectory, path); const stat = await lstat(full);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536 || secret && process.platform !== 'win32' && (stat.mode & 0o077)) throw new AppError(400, 'UNSAFE_TELEMETRY_IDENTITY');
    const handle = await open(full, 'r');
    try {
      const actual = await handle.stat();
      if (actual.dev !== stat.dev || actual.ino !== stat.ino || actual.size > 65536) throw new AppError(400, 'UNSAFE_TELEMETRY_IDENTITY');
      const bytes = Buffer.alloc(65537); const { bytesRead } = await handle.read(bytes);
      if (bytesRead > 65536) throw new AppError(400, 'UNSAFE_TELEMETRY_IDENTITY');
      return bytes.subarray(0, bytesRead);
    } finally { await handle.close(); }
  }
  try {
    const { collector, ...settings } = config;
    if (Boolean(collector.certFile) !== Boolean(collector.keyFile)) throw new AppError(400, 'INVALID_TELEMETRY_CONFIGURATION');
    const tls = { ca: await file(collector.caFile), ...(collector.certFile ? { cert: await file(collector.certFile), key: await file(collector.keyFile, true) } : {}) };
    createSecureContext(tls);
    return createTelemetry({ ...settings, collector: { url: collector.url, tls, allowPrivateNetworks: collector.allowPrivateNetworks } });
  } catch (error) { throw error instanceof AppError ? error : new AppError(400, 'TELEMETRY_CONFIGURATION_UNAVAILABLE'); }
}

/** Per-instance providers avoid global SDK/environment state when service roles share a process. */
export function createTelemetry({ serviceName = 'company-agent-runtime', samplingRatio = 0.1, exporter = undefined,
  collector = undefined, maxQueueSize = 512, maxExportBatchSize = 64, exportTimeoutMs = 3000, scheduledDelayMs = 1000 } = {}) {
  if (typeof serviceName !== 'string' || !/^[A-Za-z][A-Za-z0-9._-]{0,63}$/.test(serviceName)
      || typeof samplingRatio !== 'number' || !Number.isFinite(samplingRatio) || samplingRatio < 0 || samplingRatio > 1) throw new AppError(400, 'INVALID_TELEMETRY_CONFIGURATION');
  for (const [value, maximum] of [[maxQueueSize, 4096], [maxExportBatchSize, 1024], [exportTimeoutMs, 30000], [scheduledDelayMs, 60000]]) positiveInteger(value, maximum);
  if (maxExportBatchSize > maxQueueSize || exporter && collector) throw new AppError(400, 'INVALID_TELEMETRY_CONFIGURATION');
  if (collector) {
    if (Object.keys(process.env).some((name) => /^OTEL_EXPORTER_OTLP(?:_TRACES)?_(?:CERTIFICATE|CLIENT_CERTIFICATE|CLIENT_KEY)$/.test(name))) {
      throw new AppError(400, 'AMBIENT_TELEMETRY_IDENTITY_DENIED');
    }
    let url; try { url = new URL(collector.url); } catch { throw new AppError(400, 'INVALID_TELEMETRY_COLLECTOR'); }
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash || url.pathname !== '/v1/traces'
        || /metadata|instance-data/i.test(url.hostname) || collector.tls?.rejectUnauthorized === false) throw new AppError(400, 'INVALID_TELEMETRY_COLLECTOR');
    const host = url.hostname.replace(/^\[|\]$/g, '');
    if (isIP(host)) assertNetworkDestination(host, { allowPrivateNetworks: collector.allowPrivateNetworks === true });
    if (Boolean(collector.tls?.cert) !== Boolean(collector.tls?.key)) throw new AppError(400, 'INVALID_TELEMETRY_COLLECTOR');
    let agent;
    const agentFactory = async (protocol) => {
      if (protocol !== 'https:') throw new AppError(400, 'INVALID_TELEMETRY_COLLECTOR');
      if (agent) return agent;
      const { Agent } = await import('node:https');
      const addRequest = Reflect.get(Agent.prototype, 'addRequest');
      if (typeof addRequest !== 'function') throw new AppError(500, 'TELEMETRY_AGENT_UNSUPPORTED');
      // SDK 0.223 merges environment headers even with headers:{}; strip them at I/O.
      class CollectorAgent extends Agent {
        addRequest(req, options) {
          if (options.hostname !== host || String(options.port ?? 443) !== (url.port || '443') || options.path !== '/v1/traces') throw new AppError(400, 'INVALID_TELEMETRY_COLLECTOR');
          for (const name of req.getHeaderNames()) req.removeHeader(name);
          req.setHeader('host', url.host); req.setHeader('content-type', 'application/json');
          req.setHeader('user-agent', 'company-agent-runtime-otlp');
          addRequest.call(this, req, options);
        }
      }
      agent = new CollectorAgent({ ca: collector.tls?.ca, cert: collector.tls?.cert, key: collector.tls?.key,
        rejectUnauthorized: true, lookup: createPinnedLookup({ allowPrivateNetworks: collector.allowPrivateNetworks === true }),
        maxSockets: 1, keepAlive: false, timeout: exportTimeoutMs });
      return agent;
    };
    const compression = /** @type {import('@opentelemetry/otlp-exporter-base').CompressionAlgorithm} */ ('none');
    exporter = new OTLPTraceExporter({ url: url.toString(), headers: {}, timeoutMillis: exportTimeoutMs, concurrencyLimit: 1,
      keepAlive: false, compression, httpAgentOptions: agentFactory });
    const shutdown = exporter.shutdown.bind(exporter);
    exporter.shutdown = async () => { try { await shutdown(); } finally { agent?.destroy(); } };
  }
  let exported = 0; let failures = 0; let closed = false;
  const observedExporter = exporter && {
    export(spans, callback) {
      exporter.export(spans, (result) => {
        if (result.code === 0) { exported += spans.length; callback({ code: 0 }); }
        else { failures += 1; callback({ code: 1, error: new Error('TRACE_EXPORT_FAILED') }); }
      });
    },
    shutdown: () => exporter.shutdown(),
  };
  // API verified against sdk-trace 2.12: BatchSpanProcessor accepts an options object.
  const processor = observedExporter && new BatchSpanProcessor({ exporter: observedExporter, maxQueueSize,
    maxExportBatchSize, scheduledDelayMillis: scheduledDelayMs, exportTimeoutMillis: exportTimeoutMs });
  const provider = new TracerProvider({ resource: resourceFromAttributes({ 'service.name': serviceName }),
    sampler: new TraceIdRatioBasedSampler(exporter ? samplingRatio : 0), spanProcessors: processor ? [processor] : [],
    spanLimits: { attributeCountLimit: 16, attributeValueLengthLimit: 128, eventCountLimit: 4, linkCountLimit: 0 } });
  const tracer = provider.getTracer('company-agent-runtime', '0.1.0');
  const telemetry = {
    async span(name, input, work, { kind = SpanKind.INTERNAL } = {}) {
      if (closed || typeof work !== 'function' || typeof name !== 'string' || !/^[a-z][a-z0-9._-]{0,63}$/.test(name)) throw new AppError(500, 'INVALID_TELEMETRY_SPAN');
      const parent = requestContext.getStore() ?? {};
      const parentSpan = parent.span?.spanContext?.() ?? parseTraceparent(parent.traceparent);
      const parentContext = parentSpan ? trace.setSpanContext(ROOT_CONTEXT, parentSpan) : ROOT_CONTEXT;
      const span = tracer.startSpan(name, { kind, attributes: attributes(input) }, parentContext);
      const active = { ...parent, telemetry, span, traceparent: formatTraceparent(span.spanContext()) };
      try {
        return await requestContext.run(active, work);
      } catch (error) {
        span.setStatus({ code: SpanStatusCode.ERROR });
        // Exception messages/stacks can contain provider credentials or business content.
        span.setAttribute('error.type', error instanceof AppError ? error.code : 'INTERNAL_ERROR'); throw error;
      } finally { span.end(); }
    },
    async server(context, route, method, work) {
      return requestContext.run({ ...context, telemetry }, () => telemetry.span('http.server', {
        'http.route': route, 'http.request.method': method,
      }, work, { kind: SpanKind.SERVER }));
    },
    status: () => ({ configured: Boolean(exporter), exported, failures, samplingRatio, maxQueueSize, maxExportBatchSize, closed }),
    flush: () => provider.forceFlush({ timeoutMillis: exportTimeoutMs }),
    async close() { if (closed) return; closed = true; await provider.shutdown(); },
  };
  return Object.freeze(telemetry);
}

/** Wrap only datastore methods, not arbitrary object properties or business callback arguments.
 * @param {any} store @param {any} telemetry @param {(method:string,elapsedMs:number,failed:boolean)=>void} observe */
export function instrumentStore(store, telemetry, observe = () => {}) {
  if (!telemetry) return store;
  const wrapped = { ...store };
  for (const [property, value] of Object.entries(store)) {
    if (typeof value !== 'function') continue;
    if (property === 'maintenanceStore') { wrapped[property] = (...args) => instrumentStore(value.apply(store, args), telemetry, observe); continue; }
    if (property === 'close') { wrapped[property] = value.bind(store); continue; }
    wrapped[property] = (...args) => {
      const startedAt = performance.now();
      const observed = (failed) => { try { observe(property, performance.now() - startedAt, failed); } catch { /* Metrics cannot change committed state or outcomes. */ } };
      return telemetry.span('db.operation', { 'db.system': store.backend === 'postgres' ? 'postgresql' : 'sqlite', 'db.operation.name': property },
        () => requestContext.run({ ...(requestContext.getStore() ?? {}), telemetry }, () => value.apply(store, args)))
        .then((result) => { observed(false); return result; }, (error) => { observed(true); throw error; });
    };
  }
  return Object.freeze(wrapped);
}
