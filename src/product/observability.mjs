import { createHmac, randomBytes, randomUUID } from 'node:crypto';
import { monitorEventLoopDelay } from 'node:perf_hooks';
import { Counter, Gauge, Histogram, Registry } from '@prometheus-io/client';
import { SpanStatusCode } from '@opentelemetry/api';
import { AppError, positiveInteger } from '../protocol.mjs';
import { parseTraceparent, requestContext } from './context.mjs';
import { createTelemetry } from './telemetry.mjs';

const METHODS = new Set(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']);
const ROUTES = new Set(['/metrics', '/health/live', '/health/startup', '/health/ready', '/mcp', '/a2a', '/.well-known/agent-card.json',
  '/v1/actions', '/v1/approvals', '/v1/tasks', '/v1/tasks/list', '/v1/memory', '/v1/memory/read', '/v1/memory/delete', '/v1/audit',
  '/v1/evidence', '/v1/checkpoint', '/v1/coverage', '/v1/integrations/status', '/v1/diagnostic/read', '/v1/zanii/recover', '/v1/zanii/proof',
  '/v1/resource/status', '/v1/resource/metadata', '/v1/resource/observe', '/v1/resource/documents', '/v1/resource/import',
  '/v1/resource/deliveries', '/v1/resource/execute', '/v1/resource/diagnostic', '/v1/ops/status', '/v1/ops/jobs/list', '/v1/ops/jobs/retry',
  '/v1/ops/privacy/request', '/v1/ops/privacy/status', '/v1/ops/privacy/export', '/v1/ops/privacy/holds', '/v1/ops/privacy/holds/release', '/v1/ops/privacy/learning-reset']);
const STORE_METHODS = new Set(['get', 'put', 'list', 'delete', 'transaction', 'getOperation', 'reserveOperation', 'transitionOperation',
  'appendAudit', 'verifyAudit', 'checkpoint', 'queryAudit', 'exportAudit', 'purgeExpired', 'pruneOperationResults', 'recoverUnknown',
  'listOperations', 'backup', 'listTenants', 'claimLease', 'renewLease', 'releaseLease', 'assertLease']);
const SIGNALS = Object.freeze({ db_bytes: 'Database bytes', db_pool_total: 'Open datastore connections', db_pool_idle: 'Idle datastore connections',
  db_pool_waiting: 'Waiting datastore acquisitions', db_pool_max: 'Configured connection ceiling', disk_free_bytes: 'Free data-volume bytes',
  jobs_pending: 'Pending maintenance jobs', jobs_dlq: 'Dead-letter maintenance jobs', jobs_oldest_age_seconds: 'Oldest pending job age',
  worker_heartbeat_age_seconds: 'Maintenance heartbeat age', certificate_expiry_seconds: 'Seconds until TLS expiry',
  backup_age_seconds: 'Maximum age of captured and verified backup', backup_snapshot_age_seconds: 'Age of signed recovery point capture', backup_verification_age_seconds: 'Age of verified backup proof',
  backup_max_age_seconds: 'Configured maximum recovery point and verification age', archive_max_age_seconds: 'Configured maximum archive age', archive_age_seconds: 'Age of verified audit archive', containment_expiry_seconds: 'Seconds until containment expiry',
  log_sink_healthy: 'Configured structured log sink health', log_queue_bytes: 'Queued structured log bytes', log_dropped_events: 'Structured log events dropped since process start',
  log_write_failures: 'Structured log writes failed since process start', telemetry_configured: 'Trace exporter configured', telemetry_exported_spans: 'Spans acknowledged by configured exporter',
  telemetry_export_failures: 'Trace export failures since process start', budget_data_available: 'Fresh explicit billing evidence available', budget_spent_ratio: 'Spent minor units divided by budget minor units', budget_observation_age_seconds: 'Age of supplied billing observation' });

export function routeTemplate(value) {
  if (typeof value !== 'string' || value.length > 4096) return 'unmatched';
  let path; try { path = new URL(value, 'https://runtime.invalid').pathname; } catch { return 'unmatched'; }
  if (ROUTES.has(path)) return path;
  if (/^\/v1\/tasks\/[A-Za-z0-9._:@-]+$/.test(path)) return '/v1/tasks/:id';
  const task = path.match(/^\/v1\/tasks\/[A-Za-z0-9._:@-]+\/(delegate|revoke)$/);
  if (task) return `/v1/tasks/:id/${task[1]}`;
  if (/^\/v1\/operations\/[A-Za-z0-9._:@-]+$/.test(path)) return '/v1/operations/:id';
  const operation = path.match(/^\/v1\/operations\/[A-Za-z0-9._:@-]+\/(reconcile|cancel)$/);
  if (operation) return `/v1/operations/:id/${operation[1]}`;
  const learning = path.match(/^\/v1\/learning\/(quarantine|review|train|shadow|candidate|prepare-update|apply-update|detect|delete)$/);
  if (learning) return `/v1/learning/${learning[1]}`;
  const integration = path.match(/^\/v1\/integrations\/(register|passport|vault)$/);
  return integration ? `/v1/integrations/${integration[1]}` : 'unmatched';
}

/** Labels are bounded; identities are pseudonymized and request bodies never enter telemetry. */
export function createObservability({ logger = (line) => process.stdout.write(`${line}\n`), now = Date.now,
  rateWindowMs, rateRequests, maxConcurrency, pseudonymKey = randomBytes(32), successSampleRate = 0.1,
  random = Math.random, telemetry = createTelemetry() }) {
  for (const [value, maximum] of [[rateWindowMs, 3600000], [rateRequests, 100000], [maxConcurrency, 1024]]) positiveInteger(value, maximum);
  if (!(pseudonymKey instanceof Uint8Array) || pseudonymKey.length < 32 || typeof successSampleRate !== 'number'
      || !Number.isFinite(successSampleRate) || successSampleRate < 0 || successSampleRate > 1) throw new AppError(400, 'INVALID_OBSERVABILITY_CONFIGURATION');
  const logKey = Buffer.from(pseudonymKey); const registry = new Registry();
  const windows = new Map(); let active = 0; let total = 0; let denied = 0; let latencyMs = 0; let closed = false;
  const eventLoop = monitorEventLoopDelay({ resolution: 20 }); eventLoop.enable();
  const counter = (name, help, labelNames = []) => new Counter({ name, help, labelNames, registers: [registry] });
  /** @param {string} name @param {string} help
   * @param {Omit<import('@prometheus-io/client').GaugeConfiguration<string>, 'name'|'help'|'registers'>} options
   * @returns {import('@prometheus-io/client').Gauge<string>} */
  const gauge = (name, help, options = {}) => new Gauge({ name, help, registers: [registry], ...options });
  const aggregate = counter('runtime_requests_total', 'Incoming HTTP requests including rejected admissions');
  const aggregateDenied = counter('runtime_denied_total', 'HTTP responses with status 400 or greater');
  const duration = counter('runtime_request_duration_ms_sum', 'Aggregate HTTP handling milliseconds');
  const http = counter('runtime_http_requests_total', 'HTTP outcomes by bounded endpoint and status class', ['route', 'method', 'status_class']);
  const latency = new Histogram({ name: 'runtime_http_request_duration_seconds', help: 'HTTP request latency', labelNames: ['route', 'method'],
    buckets: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60], registers: [registry] });
  gauge('runtime_active', 'Currently admitted requests', { collect() { this.set(active); } });
  gauge('runtime_concurrency_limit', 'Configured request admission ceiling').set(maxConcurrency);
  gauge('runtime_saturation_ratio', 'Admitted requests divided by configured ceiling', { collect() { this.set(active / maxConcurrency); } });
  gauge('runtime_process_resident_memory_bytes', 'Process resident memory', { collect() { this.set(process.memoryUsage().rss); } });
  gauge('runtime_process_heap_used_bytes', 'Process heap in use', { collect() { this.set(process.memoryUsage().heapUsed); } });
  gauge('runtime_process_cpu_seconds', 'Cumulative process CPU seconds', { collect() { const cpu = process.cpuUsage(); this.set((cpu.user + cpu.system) / 1000000); } });
  gauge('runtime_process_uptime_seconds', 'Process uptime', { collect() { this.set(process.uptime()); } });
  gauge('runtime_event_loop_delay_seconds', 'Cumulative event loop delay', { labelNames: ['stat'], collect() {
    this.set({ stat: 'mean' }, Number.isFinite(eventLoop.mean) ? eventLoop.mean / 1000000000 : 0);
    this.set({ stat: 'p99' }, eventLoop.count ? eventLoop.percentile(99) / 1000000000 : 0);
  } });
  const storeLatency = new Histogram({ name: 'runtime_store_duration_seconds', help: 'Datastore operation latency', labelNames: ['operation'],
    buckets: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5], registers: [registry] });
  const storeErrors = counter('runtime_store_errors_total', 'Datastore failures', ['operation']);
  const business = counter('runtime_action_outcomes_total', 'Execution outcomes, not an independent effect oracle', ['kind', 'state']);
  const dependency = gauge('runtime_dependency_circuit_state', 'Dependency state: closed=0, half-open=1, open=2', { labelNames: ['dependency'] });
  const signalGauges = new Map(Object.entries(SIGNALS).map(([name, help]) => [name, gauge(`runtime_${name}`, help)]));
  const availableSignals = gauge('runtime_signal_available', 'An operational signal has a valid current observation', { labelNames: ['signal'] });
  for (const name of Object.keys(SIGNALS)) { availableSignals.set({ signal: name }, 0); signalGauges.get(name).set(NaN); }
  const maintenanceReady = gauge('runtime_maintenance_role_ready', 'Durable maintenance role health', { labelNames: ['role'] });
  const maintenanceRequired = gauge('runtime_maintenance_role_required', 'Maintenance role is required for protected admission', { labelNames: ['role'] });
  const maintenanceQueue = gauge('runtime_maintenance_jobs', 'Durable maintenance queue by fixed role and state', { labelNames: ['role', 'state'] });
  const maintenanceHeartbeat = gauge('runtime_maintenance_heartbeat_age_seconds', 'Durable role heartbeat age', { labelNames: ['role'] });
  const maintenanceOldest = gauge('runtime_maintenance_oldest_due_age_seconds', 'Oldest due maintenance work by role', { labelNames: ['role'] });
  const pseudonym = (value) => createHmac('sha256', logKey).update(String(value)).digest('hex').slice(0, 24);
  function limit(key) {
    if (typeof key !== 'string' || key.length > 512) throw new AppError(429, 'RATE_LIMIT_CAPACITY');
    const time = now(); let entry = windows.get(key);
    if (!entry || entry.until <= time) {
      if (windows.size >= 4096) for (const [id, value] of windows) if (value.until <= time) windows.delete(id);
      if (!windows.has(key) && windows.size >= 4096) throw new AppError(429, 'RATE_LIMIT_CAPACITY');
      entry = { until: time + rateWindowMs, count: 0 }; windows.set(key, entry);
    }
    if (++entry.count > rateRequests) throw new AppError(429, 'RATE_LIMITED');
  }
  function dependencyState(value) {
    if (!['provider', 'resource', 'register', 'passport', 'vault', 'zanii', 'object-storage', 'kms', 'audit', 'backup', 'collector', 'alerts'].includes(value.name)) return;
    dependency.set({ dependency: value.name }, { closed: 0, 'half-open': 1, open: 2 }[value.state] ?? 2);
  }
  function operation(kind, state) {
    if (['read', 'share'].includes(kind) && ['succeeded', 'failed', 'unknown', 'denied'].includes(state)) business.inc({ kind, state });
  }
  return Object.freeze({
    limit, dependencyState, operation,
    maintenanceStatus({ role, healthy, required, heartbeatAgeMs, counts, oldestAgeMs }) {
      if (!['worker', 'archive', 'backup'].includes(role)) return;
      maintenanceReady.set({ role }, healthy ? 1 : 0);
      maintenanceRequired.set({ role }, required ? 1 : 0);
      maintenanceHeartbeat.set({ role }, Number.isFinite(heartbeatAgeMs) && heartbeatAgeMs >= 0 ? heartbeatAgeMs / 1000 : NaN);
      maintenanceOldest.set({ role }, Number.isFinite(oldestAgeMs) && oldestAgeMs >= 0 ? oldestAgeMs / 1000 : counts?.queued === 0 && counts?.retry === 0 ? 0 : NaN);
      for (const state of ['queued', 'retry', 'running', 'dead', 'due']) maintenanceQueue.set({ role, state }, Number.isSafeInteger(counts?.[state]) && counts[state] >= 0 ? counts[state] : NaN);
    },
    signal(name, value) {
      if (!signalGauges.has(name) || typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new AppError(400, 'INVALID_OPERATIONAL_SIGNAL');
      signalGauges.get(name).set(value);
      availableSignals.set({ signal: name }, 1);
    },
    signalUnavailable(name) { if (!signalGauges.has(name)) throw new AppError(400, 'INVALID_OPERATIONAL_SIGNAL'); signalGauges.get(name).set(NaN); availableSignals.set({ signal: name }, 0); },
    observeStore(method, elapsedMs, failed) {
      const operation = STORE_METHODS.has(method) ? method : 'other';
      if (typeof elapsedMs !== 'number' || !Number.isFinite(elapsedMs) || elapsedMs < 0) return;
      storeLatency.observe({ operation }, elapsedMs / 1000); if (failed) storeErrors.inc({ operation });
    },
    begin(req) {
      if (closed) throw new AppError(503, 'OBSERVABILITY_CLOSED');
      total += 1; aggregate.inc(); const startedAt = now(); const requestId = randomUUID();
      const incoming = parseTraceparent(req.headers.traceparent);
      const traceparent = incoming ? `00-${incoming.traceId}-${incoming.spanId}-${incoming.traceFlags ? '01' : '00'}`
        : `00-${randomBytes(16).toString('hex')}-${randomBytes(8).toString('hex')}-01`;
      const route = routeTemplate(req.url); const method = METHODS.has(req.method) ? req.method : 'OTHER';
      let admitted = false; let acquired = false; let finished = false; let actor; let tenant;
      const context = {
        requestId, traceparent, telemetry, dependency: dependencyState, business: operation,
        admit() {
          if (admitted) return;
          const probe = ['/health/live', '/health/startup'].includes(route);
          limit(`${probe ? 'probe' : 'peer'}:${req.socket.remoteAddress ?? 'uds'}`);
          if (!probe && active >= maxConcurrency) throw new AppError(429, 'CONCURRENCY_LIMIT');
          if (!probe) { active += 1; acquired = true; } admitted = true;
        },
        bindIdentity(identity) { actor = pseudonym(identity.actorId); tenant = pseudonym(identity.tenantId); },
        httpStatus(code) {
          if (!Number.isInteger(code) || code < 100 || code > 599) return;
          const span = this.span ?? requestContext.getStore()?.span;
          span?.setAttribute('http.response.status_code', code);
          if (code >= 500) span?.setStatus({ code: SpanStatusCode.ERROR });
        },
        run(work) {
          context.admit();
          return telemetry.server({ ...(requestContext.getStore() ?? {}), ...this }, route, method, () => {
            const current = requestContext.getStore(); Object.assign(this, { span: current?.span, traceparent: current?.traceparent ?? this.traceparent });
            return work();
          });
        },
        finish(status, fallbackRoute) {
          if (finished) return; finished = true; if (acquired) active -= 1;
          const durationMs = Math.max(0, now() - startedAt); latencyMs += durationMs; duration.inc(durationMs);
          const endpoint = route === 'unmatched' ? routeTemplate(fallbackRoute) : route;
          const code = Number.isInteger(status) && status >= 100 && status <= 599 ? status : 500;
          if (code >= 400) { denied += 1; aggregateDenied.inc(); }
          http.inc({ route: endpoint, method, status_class: `${Math.floor(code / 100)}xx` }); latency.observe({ route: endpoint, method }, durationMs / 1000);
          if (code < 400 && random() >= successSampleRate) return;
          try { logger(JSON.stringify({ at: new Date(now()).toISOString(), level: code >= 500 ? 'error' : code >= 400 ? 'warn' : 'info',
            event: [401, 403, 429].includes(code) ? 'http.security' : 'http.request', requestId, traceparent: this.traceparent, route: endpoint, method, status: code, durationMs,
            ...(actor ? { actor } : {}), ...(tenant ? { tenant } : {}) })); } catch { /* Logging cannot disclose data or interrupt an authorized effect. */ }
        },
      };
      return context;
    },
    // Compatibility snapshot; the authenticated server uses the complete async registry below.
    metrics() { return `# TYPE runtime_requests_total counter\nruntime_requests_total ${total}\n# TYPE runtime_denied_total counter\nruntime_denied_total ${denied}\n# TYPE runtime_active gauge\nruntime_active ${active}\n# TYPE runtime_request_duration_ms_sum counter\nruntime_request_duration_ms_sum ${latencyMs}\n`; },
    // Keep the Prometheus spelling stable across client versions for unknown observations.
    metricsText: async () => (await registry.metrics()).replace(/ Nan(?=\n)/g, ' NaN'),
    active: () => active,
    async close() { if (closed) return; closed = true; eventLoop.disable(); logKey.fill(0); await telemetry.close(); registry.clear(); },
  });
}
