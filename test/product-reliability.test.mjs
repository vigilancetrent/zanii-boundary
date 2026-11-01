import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { readFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { InMemorySpanExporter } from '@opentelemetry/sdk-trace';
import { AppError } from '../src/protocol.mjs';
import { assertNetworkDestination, createHttpsTransport } from '../src/adapters/transport.mjs';
import { effectiveDeadline, jobTraceContext, parseTraceparent, requestContext, runJobContext, withSpan } from '../src/product/context.mjs';
import { createDependencyPolicy } from '../src/product/resilience.mjs';
import { createObservability, routeTemplate } from '../src/product/observability.mjs';
import { createConfiguredTelemetry, createTelemetry, instrumentStore } from '../src/product/telemetry.mjs';

const pem = (name) => readFileSync(`artifacts/test-pki-${name}.pem`, 'utf8');
const traceparent = `00-${'1'.repeat(32)}-${'2'.repeat(16)}-01`;
const unavailable = () => new AppError(503, 'DEPENDENCY_UNAVAILABLE');
const request = (url = '/v1/actions') => ({ url, method: 'POST', headers: { traceparent }, socket: { remoteAddress: '127.0.0.1' } });

async function tlsServer(t, handler) {
  const server = createServer({ key: pem('gateway-key'), cert: pem('gateway-cert'), ca: pem('ca'), requestCert: true, rejectUnauthorized: true }, handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  return `https://127.0.0.1:${server.address().port}`;
}
const tlsIdentity = () => ({ ca: pem('ca'), cert: pem('agent-cert'), key: pem('agent-key') });

test('SDK IP validation canonicalizes IPv6 and denies metadata, compatible and translated routes even on private profiles', () => {
  for (const address of ['169.254.170.23', '168.63.129.16', 'fd00:0ec2:0:0:0:0:0:0254', '0:0:0:0:0:ffff:a9fe:a9fe',
    '::192.168.1.2', '64:ff9b::a9fe:a9fe', '2001:0:4136:e378:8000:63bf:3fff:fdd2', '2001::1', '2002:a9fe:a9fe::1', 'ff02::1']) {
    assert.throws(() => assertNetworkDestination(address, { allowPrivateNetworks: true }), { code: 'NETWORK_DESTINATION_DENIED' });
  }
  assert.throws(() => assertNetworkDestination('198.18.0.1'), { code: 'NETWORK_DESTINATION_DENIED' });
  assert.doesNotThrow(() => assertNetworkDestination('192.168.1.2', { allowPrivateNetworks: true }));
  assert.doesNotThrow(() => assertNetworkDestination('2606:4700:4700::1111'));
  assert.throws(() => createHttpsTransport({ origin: 'https://provider.invalid', tls: { cert: 'invalid', key: 'invalid' } }), { code: 'INVALID_TRANSPORT_TLS' });
});

test('invocation budgets only narrow; durable jobs retain correlation with a new independent budget', () => {
  assert.equal(parseTraceparent(`00-${'0'.repeat(32)}-${'2'.repeat(16)}-01`), null);
  assert.equal(parseTraceparent(`00-${'1'.repeat(32)}-${'0'.repeat(16)}-01`), null);
  assert.equal(parseTraceparent(traceparent).traceId, '1'.repeat(32));
  requestContext.run({ requestId: 'origin', traceparent, deadlineAt: 1200 }, () => {
    assert.equal(effectiveDeadline({ now: 1000, timeoutMs: 1000, deadlineAt: 1500 }), 1200);
    assert.deepEqual(jobTraceContext(), { requestId: 'origin', traceparent });
  });
  requestContext.run({ deadlineAt: 1 }, () => runJobContext({ requestId: 'job-origin', traceparent }, { now: 1000, timeoutMs: 500 }, () => {
    assert.equal(requestContext.getStore().deadlineAt, 1500); assert.equal(requestContext.getStore().traceparent, traceparent);
  }));
  assert.throws(() => runJobContext({ requestId: 'one', traceparent: 'bad' }, {}, () => {}), { code: 'INVALID_TRACE_CONTEXT' });
});

test('safe work has bounded exponential jitter while mutation failures and ordinary 4xx never retry', async () => {
  let clock = 1000; const delays = []; let calls = 0;
  const policy = createDependencyPolicy({ failureThreshold: 5, now: () => clock, random: () => 0,
    sleep: async (ms) => { delays.push(ms); clock += ms; }, baseDelayMs: 50, maxAttempts: 3 });
  assert.equal(await policy.execute(async () => { calls++; if (calls < 3) throw unavailable(); return 'ok'; }, { retrySafe: true }), 'ok');
  assert.deepEqual(delays, [25, 50]); assert.equal(calls, 3);
  await assert.rejects(policy.execute(async () => { calls++; throw unavailable(); }), { code: 'DEPENDENCY_UNAVAILABLE' });
  assert.equal(calls, 4);
  await assert.rejects(policy.execute(async () => { calls++; throw new AppError(403, 'DENIED'); }, { retrySafe: true }), { code: 'DENIED' });
  assert.equal(calls, 5); assert.equal(policy.status().failures, 0);
  await assert.rejects(policy.execute(async () => { throw unavailable(); }, { deadlineAt: clock + 10, retrySafe: true }), { code: 'TRANSPORT_DEADLINE' });
  assert.equal(delays.length, 2);
});

test('one half-open probe owns recovery and stale in-flight success cannot close a newer circuit generation', async () => {
  let clock = 1000; let lateDone; let probeDone; let probeCalls = 0;
  const policy = createDependencyPolicy({ failureThreshold: 2, cooldownMs: 100, now: () => clock });
  const late = policy.execute(() => new Promise((resolve) => { lateDone = resolve; }));
  await assert.rejects(policy.execute(async () => { throw unavailable(); }));
  await assert.rejects(policy.execute(async () => { throw unavailable(); }));
  lateDone('late'); await late; assert.equal(policy.status().state, 'open');
  clock += 100;
  const probe = policy.execute(() => { probeCalls++; return new Promise((resolve) => { probeDone = resolve; }); });
  const refused = await Promise.allSettled(Array.from({ length: 20 }, () => policy.execute(async () => 'must-not-run')));
  assert.equal(refused.filter((item) => item.status === 'rejected' && item.reason.code === 'CIRCUIT_OPEN').length, 20);
  assert.equal(probeCalls, 1); probeDone('recovered'); assert.equal(await probe, 'recovered');
  assert.equal(policy.status().state, 'closed');
});

test('deadline expiry after half-open admission releases the probe and late completion never counts as timely success', async () => {
  let clock = 1000; let reads = 0; let expireAfterAdmission = false;
  const policy = createDependencyPolicy({ failureThreshold: 1, cooldownMs: 10, timeoutMs: 100,
    now: () => { reads++; if (expireAfterAdmission && reads >= 3) return clock + 200; return clock; } });
  await assert.rejects(policy.execute(async () => { throw unavailable(); }));
  clock += 10; reads = 0; expireAfterAdmission = true;
  await assert.rejects(policy.execute(async () => assert.fail('expired probe cannot run')), { code: 'TRANSPORT_DEADLINE' });
  assert.equal(policy.status().state, 'open');
  const late = createDependencyPolicy({ now: () => clock, timeoutMs: 100 });
  await assert.rejects(late.execute(async () => { clock += 101; return 'late'; }), { code: 'TRANSPORT_DEADLINE' });
});

test('real mTLS transport inherits context deadlines, propagates trace and never retries a sent mutation', async (t) => {
  let calls = 0; let receivedTrace;
  const origin = await tlsServer(t, async (req, res) => {
    calls++; receivedTrace = req.headers.traceparent; for await (const chunk of req) assert.ok(chunk.length < 1000);
    if (req.url === '/slow') { setTimeout(() => { if (!res.destroyed) { res.writeHead(200); res.end('{}'); } }, 200); return; }
    res.writeHead(503, { 'content-type': 'application/json' }); res.end('{"error":"unavailable"}');
  });
  const transport = createHttpsTransport({ origin, tls: tlsIdentity(), allowPrivateNetworks: true, timeoutMs: 1000 });
  await requestContext.run({ traceparent, deadlineAt: Date.now() + 1000 }, async () => {
    assert.equal((await transport.request('/once', { method: 'POST', body: {} })).status, 503);
  });
  assert.equal(calls, 1); assert.equal(receivedTrace, traceparent);
  const start = performance.now();
  await requestContext.run({ traceparent, deadlineAt: Date.now() + 40 }, async () => {
    await assert.rejects(transport.fetch(`${origin}/slow`, { method: 'POST', body: '{}' }), { status: 504 });
  });
  assert.ok(performance.now() - start < 180); assert.equal(calls, 2);
  await requestContext.run({ deadlineAt: Date.now() - 1 }, async () => {
    await assert.rejects(transport.request('/once', { method: 'POST', body: {} }), { code: 'TRANSPORT_DEADLINE' });
  });
  await assert.rejects(transport.request('/once', { method: 'POST', body: {}, retrySafe: true }), { code: 'MUTATION_RETRY_DENIED' });
  assert.equal(calls, 2);
});

test('open dependency circuit still validates caller paths and headers before admission', async (t) => {
  const origin = await tlsServer(t, (req, res) => { res.writeHead(503); res.end('{}'); });
  const transport = createHttpsTransport({ origin, tls: tlsIdentity(), allowPrivateNetworks: true, resilience: { failureThreshold: 1 } });
  assert.equal((await transport.request('/one')).status, 503);
  assert.equal(transport.dependencyStatus().state, 'open');
  await assert.rejects(transport.request('/one', { headers: { host: 'foreign' } }), { code: 'INVALID_TRANSPORT_HEADERS' });
  await assert.rejects(transport.request('//foreign.invalid'), { code: 'INVALID_TRANSPORT_PATH' });
  await assert.rejects(transport.request('/one'), { code: 'CIRCUIT_OPEN' });
});

test('route RED/USE telemetry includes rejected admissions and logs only pseudonymous identities', async (t) => {
  const logs = []; const o = createObservability({ rateWindowMs: 1000, rateRequests: 100, maxConcurrency: 1,
    pseudonymKey: randomBytes(32), logger: (line) => logs.push(JSON.parse(line)), successSampleRate: 0 });
  t.after(() => o.close());
  const first = o.begin(request('/v1/tasks/private-person@example.invalid')); first.admit(); first.bindIdentity({ actorId: 'person@example.invalid', tenantId: 'secret-company' });
  const second = o.begin(request('/v1/tasks/private-other')); second.bindIdentity({ actorId: 'person@example.invalid', tenantId: 'secret-company' });
  assert.throws(() => second.admit(), { code: 'CONCURRENCY_LIMIT' }); second.finish(429); first.finish(200);
  assert.equal(o.active(), 0); assert.equal(logs.length, 1); assert.equal(logs[0].level, 'warn');
  const unknown = o.begin({ ...request('/v1/secret-credential-do-not-log'), headers: { authorization: 'Bearer synthetic-secret-do-not-log' } });
  unknown.admit(); unknown.finish(401);
  const text = await o.metricsText(); assert.match(text, /runtime_requests_total 3/); assert.match(text, /runtime_denied_total 2/);
  assert.match(text, /runtime_http_requests_total\{route="\/v1\/tasks\/:id",method="POST",status_class="4xx"\} 1/);
  assert.match(text, /runtime_process_resident_memory_bytes [1-9]/); assert.match(text, /runtime_saturation_ratio 0/);
  assert.equal(JSON.stringify(logs).includes('person@'), false); assert.equal(JSON.stringify(logs).includes('secret-company'), false);
  assert.equal(JSON.stringify(logs).includes('do-not-log'), false); assert.equal(text.includes('do-not-log'), false);
  assert.equal(text.includes('private-person'), false); assert.equal(routeTemplate('/v1/random-private-id'), 'unmatched');
});

test('process liveness and startup keep their separate bounded admission while business slots are saturated', async (t) => {
  const o = createObservability({ rateWindowMs: 1000, rateRequests: 10, maxConcurrency: 1, logger: () => {} });
  t.after(() => o.close()); const business = o.begin(request()); business.admit();
  for (const path of ['/health/live', '/health/startup']) {
    const probe = o.begin({ ...request(path), method: 'GET' }); probe.admit(); probe.finish(200); assert.equal(o.active(), 1);
  }
  business.finish(200); assert.equal(o.active(), 0);
});

test('real SDK spans preserve server→store→provider and durable-job parentage without recording private attributes', async (t) => {
  const exporter = new InMemorySpanExporter(); const telemetry = createTelemetry({ exporter, samplingRatio: 1 });
  t.after(() => telemetry.close());
  const wrapped = instrumentStore(Object.freeze({ backend: 'sqlite', async get() { return 1; } }), telemetry);
  let traceMetadata;
  await telemetry.server({ requestId: 'one', traceparent, deadlineAt: Date.now() + 1000 }, '/v1/actions', 'POST', async () => {
    await wrapped.get('tenant', 'private', 'doc');
    await withSpan('http.provider', { 'runtime.dependency': 'resource', private: 'secret-payload' }, async () => {});
    await assert.rejects(telemetry.span('policy.denied', {}, async () => { throw new Error('Bearer synthetic-secret-user@example.invalid'); }));
    traceMetadata = jobTraceContext();
  });
  await runJobContext(traceMetadata, { timeoutMs: 1000 }, () => telemetry.span('worker.job', { 'runtime.job.kind': 'audit' }, async () => {}));
  await telemetry.flush(); const spans = exporter.getFinishedSpans(); assert.equal(spans.length, 5);
  assert.equal(new Set(spans.map((span) => span.spanContext().traceId)).size, 1);
  const root = spans.find((span) => span.name === 'http.server');
  assert.equal(spans.find((span) => span.name === 'db.operation').parentSpanContext.spanId, root.spanContext().spanId);
  assert.equal(spans.find((span) => span.name === 'worker.job').parentSpanContext.spanId, root.spanContext().spanId);
  assert.equal(JSON.stringify(spans.map((span) => span.attributes)).includes('secret-payload'), false);
  assert.equal(JSON.stringify(spans.map((span) => ({ attributes: span.attributes, events: span.events }))).includes('synthetic-secret'), false);
});

test('configured real OTLP exporter uses pinned mTLS collector and strips synthetic ambient identity headers', async (t) => {
  const received = []; const origin = await tlsServer(t, async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    received.push({ path: req.url, headers: req.headers, body: JSON.parse(Buffer.concat(chunks).toString()) });
    res.writeHead(200, { 'content-type': 'application/json' }); res.end('{}');
  });
  const saved = {};
  for (const name of ['OTEL_EXPORTER_OTLP_HEADERS', 'OTEL_EXPORTER_OTLP_TRACES_HEADERS', 'OTEL_EXPORTER_OTLP_ENDPOINT', 'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT']) saved[name] = process.env[name];
  process.env.OTEL_EXPORTER_OTLP_HEADERS = 'authorization=synthetic-ambient-general';
  process.env.OTEL_EXPORTER_OTLP_TRACES_HEADERS = 'x-ambient-token=synthetic-ambient-traces';
  process.env.OTEL_EXPORTER_OTLP_ENDPOINT = 'https://ambient.invalid'; process.env.OTEL_EXPORTER_OTLP_TRACES_ENDPOINT = 'https://ambient.invalid/secret';
  let telemetry;
  try {
    telemetry = await createConfiguredTelemetry({ samplingRatio: 1, maxQueueSize: 8, maxExportBatchSize: 4, exportTimeoutMs: 1000,
      collector: { url: `${origin}/v1/traces`, caFile: 'artifacts/test-pki-ca.pem', certFile: 'artifacts/test-pki-agent-cert.pem',
        keyFile: 'artifacts/test-pki-agent-key.pem', allowPrivateNetworks: true } });
    await telemetry.span('policy.authorize', { 'runtime.operation': 'read' }, async () => {});
    await telemetry.flush(); assert.equal(telemetry.status().failures, 0); assert.equal(telemetry.status().exported, 1);
    assert.equal(received.length, 1); assert.equal(received[0].path, '/v1/traces');
    assert.equal(received[0].headers.authorization, undefined); assert.equal(received[0].headers['x-ambient-token'], undefined);
    assert.equal(JSON.stringify(received).includes('synthetic-ambient'), false);
    assert.equal(received[0].body.resourceSpans[0].scopeSpans[0].spans[0].name, 'policy.authorize');
  } finally {
    await telemetry?.close();
    for (const [name, value] of Object.entries(saved)) if (value === undefined) delete process.env[name]; else process.env[name] = value;
  }
});

test('ambient OTEL TLS files are rejected before the SDK can read an unconfigured identity', () => {
  const name = 'OTEL_EXPORTER_OTLP_TRACES_CLIENT_KEY'; const saved = process.env[name];
  try {
    process.env[name] = 'synthetic-unconfigured-key-file';
    assert.throws(() => createTelemetry({ collector: { url: 'https://collector.invalid/v1/traces', tls: {} } }), { code: 'AMBIENT_TELEMETRY_IDENTITY_DENIED' });
  } finally { if (saved === undefined) delete process.env[name]; else process.env[name] = saved; }
});
