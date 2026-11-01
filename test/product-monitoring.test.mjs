import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, readFile, writeFile, readdir } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createPrivateKey, createHash, X509Certificate, randomBytes, randomUUID } from 'node:crypto';
import { SignJWT } from 'jose';
import { startProductServer } from '../src/product/server.mjs';
import { createConfiguredProbe } from '../src/product/probes.mjs';
import { createConfiguredLogSink } from '../src/product/logging.mjs';
import { evaluateBudget } from '../src/product/metrics-sources.mjs';
import { createHttpsTransport } from '../src/adapters/transport.mjs';
import { startProbeServer } from '../src/product/probe-server.mjs';
import { runProbeTarget } from '../scripts/probe-target.mjs';
import { createObservability } from '../src/product/observability.mjs';

const pem = (name) => readFile(resolve('artifacts', `test-pki-${name}.pem`), 'utf8');
async function directory(t, cleanup = []) { await mkdir('.test-data', { recursive: true }); const path = await mkdtemp(resolve('.test-data', 'monitoring-')); t.after(async () => { for (const close of cleanup.reverse()) await close(); await rm(path, { force: true, recursive: true }); }); return path; }

test('configured fixed-route mTLS probes use platform-only health/metrics scope and collect actual redacted log and disk signals', async (t) => {
  const cleanup = []; const path = await directory(t, cleanup); const ca = await pem('ca'); const cert = await pem('observer-cert'); const issuer = createPrivateKey(await pem('issuer-key'));
  const jwks = JSON.parse(await readFile(resolve('artifacts/test-pki-issuer-public.jwks.json'), 'utf8'));
  const config = { version: 1, role: 'resource', profile: 'local-test', listen: { host: '127.0.0.1', port: 0 },
    auth: { issuer: 'https://issuer.company', audience: 'resource', algorithms: ['EdDSA'], maxLifetimeSeconds: 900, requireSenderBinding: true },
    limits: { bodyBytes: 65536, requestTimeoutMs: 3000, rateWindowMs: 1000, rateRequests: 100, maxConcurrency: 8 },
    storage: { path: join(path, 'store.sqlite'), retentionMs: 60000 }, logging: { directory: join(path, 'logs') }, integrations: {}, protocols: {} };
  const service = await startProductServer({ config, material: { baseDirectory: path, tls: { ca, cert: await pem('resource-cert'), key: await pem('resource-key') }, jwks,
    encryptionKey: randomBytes(32), auditKey: randomBytes(32), signingKey: issuer } }); cleanup.push(() => service.close());
  const token = async (scope) => new SignJWT({ tenant_id: 'platform', roles: ['auditor'], scope, cnf: { 'x5t#S256': createHash('sha256').update(new X509Certificate(cert).raw).digest('base64url') } })
    .setProtectedHeader({ alg: 'EdDSA', kid: jwks.keys[0].kid }).setSubject('monitor').setIssuer('https://issuer.company').setAudience('resource').setIssuedAt().setExpirationTime('5m').setJti(randomUUID()).sign(issuer);
  const tokenPath = join(path, 'monitor.jwt'); const narrow = await token('runtime:health runtime:metrics'); await writeFile(tokenPath, narrow, { mode: 0o600 });
  const transport = createHttpsTransport({ origin: service.origin, tls: { ca, cert, key: await pem('observer-key') }, allowPrivateNetworks: true });
  const probe = await createConfiguredProbe({ version: 1, origin: service.origin, audience: 'resource', caFile: resolve('artifacts/test-pki-ca.pem'), certFile: resolve('artifacts/test-pki-observer-cert.pem'), keyFile: resolve('artifacts/test-pki-observer-key.pem'), tokenFile: tokenPath, allowPrivateNetworks: true });
  for (const mode of ['live', 'startup', 'ready']) assert.equal((await probe.run(mode)).healthy, true);
  const metrics = (await probe.run('metrics')).metrics;
  assert.match(metrics, /runtime_disk_free_bytes [1-9]/); assert.match(metrics, /runtime_budget_data_available 0/); assert.match(metrics, /runtime_log_sink_healthy 1/);
  await assert.rejects(probe.run('invoke'), { code: 'INVALID_PROBE_MODE' });
  const exporterToken = randomBytes(32).toString('hex'); const exporterTokenPath = join(path, 'exporter.token'); await writeFile(exporterTokenPath, exporterToken, { mode: 0o600 });
  const exporterConfig = { version: 1, listen: { host: '127.0.0.1', port: 0 }, tls: { caFile: resolve('artifacts/test-pki-ca.pem'), certFile: resolve('artifacts/test-pki-resource-cert.pem'), keyFile: resolve('artifacts/test-pki-resource-key.pem') },
    authorizationFile: exporterTokenPath, peers: [createHash('sha256').update(new X509Certificate(cert).raw).digest('hex')], targets: [{ name: 'resource', maxReplicas: 1, probe: { version: 1, origin: service.origin, audience: 'resource', caFile: resolve('artifacts/test-pki-ca.pem'), certFile: resolve('artifacts/test-pki-observer-cert.pem'), keyFile: resolve('artifacts/test-pki-observer-key.pem'), tokenFile: tokenPath, allowPrivateNetworks: true } }] };
  const exporter = await startProbeServer(exporterConfig); cleanup.push(() => exporter.close());
  const exporterConfigFile = join(path, 'exporter.json'); await writeFile(exporterConfigFile, JSON.stringify(exporterConfig));
  assert.equal((await runProbeTarget(['--config', exporterConfigFile, '--target', 'resource', '--mode', 'ready'])).healthy, true);
  await assert.rejects(runProbeTarget(['--config', exporterConfigFile, '--target', 'gateway', '--mode', 'ready']), { code: 'PROBE_TARGET_UNCONFIGURED' });
  const scrape = createHttpsTransport({ origin: exporter.origin, tls: { ca, cert, key: await pem('observer-key') }, allowPrivateNetworks: true });
  assert.equal((await scrape.request('/health/live')).status, 403);
  const response = await scrape.fetch(exporter.origin + '/metrics', { headers: { authorization: `Bearer ${exporterToken}` } }); assert.equal(response.status, 200);
  const samples = await response.text(); for (const mode of ['live', 'startup', 'ready']) assert.ok(samples.includes(`runtime_probe_success{target="resource",mode="${mode}"} 1`));
  assert.equal((await scrape.request('/metrics?target=https://attacker.invalid', { headers: { authorization: `Bearer ${exporterToken}` } })).status, 404);
  assert.equal((await transport.request('/v1/resource/documents', { method: 'POST', body: {}, headers: { authorization: `Bearer ${narrow}` } })).status, 403);
  await writeFile(tokenPath, await token('runtime:audit'), { mode: 0o600 }); await assert.rejects(probe.run('ready'), { code: 'NARROW_MONITOR_IDENTITY_REQUIRED' });
  await service.close(); const files = await readdir(join(path, 'logs')); const text = (await Promise.all(files.filter((name) => name.endsWith('.jsonl')).map((name) => readFile(join(path, 'logs', name), 'utf8')))).join('');
  assert.ok(text.includes('http.security')); assert.equal(text.includes(narrow), false); assert.equal(text.includes('platform'), false); assert.equal(text.includes('127.0.0.1'), false);
});

test('log files rotate with bounded queue/record schemas and refuse overwriting an unexpected rotation target', async (t) => {
  const path = await directory(t); const sink = await createConfiguredLogSink({ directory: path, maxBytes: 4096, files: 3, maxQueueBytes: 65536 }, { instanceId: 'bounded-fixture' });
  const line = { at: new Date().toISOString(), level: 'info', event: 'http.request', requestId: 'controlled', route: '/v1/actions', method: 'POST', status: 200, durationMs: 1 };
  assert.equal(sink.write({ ...line, authorization: 'secret-must-not-be-logged' }), false);
  for (let index = 0; index < 100; index++) assert.equal(sink.write(line), true); await sink.flush(); await sink.close();
  const files = await readdir(path); assert.ok(files.length <= 3);
  for (const file of files) { const text = await readFile(join(path, file), 'utf8'); assert.ok(Buffer.byteLength(text) <= 4096); assert.equal(text.includes('secret-must-not-be-logged'), false); }
  const brokenPath = join(path, 'fault'); const broken = await createConfiguredLogSink({ directory: brokenPath, maxBytes: 4096, files: 2, required: true }, { instanceId: 'fault-fixture' });
  const [name] = await readdir(brokenPath); await mkdir(join(brokenPath, `${name}.1`));
  for (let index = 0; index < 40; index++) broken.write(line); await assert.rejects(broken.flush(), { code: 'LOG_SINK_UNAVAILABLE' }); assert.equal(broken.status().healthy, false); await broken.close();
});

test('budget thresholds use integer minor units and missing/stale evidence cannot become zero spend', () => {
  const now = Date.now(); const base = { version: 1, currency: 'AED', periodStart: now - 1000, periodEnd: now + 100000, observedAt: now,
    spentMinor: '9999999999999999999', limitMinor: '10000000000000000000', source: 'operator-cost-report', sourceDigest: 'a'.repeat(64) };
  assert.equal(evaluateBudget(base, { now }).exceeded, false); assert.equal(evaluateBudget({ ...base, spentMinor: base.limitMinor }, { now }).exceeded, true);
  assert.throws(() => evaluateBudget({ ...base, spentMinor: '-1' }, { now }), { code: 'INVALID_BUDGET_OBSERVATION' });
  assert.throws(() => evaluateBudget({ ...base, observedAt: now - 1000 }, { now, maxAgeMs: 100 }), { code: 'BUDGET_OBSERVATION_STALE' });
});

test('lost operational observations clear previous gauge values and retain explicit unavailable state', async () => {
  const signals = createObservability({ logger: () => {}, rateWindowMs: 1000, rateRequests: 10, maxConcurrency: 1 });
  try { signals.signal('budget_spent_ratio', 1.2); signals.signalUnavailable('budget_spent_ratio'); const metrics = await signals.metricsText(); assert.match(metrics, /runtime_budget_spent_ratio NaN/); assert.match(metrics, /runtime_signal_available\{signal="budget_spent_ratio"\} 0/); }
  finally { await signals.close(); }
});

test('official Prometheus0.16.1 registry preserves bounded counters/histograms without automatic trace exemplars', async () => {
  assert.equal(JSON.parse(await readFile('node_modules/@prometheus-io/client/package.json', 'utf8')).version, '0.16.1');
  const signals = createObservability({ logger: () => {}, rateWindowMs: 1000, rateRequests: 10, maxConcurrency: 1 });
  try {
    const request = signals.begin({ method: 'GET', url: '/v1/tasks/private-task-id', headers: { traceparent: `00-${'a'.repeat(32)}-${'b'.repeat(16)}-01` }, socket: { remoteAddress: '127.0.0.1' } });
    await request.run(async () => {}); request.finish(200);
    const metrics = await signals.metricsText(); assert.match(metrics, /runtime_http_requests_total\{route="\/v1\/tasks\/:id",method="GET",status_class="2xx"\} 1/); assert.match(metrics, /runtime_http_request_duration_seconds_bucket/);
    for (const privateValue of ['private-task-id', 'a'.repeat(32), 'trace_id=', 'span_id=']) assert.equal(metrics.includes(privateValue), false);
    const independent = createObservability({ logger: () => {}, rateWindowMs: 1000, rateRequests: 10, maxConcurrency: 1 }); try { assert.match(await independent.metricsText(), /runtime_requests_total 0/); } finally { await independent.close(); }
  } finally { await signals.close(); }
});
