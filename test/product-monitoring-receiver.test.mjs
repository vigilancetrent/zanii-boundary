import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, writeFile, rm } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash, createPrivateKey, createPublicKey, X509Certificate, randomBytes, randomUUID } from 'node:crypto';
import { startMonitoringReceiver, verifyMonitoringReceipt } from '../src/product/monitoring-receiver.mjs';
import { createHttpsTransport } from '../src/adapters/transport.mjs';
import { createAlertDelivery, createAlertEvent } from '../src/product/alerts.mjs';
import { createConfiguredTelemetry } from '../src/product/telemetry.mjs';
import { requestContext } from '../src/product/context.mjs';
import { selectMonitoringTraceId } from '../src/product/monitoring-acceptance.mjs';
import { evaluateBudget } from '../src/product/metrics-sources.mjs';

const path = (name) => resolve('artifacts', `test-pki-${name}.pem`); const pem = (name) => readFile(path(name), 'utf8');
const fingerprint = async (name) => createHash('sha256').update(new X509Certificate(await pem(name)).raw).digest('hex');
test('controlled receipt server authenticates separate mTLS roles, deduplicates alerts durably and records actual OTLP SDK spans', async (t) => {
  await mkdir('.test-data', { recursive: true }); const directory = await mkdtemp(resolve('.test-data', 'receipts-')); let receiver; let telemetry;
  t.after(async () => { await telemetry?.close(); await receiver?.close(); await rm(directory, { force: true, recursive: true }); });
  const alertToken = randomBytes(32).toString('hex'); const readToken = randomBytes(32).toString('hex'); const hmac = randomBytes(32);
  for (const [name, value] of Object.entries({ 'alert.token': alertToken, 'read.token': readToken, 'hmac.key': hmac.toString('hex'), 'data.key': randomBytes(32).toString('hex'), 'audit.key': randomBytes(32).toString('hex') })) await writeFile(join(directory, name), value, { mode: 0o600 });
  const signingKey = createPrivateKey(await pem('issuer-key')); const publicKey = createPublicKey(signingKey);
  await writeFile(join(directory, 'public.pem'), publicKey.export({ type: 'spki', format: 'pem' }));
  const deployment = { mode: 'local-contract', profileDigest: 'a'.repeat(64), runtimeImage: `fixture/runtime@sha256:${'b'.repeat(64)}`, collectorImage: `fixture/collector@sha256:${'c'.repeat(64)}` };
  const config = { version: 1, listen: { host: '127.0.0.1', port: 0 }, tls: { caFile: path('ca'), certFile: path('gateway-cert'), keyFile: path('gateway-key') },
    peers: { alertmanager: [await fingerprint('operator-cert')], collector: [await fingerprint('broker-cert')], reader: [await fingerprint('observer-cert')], runtime: [await fingerprint('agent-cert')] },
    auth: { alertmanagerTokenFile: 'alert.token', readTokenFile: 'read.token', runtimeHmacKeyFile: 'hmac.key' }, storage: { path: 'receipts.sqlite', encryptionKeyFile: 'data.key', auditKeyFile: 'audit.key' },
    signing: { privateKeyFile: path('issuer-key'), publicKeyFile: 'public.pem' }, deployment, serviceRoles: { 'runtime-gateway': 'gateway', 'runtime-resource': 'resource' }, alertNames: ['RuntimeMonitoringAcceptance', 'RuntimeBudgetWarning', 'RuntimeBudgetExceeded'] };
  receiver = await startMonitoringReceiver(config, { baseDirectory: directory });
  const transport = async (name) => createHttpsTransport({ origin: receiver.origin, tls: { ca: await pem('ca'), cert: await pem(`${name}-cert`), key: await pem(`${name}-key`) }, allowPrivateNetworks: true });
  let alert = await transport('operator'); let reader = await transport('observer'); const collector = await transport('broker'); const nonce = randomBytes(32).toString('hex');
  const time = new Date().toISOString(); const batch = { version: '4', groupKey: 'controlled-group', status: 'firing', receiver: 'controlled-receiver', groupLabels: {}, commonLabels: {}, commonAnnotations: {}, externalURL: 'https://controlled.invalid',
    alerts: [{ status: 'firing', labels: { alertname: 'RuntimeMonitoringAcceptance', severity: 'info' }, annotations: { acceptance_nonce: nonce }, startsAt: time, endsAt: new Date(Date.now() + 60000).toISOString(), generatorURL: 'https://controlled.invalid', fingerprint: 'a'.repeat(16) }] };
  const deliver = () => alert.request('/v1/alerts/alertmanager', { method: 'POST', headers: { authorization: `Bearer ${alertToken}` }, body: batch });
  const first = await deliver(); assert.equal(first.status, 200); assert.equal(first.body.duplicate, false);
  const firstProof = verifyMonitoringReceipt(first.body.receipt, publicKey, { kind: 'alert', id: nonce, expectedDeployment: deployment });
  assert.equal((await deliver()).body.duplicate, true);
  const budgetProofs = [];
  for (const spentMinor of ['80', '100']) {
    const now = Date.now(); const budget = evaluateBudget({ version: 1, currency: 'USD', spentMinor, limitMinor: '100', periodStart: now - 1000, periodEnd: now + 60000, observedAt: now, source: 'operator-cost-report', sourceDigest: 'b'.repeat(64) }, { now });
    assert.equal(budget.warning, true); const alertname = budget.exceeded ? 'RuntimeBudgetExceeded' : 'RuntimeBudgetWarning';
    const controlled = { ...batch, alerts: [{ ...batch.alerts[0], labels: { alertname, severity: budget.exceeded ? 'critical' : 'warning' }, annotations: { summary: 'Synthetic local threshold delivery contract; no measured provider billing.' }, fingerprint: (budget.exceeded ? 'c' : 'b').repeat(16) }] };
    const observed = await alert.request('/v1/alerts/alertmanager', { method: 'POST', headers: { authorization: `Bearer ${alertToken}` }, body: controlled }); assert.equal(observed.status, 200);
    const proof = verifyMonitoringReceipt(observed.body.receipt, publicKey, { kind: 'alert', expectedDeployment: deployment }); assert.deepEqual(proof.summary.names, [alertname]); budgetProofs.push(proof);
  }
  const query = (kind, id) => reader.request('/v1/receipts/query', { method: 'POST', headers: { authorization: `Bearer ${readToken}` }, body: { kind, id } });
  assert.equal((await reader.request('/v1/alerts/alertmanager', { method: 'POST', headers: { authorization: `Bearer ${alertToken}` }, body: batch })).status, 403);
  assert.throws(() => verifyMonitoringReceipt(first.body.receipt, publicKey, { kind: 'alert', id: nonce, expectedDeployment: { ...deployment, mode: 'deployment' } }), { code: 'MONITORING_RECEIPT_BINDING_FAILED' });
  assert.throws(() => selectMonitoringTraceId(0), { code: 'MONITORING_TRACE_SAMPLING_UNAVAILABLE' });
  const traceId = selectMonitoringTraceId(0.1);
  telemetry = await createConfiguredTelemetry({ serviceName: 'runtime-gateway', samplingRatio: 0.1, scheduledDelayMs: 60000, collector: { url: `${receiver.origin}/v1/traces`, caFile: path('ca'), certFile: path('broker-cert'), keyFile: path('broker-key'), allowPrivateNetworks: true } });
  await requestContext.run({ traceparent: `00-${traceId}-${'1'.repeat(16)}-01` }, () => telemetry.span('http.server', { 'http.route': '/health/ready', authorization: 'synthetic-secret-must-not-leak' },
    () => telemetry.span('db.operation', { 'db.operation.name': 'get' }, async () => {})));
  await telemetry.flush(); const trace = await query('trace', traceId); assert.equal(trace.status, 200); assert.equal(trace.body.receipts.length, 1);
  const proof = verifyMonitoringReceipt(trace.body.receipts[0], publicKey, { kind: 'trace', id: traceId, expectedDeployment: deployment });
  assert.deepEqual(proof.summary.spans.map((item) => item.name).sort(), ['db.operation', 'http.server']); assert.equal(JSON.stringify(proof).includes('synthetic-secret'), false);
  const logId = randomUUID(); assert.equal((await collector.request('/v1/logs', { method: 'POST', body: { resourceLogs: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'runtime-gateway' } }] }, scopeLogs: [{ logRecords: [{ body: { stringValue: JSON.stringify({ requestId: logId, event: 'http.security', level: 'warn', route: '/v1/audit', status: 403, authorization: 'discarded-at-receipt-boundary' }) } }] }] }] } })).status, 200);
  const logProof = verifyMonitoringReceipt((await query('log', logId)).body.receipts[0], publicKey, { kind: 'log', id: logId, expectedDeployment: deployment }); assert.equal(JSON.stringify(logProof).includes('authorization'), false);
  const mapLogId = randomUUID(); const values = Object.entries({ requestId: mapLogId, event: 'http.request', level: 'info', route: '/health/ready' }).map(([key, value]) => ({ key, value: { stringValue: value } })); values.push({ key: 'status', value: { intValue: '200' } });
  assert.equal((await collector.request('/v1/logs', { method: 'POST', body: { resourceLogs: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'runtime-gateway' } }] }, scopeLogs: [{ logRecords: [{ body: { kvlistValue: { values } } }] }] }] } })).status, 200);
  assert.equal(verifyMonitoringReceipt((await query('log', mapLogId)).body.receipts[0], publicKey, { kind: 'log', id: mapLogId, expectedDeployment: deployment }).summary.entries[0].status, 200);
  const correlated = { resourceLogs: ['gateway', 'resource'].map((role) => ({ resource: { attributes: [{ key: 'service.name', value: { stringValue: `runtime-${role}` } }] }, scopeLogs: [{ logRecords: ['http.security', 'http.request'].map((event) => ({ body: { stringValue: JSON.stringify({ requestId: logId, event, level: 'warn', route: '/v1/audit', status: 403 }) } })) }] })) };
  assert.equal((await collector.request('/v1/logs', { method: 'POST', body: correlated })).status, 200);
  const correlatedProof = verifyMonitoringReceipt((await query('log', logId)).body.receipts[0], publicKey, { kind: 'log', id: logId, expectedDeployment: deployment });
  assert.equal(correlatedProof.summary.entries.length, 4); assert.equal(correlatedProof.summary.truncated, false); assert.deepEqual([...new Set(correlatedProof.summary.entries.map((entry) => entry.role))].sort(), ['gateway', 'resource']);
  const runtime = await transport('agent'); const delivery = createAlertDelivery({ transport: runtime, path: '/v1/alerts/runtime', key: hmac });
  const event = createAlertEvent({ key: hmac, tenantId: 'private-company', kind: 'job-dead-letter', code: 'CONTROLLED_DEAD_LETTER' });
  assert.equal((await delivery.deliver(event)).delivered, true); assert.equal((await delivery.deliver(event)).duplicate, true); await delivery.close();
  await telemetry.close(); telemetry = undefined; await receiver.close(); receiver = await startMonitoringReceiver(config, { baseDirectory: directory }); alert = await transport('operator'); reader = await transport('observer');
  const duplicate = await deliver(); assert.equal(duplicate.body.duplicate, true);
  assert.equal(verifyMonitoringReceipt(duplicate.body.receipt, publicKey, { kind: 'alert', id: nonce, expectedDeployment: deployment }).firstObservedAt, firstProof.firstObservedAt);
  for (const proof of budgetProofs) assert.deepEqual(verifyMonitoringReceipt((await query('alert', proof.id)).body.receipts[0], publicKey, { kind: 'alert', id: proof.id, expectedDeployment: deployment }), proof);
  const restartedCollector = await transport('broker'); assert.equal((await restartedCollector.request('/v1/logs', { method: 'POST', body: correlated })).status, 200);
  const restartedProof = verifyMonitoringReceipt((await query('log', logId)).body.receipts[0], publicKey, { kind: 'log', id: logId, expectedDeployment: deployment });
  assert.deepEqual(restartedProof, correlatedProof);
  assert.equal(verifyMonitoringReceipt((await query('log', logId)).body.receipts[0], publicKey, { kind: 'log', id: logId, expectedDeployment: { collectorImage: deployment.collectorImage, runtimeImage: deployment.runtimeImage, profileDigest: deployment.profileDigest, mode: deployment.mode } }).sourceDigest, restartedProof.sourceDigest);
  assert.throws(() => verifyMonitoringReceipt((duplicate.body.receipt), publicKey, { kind: 'alert', id: nonce, expectedDeployment: { ...deployment, profileDigest: 'f'.repeat(64) } }), { code: 'MONITORING_RECEIPT_BINDING_FAILED' });
  assert.equal((await restartedCollector.request('/v1/traces', { method: 'POST', body: { resourceSpans: [{ resource: { attributes: [{ key: 'service.name', value: { stringValue: 'runtime-gateway' } }] }, scopeSpans: [{ spans: proof.summary.spans.map((span) => ({ traceId, spanId: span.id, parentSpanId: span.parentId, name: span.name })) }] }] } })).status, 200);
  assert.deepEqual(verifyMonitoringReceipt((await query('trace', traceId)).body.receipts[0], publicKey, { kind: 'trace', id: traceId, expectedDeployment: deployment }), proof);
});
