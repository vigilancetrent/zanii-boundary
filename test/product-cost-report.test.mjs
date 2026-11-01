import test from 'node:test';
import assert from 'node:assert/strict';
import { COST_COMPONENTS, estimateCost, priceQuotedQuantity, formatMinorUnits, deploymentCostInventory, capacityCostObservations } from '../src/product/cost-report.mjs';
import { readDistributedDeploymentFiles } from '../src/product/distributed-deployment.mjs';
import { parseCostArguments, runCostReport } from '../scripts/cost-report.mjs';
import { runCapacityMeasurement } from '../scripts/capacity-acceptance.mjs';

const now = Date.now(); const digest = 'a'.repeat(64);
function quote(extra = {}) { return { id: 'synthetic-compute', component: 'compute', provider: 'synthetic-fixture-not-a-provider', sku: 'fixture', region: 'fixture-region', currency: 'USD', minorDigits: 2,
  unit: 'instance-second', priceMinor: '1', perUnits: '1000000', billingIncrement: '1000', quotedAt: now - 20000, validFrom: now - 10000, expiresAt: now + 10000,
  synthetic: true, evidence: { kind: 'operator-quote', reference: 'synthetic-test-only', sha256: digest, observedAt: now - 15000 }, ...extra }; }
function config(extra = {}) { return { version: 1, sourceDigest: digest, currency: 'USD', minorDigits: 2, requiredComponents: ['compute'], quotes: [quote()],
  usage: { version: 1, sourceDigest: digest, periodStart: now - 9000, periodEnd: now - 1000, observedAt: now,
    successfulRequests: '3', lines: [{ id: 'compute', component: 'compute', sku: 'fixture', region: 'fixture-region', unit: 'instance-second', quoteId: 'synthetic-compute', quantity: '1000001', kind: 'measured', evidenceDigest: digest }] }, ...extra }; }
const example = (value) => estimateCost(value, { now, allowSynthetic: true });

test('quote arithmetic preserves huge integers and rounds both quantity increments and each minor-unit line explicitly', () => {
  const actual = priceQuotedQuantity('1000001', quote()); assert.equal(actual.billedQuantity, '1001000'); assert.equal(actual.costMinor, '2');
  assert.equal(priceQuotedQuantity('0', quote()).costMinor, '0');
  const quantity = '9999999999999999999999999999999999999999'; const price = '8888888888888888888888888888888888888888';
  assert.equal(priceQuotedQuantity(quantity, quote({ priceMinor: price, perUnits: '1', billingIncrement: '1' })).costMinor, (BigInt(quantity) * BigInt(price)).toString());
  assert.equal(formatMinorUnits('12345', 2), '123.45'); assert.equal(formatMinorUnits('1', 3), '0.001'); assert.equal(formatMinorUnits('42', 0), '42');
  for (const quantity of ['-1', '1.5', '1e6', '01', 1.2]) assert.throws(() => priceQuotedQuantity(quantity, quote()), { code: 'INVALID_COST_QUOTE' });
  assert.throws(() => priceQuotedQuantity('1', quote({ perUnits: '0' })), { code: 'INVALID_COST_QUOTE' });
  for (const perUnits of ['1.5', 'NaN', '-1']) assert.throws(() => priceQuotedQuantity('1', quote({ perUnits })), { code: 'INVALID_COST_QUOTE' });
});

test('synthetic prices stay illustrative and missing quotes never become a zero total or available bill', () => {
  const result = example(config()); assert.equal(result.status, 'ILLUSTRATIVE'); assert.equal(result.totalMinor, '2'); assert.equal(result.perMillionSuccessfulRequestsMinor, '666667');
  assert.equal(result.billing.available, false); assert.equal(result.claims.observedBill, false); assert.equal(result.claims.providerQuoteAuthentication, false);
  const forbidden = estimateCost(config(), { now }); assert.equal(forbidden.status, 'BLOCKED'); assert.equal(forbidden.totalMinor, null); assert.ok(forbidden.unknownReasons.includes('SYNTHETIC_QUOTE_DENIED'));
  const missing = estimateCost(config({ quotes: [] }), { now }); assert.equal(missing.totalMinor, null); assert.equal(missing.knownSubtotalMinor, '0'); assert.equal(missing.billing.available, false);
  assert.equal(example(config({ usage: null })).totalMinor, null);
});

test('each required component and flat SKU scope must be covered by fresh matching dated evidence', () => {
  for (const change of [value => { value.quotes[0].expiresAt = now - 1; }, value => { value.quotes[0].validFrom = now; }, value => { value.quotes[0].currency = 'AED'; },
    value => { value.quotes[0].minorDigits = 3; }, value => { value.quotes[0].sku = 'foreign'; }, value => { value.quotes[0].region = 'foreign'; }, value => { value.quotes[0].unit = 'egress-byte'; },
    value => { value.usage.sourceDigest = 'b'.repeat(64); }, value => { value.usage.observedAt = now + 1; }, value => { delete value.usage.lines[0].evidenceDigest; }, value => { value.usage.lines[0].quantity = null; }]) {
    const value = config(); change(value); const result = example(value); assert.equal(result.status, 'BLOCKED'); assert.equal(result.totalMinor, null);
  }
  const required = example(config({ requiredComponents: [...COST_COMPONENTS] })); assert.equal(required.totalMinor, null); assert.equal(required.lines.filter(row => row.status === 'UNKNOWN').length, 7);
  const duplicate = config(); duplicate.quotes.push(quote()); assert.throws(() => example(duplicate), { code: 'DUPLICATE_COST_INPUT' });
  const tiered = config(); tiered.quotes[0].tiers = []; assert.throws(() => example(tiered), { code: 'INVALID_COST_CONFIGURATION' });
});

test('planning forecasts require explicit assumptions and never overwrite independent integer budget observations', () => {
  const forecast = config(); const line = forecast.usage.lines[0]; line.kind = 'planning-assumption'; delete line.evidenceDigest;
  assert.equal(example(forecast).totalMinor, null); line.assumption = 'Synthetic fixed host allocation; not measured billable usage'; forecast.usage.periodEnd = now + 1000;
  const billing = { version: 1, currency: 'USD', spentMinor: '80', limitMinor: '100', periodStart: now - 10000, periodEnd: now + 10000, observedAt: now, source: 'operator-cost-report', sourceDigest: digest };
  const result = estimateCost(forecast, { now, allowSynthetic: true, billingObservation: billing }); assert.equal(result.planningAssumptionsIncluded, true); assert.equal(result.billing.warning, true); assert.equal(result.billing.exceeded, false);
  assert.equal(result.totalMinor, '2'); assert.equal(result.billing.ratio, 0.8); assert.equal(billing.spentMinor, '80');
  assert.equal(estimateCost(forecast, { now, allowSynthetic: true, billingObservation: { ...billing, spentMinor: '100' } }).billing.exceeded, true);
  assert.equal(estimateCost(forecast, { now, allowSynthetic: true, billingObservation: { ...billing, observedAt: now - 2000 }, maxBudgetAgeMs: 1000 }).billing.available, false);
  assert.equal(estimateCost(forecast, { now, allowSynthetic: true, billingObservation: { ...billing, currency: 'AED' } }).billing.available, false);
});

test('inventory derives configured maximum containers and shared pool envelope without inventing billed hosts', async () => {
  const files = await readDistributedDeploymentFiles(); const value = deploymentCostInventory(files.profile, files.compose);
  assert.equal(value.maximumContinuousContainers, '18'); assert.equal(value.maximumManualContainers, '4'); assert.equal(value.databasePool.total, 101); assert.equal(value.billedHostCount, null);
  assert.equal(value.monitoringHostCapacityIncluded, false); assert.ok(BigInt(value.maximumMemoryBytes) > 0n);
});

test('capacity observations retain body-byte and point-in-time limitations instead of inventing provider usage', () => {
  const event = { index: 0, id: 'synthetic-cost-operation', documentId: 'doc', outcome: 'issued', status: 200, state: 'succeeded', code: null, latencyMs: 1 };
  const report = { version: 1, kind: 'capacity-measurement', sourceDigest: digest, status: 'LOCAL_MEASURED', mode: 'planning', featureProfile: 'core-only', cohorts: [{ drained: true, fatal: null,
    counts: { planned: 1, issued: 1, successful: 1, droppedLag: 0, droppedInFlight: 0, aborted: 0, pending: 0, unresolved: 0 }, statuses: { 200: 1 }, events: [event],
    observedEffects: [{ id: event.id, documentId: event.documentId, state: 'succeeded', actorId: 'agent', kind: 'read' }],
    effects: { complete: true, observed: 1, successfulResponses: 1, effectsWithoutSuccessfulResponse: 0, duplicates: 0, unexpected: 0 }, applicationJsonBytes: { request: 100, response: 200 } }] };
  const value = capacityCostObservations(report, { sourceDigest: digest }); assert.equal(value.issuedRequests, '1'); assert.equal(value.observedResourceEffects, '1'); assert.equal(value.billedNetworkEgressBytes, null);
  assert.equal(value.storageByteSeconds, null); assert.equal(value.ledgerBilledUnits, null); assert.equal(value.monetaryUsageAutomaticallyInferred, false);
  assert.throws(() => capacityCostObservations(report, { sourceDigest: 'b'.repeat(64) }), { code: 'INVALID_CAPACITY_COST_EVIDENCE' });
  assert.throws(() => capacityCostObservations({ ...report, status: 'INVALID' }, { sourceDigest: digest }), { code: 'INVALID_CAPACITY_COST_EVIDENCE' });
  for (const corrupt of [value => { value.cohorts[0].counts.successful = 11; }, value => { value.cohorts[0].effects.observed = 100; }, value => { value.cohorts[0].statuses[200] = 2; }, value => { value.cohorts[0].observedEffects[0].id = 'foreign'; }, value => { value.cohorts[0].events = []; }]) {
    const value = structuredClone(report); corrupt(value); assert.throws(() => capacityCostObservations(value, { sourceDigest: digest }), { code: 'INVALID_CAPACITY_COST_EVIDENCE' });
  }
});

test('cost observations accept actual TLS capacity smoke only after independent event/status/effect reconciliation', async () => {
  const report = await runCapacityMeasurement({ version: 1, mode: 'smoke', planningPeakRps: 1, warmupMs: 0, sustainedMs: 10, soakMs: 10, saturationMs: 10, saturationRates: [4], documents: { count: 1, bytes: 128 }, latencyTargets: { '/v1/actions': { p50Ms: 5000, p95Ms: 5000, p99Ms: 5000 } } }, { implementation: async () => digest });
  const result = capacityCostObservations(report, { sourceDigest: digest }); assert.equal(result.issuedRequests, '3'); assert.equal(result.successfulRequests, '3'); assert.equal(result.observedResourceEffects, '3'); assert.equal(result.mode, 'smoke');
});

test('actual no-quote configuration returns BLOCKED/null total and CLI rejects ambiguous or public output routes', async () => {
  const result = await runCostReport(parseCostArguments(['--config', 'config/cost.example.json'])); assert.equal(result.status, 'BLOCKED'); assert.equal(result.totalMinor, null); assert.equal(result.lines.length, 8);
  assert.equal(result.billing.available, false); assert.equal(result.deploymentInventory.billedHostCount, null);
  for (const args of [[], ['--config', 'one', '--config', 'two'], ['--price', '123'], ['--config']]) assert.throws(() => parseCostArguments(args));
  await assert.rejects(runCostReport({ '--config': 'config/cost.example.json', '--out': 'artifacts/public-cost.json' }), { code: 'PRIVATE_COST_OUTPUT_REQUIRED' });
});
