import { z } from 'zod';
import { AppError } from '../protocol.mjs';
import { distributedPoolBudget, serviceRole } from './distributed-deployment.mjs';
import { evaluateBudget } from './metrics-sources.mjs';
import { reconcileCapacityEffects, capacityFatal } from './capacity.mjs';

export const COST_COMPONENTS = Object.freeze(['compute', 'database', 'object-storage', 'object-requests', 'kms', 'ledger', 'network-egress', 'monitoring']);
const decimal = z.string().regex(/^(?:0|[1-9][0-9]{0,39})$/);
const nonzero = decimal.refine((value) => value !== '0');
const id = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/);
const hex = z.string().regex(/^[a-f0-9]{64}$/);
const timestamp = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const unit = z.string().regex(/^[a-z][a-z0-9-]{0,63}$/);
const component = z.enum(COST_COMPONENTS);
const currency = z.string().regex(/^[A-Z]{3}$/);
const quoteSchema = z.object({ id, component, provider: z.string().min(1).max(256), sku: id, region: id, currency,
  minorDigits: z.number().int().min(0).max(6), unit, priceMinor: decimal, perUnits: nonzero, billingIncrement: nonzero,
  quotedAt: timestamp, validFrom: timestamp, expiresAt: timestamp, synthetic: z.boolean(),
  evidence: z.object({ kind: z.enum(['provider-published-rate', 'provider-quote', 'operator-quote']), reference: z.string().min(1).max(1024), sha256: hex, observedAt: timestamp }).strict(),
}).strict().refine((value) => {
  if (value.evidence.kind !== 'provider-published-rate') return true;
  try { const url = new URL(value.evidence.reference); return url.protocol === 'https:' && !url.username && !url.password; } catch { return false; }
});
const lineSchema = z.object({ id, component, sku: id, region: id, unit, quoteId: id.nullable(), quantity: decimal.nullable(),
  kind: z.enum(['measured', 'planning-assumption']), evidenceDigest: hex.optional(), assumption: z.string().min(1).max(1024).optional() }).strict();
const usageSchema = z.object({ version: z.literal(1), sourceDigest: hex, periodStart: timestamp, periodEnd: timestamp, observedAt: timestamp,
  lines: z.array(lineSchema).max(128), successfulRequests: decimal.optional() }).strict();
const optionsSchema = z.object({ version: z.literal(1), sourceDigest: hex, currency, minorDigits: z.number().int().min(0).max(6),
  requiredComponents: z.array(component).min(1).max(COST_COMPONENTS.length).default([...COST_COMPONENTS]),
  quotes: z.array(quoteSchema).max(128).default([]), usage: usageSchema.nullable().default(null),
  maxQuoteAgeMs: z.number().int().min(1000).max(31622400000).default(2678400000),
  maxUsageAgeMs: z.number().int().min(1000).max(31622400000).default(86400000),
}).strict();
const fail = (code) => { throw new AppError(400, code); };
const unique = (values) => new Set(values).size === values.length;
const ceil = (numerator, denominator) => (numerator + denominator - 1n) / denominator;

/** Exact display only; no monetary value passes through a binary floating point number. */
export function formatMinorUnits(value, digits) {
  if (typeof value !== 'string' || !/^(?:0|[1-9][0-9]{0,127})$/.test(value) || !Number.isInteger(digits) || digits < 0 || digits > 6) fail('INVALID_MONEY');
  if (!digits) return value;
  const text = value.padStart(digits + 1, '0'); return `${text.slice(0, -digits)}.${text.slice(-digits)}`;
}

/** Flat quoted SKU only. Quantity increments and each line's minor-unit result round upwards. */
export function priceQuotedQuantity(quantity, quote) {
  const parsed = quoteSchema.safeParse(quote); if (!parsed.success || !decimal.safeParse(quantity).success) fail('INVALID_COST_QUOTE');
  const value = parsed.data; const charged = ceil(BigInt(quantity), BigInt(value.billingIncrement)) * BigInt(value.billingIncrement);
  const cost = ceil(charged * BigInt(value.priceMinor), BigInt(value.perUnits));
  return { quantity, billedQuantity: charged.toString(), costMinor: cost.toString(), rounding: 'ceil quantity to billingIncrement, then ceil each line to currency minor unit' };
}

/** Container envelopes are capacity requirements. They are not a billed-host inventory. */
export function deploymentCostInventory(profile, compose) {
  const pool = distributedPoolBudget(profile); const rows = []; let continuous = 0n; let maintenance = 0n; let cpu = 0n; let memory = 0n;
  for (const [name, service] of Object.entries(compose.services ?? {})) {
    const role = serviceRole(name); const manual = ['rotator', 'migrator'].includes(role); const count = profile.roles[role === 'app' ? name : role]?.maximum ?? 1;
    if (!Number.isSafeInteger(count) || count < 1 || count > 32) fail('INVALID_DEPLOYMENT_COST_INVENTORY');
    const cpuText = String(service.cpus); const match = /^(\d+)(?:\.(\d{1,3}))?$/.exec(cpuText); const bytes = /^(\d+)(m|g)$/.exec(service.mem_limit ?? '');
    if (!match || !bytes) fail('INVALID_DEPLOYMENT_COST_INVENTORY');
    const millicpu = BigInt(match[1]) * 1000n + BigInt((match[2] ?? '').padEnd(3, '0') || '0'); const memoryBytes = BigInt(bytes[1]) * (bytes[2] === 'g' ? 1073741824n : 1048576n);
    if (manual) maintenance += BigInt(count); else continuous += BigInt(count); cpu += millicpu * BigInt(count); memory += memoryBytes * BigInt(count);
    rows.push({ service: name, manual, maximumReplicas: count, cpuMillicoresPerReplica: millicpu.toString(), memoryBytesPerReplica: memoryBytes.toString() });
  }
  return { scope: 'configured maximum container envelopes, including manual-role surge; not observed utilization or billed hosts', services: rows,
    maximumContinuousContainers: continuous.toString(), maximumManualContainers: maintenance.toString(), maximumCpuMillicores: cpu.toString(), maximumMemoryBytes: memory.toString(),
    databasePool: pool, billedHostCount: null, monitoringHostCapacityIncluded: false };
}

/** Dated operator inputs can establish an estimate, never an observed invoice.
 * @param {any} raw @param {any} options */
export function estimateCost(raw, { now = Date.now(), allowSynthetic = false, billingObservation = null, maxBudgetAgeMs = 3600000 } = {}) {
  const parsed = optionsSchema.safeParse(raw); if (!parsed.success || !Number.isSafeInteger(now) || now < 1) fail('INVALID_COST_CONFIGURATION');
  const config = parsed.data;
  if (!unique(config.requiredComponents) || !unique(config.quotes.map((quote) => quote.id)) || config.usage && !unique(config.usage.lines.map((line) => line.id))) fail('DUPLICATE_COST_INPUT');
  const quotes = new Map(config.quotes.map((quote) => [quote.id, quote])); const lines = []; const reasons = [];
  const usage = config.usage;
  const usageReason = !usage ? 'USAGE_REQUIRED' : usage.sourceDigest !== config.sourceDigest ? 'FOREIGN_USAGE_SOURCE'
    : usage.periodEnd <= usage.periodStart || usage.observedAt > now || now - usage.observedAt > config.maxUsageAgeMs ? 'USAGE_STALE_OR_INVALID' : null;
  let total = 0n; let synthetic = false; let assumptions = false;
  for (const line of usage?.lines ?? []) {
    let reason = usageReason; const quote = line.quoteId ? quotes.get(line.quoteId) : null;
    if (!reason && (line.quantity === null || line.kind === 'measured' && (!line.evidenceDigest || usage.periodEnd > now || usage.observedAt < usage.periodEnd) || line.kind === 'planning-assumption' && !line.assumption)) reason = 'USAGE_EVIDENCE_REQUIRED';
    if (!reason && !quote) reason = 'QUOTE_REQUIRED';
    if (!reason && quote && (quote.component !== line.component || quote.sku !== line.sku || quote.region !== line.region || quote.unit !== line.unit)) reason = 'QUOTE_SCOPE_MISMATCH';
    if (!reason && quote && (quote.currency !== config.currency || quote.minorDigits !== config.minorDigits)) reason = 'CURRENCY_MISMATCH';
    if (!reason && quote && (quote.quotedAt > now || quote.evidence.observedAt > now || quote.evidence.observedAt < quote.quotedAt || now - quote.quotedAt > config.maxQuoteAgeMs
      || quote.validFrom > usage.periodStart || quote.expiresAt < usage.periodEnd || quote.expiresAt <= now || quote.validFrom >= quote.expiresAt)) reason = 'QUOTE_STALE_OR_INVALID';
    if (!reason && quote?.synthetic && !allowSynthetic) reason = 'SYNTHETIC_QUOTE_DENIED';
    const base = { id: line.id, component: line.component, sku: line.sku, region: line.region, unit: line.unit, quoteId: line.quoteId, quantity: line.quantity, basis: line.kind };
    if (reason) { lines.push({ ...base, status: 'UNKNOWN', costMinor: null, reason }); reasons.push(reason); continue; }
    const priced = priceQuotedQuantity(line.quantity, quote); total += BigInt(priced.costMinor); synthetic ||= quote.synthetic; assumptions ||= line.kind === 'planning-assumption';
    lines.push({ ...base, ...priced, status: quote.synthetic ? 'SYNTHETIC' : 'ESTIMATED', quoteEvidenceDigest: quote.evidence.sha256 });
  }
  for (const name of config.requiredComponents) if (!(usage?.lines ?? []).some((line) => line.component === name)) { lines.push({ component: name, status: 'UNKNOWN', costMinor: null, reason: usageReason ?? 'COMPONENT_USAGE_REQUIRED' }); reasons.push(usageReason ?? 'COMPONENT_USAGE_REQUIRED'); }
  const known = reasons.length === 0 && lines.length > 0; let budget = { available: false, reason: 'BILLING_OBSERVATION_REQUIRED' };
  if (billingObservation) { try { if (billingObservation.currency !== config.currency) throw new AppError(400, 'BUDGET_CURRENCY_MISMATCH'); budget = { ...evaluateBudget(billingObservation, { now, maxAgeMs: maxBudgetAgeMs }), reason: null }; } catch (error) { budget = { available: false, reason: error instanceof AppError ? error.code : 'BILLING_OBSERVATION_INVALID' }; } }
  const perMillion = known && usage?.successfulRequests && BigInt(usage.successfulRequests) > 0n ? ceil(total * 1000000n, BigInt(usage.successfulRequests)).toString() : null;
  return { version: 1, kind: 'quote-driven-cost-estimate', sourceDigest: config.sourceDigest, observedAt: now, currency: config.currency, minorDigits: config.minorDigits,
    status: !known ? 'BLOCKED' : synthetic ? 'ILLUSTRATIVE' : 'ESTIMATED', period: usage ? { start: usage.periodStart, end: usage.periodEnd } : null,
    totalMinor: known ? total.toString() : null, knownSubtotalMinor: total.toString(), lines, unknownReasons: [...new Set(reasons)],
    perMillionSuccessfulRequestsMinor: perMillion, planningAssumptionsIncluded: assumptions, syntheticPricesIncluded: synthetic,
    rounding: 'round quantity upward to SKU increment; round each SKU cost upward to one minor unit; sum exact integers',
    estimateScope: config.requiredComponents, billing: budget, claims: { observedBill: false, allApplicableProviderChargesCovered: false, providerQuoteAuthentication: false, productionCapacityEstablished: false, foreignExchangeApplied: false } };
}

/** Capacity observations retain their actual scope and do not manufacture billed egress/storage time. */
export function capacityCostObservations(report, { sourceDigest = undefined } = {}) {
  if (report?.version !== 1 || report.kind !== 'capacity-measurement' || report.sourceDigest !== sourceDigest || !['LOCAL_MEASURED', 'SMOKE_ONLY'].includes(report.status)
      || !['planning', 'smoke'].includes(report.mode) || !['core-only', 'runtime-preflight-local-ledger'].includes(report.featureProfile)
      || !Array.isArray(report.cohorts) || !report.cohorts.length || report.cohorts.length > 32) fail('INVALID_CAPACITY_COST_EVIDENCE');
  const allIds = new Set();
  for (const cohort of report.cohorts) {
    const events = cohort.events; const counts = cohort.counts; const statuses = {}; const tally = { planned: events?.length, issued: 0, droppedLag: 0, droppedInFlight: 0, aborted: 0, successful: 0, pending: 0, unresolved: 0 };
    if (!Array.isArray(events) || !events.length || events.length > 5000 || !Array.isArray(cohort.observedEffects) || cohort.observedEffects.length > events.length || cohort.drained !== true || cohort.fatal !== null) fail('INVALID_CAPACITY_COST_EVIDENCE');
    for (const [index, event] of events.entries()) {
      if (event.index !== index || typeof event.id !== 'string' || !/^[A-Za-z0-9_.-]{1,128}$/.test(event.id) || allIds.has(event.id) || typeof event.documentId !== 'string') fail('INVALID_CAPACITY_COST_EVIDENCE'); allIds.add(event.id);
      const field = { issued: 'issued', 'dropped-lag': 'droppedLag', 'dropped-in-flight': 'droppedInFlight', aborted: 'aborted' }[event.outcome]; if (!field) fail('INVALID_CAPACITY_COST_EVIDENCE'); tally[field]++;
      if (event.outcome !== 'issued') { if (event.status !== 0 || event.state !== null) fail('INVALID_CAPACITY_COST_EVIDENCE'); continue; }
      if (!Number.isInteger(event.status) || event.status !== 0 && (event.status < 100 || event.status > 599) || event.status === 200 && event.state !== 'succeeded' || capacityFatal(event.status, event.code)) fail('INVALID_CAPACITY_COST_EVIDENCE');
      if (event.latencyMs === null) tally.unresolved++; else if (!Number.isFinite(event.latencyMs) || event.latencyMs < 0) fail('INVALID_CAPACITY_COST_EVIDENCE');
      if (event.status === 200 && event.state === 'succeeded') tally.successful++; if (event.status === 202) tally.pending++;
      const status = event.latencyMs === null ? 'unresolved' : String(event.status || 'transport-error'); statuses[status] = (statuses[status] ?? 0) + 1;
    }
    if (tally.unresolved || tally.aborted || Object.entries(tally).some(([key, value]) => !Number.isSafeInteger(counts?.[key]) || counts[key] !== value)
        || Object.keys(cohort.statuses ?? {}).length !== Object.keys(statuses).length || Object.entries(statuses).some(([key, value]) => cohort.statuses?.[key] !== value)) fail('INVALID_CAPACITY_COST_EVIDENCE');
    try { const effects = reconcileCapacityEffects(events, cohort.observedEffects, (index) => events[index]); if (Object.entries(effects).some(([key, value]) => cohort.effects?.[key] !== value)) fail('INVALID_CAPACITY_COST_EVIDENCE'); }
    catch { fail('INVALID_CAPACITY_COST_EVIDENCE'); }
  }
  const sum = (select) => report.cohorts.reduce((total, cohort) => { const value = select(cohort); if (!Number.isSafeInteger(value) || value < 0) fail('INVALID_CAPACITY_COST_EVIDENCE'); return total + BigInt(value); }, 0n).toString();
  return { sourceDigest, mode: report.mode, featureProfile: report.featureProfile, issuedRequests: sum((value) => value.counts?.issued), successfulRequests: sum((value) => value.counts?.successful), observedResourceEffects: sum((value) => value.effects?.observed),
    applicationRequestJsonBytes: sum((value) => value.applicationJsonBytes?.request), applicationResponseJsonBytes: sum((value) => value.applicationJsonBytes?.response),
    billedNetworkEgressBytes: null, storageByteSeconds: null, ledgerBilledUnits: null,
    scope: 'local measured request/effect/JSON body counts; JSON bytes exclude HTTP/TLS/provider egress; database size samples are not storage-time integrals',
    monetaryUsageAutomaticallyInferred: false };
}
