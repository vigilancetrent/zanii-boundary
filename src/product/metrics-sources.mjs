import { stat, statfs } from 'node:fs/promises';
import { dirname } from 'node:path';
import { z } from 'zod';
import { AppError } from '../protocol.mjs';
import { readOperationsFile } from './operations-config.mjs';

export const monitoringSourcesSchema = z.object({ budgetFile: z.string().min(1).max(4096).optional(),
  maxBudgetAgeMs: z.number().int().min(1000).max(86400000).default(3600000) }).strict();
const money = z.string().regex(/^(0|[1-9][0-9]{0,19})$/);
const budgetSchema = z.object({ version: z.literal(1), currency: z.string().regex(/^[A-Z]{3}$/), spentMinor: money, limitMinor: money,
  periodStart: z.number().int().positive(), periodEnd: z.number().int().positive(), observedAt: z.number().int().positive(),
  source: z.enum(['provider-invoice', 'provider-usage-api', 'operator-cost-report']), sourceDigest: z.string().regex(/^[a-f0-9]{64}$/) }).strict();

/** Threshold decisions use integer minor units; only the display ratio is converted to a metric number. */
export function evaluateBudget(raw, { now = Date.now(), maxAgeMs = 3600000 } = {}) {
  const parsed = budgetSchema.safeParse(raw); if (!parsed.success) throw new AppError(400, 'INVALID_BUDGET_OBSERVATION'); const value = parsed.data;
  const spent = BigInt(value.spentMinor); const limit = BigInt(value.limitMinor);
  if (limit === 0n || value.periodStart > now || value.periodEnd <= now || value.observedAt > now
      || value.observedAt < value.periodStart || now - value.observedAt > maxAgeMs) throw new AppError(503, 'BUDGET_OBSERVATION_STALE');
  return { available: true, currency: value.currency, exceeded: spent >= limit, warning: spent * 100n >= limit * 80n,
    ratio: Number(spent * 1000000n / limit) / 1000000, ageMs: now - value.observedAt };
}

/** Optional instrumentation failures mark a source unavailable; no synthetic zero usage is reported.
 * @param {any} options */
export function createSignalSampler({ store, observability, telemetry, logSink, config, baseDirectory = process.cwd() }) {
  const settings = monitoringSourcesSchema.parse(config.monitoring ?? {});
  const sample = (name, value) => typeof value === 'number' && Number.isFinite(value) && value >= 0 ? observability.signal(name, value) : observability.signalUnavailable(name);
  return async ({ containment = undefined } = {}) => {
    const log = logSink?.status(); const traces = telemetry?.status?.();
    sample('log_sink_healthy', log ? Number(log.healthy) : undefined); sample('log_queue_bytes', log?.queuedBytes); sample('log_dropped_events', log?.dropped); sample('log_write_failures', log?.failures);
    sample('telemetry_configured', traces ? Number(traces.configured) : undefined); sample('telemetry_exported_spans', traces?.exported); sample('telemetry_export_failures', traces?.failures);
    sample('containment_expiry_seconds', containment?.verified ? Math.max(0, (containment.expiresAt - Date.now()) / 1000) : undefined);
    try {
      if (store.storageUsage) sample('db_bytes', (await store.storageUsage()).bytes);
      else if (store.path) { let bytes = 0; for (const suffix of ['', '-wal', '-shm']) { try { bytes += (await stat(store.path + suffix)).size; } catch (error) { if (suffix === '' || !(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error; } } sample('db_bytes', bytes); }
      else observability.signalUnavailable('db_bytes');
    } catch { observability.signalUnavailable('db_bytes'); }
    try {
      if (logSink) sample('disk_free_bytes', (await logSink.disk()).freeBytes);
      else if (store.path) { const disk = await statfs(dirname(store.path), { bigint: true }); sample('disk_free_bytes', Number(disk.bavail * disk.bsize)); }
      else observability.signalUnavailable('disk_free_bytes');
    } catch { observability.signalUnavailable('disk_free_bytes'); }
    /** @type {any} */ let budget = { available: false };
    if (settings.budgetFile) {
      try { budget = evaluateBudget(JSON.parse(await readOperationsFile(settings.budgetFile, { baseDirectory, secret: true })), { maxAgeMs: settings.maxBudgetAgeMs }); }
      catch { /* Missing or stale financial evidence stays unknown rather than zero. */ }
    }
    sample('budget_data_available', Number(budget.available)); sample('budget_spent_ratio', budget.available ? budget.ratio : undefined);
    sample('budget_observation_age_seconds', budget.available ? budget.ageMs / 1000 : undefined);
    return { logging: log ? { configured: true, healthy: log.healthy, required: log.required } : { configured: false }, budget: { available: budget.available } };
  };
}
