import { randomUUID } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { startHarness } from '../src/harness.mjs';
import { AppError, exactObject, positiveInteger } from '../src/protocol.mjs';

const DEFAULT_LEVELS = Object.freeze([1, 4, 8, 16]);
const EXPECTED_LOCAL_PEAK_RPS = 25;

function percentiles(values) {
  const sorted = [...values].sort((left, right) => left - right);
  const at = (fraction) => sorted.length ? sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)] : null;
  return { p50: at(0.5), p95: at(0.95), p99: at(0.99) };
}

/**
 * Finite closed-loop concurrency sweep, not a steady-arrival or saturation test.
 * @param {{transport?:string,concurrency?:number[],requests?:number}} options
 */
export async function runLoad(options = {}) {
  exactObject(options, [], ['transport', 'concurrency', 'requests']);
  const transport = options.transport ?? 'process';
  if (!['process', 'in-process'].includes(transport)) throw new AppError(400, 'INVALID_CONFIGURATION');
  const requests = positiveInteger(options.requests ?? 100, 1_000);
  const selected = options.concurrency ?? DEFAULT_LEVELS;
  if (!Array.isArray(selected) || !selected.length || selected.length > 8
      || Reflect.ownKeys(selected).length !== selected.length + 1) throw new AppError(400, 'INVALID_CONFIGURATION');
  const concurrency = Array.from({ length: selected.length }, (_, index) => {
    const property = Object.getOwnPropertyDescriptor(selected, String(index));
    if (!property || !('value' in property)) throw new AppError(400, 'INVALID_CONFIGURATION');
    return positiveInteger(property.value, 32);
  });
  if (new Set(concurrency).size !== concurrency.length) throw new AppError(400, 'INVALID_CONFIGURATION');
  const startedAt = Date.now();
  const levels = [];
  for (const workers of concurrency) {
    const harness = await startHarness({ transport, mode: 'coverage-bound', maxActions: requests,
      maxEvents: requests + 8, taskLifetimeMs: 120_000, coverageLifetimeMs: 120_000, providerTimeoutMs: 2_000 });
    try {
      const attempts = [];
      const succeeded = new Set();
      const issued = new Set();
      /** @type {Record<string,number>} */
      const statuses = {};
      let next = 0;
      const started = performance.now();
      await Promise.all(Array.from({ length: Math.min(workers, requests) }, async () => {
        while (next < requests) {
          next += 1;
          const id = randomUUID();
          issued.add(id);
          const before = performance.now();
          let status = 0;
          try {
            const result = await harness.client({ id, kind: 'read', documentId: 'tenant-a-guide' });
            status = result.status;
            if (status === 200) succeeded.add(id);
          } catch (error) {
            if (!(error instanceof AppError)) throw error;
          }
          const key = status ? String(status) : 'transport-error';
          statuses[key] = (statuses[key] ?? 0) + 1;
          attempts.push({ id, status, durationMs: performance.now() - before });
        }
      }));
      const durationMs = performance.now() - started;
      const observed = await harness.observe();
      const effects = observed.events.filter((event) => !event.actionId.startsWith('admission-'));
      const effectIds = new Set();
      for (const effect of effects) {
        if (!issued.has(effect.actionId) || effectIds.has(effect.actionId) || effect.via !== 'broker'
            || effect.kind !== 'read' || effect.documentId !== 'tenant-a-guide'
            || effect.actorId !== harness.task.actorId || effect.tenantId !== harness.task.tenantId) {
          throw new AppError(502, 'LOAD_OBSERVATION_MISMATCH');
        }
        effectIds.add(effect.actionId);
      }
      if ([...succeeded].some((id) => !effectIds.has(id))) throw new AppError(502, 'LOAD_OBSERVATION_MISMATCH');
      const successful = attempts.filter((attempt) => attempt.status === 200);
      const denied = attempts.filter((attempt) => attempt.status >= 400 && attempt.status < 500).length;
      levels.push({ concurrency: workers, requested: requests, successful: successful.length, denied,
        errors: attempts.length - successful.length - denied, statuses, durationMs,
        successfulRequestsPerSecond: successful.length * 1_000 / durationMs,
        observedEffects: effects.length,
        effectsWithoutSuccessfulResponse: effects.filter((effect) => !succeeded.has(effect.actionId)).length,
        latencyMs: percentiles(attempts.map((attempt) => attempt.durationMs)),
        successfulLatencyMs: percentiles(successful.map((attempt) => attempt.durationMs)) });
    } finally { await harness.close(); }
  }
  const maxObservedSuccessfulRps = Math.max(...levels.map((level) => level.successfulRequestsPerSecond));
  return { version: 1, startedAt, finishedAt: Date.now(),
    environment: { node: process.version, platform: process.platform, arch: process.arch, transport, mode: 'coverage-bound' },
    loadModel: 'finite closed-loop concurrency sweep; per-level throughput excludes fixture startup and observation',
    expectedLocalPeakRps: EXPECTED_LOCAL_PEAK_RPS,
    twoTimesLocalTargetObserved: levels.some((level) => level.successful === level.requested
      && level.successfulRequestsPerSecond >= 2 * EXPECTED_LOCAL_PEAK_RPS),
    levels, maxObservedSuccessfulRps, breakingPoint: null, firstBottleneck: 'not established',
    limitations: ['Synthetic loopback read workload only; no public service or paid model.',
      'Closed-loop burst throughput does not establish sustained arrival-rate capacity or a production ceiling.',
      'In-process transport supplies no process or OS isolation. No automatic transport fallback.'] };
}

/** @param {string[]} args */
export function parseLoadArgs(args) {
  /** @type {{transport?:string,concurrency?:number[],requests?:number}} */
  const options = {};
  const seen = new Set();
  for (const arg of args) {
    const match = /^--(transport|requests|concurrency)=(.+)$/.exec(arg);
    if (!match || seen.has(match[1])) throw new AppError(400, 'INVALID_ARGUMENTS');
    seen.add(match[1]);
    const [, name, value] = match;
    if (name === 'transport') {
      if (!['process', 'in-process'].includes(value)) throw new AppError(400, 'INVALID_ARGUMENTS');
      options.transport = value;
    } else {
      if (!/^\d+(?:,\d+)*$/.test(value) || (name === 'requests' && value.includes(','))) throw new AppError(400, 'INVALID_ARGUMENTS');
      if (name === 'requests') options.requests = positiveInteger(Number(value), 1_000);
      else options.concurrency = value.split(',').map((item) => positiveInteger(Number(item), 32));
    }
  }
  return options;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const report = await runLoad(parseLoadArgs(process.argv.slice(2)));
    const output = new URL('../artifacts/load.json', import.meta.url);
    await mkdir(dirname(fileURLToPath(output)), { recursive: true });
    await writeFile(output, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
    process.stdout.write(`${JSON.stringify({ artifact: 'artifacts/load.json', transport: report.environment.transport,
      requested: report.levels.reduce((sum, level) => sum + level.requested, 0),
      successful: report.levels.reduce((sum, level) => sum + level.successful, 0),
      maxObservedSuccessfulRps: report.maxObservedSuccessfulRps, breakingPoint: report.breakingPoint })}\n`);
  } catch (error) {
    process.stderr.write(`${JSON.stringify({ error: { code: error instanceof AppError ? error.code : 'LOAD_FAILED' } })}\n`);
    process.exitCode = 1;
  }
}
