import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { AppError, exactObject, positiveInteger } from '../src/protocol.mjs';
import { createProductFixture, seedProductFixture, resourceEffects } from './product-fixture.mjs';
import { implementationDigest } from './benchmark.mjs';
const quantiles = (values) => {
    const sorted = [...values].sort((a, b) => a - b);
    const at = (fraction) => sorted.length ? sorted[Math.ceil(fraction * sorted.length) - 1] : null;
    return { p50: at(0.5), p95: at(0.95), p99: at(0.99) };
};
/** Finite closed-loop admission stress; no claim about sustained customer capacity. */
export async function runProductLoad(options = {}) {
    exactObject(options, [], ['requests', 'concurrency']);
    const requests = positiveInteger(options.requests ?? 128, 1000);
    const concurrency = options.concurrency ?? [1, 4, 16, 64];
    if (!Array.isArray(concurrency) || !concurrency.length || concurrency.length > 8 || new Set(concurrency).size !== concurrency.length)
        throw new AppError(400, 'INVALID_LOAD_OPTIONS');
    for (const level of concurrency)
        positiveInteger(level, 128);
    const sourceDigest = await implementationDigest();
    const startedAt = Date.now();
    const levels = [];
    for (const workers of concurrency) {
        const f = await createProductFixture({ maxConcurrency: 16 });
        try {
            await seedProductFixture(f, { maxActions: requests });
            let next = 0;
            const attempts = [];
            const successfulIds = new Set();
            const issued = new Set();
            const statuses = {};
            const cpu = process.cpuUsage();
            const memoryBefore = process.memoryUsage();
            const start = performance.now();
            await Promise.all(Array.from({ length: Math.min(workers, requests) }, async () => {
                while (next < requests) {
                    const index = next++;
                    const id = `load-${index}`;
                    issued.add(id);
                    const begin = performance.now();
                    let status = 0;
                    let state;
                    try {
                        const response = await f.agent.call('/v1/actions', { taskId: 'evaluation-task', action: { id, kind: 'read', documentId: 'guide' } });
                        status = response.status;
                        state = response.body?.state;
                        if (status === 200 && state === 'succeeded')
                            successfulIds.add(id);
                    }
                    catch { /* Transport errors are counted, never retried. */ }
                    statuses[status || 'transport-error'] = (statuses[status || 'transport-error'] ?? 0) + 1;
                    attempts.push({ id, status, state, durationMs: performance.now() - begin });
                }
            }));
            const durationMs = performance.now() - start;
            const used = process.cpuUsage(cpu);
            const memoryAfter = process.memoryUsage();
            const effects = (await resourceEffects(f.resourceStore));
            const effectIds = new Set();
            for (const effect of effects) {
                if (!issued.has(effect.id) || effectIds.has(effect.id) || effect.actorId !== 'agent' || effect.kind !== 'read' || effect.documentId !== 'guide')
                    throw new AppError(500, 'LOAD_EFFECT_MISMATCH');
                effectIds.add(effect.id);
            }
            if ([...successfulIds].some((id) => !effectIds.has(id)))
                throw new AppError(500, 'LOAD_EFFECT_MISMATCH');
            const successful = attempts.filter((item) => successfulIds.has(item.id));
            const throttled = attempts.filter((item) => item.status === 429).length;
            const pending = attempts.filter((item) => item.status === 202).length;
            const denied = attempts.filter((item) => item.status >= 400 && item.status < 500 && item.status !== 429).length;
            const errors = attempts.length - successful.length - throttled - pending - denied;
            levels.push({ concurrency: workers, requested: requests, successful: successful.length, throttled, pending, denied, errors, statuses, durationMs,
                successfulRequestsPerSecond: successful.length * 1000 / durationMs, observedEffects: effects.length,
                effectsWithoutSuccessfulResponse: effects.filter((effect) => !successfulIds.has(effect.id)).length,
                latencyMs: quantiles(attempts.map((item) => item.durationMs)), successfulLatencyMs: quantiles(successful.map((item) => item.durationMs)),
                cpuMilliseconds: { user: used.user / 1000, system: used.system / 1000 },
                memoryBytes: { rssBefore: memoryBefore.rss, rssAfter: memoryAfter.rss, heapUsedAfter: memoryAfter.heapUsed } });
        }
        finally {
            await f.close();
        }
    }
    if (await implementationDigest() !== sourceDigest)
        throw new AppError(409, 'IMPLEMENTATION_CHANGED');
    return { version: 1, kind: 'product-load', startedAt, finishedAt: Date.now(), sourceDigest,
        environment: { node: process.version, platform: process.platform, arch: process.arch, transport: 'in-process-real-mtls', model: 'none' },
        targets: { illustrativeLocalPeakRps: 10, p50Ms: 250, p95Ms: 2000, p99Ms: 5000 }, configuredGatewayConcurrency: 16,
        levels, maxObservedSuccessfulRps: Math.max(...levels.map((level) => level.successfulRequestsPerSecond)),
        twoTimesIllustrativeLocalPeakObserved: levels.some((level) => level.successful === level.requested && level.successfulRequestsPerSecond >= 20),
        admissionSaturationObserved: levels.some((level) => level.throttled > 0), hardwareBreakingPoint: null,
        firstConstraint: levels.some((level) => level.throttled > 0) ? 'Configured gateway maxConcurrency=16 admission limit' : 'Not established',
        limitations: ['Finite closed-loop synthetic reads; startup and observation excluded from per-level throughput.',
            'Combined gateway/resource/evaluator process CPU and RSS; not independent service utilization.',
            'No arrival-rate soak, deployed capacity, hardware ceiling, autoscaling or monetary billing measurement.'] };
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    (async () => {
        if (process.argv.length !== 2)
            throw new AppError(400, 'INVALID_ARGUMENTS');
        const payload = await runProductLoad();
        await mkdir(new URL('../artifacts/', import.meta.url), { recursive: true });
        await writeFile(new URL('../artifacts/product-load.json', import.meta.url), `${JSON.stringify(payload, null, 2)}\n`);
        process.stdout.write(`${JSON.stringify({ requested: payload.levels.reduce((sum, item) => sum + item.requested, 0), successful: payload.levels.reduce((sum, item) => sum + item.successful, 0), maxObservedSuccessfulRps: payload.maxObservedSuccessfulRps, firstConstraint: payload.firstConstraint })}\n`);
    })().catch((error) => { process.stderr.write(`${JSON.stringify({ code: error instanceof AppError ? error.code : 'PRODUCT_LOAD_FAILED' })}\n`); process.exitCode = 1; });
}
