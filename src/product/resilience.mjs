import { AppError, positiveInteger } from '../protocol.mjs';
import { effectiveDeadline, remainingBudget } from './context.mjs';

const transient = (error) => error instanceof AppError && (error.status >= 500 || error.status === 429)
  && !['CIRCUIT_OPEN', 'TRANSPORT_ROUTE_DENIED', 'NETWORK_DESTINATION_DENIED', 'INVALID_PROVIDER_JSON', 'INVALID_TRANSPORT_HEADERS'].includes(error.code);

/** One policy belongs to one configured dependency; caller input cannot create breaker keys. */
export function createDependencyPolicy({ name = 'provider', failureThreshold = 3, cooldownMs = 10000,
  maxAttempts = 3, baseDelayMs = 50, maxDelayMs = 1000, timeoutMs = 10000,
  now = Date.now, sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)), random = Math.random,
  retryable = transient, onState = (state) => { void state; } } = {}) {
  if (typeof name !== 'string' || !/^[a-z][a-z0-9._-]{0,63}$/.test(name) || typeof retryable !== 'function') throw new AppError(400, 'INVALID_DEPENDENCY_POLICY');
  for (const [value, maximum] of [[failureThreshold, 100], [cooldownMs, 300000], [maxAttempts, 8], [baseDelayMs, 60000], [maxDelayMs, 60000], [timeoutMs, 3600000]]) positiveInteger(value, maximum);
  if (baseDelayMs > maxDelayMs) throw new AppError(400, 'INVALID_DEPENDENCY_POLICY');
  let failures = 0; let openedAt = null; let probe = false; let attemptsTotal = 0; let generation = 0;
  const state = () => openedAt === null ? 'closed' : probe ? 'half-open' : 'open';
  function report() { try { onState({ name, state: state(), failures, openedAt }); } catch { /* Telemetry cannot grant authority or change retry behavior. */ } }
  function enter() {
    if (openedAt === null) return false;
    if (probe || now() - openedAt < cooldownMs) throw new AppError(503, 'CIRCUIT_OPEN');
    probe = true; report(); return true;
  }
  function failed(isProbe, admittedGeneration) {
    if (admittedGeneration !== generation) return;
    failures += 1;
    if (isProbe || failures >= failureThreshold) { openedAt = now(); probe = false; generation += 1; }
    report();
  }
  return Object.freeze({
    async execute(work, { deadlineAt = undefined, retrySafe = false } = {}) {
      if (typeof work !== 'function' || typeof retrySafe !== 'boolean') throw new AppError(400, 'INVALID_DEPENDENCY_INVOCATION');
      const deadline = effectiveDeadline({ deadlineAt, timeoutMs, now: now() });
      const isProbe = enter(); const admittedGeneration = generation; const attempts = retrySafe && !isProbe ? maxAttempts : 1;
      try {
        for (let attempt = 1; attempt <= attempts; attempt++) {
          const remaining = remainingBudget(deadline, now()); attemptsTotal += 1;
          const controller = new AbortController(); let timer;
          try {
            const result = await Promise.race([
              Promise.resolve().then(() => work({ attempt, deadlineAt: deadline, signal: controller.signal })),
              new Promise((resolve, reject) => { timer = setTimeout(() => { const error = new AppError(504, 'TRANSPORT_DEADLINE'); controller.abort(error); reject(error); }, remaining); }),
            ]);
            remainingBudget(deadline, now());
            if (admittedGeneration === generation) { failures = 0; openedAt = null; probe = false; report(); }
            return result;
          } catch (error) {
            if (!retryable(error)) {
              // A completed non-outage response resets consecutive dependency failures.
              if (admittedGeneration === generation) { openedAt = null; failures = 0; probe = false; report(); }
              throw error;
            }
            failed(isProbe, admittedGeneration);
            if (attempt >= attempts || openedAt !== null) throw error;
            const entropy = random();
            if (typeof entropy !== 'number' || !Number.isFinite(entropy) || entropy < 0 || entropy >= 1) throw new AppError(500, 'INVALID_RETRY_RANDOM');
            const cap = Math.min(maxDelayMs, baseDelayMs * 2 ** (attempt - 1));
            const delay = Math.floor(cap / 2 + entropy * cap / 2);
            if (delay >= remainingBudget(deadline, now())) throw new AppError(504, 'TRANSPORT_DEADLINE');
            await sleep(delay);
          } finally { clearTimeout(timer); }
        }
        throw new AppError(503, 'DEPENDENCY_UNAVAILABLE');
      } finally {
        // Deadline or clock failures before work must never strand a half-open owner.
        if (isProbe && probe && admittedGeneration === generation) {
          openedAt = now(); probe = false; generation += 1; report();
        }
      }
    },
    status: () => ({ name, state: state(), failures, attempts: attemptsTotal, ...(openedAt === null ? {} : { retryAt: openedAt + cooldownMs }) }),
  });
}
