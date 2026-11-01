import { randomBytes, randomUUID } from 'node:crypto';
import { AppError } from '../protocol.mjs';

/** Only bounded identifiers/counters leave the runtime. No request bodies, bearer values or content. */
export function createObservability({ logger = (line) => process.stdout.write(`${line}\n`), now = Date.now, rateWindowMs, rateRequests, maxConcurrency }) {
  const windows = new Map(); let active = 0; let total = 0; let denied = 0; let latencyMs = 0;
  function limit(key) {
    const time = now(); let entry = windows.get(key);
    if (!entry || entry.until <= time) {
      if (windows.size >= 4096) { for (const [id, value] of windows) if (value.until <= time) windows.delete(id); }
      if (!windows.has(key) && windows.size >= 4096) throw new AppError(429, 'RATE_LIMIT_CAPACITY');
      entry = { until: time + rateWindowMs, count: 0 }; windows.set(key, entry);
    }
    if (++entry.count > rateRequests) throw new AppError(429, 'RATE_LIMITED');
  }
  return Object.freeze({
    limit,
    begin(req) {
      limit(`peer:${req.socket.remoteAddress ?? 'uds'}`);
      if (active >= maxConcurrency) throw new AppError(429, 'CONCURRENCY_LIMIT');
      active++; total++; const startedAt = now(); const requestId = randomUUID();
      const incoming = req.headers.traceparent;
      const traceparent = typeof incoming === 'string' && /^00-[a-f0-9]{32}-[a-f0-9]{16}-0[01]$/.test(incoming)
        && !incoming.includes('00000000000000000000000000000000') && incoming.slice(36, 52) !== '0000000000000000'
        ? `00-${incoming.slice(3, 35)}-${randomBytes(8).toString('hex')}-${incoming.slice(-2)}`
        : `00-${randomBytes(16).toString('hex')}-${randomBytes(8).toString('hex')}-01`;
      let finished = false;
      return { requestId, traceparent, finish(status, route) {
        if (finished) return; finished = true; active--; const durationMs = Math.max(0, now() - startedAt); latencyMs += durationMs;
        if (status >= 400) denied++;
        try { logger(JSON.stringify({ at: new Date(now()).toISOString(), event: 'http.request', requestId, traceparent, route, status, durationMs })); } catch { /* Logging cannot disclose data or interrupt an authorized effect. */ }
      } };
    },
    metrics() { return `# TYPE runtime_requests_total counter\nruntime_requests_total ${total}\n# TYPE runtime_denied_total counter\nruntime_denied_total ${denied}\n# TYPE runtime_active gauge\nruntime_active ${active}\n# TYPE runtime_request_duration_ms_sum counter\nruntime_request_duration_ms_sum ${latencyMs}\n`; },
    active: () => active,
  });
}
