import { AsyncLocalStorage } from 'node:async_hooks';
import { randomUUID } from 'node:crypto';
import { AppError, exactObject, identifier, positiveInteger } from '../protocol.mjs';

export const requestContext = new AsyncLocalStorage();

export function parseTraceparent(value) {
  if (typeof value !== 'string' || !/^00-[a-f0-9]{32}-[a-f0-9]{16}-0[01]$/.test(value)) return null;
  const [, traceId, spanId, flags] = value.split('-');
  if (/^0+$/.test(traceId) || /^0+$/.test(spanId)) return null;
  return { traceId, spanId, traceFlags: Number.parseInt(flags, 16), isRemote: true };
}

export const formatTraceparent = ({ traceId, spanId, traceFlags }) => `00-${traceId}-${spanId}-${traceFlags & 1 ? '01' : '00'}`;

/** A child call can shorten an invocation budget, never extend it. */
export function effectiveDeadline({ deadlineAt = undefined, timeoutMs = 10000, now = Date.now() } = {}) {
  positiveInteger(timeoutMs, 3_600_000);
  if (deadlineAt !== undefined && (!Number.isFinite(deadlineAt) || deadlineAt <= 0)) throw new AppError(400, 'INVALID_DEADLINE');
  const inherited = requestContext.getStore()?.deadlineAt;
  const deadline = Math.min(now + timeoutMs, deadlineAt ?? Infinity, inherited ?? Infinity);
  if (!Number.isFinite(deadline) || deadline <= now) throw new AppError(504, 'TRANSPORT_DEADLINE');
  return deadline;
}

export function remainingBudget(deadlineAt, now = Date.now()) {
  const remaining = deadlineAt - now;
  if (!Number.isFinite(remaining) || remaining <= 0) throw new AppError(504, 'TRANSPORT_DEADLINE');
  return remaining;
}

/** Only correlation survives a durable queue; the worker receives its own bounded budget. */
export function jobTraceContext() {
  const current = requestContext.getStore();
  return { requestId: current?.requestId ?? randomUUID(), ...(parseTraceparent(current?.traceparent) ? { traceparent: current.traceparent } : {}) };
}

export function runJobContext(metadata, { timeoutMs = 10000, now = Date.now() } = {}, work) {
  exactObject(metadata, ['requestId'], ['traceparent']); identifier(metadata.requestId);
  if (metadata.traceparent !== undefined && !parseTraceparent(metadata.traceparent)) throw new AppError(400, 'INVALID_TRACE_CONTEXT');
  return requestContext.run(metadata, () => requestContext.run({ ...metadata, deadlineAt: effectiveDeadline({ timeoutMs, now }) }, work));
}

export function withSpan(name, attributes, work) {
  const telemetry = requestContext.getStore()?.telemetry;
  return telemetry ? telemetry.span(name, attributes, work) : work();
}
