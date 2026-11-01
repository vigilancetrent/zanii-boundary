import { isDeepStrictEqual } from 'node:util';
import { AppError, exactObject, identifier, positiveInteger, validateAction, validateTask, verifyEnvelope } from './protocol.mjs';
import { validateResourceEvent } from './resource.mjs';
import { MODES } from './broker.mjs';

export const SCENARIOS = Object.freeze(['healthy', 'scope-misuse', 'direct-denied', 'tool-drift',
  'expired-coverage', 'queued-revocation', 'broken-resource', 'uncertain-response']);

function invalid() { throw new AppError(400, 'INVALID_EXPERIMENT'); }
function boundedArray(value, maximum) {
  if (!Array.isArray(value) || value.length > maximum || Object.keys(value).length !== value.length) invalid();
}
function milliseconds(value) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 60_000) invalid();
}
function text(value, maximum = 128) {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum || /[\u0000-\u001f]/.test(value)) invalid();
}

/** Fixed, model-free test corpus. IDs are deterministic; credentials and fixture identities are fresh. */
export function scenarioActions(mode, scenario) {
  if (!MODES.includes(mode) || !SCENARIOS.includes(scenario)) invalid();
  const read = (documentId = 'tenant-a-guide') => ({ kind: 'read', documentId });
  const share = (recipient = 'internal-team') => ({ kind: 'share', documentId: 'tenant-a-guide', recipient });
  const spec = {
    healthy: [['client', read()], ['client', share()]],
    'scope-misuse': [['client', read('tenant-a-secret')], ['client', read('tenant-b-secret')], ['client', share('external-recipient')]],
    'direct-denied': [['direct', read('tenant-a-secret')]],
    'tool-drift': [['client', read()]],
    'expired-coverage': [['client', read()]],
    'queued-revocation': [['client', read()]],
    'broken-resource': [['client', read()], ['direct', read('tenant-a-secret')]],
    'uncertain-response': [['client', share()]],
  };
  return spec[scenario].map(([route, action], index) => ({
    route, action: validateAction({ id: `${mode}-${scenario}-${index}`, ...action }),
  }));
}

function percentile(values, fraction) {
  const sorted = [...values].sort((a, b) => a - b);
  return Math.round((sorted[Math.max(0, Math.ceil(sorted.length * fraction) - 1)] ?? 0) * 1_000) / 1_000;
}

/** Counts are derived from independently observed effects, never from a broker's success message. */
export function summarizeExperiment(payload) {
  return Object.fromEntries(MODES.map((mode) => {
    const cases = payload.cases.filter((item) => item.mode === mode);
    const attempts = cases.flatMap((item) => item.attempts);
    const effects = cases.flatMap((item) => item.events.filter((event) => !event.actionId.startsWith('admission-'))
      .map((event) => ({ event, item })));
    const forbidden = ({ event, item }) => event.actorId !== item.task.actorId || event.tenantId !== item.task.tenantId
      || !item.task.documentIds.includes(event.documentId)
      || (event.kind === 'share' && !item.task.recipients.includes(event.recipient))
      || event.at >= item.task.expiresAt || item.scenario === 'queued-revocation';
    const healthy = effects.filter((value) => value.item.scenario === 'healthy' && !forbidden(value)).length;
    const durations = attempts.map((attempt) => attempt.elapsedMs);
    return [mode, {
      cases: cases.length, attempts: attempts.length,
      successfulResponses: attempts.filter((attempt) => attempt.status === 200).length,
      rejectedResponses: attempts.filter((attempt) => attempt.status >= 400 && attempt.status !== 504).length,
      uncertainResponses: attempts.filter((attempt) => attempt.status === 0 || attempt.status === 504).length,
      observedWorkloadEffects: effects.length, forbiddenEffects: effects.filter(forbidden).length,
      staleBrokerDispatches: effects.filter(({ event, item }) => event.via === 'broker'
        && event.configurationVersion !== item.coverage.configurationVersion).length,
      expiredCoverageDispatches: effects.filter(({ event, item }) => event.via === 'broker' && event.at >= item.coverage.expiresAt).length,
      revokedEffects: effects.filter(({ item }) => item.scenario === 'queued-revocation').length,
      effectsWithoutSuccessResponse: effects.filter(({ event, item }) => item.attempts.some((attempt) => attempt.action.id === event.actionId && attempt.status !== 200)).length,
      healthyExpected: 2, healthyCompleted: healthy, healthyNotCompleted: 2 - healthy,
      p50Ms: percentile(durations, 0.50), p95Ms: percentile(durations, 0.95), p99Ms: percentile(durations, 0.99),
    }];
  }));
}

/** Validate one historical run. No current-time freshness test is applied to archived evidence. */
export function validateExperiment(payload) {
  exactObject(payload, ['version', 'runId', 'startedAt', 'finishedAt', 'environment', 'cases', 'summary']);
  if (payload.version !== 1) invalid();
  identifier(payload.runId); positiveInteger(payload.startedAt); positiveInteger(payload.finishedAt);
  if (payload.finishedAt < payload.startedAt || payload.finishedAt - payload.startedAt > 3_600_000) invalid();
  exactObject(payload.environment, ['node', 'platform', 'arch', 'transport', 'model', 'sourceDigest']);
  for (const field of ['node', 'platform', 'arch']) text(payload.environment[field], 64);
  if (!['process', 'in-process'].includes(payload.environment.transport) || payload.environment.model !== 'none') invalid();
  if (typeof payload.environment.sourceDigest !== 'string' || !/^[a-f0-9]{64}$/.test(payload.environment.sourceDigest)) invalid();
  boundedArray(payload.cases, MODES.length * SCENARIOS.length);
  if (payload.cases.length !== MODES.length * SCENARIOS.length) invalid();
  const pairs = new Set(); const resources = new Set(); const eventIds = new Set(); const actionIds = new Set();
  for (const item of payload.cases) {
    exactObject(item, ['mode', 'scenario', 'resourceId', 'task', 'configurationVersion', 'coverage', 'observedTotal', 'attempts', 'events', 'durationMs']);
    if (!MODES.includes(item.mode) || !SCENARIOS.includes(item.scenario)) invalid();
    const pair = `${item.mode}/${item.scenario}`;
    if (pairs.has(pair)) invalid(); pairs.add(pair);
    identifier(item.resourceId);
    if (resources.has(item.resourceId)) invalid(); resources.add(item.resourceId);
    const task = validateTask(item.task);
    if (task.actorId !== 'agent-a' || task.tenantId !== 'tenant-a' || task.revoked
        || !isDeepStrictEqual(task.documentIds, ['tenant-a-guide']) || !isDeepStrictEqual(task.recipients, ['internal-team'])) invalid();
    positiveInteger(item.configurationVersion);
    exactObject(item.coverage, ['configurationVersion', 'issuedAt', 'expiresAt']);
    positiveInteger(item.coverage.configurationVersion); positiveInteger(item.coverage.issuedAt); positiveInteger(item.coverage.expiresAt);
    if (item.coverage.expiresAt <= item.coverage.issuedAt || item.coverage.expiresAt - item.coverage.issuedAt > 900_000
        || item.coverage.configurationVersion > item.configurationVersion) invalid();
    milliseconds(item.durationMs);
    boundedArray(item.attempts, 3); boundedArray(item.events, 8);
    if (!Number.isSafeInteger(item.observedTotal) || item.observedTotal !== item.events.length) invalid();
    const spec = scenarioActions(item.mode, item.scenario);
    if (item.attempts.length !== spec.length) invalid();
    const attemptsById = new Map();
    for (let index = 0; index < item.attempts.length; index += 1) {
      const attempt = item.attempts[index];
      exactObject(attempt, ['action', 'route', 'status', 'code', 'at', 'elapsedMs']);
      const action = validateAction(attempt.action);
      if (!isDeepStrictEqual(action, spec[index].action) || attempt.route !== spec[index].route || actionIds.has(action.id)) invalid();
      actionIds.add(action.id); attemptsById.set(action.id, attempt);
      if (!Number.isInteger(attempt.status) || (attempt.status !== 0 && attempt.status !== 200
          && (attempt.status < 400 || attempt.status > 599))) invalid();
      if (attempt.status === 200 ? attempt.code !== null : typeof attempt.code !== 'string') invalid();
      if (attempt.code !== null) identifier(attempt.code);
      positiveInteger(attempt.at); milliseconds(attempt.elapsedMs);
      if (attempt.at < payload.startedAt || attempt.at > payload.finishedAt) invalid();
    }
    const effectsByAction = new Map(); let probes = 0;
    for (const raw of item.events) {
      const event = validateResourceEvent(raw);
      if (eventIds.has(event.id) || event.configurationVersion > item.configurationVersion
          || event.at < payload.startedAt || event.at > payload.finishedAt) invalid();
      eventIds.add(event.id);
      if (event.actionId.startsWith('admission-')) {
        if (event.via !== 'broker' || event.kind !== 'read' || event.documentId !== 'tenant-a-guide'
            || event.actorId !== task.actorId || event.tenantId !== task.tenantId) invalid();
        probes += 1; continue;
      }
      const attempt = attemptsById.get(event.actionId);
      if (!attempt || event.at < attempt.at || event.kind !== attempt.action.kind
          || event.documentId !== attempt.action.documentId || event.recipient !== attempt.action.recipient
          || event.via !== (attempt.route === 'client' ? 'broker' : 'legacy') || effectsByAction.has(event.actionId)) invalid();
      effectsByAction.set(event.actionId, event);
    }
    if (probes < 1) invalid();
    for (const attempt of item.attempts) if (attempt.status === 200 && !effectsByAction.has(attempt.action.id)) invalid();
  }
  const summary = summarizeExperiment(payload);
  if (!isDeepStrictEqual(payload.summary, summary)) invalid();
  return payload;
}

/** Offline authenticity and internal consistency; neither exhaustive coverage nor producer honesty is proved. */
export function verifyEvidence(envelope, pinnedPublicKey) {
  try {
    const payload = verifyEnvelope(envelope, pinnedPublicKey, 'experiment');
    validateExperiment(payload);
    return { ok: true, runId: payload.runId, environment: payload.environment, summary: payload.summary };
  } catch { throw new AppError(403, 'INVALID_EXPERIMENT_EVIDENCE'); }
}
