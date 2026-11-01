import { AppError, exactObject, identifier, positiveInteger, validateAction, validateCoverage, validateTask } from './protocol.mjs';

/** Authorization uses trusted server identity; tenant is never accepted from the action. */
export function authorizeAction(taskValue, actionValue, identity) {
  const task = validateTask(taskValue);
  const action = validateAction(actionValue);
  exactObject(identity, ['actorId', 'tenantId'], ['now']);
  identifier(identity.actorId);
  identifier(identity.tenantId);
  const now = identity.now ?? Date.now();
  positiveInteger(now);
  if (identity.actorId !== task.actorId || identity.tenantId !== task.tenantId) throw new AppError(403, 'IDENTITY_DENIED');
  if (task.revoked) throw new AppError(403, 'TASK_REVOKED');
  if (now >= task.expiresAt) throw new AppError(403, 'TASK_EXPIRED');
  if (!task.documentIds.includes(action.documentId)) throw new AppError(403, 'DOCUMENT_DENIED');
  if (action.kind === 'share' && !task.recipients.includes(action.recipient)) throw new AppError(403, 'RECIPIENT_DENIED');
  return action;
}

/** Check the verified coverage payload against trusted current state, not request claims. */
export function authorizeCoverage(coverageValue, { taskId, resourceId, configurationVersion, now = Date.now() }) {
  const coverage = validateCoverage(coverageValue);
  identifier(taskId); identifier(resourceId); positiveInteger(configurationVersion); positiveInteger(now);
  if (coverage.taskId !== taskId || coverage.resourceId !== resourceId) throw new AppError(403, 'COVERAGE_SCOPE');
  if (now < coverage.issuedAt || now >= coverage.expiresAt) throw new AppError(403, 'COVERAGE_EXPIRED');
  if (coverage.configurationVersion !== configurationVersion) throw new AppError(409, 'COVERAGE_STALE');
  return coverage;
}

/** Synchronous reservation runs before provider awaits. IDs and quota remain consumed on uncertain outcomes. */
export function createAdmission(taskValue, identityValue, { now = Date.now } = {}) {
  const task = validateTask(taskValue);
  exactObject(identityValue, ['actorId', 'tenantId']);
  const identity = Object.freeze({ actorId: identifier(identityValue.actorId), tenantId: identifier(identityValue.tenantId) });
  if (typeof now !== 'function') throw new AppError(400, 'INVALID_INPUT');
  const ids = new Set();
  let revoked = task.revoked;
  return Object.freeze({
    reserve(actionValue) {
      const action = authorizeAction({ ...task, revoked }, actionValue, { ...identity, now: now() });
      if (ids.has(action.id)) throw new AppError(409, 'REPLAY');
      if (ids.size >= task.maxActions) throw new AppError(429, 'TASK_QUOTA');
      ids.add(action.id);
      return action;
    },
    revoke() { revoked = true; },
    snapshot() { return Object.freeze({ taskId: task.id, admitted: ids.size, remaining: task.maxActions - ids.size, revoked }); },
  });
}
