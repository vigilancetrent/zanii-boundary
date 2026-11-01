import { AppError, exactObject, identifier, positiveInteger, tokenMatches, validateAction, validateCoverage, validateTask, verifyEnvelope } from './protocol.mjs';
import { authorizeCoverage, createAdmission } from './policy.mjs';
import { listenLoopback, loopbackOrigin, readJson, requestJson, requireBearer, sendJson } from './http.mjs';
import { validateResourceState } from './resource.mjs';

export const MODES = Object.freeze(['broker-static', 'lease-only', 'coverage-bound']);

export function validateBrokerConfig(value) {
  exactObject(value, ['version', 'mode', 'resourceOrigin', 'resourceId', 'resourceToken', 'clientToken', 'controlToken',
    'task', 'publicKey', 'coverage', 'providerTimeoutMs']);
  if (value.version !== 1 || !MODES.includes(value.mode)) throw new AppError(400, 'INVALID_CONFIGURATION');
  for (const key of ['resourceToken', 'clientToken', 'controlToken']) if (typeof value[key] !== 'string' || !tokenMatches(value[key], value[key])) throw new AppError(400, 'INVALID_CONFIGURATION');
  if (new Set([value.resourceToken, value.clientToken, value.controlToken]).size !== 3) throw new AppError(400, 'INVALID_CONFIGURATION');
  if (typeof value.publicKey !== 'string' || value.publicKey.length > 2_048) throw new AppError(400, 'INVALID_CONFIGURATION');
  const coverage = validateCoverage(verifyEnvelope(value.coverage, value.publicKey));
  return Object.freeze({ ...value, task: validateTask(value.task), resourceId: identifier(value.resourceId),
    resourceOrigin: loopbackOrigin(value.resourceOrigin), providerTimeoutMs: positiveInteger(value.providerTimeoutMs, 2_000), coverage });
}

function validateResult(value, action, resourceId) {
  exactObject(value, ['ok', 'resourceId', 'configurationVersion', 'actionId', 'kind', 'documentId', 'result'], ['recipient', 'content']);
  positiveInteger(value.configurationVersion);
  if (value.ok !== true || value.resourceId !== resourceId || value.actionId !== action.id || value.kind !== action.kind
      || value.documentId !== action.documentId || value.result !== (action.kind === 'read' ? 'read' : 'shared')
      || value.recipient !== action.recipient || (action.kind === 'read' ? typeof value.content !== 'string' || value.content.length > 4_096 : Object.hasOwn(value, 'content'))) throw new AppError(502, 'INVALID_DOWNSTREAM');
  return value;
}

export async function startBroker(configuration) {
  const config = validateBrokerConfig(configuration);
  let coverage = config.coverage;
  const admission = createAdmission(config.task, { actorId: config.task.actorId, tenantId: config.task.tenantId });
  const service = await listenLoopback(async (request, response, context) => {
    const url = new URL(request.url ?? '/', 'http://127.0.0.1');
    if (request.method === 'GET' && url.pathname === '/health/live' && !url.search) { sendJson(response, 200, { ok: true }, context); return; }
    if (request.method === 'GET' && url.pathname === '/health/ready' && !url.search) {
      try {
        const result = await requestJson(config.resourceOrigin, '/v1/status', { token: config.resourceToken,
          timeoutMs: config.providerTimeoutMs, validate: validateResourceState });
        const ready = result.status === 200 && result.body.resourceId === config.resourceId;
        sendJson(response, ready ? 200 : 503, { ok: ready }, context);
      } catch { sendJson(response, 503, { ok: false }, context); }
      return;
    }
    if (url.pathname.startsWith('/v1/control/') && !url.search) {
      requireBearer(request, config.controlToken);
      if (request.method === 'GET' && url.pathname === '/v1/control/state') {
        sendJson(response, 200, { mode: config.mode, admission: admission.snapshot(), coverage }, context); return;
      }
      if (request.method === 'POST' && url.pathname === '/v1/control/revoke') {
        exactObject(await readJson(request), []); admission.revoke(); sendJson(response, 200, { ok: true }, context); return;
      }
      if (request.method === 'POST' && url.pathname === '/v1/control/coverage') {
        const body = await readJson(request); exactObject(body, ['envelope']);
        const candidate = validateCoverage(verifyEnvelope(body.envelope, config.publicKey));
        if (candidate.taskId !== config.task.id || candidate.resourceId !== config.resourceId) throw new AppError(403, 'COVERAGE_SCOPE');
        coverage = candidate; sendJson(response, 200, { ok: true }, context); return;
      }
      throw new AppError(404, 'NOT_FOUND');
    }
    if (request.method !== 'POST' || url.pathname !== '/v1/actions' || url.search) throw new AppError(404, 'NOT_FOUND');
    requireBearer(request, config.clientToken);
    const action = validateAction(await readJson(request));
    let deadlineAt = Math.min(Date.now() + config.providerTimeoutMs, config.task.expiresAt);
    let expectedConfigurationVersion;
    if (config.mode !== 'broker-static') {
      const current = coverage;
      deadlineAt = Math.min(deadlineAt, current.expiresAt);
      if (config.mode === 'coverage-bound') {
        const status = await requestJson(config.resourceOrigin, '/v1/status', { token: config.resourceToken,
          timeoutMs: config.providerTimeoutMs, validate: validateResourceState });
        if (status.status !== 200) throw new AppError(503, 'DEPENDENCY_UNAVAILABLE');
        authorizeCoverage(current, { taskId: config.task.id, resourceId: status.body.resourceId, configurationVersion: status.body.configurationVersion });
        expectedConfigurationVersion = status.body.configurationVersion;
      } else {
        authorizeCoverage(current, { taskId: config.task.id, resourceId: config.resourceId, configurationVersion: current.configurationVersion });
      }
    }
    // Recheck revocation, task expiry and quota after the status await, immediately before dispatch.
    if (response.writableEnded || response.destroyed || Date.now() >= deadlineAt) throw new AppError(504, 'DISPATCH_DEADLINE');
    const reserved = admission.reserve(action);
    let upstream;
    try {
      upstream = await requestJson(config.resourceOrigin, '/v1/actions', { method: 'POST', token: config.resourceToken,
        timeoutMs: Math.max(1, deadlineAt - Date.now()), body: { actorId: config.task.actorId, tenantId: config.task.tenantId,
          action: reserved, deadlineAt, ...(expectedConfigurationVersion === undefined ? {} : { expectedConfigurationVersion }) } });
      if (upstream.status >= 500) throw new AppError(504, 'OUTCOME_UNCERTAIN');
      if (upstream.status !== 200) {
        exactObject(upstream.body, ['error']); exactObject(upstream.body.error, ['code', 'requestId']);
        identifier(upstream.body.error.code); identifier(upstream.body.error.requestId);
        throw new AppError(upstream.status, 'RESOURCE_REJECTED');
      }
      validateResult(upstream.body, reserved, config.resourceId);
    } catch (error) {
      if (error instanceof AppError && error.code === 'RESOURCE_REJECTED') throw error;
      throw new AppError(504, 'OUTCOME_UNCERTAIN');
    }
    sendJson(response, 200, upstream.body, context);
  });
  return service;
}
