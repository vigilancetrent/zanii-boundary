import { randomUUID } from 'node:crypto';
import { AppError, exactObject, identifier, positiveInteger, tokenMatches, validateAction } from './protocol.mjs';
import { listenLoopback, readJson, requireBearer, sendJson } from './http.mjs';

export const DOCUMENTS = Object.freeze({
  'tenant-a-guide': Object.freeze({ tenantId: 'tenant-a', content: 'Synthetic approved support guide.' }),
  'tenant-a-secret': Object.freeze({ tenantId: 'tenant-a', content: 'Synthetic restricted project document.' }),
  'tenant-b-secret': Object.freeze({ tenantId: 'tenant-b', content: 'Synthetic second tenant document.' }),
});

function credential(value) {
  if (typeof value !== 'string' || !tokenMatches(value, value)) throw new AppError(400, 'INVALID_CONFIGURATION');
  return value;
}

export function validateResourceConfig(value) {
  exactObject(value, ['version', 'resourceId', 'brokerToken', 'controlToken', 'observerToken', 'legacyToken', 'maxEvents']);
  if (value.version !== 1) throw new AppError(400, 'INVALID_CONFIGURATION');
  for (const key of ['brokerToken', 'controlToken', 'observerToken', 'legacyToken']) credential(value[key]);
  if (new Set([value.brokerToken, value.controlToken, value.observerToken, value.legacyToken]).size !== 4) throw new AppError(400, 'INVALID_CONFIGURATION');
  return Object.freeze({ ...value, resourceId: identifier(value.resourceId), maxEvents: positiveInteger(value.maxEvents, 20_000) });
}

export function validateResourceState(value) {
  exactObject(value, ['resourceId', 'configurationVersion', 'toolVersion', 'brokerOnly', 'legacyEnabled', 'delayMs', 'responseDelayMs', 'changedAt']);
  identifier(value.resourceId); positiveInteger(value.configurationVersion); positiveInteger(value.toolVersion);
  positiveInteger(value.changedAt);
  for (const key of ['brokerOnly', 'legacyEnabled']) if (typeof value[key] !== 'boolean') throw new AppError(400, 'INVALID_INPUT');
  for (const key of ['delayMs', 'responseDelayMs']) if (!Number.isSafeInteger(value[key]) || value[key] < 0 || value[key] > 3_000) throw new AppError(400, 'INVALID_INPUT');
  return Object.freeze({ ...value });
}

/** Validate independently observed provider effects before they become research evidence. */
export function validateResourceEvent(value) {
  exactObject(value, ['id', 'actionId', 'kind', 'documentId', 'actorId', 'tenantId', 'via', 'configurationVersion', 'at', 'result'], ['recipient']);
  identifier(value.id); identifier(value.actorId); identifier(value.tenantId);
  validateAction({ id: value.actionId, kind: value.kind, documentId: value.documentId,
    ...(Object.hasOwn(value, 'recipient') ? { recipient: value.recipient } : {}) });
  positiveInteger(value.configurationVersion); positiveInteger(value.at);
  if (!['broker', 'legacy'].includes(value.via) || value.result !== (value.kind === 'read' ? 'read' : 'shared')) throw new AppError(502, 'INVALID_OBSERVATION');
  return Object.freeze({ ...value });
}

export async function startResource(configuration) {
  const config = validateResourceConfig(configuration);
  let state = validateResourceState({ resourceId: config.resourceId, configurationVersion: 1, toolVersion: 1,
    brokerOnly: true, legacyEnabled: false, delayMs: 0, responseDelayMs: 0, changedAt: Date.now() });
  const events = [];
  const completed = new Set();
  const service = await listenLoopback(async (request, response, context) => {
    const url = new URL(request.url ?? '/', 'http://127.0.0.1');
    if (request.method === 'GET' && ['/health/live', '/health/ready'].includes(url.pathname) && !url.search) {
      sendJson(response, 200, { ok: true }, context); return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/status' && !url.search) {
      requireBearer(request, config.brokerToken); sendJson(response, 200, state, context); return;
    }
    if (request.method === 'GET' && url.pathname === '/v1/observations') {
      requireBearer(request, config.observerToken);
      if ([...url.searchParams.keys()].some((key) => !['after', 'limit'].includes(key))
          || [...url.searchParams.keys()].some((key) => url.searchParams.getAll(key).length !== 1)) throw new AppError(400, 'INVALID_INPUT');
      const afterText = url.searchParams.get('after') ?? '0';
      const limitText = url.searchParams.get('limit') ?? '32';
      if (!/^\d{1,6}$/.test(afterText) || !/^\d{1,2}$/.test(limitText)) throw new AppError(400, 'INVALID_INPUT');
      const after = Number(afterText); const limit = positiveInteger(Number(limitText), 32);
      if (after > events.length) throw new AppError(400, 'INVALID_INPUT');
      sendJson(response, 200, { resourceId: config.resourceId, configurationVersion: state.configurationVersion,
        events: events.slice(after, after + limit), total: events.length }, context); return;
    }
    if (request.method === 'POST' && url.pathname === '/v1/control' && !url.search) {
      requireBearer(request, config.controlToken);
      const patch = await readJson(request);
      exactObject(patch, [], ['brokerOnly', 'legacyEnabled', 'toolVersion', 'delayMs', 'responseDelayMs']);
      if (Object.keys(patch).length === 0) throw new AppError(400, 'INVALID_INPUT');
      state = validateResourceState({ ...state, ...patch, configurationVersion: state.configurationVersion + 1, changedAt: Date.now() });
      sendJson(response, 200, state, context); return;
    }
    if (request.method !== 'POST' || url.pathname !== '/v1/actions' || url.search) throw new AppError(404, 'NOT_FOUND');
    const header = request.headers.authorization;
    const token = typeof header === 'string' && header.startsWith('Bearer ') ? header.slice(7) : '';
    const broker = tokenMatches(token, config.brokerToken);
    const legacy = tokenMatches(token, config.legacyToken);
    if (!broker && !legacy) throw new AppError(401, 'AUTHENTICATION_REQUIRED');
    if (legacy && (state.brokerOnly || !state.legacyEnabled)) throw new AppError(403, 'DIRECT_DENIED');
    const body = await readJson(request);
    exactObject(body, ['actorId', 'tenantId', 'action'], ['expectedConfigurationVersion', 'deadlineAt']);
    identifier(body.actorId); identifier(body.tenantId);
    const action = validateAction(body.action);
    if (body.expectedConfigurationVersion !== undefined) positiveInteger(body.expectedConfigurationVersion);
    if (body.deadlineAt !== undefined) positiveInteger(body.deadlineAt);
    if (state.delayMs) await new Promise((resolve) => setTimeout(resolve, state.delayMs));
    if (body.deadlineAt !== undefined && Date.now() >= body.deadlineAt) throw new AppError(408, 'DISPATCH_DEADLINE');
    if (body.expectedConfigurationVersion !== undefined && body.expectedConfigurationVersion !== state.configurationVersion) throw new AppError(409, 'CONFIGURATION_CHANGED');
    if (legacy && (state.brokerOnly || !state.legacyEnabled)) throw new AppError(403, 'DIRECT_DENIED');
    // A legacy key's subject is fixed by the resource, never by caller-supplied claims.
    const actorId = legacy ? 'agent-a' : body.actorId;
    const tenantId = legacy ? 'tenant-a' : body.tenantId;
    const document = DOCUMENTS[action.documentId];
    if (!document || document.tenantId !== tenantId) throw new AppError(403, 'TENANT_DENIED');
    if (action.kind === 'share' && action.recipient !== 'internal-team') throw new AppError(403, 'DESTINATION_DENIED');
    if (completed.has(action.id)) throw new AppError(409, 'REPLAY');
    if (events.length >= config.maxEvents) throw new AppError(429, 'RESOURCE_QUOTA');
    completed.add(action.id);
    const event = Object.freeze({ id: randomUUID(), actionId: action.id, kind: action.kind, documentId: action.documentId,
      ...(action.recipient ? { recipient: action.recipient } : {}), actorId, tenantId,
      via: broker ? 'broker' : 'legacy', configurationVersion: state.configurationVersion, at: Date.now(), result: action.kind === 'read' ? 'read' : 'shared' });
    events.push(event);
    // Delaying a response after committing an effect deliberately models an uncertain outcome.
    if (state.responseDelayMs) await new Promise((resolve) => setTimeout(resolve, state.responseDelayMs));
    sendJson(response, 200, { ok: true, resourceId: config.resourceId, configurationVersion: event.configurationVersion,
      actionId: action.id, kind: action.kind, documentId: action.documentId, result: event.result,
      ...(action.recipient ? { recipient: action.recipient } : {}), ...(action.kind === 'read' ? { content: document.content } : {}) }, context);
  });
  return service;
}
