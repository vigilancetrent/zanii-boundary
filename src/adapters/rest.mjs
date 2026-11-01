import { AppError, exactObject, identifier, positiveInteger } from '../protocol.mjs';
import { assertProductIdentity, validateProductAction, validateResourceMetadata } from '../product/policy.mjs';

/** Internal REST/document connector. Routing and credentials are trusted config.
 * @param {any} options */
export function createRestAdapter({ transport, credentialProvider, paths = {} } = {}) {
  if (!transport || typeof transport.request !== 'function' || typeof credentialProvider !== 'function') throw new AppError(400, 'INVALID_REST_ADAPTER');
  const routes = { metadata: '/v1/resource/metadata', status: '/v1/resource/status', execute: '/v1/resource/execute', observe: '/v1/resource/observe', ...paths };
  async function call(name, identity, payload, context = {}) {
    assertProductIdentity(identity);
    const token = await credentialProvider({ identity, ...context, scope: `resource:${name}` });
    if (typeof token !== 'string' || !token || /[\r\n]/.test(token)) throw new AppError(503, 'RESOURCE_CREDENTIAL_UNAVAILABLE');
    const response = await transport.request(routes[name], { method: name === 'status' ? 'GET' : 'POST',
      headers: { authorization: `Bearer ${token}` }, ...(name === 'status' ? {} : { body: payload }), deadlineAt: context.deadlineAt });
    if (response.status < 200 || response.status >= 300) throw new AppError(response.status >= 500 ? 503 : 403, 'RESOURCE_PROVIDER_DENIED');
    return response.body;
  }
  return Object.freeze({
    async metadata(identity, action) {
      const checked = validateProductAction(action);
      const result = await call('metadata', identity, { action: checked }, { action: checked });
      const valid = validateResourceMetadata(result);
      if (valid.documentId !== checked.documentId || valid.tenantId !== identity.tenantId) throw new AppError(502, 'RESOURCE_SCOPE_MISMATCH');
      return valid;
    },
    async status(identity) {
      const result = await call('status', identity, null);
      exactObject(result, ['resourceId', 'configurationVersion', 'toolVersion', 'healthy'], ['persistence', 'deliveryChannel', 'maxContentBytes']);
      identifier(result.resourceId); identifier(result.toolVersion); positiveInteger(result.configurationVersion);
      if (result.healthy !== true) throw new AppError(503, 'RESOURCE_UNHEALTHY');
      return result;
    },
    /** @param {any} identity @param {any} action @param {any} context */
    async execute(identity, action, { operationId, expectedVersion, deadlineAt, grant } = {}) {
      const checked = validateProductAction(action); identifier(operationId); positiveInteger(expectedVersion); positiveInteger(deadlineAt);
      const result = await call('execute', identity, { action: checked, operationId, expectedVersion, deadlineAt, ...(grant ? { grant } : {}) },
        { action: checked, operationId, expectedVersion, deadlineAt, grant });
      if (result?.resultExpired === true) validateExpired(result, operationId); else validateResult(result, checked);
      return result;
    },
    async observe(identity, operationId) {
      identifier(operationId);
      const result = await call('observe', identity, { operationId }, { operationId });
      exactObject(result, ['operationId', 'state'], ['result', 'resultExpired']);
      if (result.operationId !== operationId || !['succeeded', 'failed', 'unknown', 'absent'].includes(result.state)) throw new AppError(502, 'INVALID_RESOURCE_OUTCOME');
      if (result.resultExpired === true) validateExpired(result, operationId);
      else if (result.state === 'succeeded') validateResult(result.result);
      return result;
    },
  });
}

function validateExpired(result, operationId) {
  exactObject(result, ['operationId', 'state', 'resultExpired']);
  if (result.operationId !== operationId || result.state !== 'succeeded' || result.resultExpired !== true) throw new AppError(502, 'INVALID_RESOURCE_OUTCOME');
}

function validateResult(result, action) {
  if (result?.kind === 'read') {
    exactObject(result, ['kind', 'documentId', 'label', 'content']);
    if (!['public', 'internal', 'confidential', 'restricted'].includes(result.label) || typeof result.content !== 'string'
        || Buffer.byteLength(result.content) > 32768) throw new AppError(502, 'INVALID_RESOURCE_RESULT');
  } else if (result?.kind === 'share') {
    exactObject(result, ['kind', 'documentId', 'recipient', 'deliveryId', 'status', 'channel']);
    identifier(result.recipient); identifier(result.deliveryId);
    if (result.status !== 'committed' || result.channel !== 'internal-mailbox') throw new AppError(502, 'INVALID_RESOURCE_RESULT');
  } else throw new AppError(502, 'INVALID_RESOURCE_RESULT');
  identifier(result.documentId);
  if (action && (result.kind !== action.kind || result.documentId !== action.documentId
      || action.kind === 'share' && result.recipient !== action.recipient)) throw new AppError(502, 'RESOURCE_SCOPE_MISMATCH');
}
