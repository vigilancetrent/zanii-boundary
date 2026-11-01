import { randomUUID } from 'node:crypto';
import { AppError, exactObject, identifier, positiveInteger } from '../protocol.mjs';
import { assertProductIdentity, validateProductAction } from '../product/policy.mjs';

export const A2A_VERSION = '0.3.0';
const failed = (id, code, message) => ({ status: 200, body: { jsonrpc: '2.0', id: id ?? null, error: { code, message } } });
const response = (id, result) => ({ status: 200, body: { jsonrpc: '2.0', id, result } });
const terminal = new Set(['completed', 'failed', 'canceled', 'rejected']);
function state(result) {
  const status = result.state ?? result.status;
  if (['succeeded', 'committed', 'completed'].includes(status) && result.status !== 202) return 'completed';
  if (['failed', 'rejected'].includes(status)) return 'failed';
  if (status === 'canceled') return 'canceled';
  return 'working';
}
/** Archived contract: https://a2a-protocol.org/v0.3.0/specification/ (JSON-RPC transport). */
export function createA2aAdapter({ store, execute, cancel, readOperation, publicUrl, now = Date.now, retentionMs = 86400000 }) {
  positiveInteger(retentionMs, 365 * 86400000);
  const url = new URL(publicUrl);
  if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search || typeof execute !== 'function'
      || typeof store?.get !== 'function' || typeof store?.put !== 'function') throw new AppError(400, 'INVALID_A2A_CONFIGURATION');
  const view = (task) => ({ id: task.id, contextId: task.contextId, kind: 'task', status: task.status,
    ...(task.artifacts ? { artifacts: task.artifacts } : {}) });
  const save = (identity, task) => { store.put(identity.tenantId, 'a2a', task.id, task, { expiresAt: task.expiresAt }); return task; };
  const apply = (task, result) => {
    if (!result || !['string', 'number'].includes(typeof result.status) || Buffer.byteLength(JSON.stringify(result)) > 60000) throw new AppError(502, 'INVALID_OPERATION_RESULT');
    return { ...task, operationId: result.operationId ?? result.id ?? task.operationId ?? null,
      status: { state: state(result), timestamp: new Date(now()).toISOString() },
      artifacts: [{ artifactId: 'operation-result', parts: [{ kind: 'data', data: result }] }] };
  };
  return Object.freeze({
    version: A2A_VERSION,
    agentCard: () => ({ protocolVersion: A2A_VERSION, name: 'Company agent runtime', description: 'Task constrained document execution',
      url: url.toString(), preferredTransport: 'JSONRPC', version: '1.0.0', capabilities: { streaming: false, pushNotifications: false },
      defaultInputModes: ['application/json'], defaultOutputModes: ['application/json'],
      securitySchemes: { bearer: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } }, security: [{ bearer: [] }],
      skills: [{ id: 'document-actions', name: 'Document actions', description: 'Execute structured read and share actions under existing grants', tags: ['documents', 'authorization'] }] }),
    async handle({ method, body }, identity) {
      assertProductIdentity(identity);
      if (method !== 'POST') return { status: 405, headers: { Allow: 'POST' } };
      try {
        if (Buffer.byteLength(JSON.stringify(body) ?? '') > 65536) throw new Error('bound');
        exactObject(body, ['jsonrpc', 'id', 'method', 'params']);
        if (body.jsonrpc !== '2.0' || (typeof body.id !== 'string' && !Number.isSafeInteger(body.id)) || typeof body.method !== 'string') throw new Error('rpc');
      } catch { return failed(null, -32600, 'Invalid Request'); }
      if (!['message/send', 'tasks/get', 'tasks/cancel'].includes(body.method)) return failed(body.id, -32601, 'Method not found');
      let task;
      try {
        if (body.method === 'message/send') {
          exactObject(body.params, ['message'], ['configuration', 'metadata']);
          if (body.params.configuration !== undefined) {
            exactObject(body.params.configuration, [], ['acceptedOutputModes', 'blocking', 'historyLength']);
            if (body.params.configuration.historyLength !== undefined && body.params.configuration.historyLength !== 0) throw new Error('history unsupported');
            if (body.params.configuration.blocking !== undefined && typeof body.params.configuration.blocking !== 'boolean') throw new Error('blocking');
            const modes = body.params.configuration.acceptedOutputModes;
            if (modes !== undefined && (!Array.isArray(modes) || modes.length > 8 || !modes.includes('application/json')
                || modes.some((mode) => typeof mode !== 'string' || mode.length > 128))) throw new Error('output modes');
          }
          if (body.params.metadata !== undefined) throw new Error('metadata unsupported');
          const msg = body.params.message;
          exactObject(msg, ['kind', 'role', 'messageId', 'parts'], ['contextId']);
          identifier(msg.messageId);
          if (msg.kind !== 'message' || msg.role !== 'user' || !Array.isArray(msg.parts) || msg.parts.length !== 1) throw new Error('message');
          const part = msg.parts[0]; exactObject(part, ['kind', 'data']);
          if (part.kind !== 'data') throw new Error('data only');
          exactObject(part.data, ['taskId', 'action']);
          const taskId = identifier(part.data.taskId); const action = validateProductAction(part.data.action);
          const id = randomUUID();
          task = save(identity, { id, contextId: msg.contextId === undefined ? randomUUID() : identifier(msg.contextId),
            ownerId: identity.actorId, taskId, operationId: action.id, expiresAt: now() + Math.min(86400000, retentionMs),
            status: { state: 'submitted', timestamp: new Date(now()).toISOString() } });
          try { task = save(identity, apply(task, await execute(identity, { taskId, action }))); }
          catch (error) {
            task = save(identity, { ...task, status: { state: error instanceof AppError && error.status < 500 ? 'rejected' : 'working', timestamp: new Date(now()).toISOString() } });
          }
          return response(body.id, view(task));
        }
        exactObject(body.params, ['id'], body.method === 'tasks/get' ? ['historyLength'] : []);
        if (body.params.historyLength !== undefined && body.params.historyLength !== 0) throw new Error('history unsupported');
        task = store.get(identity.tenantId, 'a2a', identifier(body.params.id));
      } catch { return failed(body.id, -32602, 'Invalid params'); }
      if (!task || task.ownerId !== identity.actorId) return failed(body.id, -32001, 'Task not found');
      if (body.method === 'tasks/get') {
        // Persisted artifacts are data, not continuing authority to release content.
        if (task.operationId && (!terminal.has(task.status.state) || task.artifacts)) {
          if (typeof readOperation !== 'function') return failed(body.id, -32603, 'Operation lookup unavailable');
          try {
            const result = await readOperation(identity, task.operationId);
            if (result) task = save(identity, apply(task, result));
          } catch { return failed(body.id, -32603, 'Operation lookup unavailable'); }
        }
        return response(body.id, view(task));
      }
      if (terminal.has(task.status.state) || !task.operationId || typeof cancel !== 'function') return failed(body.id, -32002, 'Task cannot be canceled');
      let result;
      try { result = await cancel(identity, task.operationId); }
      catch (error) { return failed(body.id, error instanceof AppError && error.status === 409 ? -32002 : -32603, 'Cancellation unavailable'); }
      // The executor must prove cancellation before dispatch. Never relabel committed or unknown work.
      if (!result || (result.status !== 'canceled' && result.canceled !== true) || result.dispatched !== false) return failed(body.id, -32002, 'Task cannot be canceled');
      task = save(identity, { ...task, status: { state: 'canceled', timestamp: new Date(now()).toISOString() } });
      return response(body.id, view(task));
    },
  });
}
