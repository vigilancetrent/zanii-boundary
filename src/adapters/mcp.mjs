import { asAsyncStore } from '../product/async-store.mjs';
import { randomUUID } from 'node:crypto';
import { AppError, exactObject, identifier } from '../protocol.mjs';
import { assertProductIdentity, validateProductAction } from '../product/policy.mjs';

export const MCP_VERSION = '2025-11-25';
const idSchema = { type: 'string', minLength: 1, maxLength: 128, pattern: '^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$' };
const properties = { taskId: idSchema, id: idSchema, documentId: idSchema, approvalId: idSchema, toolVersion: idSchema,
  sourceRefs: { type: 'array', maxItems: 64, uniqueItems: true, items: idSchema } };
const tools = ['read', 'share'].map((kind) => ({ name: `document_${kind}`, description: `${kind === 'read' ? 'Read' : 'Share'} a document under an existing task grant.`,
  inputSchema: { type: 'object', additionalProperties: false, required: ['taskId', 'id', 'documentId', ...(kind === 'share' ? ['recipient'] : [])],
    properties: { ...properties, ...(kind === 'share' ? { recipient: idSchema } : {}) } } }));
const header = (headers, name) => Object.entries(headers ?? {}).find(([key]) => key.toLowerCase() === name)?.[1];
const rpc = (id, result) => ({ jsonrpc: '2.0', id, result });
const failure = (id, code, message, status = 400) => ({ status, body: { jsonrpc: '2.0', id: id ?? null, error: { code, message } } });

/** Streamable HTTP JSON response mode: https://modelcontextprotocol.io/specification/2025-11-25/basic/transports */
export function createMcpAdapter({ execute, allowedOrigins = [], now = Date.now, maxSessions = 1000, store } ) {
  if (typeof execute !== 'function' || !Array.isArray(allowedOrigins) || allowedOrigins.some((v) => new URL(v).origin !== v)
      || !Number.isSafeInteger(maxSessions) || maxSessions < 1 || maxSessions > 10000) throw new AppError(400, 'INVALID_MCP_CONFIGURATION');
  const persistent = store ? asAsyncStore(store) : null;
  const sessions = new Map();
  async function loadSession(identity, id) {
    if (typeof id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/.test(id)) return null;
    const session = persistent ? await persistent.get(identity.tenantId, 'protocol-sessions', id) : sessions.get(id);
    return session && session.protocolVersion === MCP_VERSION && session.expiresAt > now() ? session : null;
  }
  async function initialize(identity) {
    const save = async () => {
      let count = 0; let after;
      if (persistent) {
        do {
          const page = await persistent.list(identity.tenantId, 'protocol-sessions', { limit: 100, ...(after ? { after } : {}) });
          count += page.items.filter(({ value }) => value.protocolVersion === MCP_VERSION && value.expiresAt > now()).length;
          if (count >= maxSessions) return null;
          after = page.next;
        } while (after);
      } else if (sessions.size >= maxSessions) return null;
      const id = randomUUID();
      const session = { tenantId: identity.tenantId, actorId: identity.actorId, protocolVersion: MCP_VERSION, initialized: false,
        expiresAt: Math.min(identity.expiresAt ?? now() + 900000, now() + 900000) };
      if (persistent) await persistent.put(identity.tenantId, 'protocol-sessions', id, session, { expiresAt: session.expiresAt });
      else sessions.set(id, session);
      return id;
    };
    return persistent ? persistent.transaction(save, { tenantId: identity.tenantId }) : save();
  }
  async function markInitialized(identity, id) {
    const save = async () => {
      const value = await loadSession(identity, id);
      if (!value || value.actorId !== identity.actorId || value.tenantId !== identity.tenantId) return false;
      if (persistent) await persistent.put(identity.tenantId, 'protocol-sessions', id, { ...value, initialized: true }, { expiresAt: value.expiresAt });
      else value.initialized = true;
      return true;
    };
    return persistent ? persistent.transaction(save, { tenantId: identity.tenantId }) : save();
  }
  return Object.freeze({
    version: MCP_VERSION,
    async handle({ method, headers = {}, body }, identity) {
      assertProductIdentity(identity);
      const origin = header(headers, 'origin');
      if (origin !== undefined && (typeof origin !== 'string' || !allowedOrigins.includes(origin))) return { status: 403, body: { error: 'ORIGIN_DENIED' } };
      if (method !== 'POST') return { status: 405, headers: { Allow: 'POST' } };
      const accept = header(headers, 'accept');
      if (typeof accept !== 'string' || !accept.includes('application/json') || !accept.includes('text/event-stream')) return { status: 406, body: { error: 'ACCEPT_REQUIRED' } };
      const contentType = header(headers, 'content-type');
      if (typeof contentType !== 'string' || contentType.split(';')[0].trim() !== 'application/json') return { status: 415, body: { error: 'JSON_REQUIRED' } };
      let requestId = null;
      try {
        if (Buffer.byteLength(JSON.stringify(body) ?? '') > 65536) throw new Error('bound');
        exactObject(body, ['jsonrpc', 'method'], ['id', 'params']);
        if (body.jsonrpc !== '2.0' || typeof body.method !== 'string' || body.method.length > 128
            || (body.id !== undefined && typeof body.id !== 'string' && !Number.isSafeInteger(body.id))) throw new Error('rpc');
        requestId = body.id ?? null;
      } catch { return failure(requestId, -32600, 'Invalid Request'); }
      for (const [id, session] of sessions) if (session.expiresAt <= now()) sessions.delete(id);
      const sessionId = header(headers, 'mcp-session-id');
      const session = await loadSession(identity, sessionId);
      if (body.method === 'initialize') {
        if (body.id === undefined) return failure(null, -32600, 'Initialize requires an id');
        try {
          exactObject(body.params, ['protocolVersion', 'capabilities', 'clientInfo']);
          exactObject(body.params.clientInfo, ['name', 'version'], ['title', 'description', 'websiteUrl', 'icons']);
          if (body.params.protocolVersion !== MCP_VERSION || typeof body.params.clientInfo.name !== 'string'
              || typeof body.params.clientInfo.version !== 'string' || !body.params.capabilities || typeof body.params.capabilities !== 'object'
              || Array.isArray(body.params.capabilities)) throw new Error('initialize');
        } catch { return failure(body.id, -32602, 'Unsupported protocol version or invalid initialization'); }
        const id = await initialize(identity);
        if (!id) return { status: 429, body: { error: 'SESSION_CAPACITY' } };
        return { status: 200, headers: { 'Mcp-Session-Id': id }, body: rpc(body.id, { protocolVersion: MCP_VERSION,
          capabilities: { tools: { listChanged: false } }, serverInfo: { name: 'agent-runtime', version: '1.0.0' } }) };
      }
      if (header(headers, 'mcp-protocol-version') !== MCP_VERSION) return failure(body.id, -32600, 'MCP-Protocol-Version required');
      if (!sessionId) return failure(body.id, -32600, 'Mcp-Session-Id required');
      if (!session || session.tenantId !== identity.tenantId || session.actorId !== identity.actorId) return { status: 404, body: { error: 'SESSION_NOT_FOUND' } };
      if (body.method === 'notifications/initialized') {
        try { if (body.id !== undefined) throw new Error('notification id'); if (body.params !== undefined) exactObject(body.params, []); }
        catch { return failure(body.id, -32600, 'Invalid notification'); }
        if (!await markInitialized(identity, sessionId)) return { status: 404, body: { error: 'SESSION_NOT_FOUND' } };
        return { status: 202 };
      }
      if (!session.initialized) return failure(body.id, -32000, 'Initialization incomplete');
      if (body.id === undefined) return { status: 202 };
      if (body.method === 'ping') {
        try { if (body.params !== undefined) exactObject(body.params, []); } catch { return failure(body.id, -32602, 'Invalid params'); }
        return { status: 200, body: rpc(body.id, {}) };
      }
      if (body.method === 'tools/list') {
        try { if (body.params !== undefined) exactObject(body.params, []); } catch { return failure(body.id, -32602, 'Invalid params'); }
        return { status: 200, body: rpc(body.id, { tools: structuredClone(tools) }) };
      }
      if (body.method !== 'tools/call') return failure(body.id, -32601, 'Method not found');
      let taskId; let action;
      try {
        exactObject(body.params, ['name', 'arguments']);
        const kind = { document_read: 'read', document_share: 'share' }[body.params.name];
        if (!kind) throw new Error('tool');
        exactObject(body.params.arguments, ['taskId', 'id', 'documentId'], ['recipient', 'approvalId', 'toolVersion', 'sourceRefs']);
        const { taskId: task, ...args } = body.params.arguments; taskId = identifier(task);
        action = validateProductAction({ ...args, kind });
      } catch { return failure(body.id, -32602, 'Invalid tool arguments'); }
      try {
        const result = await execute(identity, { taskId, action });
        if (!result || Buffer.byteLength(JSON.stringify(result)) > 60000) throw new AppError(502, 'EXECUTOR_RESULT_INVALID');
        return { status: 200, body: rpc(body.id, { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result, isError: false }) };
      } catch (error) {
        return { status: 200, body: rpc(body.id, { content: [{ type: 'text', text: error instanceof AppError ? error.code : 'EXECUTION_FAILED' }], isError: true }) };
      }
    },
  });
}
