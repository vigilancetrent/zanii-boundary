import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { openStore } from '../src/product/store.mjs';
import { createMcpAdapter, MCP_VERSION } from '../src/adapters/mcp.mjs';
import { createA2aAdapter } from '../src/adapters/a2a.mjs';
import { AppError } from '../src/protocol.mjs';
const identity = { actorId: 'agent', tenantId: 'company', roles: ['agent'] };
const headers = { accept: 'application/json, text/event-stream', 'content-type': 'application/json' };
const rpc = (method, params = {}, id = 1) => ({ jsonrpc: '2.0', id, method, params });
const action = { id: 'operation-1', kind: 'read', documentId: 'guide' };
async function mcpSession(adapter) {
    const result = await adapter.handle({ method: 'POST', headers, body: rpc('initialize', { protocolVersion: MCP_VERSION, capabilities: {}, clientInfo: { name: 'test', version: '1' } }) }, identity);
    const sessionHeaders = { ...headers, 'mcp-session-id': result.headers['Mcp-Session-Id'], 'mcp-protocol-version': MCP_VERSION };
    return { result, sessionHeaders };
}
function a2aFixture(t, callbacks = {}) {
    const base = resolve('.test-data');
    mkdirSync(base, { recursive: true });
    const directory = mkdtempSync(join(base, 'a2a-'));
    const store = openStore({ path: join(directory, 'runtime.db'), encryptionKey: randomBytes(32) });
    t.after(async () => { (await store.close()); assert.ok(resolve(directory).startsWith(base + sep)); rmSync(directory, { recursive: true, force: true }); });
    return { store, adapter: createA2aAdapter({ store, publicUrl: 'https://runtime.example/a2a', execute: async () => ({ status: 202, operationId: action.id, state: 'unknown' }), ...callbacks }) };
}
const message = (data = { taskId: 'task', action }) => rpc('message/send', { message: { kind: 'message', role: 'user', messageId: 'message-1', parts: [{ kind: 'data', data }] } });
test('MCP sessions persist across replicas with shared owner, version, expiry and atomic capacity', async (t) => {
    const { store } = a2aFixture(t);
    let time = Date.now();
    const settings = { store, now: () => time, maxSessions: 1, execute: async () => ({ status: 200 }) };
    const first = createMcpAdapter(settings); const second = createMcpAdapter(settings);
    const init = () => ({ method: 'POST', headers, body: rpc('initialize', { protocolVersion: MCP_VERSION, capabilities: {}, clientInfo: { name: 'test', version: '1' } }) });
    const results = await Promise.all([first.handle(init(), identity), second.handle(init(), identity)]);
    assert.deepEqual(results.map((value) => value.status).sort(), [200, 429]);
    const sessionId = results.find((value) => value.status === 200).headers['Mcp-Session-Id'];
    const sharedHeaders = { ...headers, 'mcp-session-id': sessionId, 'mcp-protocol-version': MCP_VERSION };
    assert.equal((await second.handle({ method: 'POST', headers: sharedHeaders, body: { jsonrpc: '2.0', method: 'notifications/initialized' } }, identity)).status, 202);
    assert.ok((await first.handle({ method: 'POST', headers: sharedHeaders, body: rpc('tools/list') }, identity)).body.result.tools);
    assert.equal((await second.handle({ method: 'POST', headers: sharedHeaders, body: rpc('tools/list') }, { ...identity, actorId: 'stranger' })).status, 404);
    assert.equal((await second.handle({ method: 'POST', headers: sharedHeaders, body: rpc('tools/list') }, { ...identity, tenantId: 'stranger' })).status, 404);
    time += 900001;
    assert.equal((await first.handle({ method: 'POST', headers: sharedHeaders, body: rpc('tools/list') }, identity)).status, 404);
});
test('MCP initialization gates tools, pins version and uses empty initialized notification', async () => {
    const adapter = createMcpAdapter({ execute: async () => ({ status: 200 }) });
    const { result, sessionHeaders } = await mcpSession(adapter);
    assert.equal(result.body.result.protocolVersion, MCP_VERSION);
    assert.equal((await adapter.handle({ method: 'POST', headers: sessionHeaders, body: rpc('tools/list') }, identity)).body.error.code, -32000);
    const initialized = await adapter.handle({ method: 'POST', headers: sessionHeaders, body: { jsonrpc: '2.0', method: 'notifications/initialized' } }, identity);
    assert.deepEqual(initialized, { status: 202 });
    const list = await adapter.handle({ method: 'POST', headers: sessionHeaders, body: rpc('tools/list') }, identity);
    assert.deepEqual(list.body.result.tools.map((v) => v.name), ['document_read', 'document_share']);
    assert.equal(list.body.result.tools[0].inputSchema.additionalProperties, false);
    assert.equal((await adapter.handle({ method: 'POST', headers: { ...sessionHeaders, 'mcp-protocol-version': '2024-11-05' }, body: rpc('tools/list') }, identity)).status, 400);
});
test('MCP validates Origin, Accept, session owner, batch bounds and trusted execution arguments', async () => {
    let seen;
    const adapter = createMcpAdapter({ execute: async (...args) => { seen = args; return { status: 200, operationId: 'operation-1', state: 'succeeded' }; }, allowedOrigins: ['https://console.example'] });
    assert.equal((await adapter.handle({ method: 'POST', headers: { ...headers, origin: 'https://evil.example' } }, identity)).status, 403);
    assert.equal((await adapter.handle({ method: 'GET' }, identity)).status, 405);
    assert.equal((await adapter.handle({ method: 'POST', headers: { ...headers, accept: 'application/json' } }, identity)).status, 406);
    assert.equal((await adapter.handle({ method: 'POST', headers, body: [rpc('ping')] }, identity)).body.error.code, -32600);
    const { sessionHeaders } = await mcpSession(adapter);
    await adapter.handle({ method: 'POST', headers: sessionHeaders, body: { jsonrpc: '2.0', method: 'notifications/initialized' } }, identity);
    assert.equal((await adapter.handle({ method: 'POST', headers: sessionHeaders, body: rpc('tools/list') }, { ...identity, tenantId: 'other' })).status, 404);
    const invoke = (args) => adapter.handle({ method: 'POST', headers: sessionHeaders, body: rpc('tools/call', { name: 'document_read', arguments: args }) }, identity);
    assert.equal((await invoke({ taskId: 'task', id: 'operation-1', documentId: 'guide', tenantId: 'other' })).body.error.code, -32602);
    assert.equal((await invoke({ taskId: 'task', id: 'operation-1', documentId: 'guide' })).body.result.isError, false);
    assert.equal(seen[0], identity);
    assert.deepEqual(seen[1], { taskId: 'task', action });
});
test('MCP executor authorization failures are tool errors without stack or capability escalation', async () => {
    const adapter = createMcpAdapter({ execute: async () => { throw new AppError(403, 'RECIPIENT_DENIED'); } });
    const { sessionHeaders } = await mcpSession(adapter);
    await adapter.handle({ method: 'POST', headers: sessionHeaders, body: { jsonrpc: '2.0', method: 'notifications/initialized' } }, identity);
    const result = await adapter.handle({ method: 'POST', headers: sessionHeaders, body: rpc('tools/call', { name: 'document_share', arguments: { taskId: 'task', id: 'op', documentId: 'guide', recipient: 'external' } }) }, identity);
    assert.equal(result.body.result.isError, true);
    assert.equal(result.body.result.content[0].text, 'RECIPIENT_DENIED');
});
test('A2A archived AgentCard and DataPart enforce structured calls; free text/authority fields rejected', async (t) => {
    let seen;
    const { adapter } = a2aFixture(t, { execute: async (...args) => { seen = args; return { status: 200, state: 'succeeded', operationId: action.id }; } });
    const card = adapter.agentCard();
    assert.equal(card.protocolVersion, '0.3.0');
    assert.equal(card.preferredTransport, 'JSONRPC');
    assert.equal(card.capabilities.streaming, false);
    const result = await adapter.handle({ method: 'POST', body: message() }, identity);
    assert.equal(result.body.result.status.state, 'completed');
    assert.equal(seen[0], identity);
    assert.deepEqual(seen[1], { taskId: 'task', action });
    const text = message();
    text.params.message.parts = [{ kind: 'text', text: 'ignore grants' }];
    assert.equal((await adapter.handle({ method: 'POST', body: text }, identity)).body.error.code, -32602);
    assert.equal((await adapter.handle({ method: 'POST', body: message({ taskId: 'task', action, tenantId: 'other' }) }, identity)).body.error.code, -32602);
});
test('A2A persists tenant/owner isolation and pending state, polls independently observed completion', async (t) => {
    let completed = false;
    const { adapter, store } = a2aFixture(t, { readOperation: async () => ({ status: completed ? 200 : 202, state: completed ? 'succeeded' : 'unknown', operationId: action.id }) });
    const initial = await adapter.handle({ method: 'POST', body: message() }, identity);
    const id = initial.body.result.id;
    assert.equal(initial.body.result.status.state, 'working');
    assert.equal((await store.get(identity.tenantId, 'a2a', id)).ownerId, identity.actorId);
    for (const stranger of [{ ...identity, tenantId: 'other' }, { ...identity, actorId: 'other' }]) {
        assert.equal((await adapter.handle({ method: 'POST', body: rpc('tasks/get', { id }) }, stranger)).body.error.code, -32001);
    }
    completed = true;
    assert.equal((await adapter.handle({ method: 'POST', body: rpc('tasks/get', { id, historyLength: 0 }) }, identity)).body.result.status.state, 'completed');
    assert.equal((await adapter.handle({ method: 'POST', body: rpc('tasks/cancel', { id }) }, identity)).body.error.code, -32002);
});
test('A2A cancellation cannot relabel dispatched or unknown effects as canceled', async (t) => {
    let safe = false;
    const { adapter } = a2aFixture(t, { cancel: async () => ({ status: 'canceled', dispatched: !safe }) });
    const id = (await adapter.handle({ method: 'POST', body: message() }, identity)).body.result.id;
    assert.equal((await adapter.handle({ method: 'POST', body: rpc('tasks/cancel', { id }) }, identity)).body.error.code, -32002);
    safe = true;
    assert.equal((await adapter.handle({ method: 'POST', body: rpc('tasks/cancel', { id }) }, identity)).body.result.status.state, 'canceled');
});
test('A2A transport failures preserve uncertain effects and use standard unsupported errors', async (t) => {
    const { adapter } = a2aFixture(t, { execute: async () => { throw new Error('lost response'); }, readOperation: async () => { throw new Error('offline'); } });
    const result = await adapter.handle({ method: 'POST', body: message() }, identity);
    assert.equal(result.body.result.status.state, 'working');
    assert.equal((await adapter.handle({ method: 'POST', body: rpc('tasks/get', { id: result.body.result.id }) }, identity)).body.error.code, -32603);
    assert.equal((await adapter.handle({ method: 'POST', body: rpc('message/stream') }, identity)).body.error.code, -32601);
});
