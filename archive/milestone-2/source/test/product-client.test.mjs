import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { readFileSync } from 'node:fs';
import { createProductClient } from '../src/product/client.mjs';
import { Readable, Writable } from 'node:stream';
import { runAgent } from '../scripts/agent-runner.mjs';

const pem = (name) => readFileSync(`artifacts/test-pki-${name}.pem`, 'utf8');

test('Node product client uses real mTLS, rejects redirects and missing identity, and sends a mutation once', async (t) => {
  let effects = 0;
  const server = createServer({ key: pem('gateway-key'), cert: pem('gateway-cert'), ca: pem('ca'), requestCert: true, rejectUnauthorized: true }, async (req, res) => {
    if (req.url === '/redirect') { res.writeHead(302, { location: 'https://foreign.example' }); res.end(); return; }
    assert.equal(req.headers.authorization, 'Bearer test.token.value'); assert.equal(req.client.authorized, true);
    for await (const chunk of req) assert.ok(chunk.length < 65536);
    effects += 1; res.writeHead(202, { 'content-type': 'application/json' }); res.end('{"state":"unknown"}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const config = { origin: `https://127.0.0.1:${server.address().port}`, ca: pem('ca'), cert: pem('agent-cert'), key: pem('agent-key'), allowPrivateNetworks: true };
  const client = createProductClient({ ...config, token: 'test.token.value' });
  assert.equal((await client.execute('task', { id: 'op', kind: 'read', documentId: 'guide' })).body.state, 'unknown'); assert.equal(effects, 1);
  await assert.rejects(client.request('/redirect'), { code: 'TRANSPORT_REDIRECT_DENIED' });
  await assert.rejects(createProductClient(config).execute('task', {}), { code: 'CLIENT_TOKEN_REQUIRED' });
});

test('runner preserves the operation ID and uncertain outcome after a real mTLS commit then connection drop', async (t) => {
  const effects = [];
  const server = createServer({ key: pem('gateway-key'), cert: pem('gateway-cert'), ca: pem('ca'), requestCert: true, rejectUnauthorized: true }, async (req, res) => {
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    effects.push(JSON.parse(Buffer.concat(chunks).toString('utf8')).action.id);
    res.destroy();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const client = createProductClient({ origin: `https://127.0.0.1:${server.address().port}`, ca: pem('ca'), cert: pem('agent-cert'), key: pem('agent-key'), allowPrivateNetworks: true, token: 'test.token.value' });
  const lines = [];
  await runAgent({ client, input: Readable.from(['{"taskId":"task","action":{"id":"invalid"}}\n{"taskId":"task","action":{"id":"stable-op","kind":"read","documentId":"guide"}}\n']),
    output: new Writable({ write(bytes, encoding, done) { lines.push(JSON.parse(bytes.toString())); done(); } }) });
  assert.deepEqual(effects, ['stable-op']);
  assert.equal(lines[0].status, 400);
  assert.deepEqual(lines[1], { status: 202, body: { code: 'AGENT_OUTCOME_UNKNOWN', operationId: 'stable-op', state: 'unknown', retryAutomatically: false } });
});

