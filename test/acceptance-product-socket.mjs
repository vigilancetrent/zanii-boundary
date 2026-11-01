import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:https';
import { readFileSync, mkdirSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { createProductClient } from '../src/product/client.mjs';

const pem = (name) => readFileSync(`artifacts/test-pki-${name}.pem`, 'utf8');

// Explicit Linux deployment gate; a Windows pipe cannot establish Linux UDS acceptance.
test('Node client verifies Linux UDS mTLS using the pinned gateway hostname', async (t) => {
  if (process.platform !== 'linux') throw new Error('SOCKET_ACCEPTANCE_REQUIRES_LINUX');
  mkdirSync(resolve('.test-data'), { recursive: true });
  const path = resolve('.test-data', `socket-${randomUUID()}.sock`);
  const server = createServer({ key: pem('gateway-key'), cert: pem('gateway-cert'), ca: pem('ca'), requestCert: true, rejectUnauthorized: true }, (req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"authenticated":true}');
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(path, resolve); });
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const client = createProductClient({ origin: 'https://gateway', socketPath: path, ca: pem('ca'), cert: pem('agent-cert'), key: pem('agent-key'), token: 'test.token.value' });
  assert.equal((await client.request('/health/live')).body.authenticated, true);
});
