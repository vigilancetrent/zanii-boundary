import { createServer } from 'node:https';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { createHash, createPrivateKey, randomBytes, X509Certificate } from 'node:crypto';
import { generateKeypair, createCert, certHash, jcsHash, verifyReceipt, receiptHash } from '@zanii/core';
import { AppError, signEnvelope } from '../src/protocol.mjs';
import { readJson, sendJson, sendError } from '../src/http.mjs';
import { RUNTIME_PREFLIGHT_TOOL, RUNTIME_REVOCATION_PURPOSE } from '../src/adapters/zanii-runtime.mjs';

/** Actual local TLS receipt acceptance and signed authority for tests/measurements, never a live company ledger.
 * @param {any} options */
export async function startLocalRuntimeLedgerFixture({ directory, pkiDirectory = resolve('artifacts'), tenantId = 'company', authorityLifetimeMs = 300000, scopes = ['broker.resource.post', RUNTIME_PREFLIGHT_TOOL] }) {
  if (!Number.isSafeInteger(authorityLifetimeMs) || authorityLifetimeMs < 1000 || authorityLifetimeMs > 900000) throw new AppError(400, 'INVALID_FIXTURE_AUTHORITY_LIFETIME');
  const pem = (name) => readFile(resolve(pkiDirectory, `test-pki-${name}.pem`), 'utf8');
  const owner = generateKeypair(); const agent = generateKeypair(); const log = generateKeypair(); const apiKey = randomBytes(32).toString('hex');
  const ownerKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), owner.privateKey]), format: 'der', type: 'pkcs8' });
  const delegation = [createCert({ issuer: owner.did, subject: agent.did, scopes, exp: new Date(Date.now() + authorityLifetimeMs).toISOString() }, owner.privateKey)];
  const file = (name) => join(directory, `runtime-fixture-${name}`); let revision = 0; let revoked = []; let closed = false; let outage = false; let afterReceipt;
  const writeSnapshot = async ({ issuedAt = Date.now(), expiresAt = Math.min(Date.parse(delegation[0].exp), issuedAt + authorityLifetimeMs) } = {}) => {
    revision++; const value = { version: 1, type: 'zanii-boundary.runtime-revocations', tenantId, agentDid: agent.did, ownerDid: owner.did,
      delegationDigest: jcsHash(delegation), revision, issuedAt, expiresAt, revoked };
    await writeFile(file('revocations.json'), JSON.stringify(signEnvelope(value, ownerKey, RUNTIME_REVOCATION_PURPOSE)), { mode: 0o600 }); return value;
  };
  await writeFile(file('agent.hex'), Buffer.from(agent.privateKey).toString('hex'), { mode: 0o600 });
  await writeFile(file('delegation.json'), JSON.stringify(delegation), { mode: 0o600 }); await writeFile(file('api.token'), apiKey, { mode: 0o600 }); await writeSnapshot();
  const ca = await pem('ca'); const client = new X509Certificate(await pem('broker-cert')); const fingerprint = createHash('sha256').update(client.raw).digest('hex');
  let head = null; let acceptedReceipts = 0; let duplicateReceipts = 0; let runtimeIntentReceipts = 0; let runtimeResultReceipts = 0; const received = []; const hashes = new Set();
  const server = createServer({ ca, cert: await pem('resource-cert'), key: await pem('resource-key'), minVersion: 'TLSv1.3', requestCert: true, rejectUnauthorized: true }, (req, res) => {
    Promise.resolve().then(async () => {
      const socket = /** @type {import('node:tls').TLSSocket} */ (req.socket); const peer = socket.getPeerCertificate();
      if (closed || !socket.authorized || !peer.raw || createHash('sha256').update(peer.raw).digest('hex') !== fingerprint) throw new AppError(403, 'FIXTURE_LEDGER_AUTHENTICATION_REQUIRED');
      if (outage) throw new AppError(503, 'FIXTURE_LEDGER_OUTAGE');
      if (req.method === 'GET' && req.url.startsWith('/v1/head/')) {
        if (decodeURIComponent(req.url.slice('/v1/head/'.length)) !== agent.did) throw new AppError(404, 'FIXTURE_AGENT_UNKNOWN'); return sendJson(res, 200, { head });
      }
      if (req.method !== 'POST' || req.url !== '/v1/receipts') throw new AppError(404, 'FIXTURE_ROUTE_NOT_FOUND');
      if (req.headers.authorization !== `Bearer ${apiKey}`) throw new AppError(403, 'FIXTURE_LEDGER_AUTHENTICATION_REQUIRED');
      const body = await readJson(req, { maxBytes: 65536, timeoutMs: 3000 });
      if (!Array.isArray(body.receipts) || !body.receipts.length || body.receipts.length > 64) throw new AppError(400, 'FIXTURE_RECEIPT_BATCH_INVALID');
      const results = [];
      for (const receipt of body.receipts) {
        if (!verifyReceipt(receipt).ok || receipt.agent_id !== agent.did) throw new AppError(403, 'FIXTURE_RECEIPT_INVALID'); const hash = receiptHash(receipt);
        if (hashes.has(hash)) { duplicateReceipts++; results.push({ status: 'duplicate', hash }); continue; }
        if (receipt.prev !== head) throw new AppError(409, 'FIXTURE_HEAD_CONFLICT');
        head = hash; hashes.add(hash); acceptedReceipts++;
        if (receipt.target === RUNTIME_PREFLIGHT_TOOL) { if (receipt.action === 'action_intent') runtimeIntentReceipts++; if (receipt.action === 'action_result') runtimeResultReceipts++; }
        received.push(structuredClone(receipt)); if (received.length > 256) hashes.delete(receiptHash(received.shift()));
        results.push({ status: 'accepted', hash });
      }
      await afterReceipt?.(structuredClone(body.receipts)); sendJson(res, 200, { results });
    }).catch((error) => sendError(res, error));
  });
  server.maxConnections = 128; server.maxHeadersCount = 32; server.requestTimeout = 3000; server.headersTimeout = 3000; server.timeout = 3000; server.on('timeout', (socket) => socket.destroy());
  await new Promise((done, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', () => { server.off('error', reject); done(); }); });
  const port = /** @type {import('node:net').AddressInfo} */ (server.address()).port;
  return { config: { origin: `https://127.0.0.1:${port}`, caFile: resolve(pkiDirectory, 'test-pki-ca.pem'), certFile: resolve(pkiDirectory, 'test-pki-broker-cert.pem'), keyFile: resolve(pkiDirectory, 'test-pki-broker-key.pem'),
      tenantId, agentDid: agent.did, agentPrivateKeyFile: file('agent.hex'), delegationFile: file('delegation.json'), apiKeyFile: file('api.token'), expectedLogDid: log.did,
      allowPrivateNetworks: true, required: true, requireRuntime: true, runtime: { version: 1, mode: 'authorization-preflight-v1', ownerDid: owner.did, revocationSnapshotFile: file('revocations.json'), maxSnapshotAgeMs: authorityLifetimeMs, timeoutMs: 3000, maxConcurrency: 32 } },
    status: () => ({ mode: 'local-controlled-ledger', acceptedReceipts, duplicateReceipts, runtimeIntentReceipts, runtimeResultReceipts, capturedReceipts: received.length, liveCompanyValidated: false }),
    records: () => structuredClone(received), setOutage(value) { outage = Boolean(value); }, afterReceipt(work) { afterReceipt = work; },
    async revokeDelegation() { revoked = [certHash(delegation[0])]; return writeSnapshot(); },
    refreshSnapshot: writeSnapshot,
    async close() { if (closed) return; closed = true; await new Promise((done) => { const timer = setTimeout(() => { server.closeAllConnections(); done(); }, 4000); timer.unref(); server.close(() => { clearTimeout(timer); done(); }); server.closeIdleConnections(); }); },
  };
}
