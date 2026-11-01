import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createPrivateKey, createPublicKey } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { createBroker } from '@zanii/broker';
import { ZaniiAgent, fetchAndVerifyProof } from '@zanii/sdk';
import { didFromPublicKey, receiptHash, verifyReceipt } from '@zanii/core';
import { AppError, exactObject, identifier } from '../protocol.mjs';
import { assertProductIdentity } from '../product/policy.mjs';
import { createHttpsTransport } from './transport.mjs';

const unavailable = (code = 'ZANII_LEDGER_UNAVAILABLE') => new AppError(503, code);
function version(name) {
  try { return JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.resolve(name))), '..', 'package.json'), 'utf8')).version; } catch { return null; }
}
export async function zaniiCapabilities({ requireRuntime = false } = {}) {
  const runtimeVersion = version('@zanii/runtime'); let runtimeAvailable = false;
  if (runtimeVersion && (Number(runtimeVersion.split('.')[0]) > 0 || Number(runtimeVersion.split('.')[1]) >= 4)) {
    try { const name = '@zanii/runtime'; const runtime = await import(name); runtimeAvailable = typeof runtime.createRuntime === 'function' || typeof runtime.Runtime === 'function'; } catch { /* Missing optional package fails closed below. */ }
  }
  if (requireRuntime && !runtimeAvailable) throw unavailable('ZANII_RUNTIME_UNAVAILABLE');
  return { brokerVersion: version('@zanii/broker'), sdkVersion: version('@zanii/sdk'), coreVersion: version('@zanii/core'),
    runtimeVersion, runtimeAvailable, liveLedgerValidated: false };
}

/** Load only operator-owned secret files; never return their material.
 * @param {any} options */
export async function createConfiguredZaniiLedger({ store, config, baseDirectory = process.cwd() }) {
  exactObject(config, ['origin', 'caFile', 'certFile', 'keyFile', 'tenantId', 'agentDid', 'agentPrivateKeyFile', 'delegationFile', 'apiKeyFile', 'expectedLogDid'],
    ['requireRuntime', 'required', 'allowPrivateNetworks']);
  for (const name of ['requireRuntime', 'required', 'allowPrivateNetworks']) {
    if (config[name] !== undefined && typeof config[name] !== 'boolean') throw unavailable('ZANII_CONFIGURATION_REQUIRED');
  }
  await zaniiCapabilities({ requireRuntime: config.requireRuntime === true });
  async function file(name, secret = false) {
    const configured = config[name];
    if (typeof configured !== 'string' || !configured || configured.length > 4096) throw unavailable('ZANII_SECRET_FILE_INVALID');
    const path = resolve(baseDirectory, configured); const stat = await lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536 || secret && process.platform !== 'win32' && (stat.mode & 0o077)) throw unavailable('ZANII_SECRET_FILE_INVALID');
    const actual = await realpath(path); const handle = await open(actual, 'r');
    try {
      const opened = await handle.stat();
      if (!opened.isFile() || opened.size > 65536 || opened.dev !== stat.dev || opened.ino !== stat.ino
          || secret && process.platform !== 'win32' && (opened.mode & 0o077)) throw unavailable('ZANII_SECRET_FILE_INVALID');
      const bytes = Buffer.alloc(65537); const { bytesRead } = await handle.read(bytes);
      if (bytesRead > 65536) throw unavailable('ZANII_SECRET_FILE_INVALID');
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, bytesRead));
    } finally { await handle.close(); }
  }
  try {
    const [ca, cert, key, agentKey, delegationText, apiKeyText] = await Promise.all([
      file('caFile'), file('certFile'), file('keyFile', true), file('agentPrivateKeyFile', true), file('delegationFile'), file('apiKeyFile', true)]);
    const privateKey = /^[a-f\d]{64}$/i.test(agentKey.trim())
      ? createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(agentKey.trim(), 'hex')]), format: 'der', type: 'pkcs8' })
      : createPrivateKey(agentKey);
    if (privateKey.asymmetricKeyType !== 'ed25519') throw unavailable('ZANII_SIGNING_KEY_INVALID');
    const jwk = privateKey.export({ format: 'jwk' }); const pub = createPublicKey(privateKey).export({ format: 'jwk' });
    if (didFromPublicKey(Buffer.from(pub.x, 'base64url')) !== config.agentDid) throw unavailable('ZANII_SIGNING_KEY_INVALID');
    const apiKey = apiKeyText.trim();
    if (!apiKey || apiKey.length > 4096 || /[\r\n\0]/.test(apiKey)) throw unavailable('ZANII_CONFIGURATION_REQUIRED');
    const transport = createHttpsTransport({ origin: config.origin, tls: { ca, cert, key }, allowPrivateNetworks: config.allowPrivateNetworks === true,
      allowedMethods: ['GET', 'POST'], allowedPaths: ['/v1/head', '/v1/receipts', '/v1/proof'] });
    return createZaniiLedger({ store, transport, tenantId: config.tenantId, agentDid: config.agentDid,
      agentPrivateKey: Buffer.from(jwk.d, 'base64url'), delegation: JSON.parse(delegationText), apiKey, expectedLogDid: config.expectedLogDid });
  } catch (error) { throw error instanceof AppError ? error : unavailable('ZANII_CONFIGURATION_UNAVAILABLE'); }
}

/** Signed receipt outbox. Acceptance and trusted anchoring are separate states.
 * @param {any} options */
export function createZaniiLedger({ store, transport, agentDid, agentPrivateKey, signer, delegation,
  tenantId, apiKey, expectedLogDid, maxPending = 64 } = {}) {
  if (!store || !transport || !agentDid || !expectedLogDid || !apiKey || !Array.isArray(delegation) || !delegation.length) throw unavailable('ZANII_CONFIGURATION_REQUIRED');
  identifier(tenantId);
  if (!Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > 64) throw unavailable('ZANII_CONFIGURATION_REQUIRED');
  if (version('@zanii/sdk') !== '0.5.4') throw unavailable('ZANII_SDK_VERSION_UNSUPPORTED');
  let tail = Promise.resolve(); let pending = 0; let blocked = false; let closed = false;
  function bind(identity) {
    assertProductIdentity(identity);
    if (identity.tenantId !== tenantId) throw unavailable('ZANII_TENANT_MISMATCH');
  }
  function pendingRows(identity) {
    const values = []; let after = '';
    do { const page = store.list(identity.tenantId, 'outbox', { limit: 100, after });
      for (const row of page.items) if (row.value.agentDid === agentDid && row.value.state === 'pending') values.push(row);
      after = page.next;
      if (values.length > maxPending) throw unavailable('ZANII_OUTBOX_CAPACITY');
    } while (after);
    return values;
  }
  const single = (work) => {
    if (closed) return Promise.reject(unavailable('ZANII_LEDGER_CLOSED'));
    if (pending >= maxPending) return Promise.reject(unavailable('ZANII_BACKPRESSURE'));
    pending++;
    const run = tail.then(work); tail = run.catch(() => {});
    return run.finally(() => { pending--; });
  };
  const outboxId = (hash) => `receipt-${hash.replace(/^sha256:/, '')}`;
  function validateBatch(body, receipts) {
    exactObject(body, ['results']);
    if (!Array.isArray(body.results) || body.results.length !== receipts.length) throw unavailable('ZANII_INVALID_ACK');
    return body.results.map((result, index) => {
      exactObject(result, ['status', 'hash'], ['index']);
      if (!['accepted', 'duplicate'].includes(result.status) || result.hash !== receiptHash(receipts[index])
          || result.index !== undefined && (!Number.isSafeInteger(result.index) || result.index < 0)) throw unavailable('ZANII_INVALID_ACK');
      return result;
    });
  }
  async function sdkFetch(input, init = {}) {
    try {
      let receipts;
      if (new URL(input).pathname === '/v1/receipts') {
        const envelope = JSON.parse(String(init.body)); exactObject(envelope, ['receipts']); receipts = envelope.receipts;
        if (!Array.isArray(receipts) || !receipts.length || receipts.length > maxPending) throw unavailable('ZANII_RECEIPT_INVALID');
        for (const receipt of receipts) {
          const saved = store.get(tenantId, 'outbox', outboxId(receiptHash(receipt)));
          if (!verifyReceipt(receipt).ok || !saved || receiptHash(saved.receipt) !== receiptHash(receipt)
              || saved.agentDid !== agentDid || typeof saved.nonce !== 'string') throw unavailable('ZANII_RECEIPT_INVALID');
        }
      }
      const response = await transport.fetch(input, init);
      if (!response.ok) throw unavailable();
      const body = await response.json();
      if (new URL(input).pathname === '/v1/receipts') {
        validateBatch(body, receipts);
      } else if (new URL(input).pathname.startsWith('/v1/head/')) {
        exactObject(body, ['head']);
        if (body.head !== null && (typeof body.head !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(body.head))) throw unavailable('ZANII_INVALID_HEAD');
      }
      return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
    } catch (error) { throw error instanceof AppError ? error : unavailable(); }
  }
  const agent = new ZaniiAgent({ serverUrl: transport.origin, agentDid, ...(signer ? { signer } : { agentPrivateKey }),
    delegation, apiKey, flushMs: 2147483647, flushSize: maxPending + 1, maxQueue: maxPending, fetchImpl: sdkFetch });
  // SDK0.5.4 has no dispose port. Cancelling its implementation timer is the
  // version-specific lifecycle shim; durable recovery below owns all retries.
  if (!Object.hasOwn(agent, 'timer') || !Object.hasOwn(agent, 'queue') || !Object.hasOwn(agent, 'opts')
      || Reflect.get(agent, 'opts').flushMs !== 2147483647) throw unavailable('ZANII_SDK_LIFECYCLE_UNSUPPORTED');
  const stopTimer = () => { clearTimeout(Reflect.get(agent, 'timer')); Reflect.set(agent, 'timer', null); };
  async function proof(hash) {
    const result = await fetchAndVerifyProof(transport.origin, hash, sdkFetch);
    if (!result.ok || result.sth?.log_id !== expectedLogDid) throw unavailable('ZANII_TRUSTED_PROOF_REQUIRED');
    return { included: true, anchored: false, logId: expectedLogDid, size: result.sth.size };
  }
  return Object.freeze({
    record(identity, fields) {
      bind(identity);
      return single(async () => {
        if (blocked) throw unavailable('ZANII_RECOVERY_REQUIRED');
        let saved;
        try {
          // A restart must reconcile existing receipts before creating a new chain link.
          if (pendingRows(identity).length) throw unavailable('ZANII_RECOVERY_REQUIRED');
          const recorded = await agent.record(structuredClone(fields)); stopTimer();
          if (!recorded || !verifyReceipt(recorded.receipt).ok) throw unavailable('ZANII_RECEIPT_INVALID');
          saved = { agentDid, receipt: recorded.receipt, hash: recorded.hash, nonce: recorded.nonce, state: 'pending', createdAt: Date.now() };
          store.put(identity.tenantId, 'outbox', outboxId(recorded.hash), saved);
          const results = await agent.flush(); stopTimer(); validateBatch({ results }, [recorded.receipt]);
          store.put(identity.tenantId, 'outbox', outboxId(recorded.hash), { ...saved, state: 'accepted', acknowledgement: results[0] });
          return { hash: recorded.hash, accepted: true, anchored: false };
        } catch (error) {
          stopTimer(); if (saved || Reflect.get(agent, 'queue').length) blocked = true;
          throw error instanceof AppError ? error : unavailable();
        }
      });
    },
    recover(identity) {
      assertProductIdentity(identity, ['operator']); bind(identity);
      return single(async () => {
        const rows = pendingRows(identity);
        // Follow cryptographic prev links rather than lexicographic receipt hashes.
        const hashes = new Set(rows.map(({ value }) => value.hash));
        rows.sort((a, b) => a.value.createdAt - b.value.createdAt);
        const ordered = []; let previous;
        while (rows.length) {
          const index = rows.findIndex(({ value }) => previous ? value.receipt.prev === previous : !hashes.has(value.receipt.prev));
          if (index < 0) throw unavailable('ZANII_OUTBOX_CHAIN_INVALID');
          const [row] = rows.splice(index, 1); ordered.push(row); previous = row.value.hash;
        }
        const outcomes = [];
        for (const { id, value } of ordered) {
          const response = await sdkFetch(`${transport.origin}/v1/receipts`, { method: 'POST',
            headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' }, body: JSON.stringify({ receipts: [value.receipt] }) });
          const ack = (await response.json()).results[0];
          store.put(identity.tenantId, 'outbox', id, { ...value, state: 'accepted', acknowledgement: ack }); outcomes.push({ hash: value.hash, accepted: true });
        }
        // Existing SDK queue may contain this exact receipt. A duplicate flush
        // reconciles its in-memory chain without executing any business request.
        await agent.flush(); stopTimer(); blocked = false;
        return outcomes;
      });
    },
    verifyProof: proof,
    status: () => ({ configured: true, blocked, queuedWriters: pending, liveLedgerValidated: false, expectedLogDid }),
    close() { closed = true; stopTimer(); },
  });
}

/** Actual @zanii/broker wrapped to freeze requests and contain secret echoes.
 * @param {any} options */
export function createZaniiBroker({ credentials, transport, ledger, identity, gate = async () => true, validateResponse } = {}) {
  assertProductIdentity(identity);
  const specs = structuredClone(credentials);
  const secrets = Object.values(specs).map((spec) => {
    if (!['bearer', 'header'].includes(spec.inject) || typeof spec.secret !== 'string' || spec.secret.length < 8) throw unavailable('INVALID_BROKER_CREDENTIAL');
    return spec.secret;
  });
  const broker = createBroker({ credentials: specs, gate,
    record: (fields) => ledger.record(identity, fields), fetchImpl: transport.fetch,
    stripResponseHeaders: ['set-cookie', 'authorization', 'proxy-authorization', 'x-api-key'] });
  return Object.freeze({
    list: () => broker.list(),
    async execute(input) {
      exactObject(input, ['credential', 'method', 'url'], ['headers', 'body']); identifier(input.credential);
      if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(input.method) || typeof input.url !== 'string'
          || input.body !== undefined && typeof input.body !== 'string') throw new AppError(400, 'INVALID_BROKER_REQUEST');
      const request = structuredClone(input);
      if (request.headers) Object.freeze(request.headers);
      Object.freeze(request);
      try {
        const result = await broker.execute(request);
        if (secrets.some((secret) => result.body.includes(secret) || Object.values(result.headers).some((value) => value.includes(secret)))) throw unavailable('BROKER_SECRET_REFLECTION');
        if (validateResponse) validateResponse(result);
        return result;
      } catch (error) { throw error instanceof AppError ? error : unavailable('BROKER_EXECUTION_DENIED'); }
    },
  });
}
