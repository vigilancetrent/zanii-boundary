import { AsyncLocalStorage } from 'node:async_hooks';
import { storeHash } from '../product/storage-crypto.mjs';
import { requestContext,effectiveDeadline } from '../product/context.mjs';
import { asAsyncStore } from '../product/async-store.mjs';
import { fileURLToPath } from 'node:url';
import { readFileSync } from 'node:fs';
import { lstat, open, realpath } from 'node:fs/promises';
import { createPrivateKey, createPublicKey, randomUUID } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { createBroker } from '@zanii/broker';
import { ZaniiAgent, fetchAndVerifyProof } from '@zanii/sdk';
import { didFromPublicKey, receiptHash, verifyReceipt } from '@zanii/core';
import { AppError, exactObject, identifier } from '../protocol.mjs';
import { assertProductIdentity } from '../product/policy.mjs';
import { createHttpsTransport } from './transport.mjs';
import { createRuntimePreflight, runtimePreflightSchema, readRuntimeAuthorityFile } from './zanii-runtime.mjs';
const unavailable = (code = 'ZANII_LEDGER_UNAVAILABLE') => new AppError(503, code);
function version(name) {
    try {
        return JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.resolve(name))), '..', 'package.json'), 'utf8')).version;
    }
    catch {
        return null;
    }
}
export async function zaniiCapabilities({ requireRuntime = false } = {}) {
    const runtimeVersion = version('@zanii/runtime');
    let runtimeAvailable = false;
    if (runtimeVersion && (Number(runtimeVersion.split('.')[0]) > 0 || Number(runtimeVersion.split('.')[1]) >= 4)) {
        try {
            const name = '@zanii/runtime';
            const runtime = await import(name);
            runtimeAvailable = typeof runtime.createRuntime === 'function' || typeof runtime.Runtime === 'function';
        }
        catch { /* Missing optional package fails closed below. */ }
    }
    if (requireRuntime && !runtimeAvailable)
        throw unavailable('ZANII_RUNTIME_UNAVAILABLE');
    return { brokerVersion: version('@zanii/broker'), sdkVersion: version('@zanii/sdk'), coreVersion: version('@zanii/core'),
        runtimeVersion, runtimeAvailable, liveLedgerValidated: false };
}
/** Load only operator-owned secret files; never return their material.
 * @param {any} options */
export async function createConfiguredZaniiLedger({ store, config, baseDirectory = process.cwd() }) {
    exactObject(config, ['origin', 'caFile', 'certFile', 'keyFile', 'tenantId', 'agentDid', 'agentPrivateKeyFile', 'delegationFile', 'apiKeyFile', 'expectedLogDid'], ['requireRuntime', 'required', 'allowPrivateNetworks', 'runtime']);
    for (const name of ['requireRuntime', 'required', 'allowPrivateNetworks']) {
        if (config[name] !== undefined && typeof config[name] !== 'boolean')
            throw unavailable('ZANII_CONFIGURATION_REQUIRED');
    }
    await zaniiCapabilities({ requireRuntime: config.requireRuntime === true || Boolean(config.runtime) });
    if (config.requireRuntime && !config.runtime || config.runtime && (config.required === false || version('@zanii/runtime') !== '0.4.0')) throw unavailable('ZANII_RUNTIME_CONFIGURATION_REQUIRED');
    const runtimeConfig = Object.hasOwn(config, 'runtime') ? runtimePreflightSchema.parse(config.runtime) : undefined;
    async function file(name, secret = false, override = undefined) {
        const configured = override ?? config[name];
        if (typeof configured !== 'string' || !configured || configured.length > 4096)
            throw unavailable('ZANII_SECRET_FILE_INVALID');
        const path = resolve(baseDirectory, configured);
        const stat = await lstat(path);
        if (!stat.isFile() || stat.isSymbolicLink() || stat.size > 65536 || secret && process.platform !== 'win32' && (stat.mode & 0o077))
            throw unavailable('ZANII_SECRET_FILE_INVALID');
        const actual = await realpath(path);
        const handle = await open(actual, 'r');
        try {
            const opened = await handle.stat();
            if (!opened.isFile() || opened.size > 65536 || opened.dev !== stat.dev || opened.ino !== stat.ino
                || secret && process.platform !== 'win32' && (opened.mode & 0o077))
                throw unavailable('ZANII_SECRET_FILE_INVALID');
            const bytes = Buffer.alloc(65537);
            const { bytesRead } = await handle.read(bytes);
            if (bytesRead > 65536)
                throw unavailable('ZANII_SECRET_FILE_INVALID');
            return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, bytesRead));
        }
        finally {
            await handle.close();
        }
    }
    try {
        const [ca, cert, key, agentKey, delegationText, apiKeyText] = await Promise.all([
            file('caFile'), file('certFile'), file('keyFile', true), file('agentPrivateKeyFile', true), file('delegationFile'), file('apiKeyFile', true)
        ]);
        const privateKey = /^[a-f\d]{64}$/i.test(agentKey.trim())
            ? createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(agentKey.trim(), 'hex')]), format: 'der', type: 'pkcs8' })
            : createPrivateKey(agentKey);
        if (privateKey.asymmetricKeyType !== 'ed25519')
            throw unavailable('ZANII_SIGNING_KEY_INVALID');
        const jwk = privateKey.export({ format: 'jwk' });
        const pub = createPublicKey(privateKey).export({ format: 'jwk' });
        if (didFromPublicKey(Buffer.from(pub.x, 'base64url')) !== config.agentDid)
            throw unavailable('ZANII_SIGNING_KEY_INVALID');
        const apiKey = apiKeyText.trim();
        if (!apiKey || apiKey.length > 4096 || /[\r\n\0]/.test(apiKey))
            throw unavailable('ZANII_CONFIGURATION_REQUIRED');
        const transport = createHttpsTransport({ origin: config.origin, tls: { ca, cert, key }, allowPrivateNetworks: config.allowPrivateNetworks === true,
            dependencyName: 'zanii', allowedMethods: ['GET', 'POST'], allowedPaths: ['/v1/head', '/v1/receipts', '/v1/proof'] });
        const ledger = createZaniiLedger({ store, transport, tenantId: config.tenantId, agentDid: config.agentDid,
            agentPrivateKey: Buffer.from(jwk.d, 'base64url'), delegation: JSON.parse(delegationText), apiKey, expectedLogDid: config.expectedLogDid });
        if (!runtimeConfig) return ledger;
        try {
            const runtimePreflight = createRuntimePreflight({ store, ledger, config: runtimeConfig, tenantId: config.tenantId, agentDid: config.agentDid,
                loadAuthority: async () => ({ delegation: JSON.parse(await file('delegationFile')), revocations: JSON.parse(await file('runtimeRevocations', false, runtimeConfig.revocationSnapshotFile)) }),
                loadAuthoritySync: () => ({ delegation: JSON.parse(readRuntimeAuthorityFile(resolve(baseDirectory, config.delegationFile))), revocations: JSON.parse(readRuntimeAuthorityFile(resolve(baseDirectory, runtimeConfig.revocationSnapshotFile))) }) });
            await runtimePreflight.initialize();
            return Object.freeze({ ...ledger, runtimePreflight, async status() { return { ...await ledger.status(), runtime: runtimePreflight.status() }; },
                async close() { try { await runtimePreflight.close(); } finally { await ledger.close(); } } });
        } catch (error) { await ledger.close(); throw error; }
    }
    catch (error) {
        throw error instanceof AppError ? error : unavailable('ZANII_CONFIGURATION_UNAVAILABLE');
    }
}
/** Signed receipt outbox. Acceptance and trusted anchoring are separate states.
 * @param {any} options */
export function createZaniiLedger({ store, transport, agentDid, agentPrivateKey, signer, delegation, tenantId, apiKey, expectedLogDid, maxPending = 64, writerLeaseMs = 60000, acceptedHistoryRetentionMs = 2592000000 } = {}) {
    store = asAsyncStore(store);
    if (!store || !transport || !agentDid || !expectedLogDid || !apiKey || !Array.isArray(delegation) || !delegation.length)
        throw unavailable('ZANII_CONFIGURATION_REQUIRED');
    identifier(tenantId);
    if (!Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > 64)
        throw unavailable('ZANII_CONFIGURATION_REQUIRED');
    if (version('@zanii/sdk') !== '0.5.4')
        throw unavailable('ZANII_SDK_VERSION_UNSUPPORTED');
    if (!Number.isSafeInteger(writerLeaseMs) || writerLeaseMs < 100 || writerLeaseMs > 300000) throw unavailable('ZANII_CONFIGURATION_REQUIRED');
    const writerContext = new AsyncLocalStorage();
    const writerOwner = randomUUID();
    let tail = Promise.resolve();
    let pending = 0;
    let blocked = false;
    let closed = false;
    function bind(identity) {
        assertProductIdentity(identity);
        if (identity.tenantId !== tenantId)
            throw unavailable('ZANII_TENANT_MISMATCH');
    }
    if (!Number.isSafeInteger(acceptedHistoryRetentionMs) || acceptedHistoryRetentionMs < 60000 || acceptedHistoryRetentionMs > 31536000000) throw unavailable('ZANII_CONFIGURATION_REQUIRED');
    const pendingHeadId = `zanii-pending-${storeHash(agentDid)}`;
    async function pendingRows(identity) {
        const result = await store.transaction(async () => {
            let head = await store.get(tenantId, 'metadata', pendingHeadId);
            if (!head) head = { version: 1, agentDid, ids: [], after: '', ready: false };
            if (head.version !== 1 || head.agentDid !== agentDid || !Array.isArray(head.ids) || head.ids.length > maxPending || new Set(head.ids).size !== head.ids.length) throw unavailable('ZANII_PENDING_INDEX_INVALID');
            if (!head.ready) {
                const page = await store.list(identity.tenantId, 'outbox', { limit: 100, after: head.after });
                for (const row of page.items) if (row.value.agentDid === agentDid && row.value.state === 'pending' && !head.ids.includes(row.id)) head.ids.push(row.id);
                if (head.ids.length > maxPending) throw unavailable('ZANII_OUTBOX_CAPACITY');
                head = { ...head, after: page.next ?? '', ready: !page.next };
                await store.put(tenantId, 'metadata', pendingHeadId, head);
            }
            if (!head.ready) return { rebuilding: true, rows: [] };
            const rows = [];
            for (const id of head.ids) {
                const value = await store.get(tenantId, 'outbox', id);
                if (!value || value.agentDid !== agentDid || value.state !== 'pending' || !value.receipt || receiptHash(value.receipt) !== value.hash || !verifyReceipt(value.receipt).ok) throw unavailable('ZANII_PENDING_INDEX_INVALID');
                rows.push({ id, value });
            }
            return { rebuilding: false, rows };
        }, { tenantId });
        if (result.rebuilding) throw unavailable('ZANII_PENDING_INDEX_REBUILD_REQUIRED');
        return result.rows;
    }
    async function withWriterLease(work) {
        if (closed) throw unavailable('ZANII_LEDGER_CLOSED');
        const inherited = requestContext.getStore();
        const deadlineAt = Math.min(inherited?.deadlineAt ?? Infinity, Date.now() + writerLeaseMs);
        const lease = await store.claimLease(tenantId, `receipt:${agentDid}`, { ownerId: writerOwner, ttlMs: Math.max(1, deadlineAt - Date.now()) });
        if (!lease) throw unavailable('ZANII_WRITER_BUSY');
        try {
            return await requestContext.run({ ...inherited, deadlineAt: Math.min(deadlineAt, lease.expiresAt) },
                () => writerContext.run(lease, work));
        } finally { await store.releaseLease(lease); }
    }
    const single = (work) => {
        if (closed)
            return Promise.reject(unavailable('ZANII_LEDGER_CLOSED'));
        if (pending >= maxPending)
            return Promise.reject(unavailable('ZANII_BACKPRESSURE'));
        pending++;
        const run = tail.then(() => withWriterLease(work));
        tail = run.catch(() => { });
        return run.finally(() => { pending--; });
    };
    const outboxId = (hash) => `receipt-${hash.replace(/^sha256:/, '')}`;
    async function saveReceipt(id, value) {
        return store.transaction(async () => {
            await store.assertLease(writerContext.getStore());
            const head = await store.get(tenantId, 'metadata', pendingHeadId);
            if (!head?.ready || head.agentDid !== agentDid || !Array.isArray(head.ids)) throw unavailable('ZANII_PENDING_INDEX_INVALID');
            const ids = head.ids.filter((item) => item !== id);
            if (value.state === 'pending') ids.push(id);
            if (ids.length > maxPending) throw unavailable('ZANII_OUTBOX_CAPACITY');
            await store.put(tenantId, 'outbox', id, value, value.state === 'accepted' ? { expiresAt: Date.now() + acceptedHistoryRetentionMs } : {});
            await store.put(tenantId, 'metadata', pendingHeadId, { ...head, ids });
        }, { tenantId });
    }
    function validateBatch(body, receipts) {
        exactObject(body, ['results']);
        if (!Array.isArray(body.results) || body.results.length !== receipts.length)
            throw unavailable('ZANII_INVALID_ACK');
        return body.results.map((result, index) => {
            exactObject(result, ['status', 'hash'], ['index']);
            if (!['accepted', 'duplicate'].includes(result.status) || result.hash !== receiptHash(receipts[index])
                || result.index !== undefined && (!Number.isSafeInteger(result.index) || result.index < 0))
                throw unavailable('ZANII_INVALID_ACK');
            return result;
        });
    }
    async function sdkFetch(input, init = {}) {
        try {
            const lease = writerContext.getStore();
            if (lease) await store.assertLease(lease);
            let receipts;
            if (new URL(input).pathname === '/v1/receipts') {
                const envelope = JSON.parse(String(init.body));
                exactObject(envelope, ['receipts']);
                receipts = envelope.receipts;
                if (!Array.isArray(receipts) || !receipts.length || receipts.length > maxPending)
                    throw unavailable('ZANII_RECEIPT_INVALID');
                for (const receipt of receipts) {
                    const saved = (await store.get(tenantId, 'outbox', outboxId(receiptHash(receipt))));
                    if (!verifyReceipt(receipt).ok || !saved || receiptHash(saved.receipt) !== receiptHash(receipt)
                        || saved.agentDid !== agentDid || typeof saved.nonce !== 'string')
                        throw unavailable('ZANII_RECEIPT_INVALID');
                }
            }
            if (lease) await store.assertLease(lease);
            const response = await transport.fetch(input, init);
            if (!response.ok)
                throw unavailable();
            const body = await response.json();
            if (new URL(input).pathname === '/v1/receipts') {
                validateBatch(body, receipts);
            }
            else if (new URL(input).pathname.startsWith('/v1/head/')) {
                exactObject(body, ['head']);
                if (body.head !== null && (typeof body.head !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(body.head)))
                    throw unavailable('ZANII_INVALID_HEAD');
            }
            return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
        }
        catch (error) {
            throw error instanceof AppError ? error : unavailable();
        }
    }
    const boundedSigner = signer && { publicKey: Buffer.from(signer.publicKey), async sign(message) {
        const deadlineAt = requestContext.getStore()?.deadlineAt ?? Date.now() + writerLeaseMs;
        const remaining = deadlineAt - Date.now();
        if (remaining <= 0) throw new AppError(504, 'ZANII_SIGNER_DEADLINE');
        let timer;
        try {
            return await Promise.race([Promise.resolve().then(() => signer.sign(message)),
                new Promise((_, reject) => { timer = setTimeout(() => reject(new AppError(504, 'ZANII_SIGNER_DEADLINE')), remaining); })]);
        } catch (error) { throw error instanceof AppError ? error : unavailable('ZANII_SIGNER_UNAVAILABLE'); }
        finally { clearTimeout(timer); }
    } };
    const agentOptions = { serverUrl: transport.origin, agentDid, ...(boundedSigner ? { signer: boundedSigner } : { agentPrivateKey }),
        delegation, apiKey, flushMs: 2147483647, flushSize: maxPending + 1, maxQueue: maxPending, fetchImpl: sdkFetch };
    function freshAgent() {
        const value = new ZaniiAgent(agentOptions);
        if (!Object.hasOwn(value, 'timer') || !Object.hasOwn(value, 'queue') || !Object.hasOwn(value, 'opts')
            || Reflect.get(value, 'opts').flushMs !== 2147483647) throw unavailable('ZANII_SDK_LIFECYCLE_UNSUPPORTED');
        return value;
    }
    let agent = freshAgent();
    // SDK 0.5.4 has no dispose port; only the pinned timer lifecycle requires reflection.
    const stopTimer = () => { clearTimeout(Reflect.get(agent, 'timer')); Reflect.set(agent, 'timer', null); };
    async function proof(hash) {
        const result = await fetchAndVerifyProof(transport.origin, hash, sdkFetch);
        if (!result.ok || result.sth?.log_id !== expectedLogDid)
            throw unavailable('ZANII_TRUSTED_PROOF_REQUIRED');
        return { included: true, anchored: false, logId: expectedLogDid, size: result.sth.size };
    }
    const durableStatus=async()=>{
            try {
                const rows = await pendingRows({ tenantId });
                return { configured: true, blocked: blocked || rows.length > 0, pendingReceipts: rows.length,
                    queuedWriters: pending, liveLedgerValidated: false, expectedLogDid };
            } catch (error) {
                return { configured: true, blocked: true, queuedWriters: pending, liveLedgerValidated: false,
                    reason: error instanceof AppError ? error.code : 'ZANII_STORE_UNAVAILABLE', expectedLogDid };
            }
    };
    return Object.freeze({
        record(identity, fields) {
            bind(identity);
            return single(async () => {
                let saved;
                try {
                    // A restart must reconcile existing receipts before creating a new chain link.
                    if ((await pendingRows(identity)).length)
                        throw unavailable('ZANII_RECOVERY_REQUIRED');
                    // No durable pending receipt exists. Discard unsaved/acknowledged SDK memory, never upload it.
                    stopTimer(); agent = freshAgent(); blocked = false;
                    const recorded = await agent.record(structuredClone(fields));
                    stopTimer();
                    if (!recorded || !verifyReceipt(recorded.receipt).ok)
                        throw unavailable('ZANII_RECEIPT_INVALID');
                    saved = { agentDid, receipt: recorded.receipt, hash: recorded.hash, nonce: recorded.nonce, state: 'pending', createdAt: Date.now() };
                    await saveReceipt(outboxId(recorded.hash), saved);
                    const results = await agent.flush();
                    stopTimer();
                    validateBatch({ results }, [recorded.receipt]);
                    await saveReceipt(outboxId(recorded.hash), { ...saved, state: 'accepted', acknowledgement: results[0] });
                    return { hash: recorded.hash, accepted: true, anchored: false, delivery: { hash: results[0].hash, status: results[0].status } };
                }
                catch (error) {
                    stopTimer();
                    if (saved || Reflect.get(agent, 'queue').length)
                        blocked = true;
                    throw error instanceof AppError ? error : unavailable();
                }
            });
        },
        recover(identity) {
            assertProductIdentity(identity, ['operator']);
            bind(identity);
            return single(async () => {
                const rows = (await pendingRows(identity));
                // Follow cryptographic prev links rather than lexicographic receipt hashes.
                const hashes = new Set(rows.map(({ value }) => value.hash));
                rows.sort((a, b) => a.value.createdAt - b.value.createdAt);
                const ordered = [];
                let previous;
                while (rows.length) {
                    const index = rows.findIndex(({ value }) => previous ? value.receipt.prev === previous : !hashes.has(value.receipt.prev));
                    if (index < 0)
                        throw unavailable('ZANII_OUTBOX_CHAIN_INVALID');
                    const [row] = rows.splice(index, 1);
                    ordered.push(row);
                    previous = row.value.hash;
                }
                const outcomes = [];
                for (const { id, value } of ordered) {
                    const response = await sdkFetch(`${transport.origin}/v1/receipts`, { method: 'POST',
                        headers: { authorization: `Bearer ${apiKey}`, 'content-type': 'application/json' }, body: JSON.stringify({ receipts: [value.receipt] }) });
                    const ack = (await response.json()).results[0];
                    await saveReceipt(id, { ...value, state: 'accepted', acknowledgement: ack });
                    outcomes.push({ hash: value.hash, accepted: true });
                }
                // Recovery sends only the durable outbox. Old SDK memory cannot authorize another upload.
                stopTimer(); agent = freshAgent(); blocked = false;
                return outcomes;
            });
        },
        verifyProof: proof,
        status: durableStatus,
        authorizationStatus({deadlineAt=undefined}={}) {
            if(closed)return Promise.reject(unavailable('ZANII_LEDGER_CLOSED'));
            if(writerContext.getStore())return Promise.reject(unavailable('ZANII_WRITER_REENTRANT'));
            const inherited=requestContext.getStore();const deadline=effectiveDeadline({deadlineAt,timeoutMs:writerLeaseMs});const existing=tail;let expired=false;let timer;
            const check=()=>{if(expired||Date.now()>=deadline)throw new AppError(504,'ZANII_WRITER_WAIT_DEADLINE');if(closed)throw unavailable('ZANII_LEDGER_CLOSED');};
            // A read barrier prevents a new local writer racing between the wait and durable status.
            const read=existing.then(()=>{check();return requestContext.run({...inherited,deadlineAt:deadline},durableStatus);}).then(value=>{check();return value;});
            tail=read.then(()=>{},()=>{});
            return Promise.race([read,new Promise((_,reject)=>{timer=setTimeout(()=>{expired=true;reject(new AppError(504,'ZANII_WRITER_WAIT_DEADLINE'));},Math.max(1,deadline-Date.now()));})]).finally(()=>clearTimeout(timer));
        },
        async close() { closed = true; stopTimer(); await tail; stopTimer(); },
    });
}
/** Actual @zanii/broker wrapped to freeze requests and contain secret echoes.
 * @param {any} options */
export function createZaniiBroker({ credentials, transport, ledger, identity, gate = async () => true, validateResponse } = {}) {
    assertProductIdentity(identity);
    const specs = structuredClone(credentials);
    const secrets = Object.values(specs).map((spec) => {
        if (!['bearer', 'header'].includes(spec.inject) || typeof spec.secret !== 'string' || spec.secret.length < 8)
            throw unavailable('INVALID_BROKER_CREDENTIAL');
        return spec.secret;
    });
    const broker = createBroker({ credentials: specs, gate,
        record: (fields) => ledger.record(identity, fields), fetchImpl: transport.fetch,
        stripResponseHeaders: ['set-cookie', 'authorization', 'proxy-authorization', 'x-api-key'] });
    return Object.freeze({
        list: () => broker.list(),
        async execute(input) {
            exactObject(input, ['credential', 'method', 'url'], ['headers', 'body']);
            identifier(input.credential);
            if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(input.method) || typeof input.url !== 'string'
                || input.body !== undefined && typeof input.body !== 'string')
                throw new AppError(400, 'INVALID_BROKER_REQUEST');
            const request = structuredClone(input);
            if (request.headers)
                Object.freeze(request.headers);
            Object.freeze(request);
            try {
                const result = await broker.execute(request);
                if (secrets.some((secret) => result.body.includes(secret) || Object.values(result.headers).some((value) => value.includes(secret))))
                    throw unavailable('BROKER_SECRET_REFLECTION');
                if (validateResponse)
                    validateResponse(result);
                return result;
            }
            catch (error) {
                throw error instanceof AppError ? error : unavailable('BROKER_EXECUTION_DENIED');
            }
        },
    });
}
