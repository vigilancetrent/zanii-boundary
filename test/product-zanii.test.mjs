import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { randomBytes, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { resolve, join } from 'node:path';
import { generateKeypair, createCert, receiptHash, leafHash, canonicalBytes, createSTH, verifyReceipt } from '@zanii/core';
import { openStore } from '../src/product/store.mjs';
import { asAsyncStore } from '../src/product/async-store.mjs';
import { createZaniiLedger, createZaniiBroker, createConfiguredZaniiLedger, zaniiCapabilities } from '../src/adapters/zanii.mjs';
import { localTls } from './product-adapters.test.mjs';
const operator = { actorId: 'operator', tenantId: 'company-a', roles: ['operator'] };
async function fixture(t) {
    const base = resolve('.test-data');
    mkdirSync(base, { recursive: true });
    const dir = mkdtempSync(join(base, 'zanii-'));
    const store = openStore({ path: join(dir, 'db.sqlite'), encryptionKey: randomBytes(32) });
    t.after(async () => { (await store.close()); assert.ok(resolve(dir).startsWith(base)); rmSync(dir, { recursive: true, force: true }); });
    const owner = generateKeypair();
    const agent = generateKeypair();
    const log = generateKeypair();
    const delegation = [createCert({ issuer: owner.did, subject: agent.did, scopes: ['broker.*'], exp: new Date(Date.now() + 86400000).toISOString() }, owner.privateKey)];
    const received = [];
    let head = null;
    let mode = 'healthy';
    let effectCalls = 0;
    let echo = false;
    const { origin, transport } = await localTls(t, async (req, res) => {
        const json = (body, status = 200) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
        if (req.url.startsWith('/v1/head/'))
            return json({ head });
        if (req.url === '/v1/receipts') {
            const chunks = [];
            for await (const chunk of req)
                chunks.push(chunk);
            const batch = JSON.parse(Buffer.concat(chunks).toString()).receipts;
            // The receipt and nonce have to be durable BEFORE the SDK reaches the log.
            for (const receipt of batch) {
                const hash = receiptHash(receipt);
                assert.equal(verifyReceipt(receipt).ok, true);
                const saved = (await store.get(operator.tenantId, 'outbox', `receipt-${hash.replace(/^sha256:/, '')}`));
                assert.deepEqual(saved.receipt, receipt);
                assert.equal(typeof saved.nonce, 'string');
            }
            if (mode === 'outage')
                return json({ error: 'DO_NOT_LEAK_UPSTREAM_SECRET' }, 503);
            if (mode === 'short')
                return json({ results: [] });
            if (mode === 'mismatch')
                return json({ results: batch.map(() => ({ status: 'accepted', hash: `sha256:${'0'.repeat(64)}` })) });
            const results = batch.map((receipt) => {
                const hash = receiptHash(receipt);
                const duplicate = received.some((item) => receiptHash(item) === hash);
                if (!duplicate)
                    received.push(receipt);
                head = hash;
                return { status: duplicate ? 'duplicate' : 'accepted', hash, index: received.findIndex((item) => receiptHash(item) === hash) };
            });
            return json({ results });
        }
        if (req.url.startsWith('/v1/proof/')) {
            const receipt = received.find((item) => receiptHash(item) === decodeURIComponent(req.url.slice('/v1/proof/'.length)));
            const signingLog = mode === 'foreign-log' ? generateKeypair() : log;
            const root = Buffer.from(leafHash(canonicalBytes(receipt))).toString('hex');
            return json({ receipt, index: 0, proof: [], sth: createSTH({ logId: signingLog.did, size: 1, root: `sha256:${root}`, ts: new Date().toISOString() }, signingLog.privateKey) });
        }
        if (req.url === '/company/effect') {
            effectCalls++;
            assert.equal(req.headers.authorization, 'Bearer fixture-company-secret');
            return json({ committed: true, ...(echo ? { leaked: 'fixture-company-secret' } : {}) });
        }
        return json({ error: 'absent' }, 404);
    });
    const ledgerOptions = { store, transport, tenantId: operator.tenantId, agentDid: agent.did, agentPrivateKey: agent.privateKey, delegation, apiKey: 'fixture-ledger-api-key', expectedLogDid: log.did };
    const ledger = createZaniiLedger(ledgerOptions);
    t.after(() => ledger.close());
    const broker = createZaniiBroker({ credentials: { company: { inject: 'bearer', secret: 'fixture-company-secret', allow: [`${origin}/company`] } }, transport, ledger, identity: operator });
    return { store, ledger, broker, origin, received, ledgerOptions, directory: dir, mode(value) { mode = value; }, echo(value) { echo = value; }, calls: () => effectCalls };
}

test('authorization status waits only behind its local writer and expires without receipt mutation or peer waiver',async(t)=>{
    const f=await fixture(t);let enter;let release;const ready=new Promise(done=>{enter=done;});const gate=new Promise(done=>{release=done;});
    const transport={...f.ledgerOptions.transport,async fetch(input,init){if(new URL(input).pathname==='/v1/receipts'&&init.method==='POST'){enter();await gate;}return f.ledgerOptions.transport.fetch(input,init);}};
    const local=createZaniiLedger({...f.ledgerOptions,transport,writerLeaseMs:2000});t.after(()=>local.close());const writer=local.record(operator,{target:'broker.company.post',payload:{binding:'bounded-read'}});await ready;
    try{assert.equal((await local.status()).blocked,true);assert.equal((await f.ledger.authorizationStatus({deadlineAt:Date.now()+500})).blocked,true);const started=Date.now();await assert.rejects(local.authorizationStatus({deadlineAt:Date.now()+30}),{code:'ZANII_WRITER_WAIT_DEADLINE'});assert.ok(Date.now()-started<500);assert.equal(f.received.length,0);assert.equal(f.calls(),0);}finally{release();}
    await writer;assert.equal((await local.authorizationStatus({deadlineAt:Date.now()+1000})).blocked,false);assert.equal(f.received.length,1);assert.equal((await f.store.list(operator.tenantId,'outbox')).items[0].value.state,'accepted');
});
test('installed Zanii SDK and broker persist signed evidence before actual TLS credential injection', async (t) => {
    const f = await fixture(t);
    const result = await f.broker.execute({ credential: 'company', method: 'POST', url: `${f.origin}/company/effect`, body: '{"approved":true}' });
    assert.equal(result.status, 200);
    assert.equal(f.calls(), 1);
    assert.equal(f.received.length, 1);
    const row = (await f.store.list(operator.tenantId, 'outbox')).items[0].value;
    assert.equal(row.state, 'accepted');
    assert.equal(row.receipt.target, 'broker.company.post');
    const proof = await f.ledger.verifyProof(row.hash);
    assert.equal(proof.included, true);
    assert.equal(proof.anchored, false);
    f.mode('foreign-log');
    await assert.rejects(f.ledger.verifyProof(row.hash), { code: 'ZANII_TRUSTED_PROOF_REQUIRED' });
    f.mode('healthy');
    f.echo(true);
    await assert.rejects(f.broker.execute({ credential: 'company', method: 'POST', url: `${f.origin}/company/effect` }), { code: 'BROKER_SECRET_REFLECTION' });
});
test('receipt outage refuses business request; recovery only resubmits stored exact receipt', async (t) => {
    const f = await fixture(t);
    f.mode('outage');
    await assert.rejects(f.broker.execute({ credential: 'company', method: 'POST', url: `${f.origin}/company/effect` }), { code: 'ZANII_LEDGER_UNAVAILABLE' });
    assert.equal(f.calls(), 0);
    assert.equal((await f.store.list(operator.tenantId, 'outbox')).items[0].value.state, 'pending');
    f.mode('healthy');
    const recovered = await f.ledger.recover(operator);
    assert.equal(recovered.length, 1);
    assert.equal(f.calls(), 0);
    assert.equal(f.received.length, 1);
});
test('malformed SDK acknowledgements never unlock company credentials', async (t) => {
    for (const mode of ['short', 'mismatch']) {
        const f = await fixture(t);
        f.mode(mode);
        await assert.rejects(f.broker.execute({ credential: 'company', method: 'POST', url: `${f.origin}/company/effect` }), { code: 'ZANII_INVALID_ACK' });
        assert.equal(f.calls(), 0);
    }
});
test('runtime capability distinguishes the actual installed package from live ledger validation', async () => {
    const status = await zaniiCapabilities();
    assert.equal(status.brokerVersion, '0.1.0');
    assert.equal(status.sdkVersion, '0.5.4');
    assert.equal(status.liveLedgerValidated, false);
    assert.equal(status.runtimeAvailable, true); assert.equal(status.runtimeVersion, '0.4.0');
    assert.equal((await zaniiCapabilities({ requireRuntime: true })).liveLedgerValidated, false);
});
test('leased SDK writers refresh their cached chain head and durable readiness sees another writer pending receipt', async (t) => {
    const f = await fixture(t);
    const second = createZaniiLedger(f.ledgerOptions); t.after(() => second.close());
    const fields = { target: 'broker.company.post', payload: { approved: true } };
    const first = await f.ledger.record(operator, fields);
    const middle = await second.record(operator, fields);
    await f.ledger.record(operator, fields);
    assert.equal(f.received[1].prev, first.hash);
    assert.equal(f.received[2].prev, middle.hash);
    const lease = await f.store.claimLease(operator.tenantId, `receipt:${f.ledgerOptions.agentDid}`, { ownerId: 'another-writer', ttlMs: 5000 });
    assert.ok(lease);
    await assert.rejects(second.record(operator, fields), { code: 'ZANII_WRITER_BUSY' });
    assert.equal(f.received.length, 3);
    await f.store.releaseLease(lease);
    f.mode('outage');
    await assert.rejects(second.record(operator, fields), { code: 'ZANII_LEDGER_UNAVAILABLE' });
    const state = await f.ledger.status();
    assert.equal(state.blocked, true); assert.equal(state.pendingReceipts, 1);
    assert.equal(f.calls(), 0);
});
test('an expired SDK signer cannot insert or upload a stale receipt after a new leased writer advances the chain', async (t) => {
    const f = await fixture(t); let entered; let release;
    const started = new Promise((resolve) => { entered = resolve; });
    const held = new Promise((resolve) => { release = resolve; });
    const privateKey = createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(f.ledgerOptions.agentPrivateKey),
    ]) });
    const publicKey = Buffer.from(createPublicKey(privateKey).export({ format: 'jwk' }).x, 'base64url');
    const shared = asAsyncStore(f.store); let heldLease;
    const leasedStore = { ...shared, async claimLease(...args) { heldLease = await shared.claimLease(...args); return heldLease; } };
    const stale = createZaniiLedger({ ...f.ledgerOptions, store: leasedStore, agentPrivateKey: undefined,
        signer: { publicKey, async sign(message) { entered(); await held; return sign(null, message, privateKey); } } });
    t.after(() => stale.close());
    const fields = { target: 'broker.company.post', payload: { approved: true } };
    const pending = stale.record(operator, fields);
    const rejection = assert.rejects(pending, { code: 'LEASE_LOST' });
    await started;
    await shared.renewLease(heldLease, { ttlMs: 1 });
    await new Promise((resolve) => setTimeout(resolve, 20));
    const fresh = await f.ledger.record(operator, fields); release(); await rejection;
    assert.equal(f.received.length, 1); assert.equal(receiptHash(f.received[0]), fresh.hash);
    assert.equal((await f.store.list(operator.tenantId, 'outbox')).items.length, 1);
    assert.equal(f.calls(), 0);
    const resumed = await stale.record(operator, fields);
    assert.equal(f.received.length, 2); assert.equal(f.received[1].prev, fresh.hash);
    assert.equal(receiptHash(f.received[1]), resumed.hash);
});
test('a nonresponsive remote signer expires without a persisted receipt or a business dispatch', async (t) => {
    const f = await fixture(t);
    const privateKey = createPrivateKey({ format: 'der', type: 'pkcs8', key: Buffer.concat([
        Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(f.ledgerOptions.agentPrivateKey),
    ]) });
    const signer = { publicKey: Buffer.from(createPublicKey(privateKey).export({ format: 'jwk' }).x, 'base64url'), sign: () => new Promise(() => {}) };
    const ledger = createZaniiLedger({ ...f.ledgerOptions, agentPrivateKey: undefined, signer, writerLeaseMs: 1000 });
    t.after(() => ledger.close());
    await assert.rejects(ledger.record(operator, { target: 'broker.company.post', payload: {} }), { code: 'ZANII_SIGNER_DEADLINE' });
    assert.equal(f.received.length, 0); assert.equal(f.calls(), 0);
    assert.equal((await f.store.list(operator.tenantId, 'outbox')).items.length, 0);
});
test('SDK restart recovers exact durable receipt; tenant mismatch and closed writers fail', async (t) => {
    const f = await fixture(t);
    f.mode('outage');
    await assert.rejects(f.ledger.record(operator, { target: 'broker.company.post', payload: { approved: true } }), { code: 'ZANII_LEDGER_UNAVAILABLE' });
    const hash = (await f.store.list(operator.tenantId, 'outbox')).items[0].value.hash;
    await f.ledger.close();
    await assert.rejects(f.ledger.record(operator, { target: 'broker.company.post', payload: {} }), { code: 'ZANII_LEDGER_CLOSED' });
    const restarted = createZaniiLedger(f.ledgerOptions);
    t.after(() => restarted.close());
    assert.throws(() => restarted.record({ ...operator, tenantId: 'company-b' }, { target: 'broker.company.post', payload: {} }), { code: 'ZANII_TENANT_MISMATCH' });
    await assert.rejects(restarted.record(operator, { target: 'broker.company.post', payload: {} }), { code: 'ZANII_RECOVERY_REQUIRED' });
    f.mode('healthy');
    const outcomes = await restarted.recover(operator);
    assert.equal(outcomes[0].hash, hash);
    assert.equal(f.received.length, 1);
    assert.equal(f.calls(), 0);
});
test('configured ledger loads operator secret files and uses actual SDK over mTLS', async (t) => {
    const f = await fixture(t);
    await f.ledger.close();
    writeFileSync(join(f.directory, 'seed.hex'), Buffer.from(f.ledgerOptions.agentPrivateKey).toString('hex'), { mode: 0o600 });
    writeFileSync(join(f.directory, 'delegation.json'), JSON.stringify(f.ledgerOptions.delegation), { mode: 0o600 });
    writeFileSync(join(f.directory, 'api.key'), 'fixture-ledger-api-key', { mode: 0o600 });
    const config = { origin: f.origin, caFile: resolve('artifacts/test-pki-ca.pem'), certFile: resolve('artifacts/test-pki-gateway-cert.pem'),
        keyFile: resolve('artifacts/test-pki-gateway-key.pem'), tenantId: operator.tenantId, agentDid: f.ledgerOptions.agentDid,
        agentPrivateKeyFile: 'seed.hex', delegationFile: 'delegation.json', apiKeyFile: 'api.key',
        expectedLogDid: f.ledgerOptions.expectedLogDid, allowPrivateNetworks: true };
    const configured = await createConfiguredZaniiLedger({ store: f.store, config, baseDirectory: f.directory });
    t.after(() => configured.close());
    const receipt = await configured.record(operator, { target: 'broker.company.post', payload: { test: 'configured' } });
    assert.equal(receipt.accepted, true);
    assert.equal(f.received.length, 1);
    await assert.rejects(createConfiguredZaniiLedger({ store: f.store, config: { ...config, requireRuntime: true }, baseDirectory: f.directory }), { code: 'ZANII_RUNTIME_CONFIGURATION_REQUIRED' });
    await assert.rejects(createConfiguredZaniiLedger({ store: f.store, config: { ...config, agentDid: generateKeypair().did }, baseDirectory: f.directory }), { code: 'ZANII_SIGNING_KEY_INVALID' });
});
