import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { performance } from 'node:perf_hooks';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { openStore } from '../src/product/store.mjs';
import { asAsyncStore } from '../src/product/async-store.mjs';
import { requestContext } from '../src/product/context.mjs';

function fixture(t, options = {}) {
  const base = resolve('.test-data'); mkdirSync(base, { recursive: true }); const directory = mkdtempSync(join(base, 'async-store-'));
  const raw = openStore({ path: join(directory, 'state.db'), encryptionKey: randomBytes(32), ...options }); const store = asAsyncStore(raw);
  t.after(async () => { await store.close(); assert.ok(resolve(directory).startsWith(base + sep)); rmSync(directory, { recursive: true, force: true }); });
  return { raw, store };
}

test('owned async SQLite transactions serialize outside reads and roll back across awaited calls', async (t) => {
  const { raw, store } = fixture(t); assert.equal(asAsyncStore(raw), store); assert.equal(asAsyncStore(store), store);
  let unblock; let started; const gate = new Promise((done) => { unblock = done; }); const ready = new Promise((done) => { started = done; });
  const write = store.transaction(async () => { await store.put('tenant', 'memory', 'note', { text: 'uncommitted' }); started(); await gate; throw new Error('abort'); });
  await ready; let readFinished = false;
  const read = store.get('tenant', 'memory', 'note').then((value) => { readFinished = true; return value; });
  await Promise.resolve(); assert.equal(readFinished, false); unblock(); await assert.rejects(write, /abort/); assert.equal(await read, null);
  await assert.rejects(store.transaction(() => store.get('foreign', 'memory', 'note'), { tenantId: 'tenant' }), { code: 'TENANT_TRANSACTION_MISMATCH' });
  assert.throws(() => raw.transaction(async () => {}), { code: 'ASYNC_TRANSACTION' });
});

test('operation ownership survives peer startup, expires safely, and fresh observation fences can reconcile', async (t) => {
  const { store } = fixture(t); const now = Date.now(); const tenant = 'tenant';
  await store.put(tenant, 'tasks', 'task', { id: 'task', rootTaskId: 'task', parentId: null, actorId: 'agent', expiresAt: now + 60000, maxActions: 3 });
  const lease = await store.claimLease(tenant, 'operation:one', { ownerId: 'owner-a', ttlMs: 1000, now });
  assert.equal(await store.claimLease(tenant, 'operation:one', { ownerId: 'owner-b', ttlMs: 1000, now }), null);
  await store.reserveOperation({ tenantId: tenant, taskId: 'task', operationId: 'one', actionDigest: 'digest', policyDigest: 'policy',
    action: { id: 'one', kind: 'read', documentId: 'guide' }, toolVersion: 'v1', maxActions: 3, now, lease });
  await store.transitionOperation(tenant, 'one', 'dispatched', null, { lease, now });
  assert.deepEqual(await store.recoverUnknown(tenant, { now: now + 10 }), []);
  assert.equal((await store.recoverUnknown(tenant, { now: now + 1001 })).length, 1);
  const observer = await store.claimLease(tenant, 'operation:one', { ownerId: 'observer', ttlMs: 1000, now: now + 1002 });
  assert.equal(observer.fence, 2); assert.equal(await store.releaseLease(lease), false);
  await assert.rejects(store.transitionOperation(tenant, 'one', 'succeeded', { content: 'old' }, { lease, now: now + 1003 }), { code: 'LEASE_LOST' });
  const observed = await store.transitionOperation(tenant, 'one', 'succeeded', { content: 'independently-observed' }, { lease: observer, now: now + 1003 });
  assert.equal(observed.lease.fence, 2); assert.equal(observed.result.content, 'independently-observed');
});

test('expired async SQLite transaction cannot commit after its invocation budget', async (t) => {
  const { store } = fixture(t, { transactionTimeoutMs: 30 });
  const write = store.transaction(async () => { await store.put('tenant', 'memory', 'late', { text: 'must-rollback' }); await new Promise((done) => setTimeout(done, 60)); });
  await assert.rejects(write, { code: 'DATABASE_TIMEOUT' });
  await new Promise((done) => setTimeout(done, 60));
  assert.equal(await store.get('tenant', 'memory', 'late'), null);
});

test('native SQLite busy waits honor direct-call and transaction deadlines under a real peer write lock',async(t)=>{
  const {raw,store}=fixture(t);const peer=new DatabaseSync(raw.path);peer.exec('BEGIN IMMEDIATE');
  try{for(const work of [()=>store.put('review','metadata','bounded',{value:true}),()=>store.transaction(()=>store.put('review','metadata','bounded',{value:true}))]){const started=performance.now();await assert.rejects(requestContext.run({deadlineAt:Date.now()+50},work),{code:'DATABASE_TIMEOUT'});assert.ok(performance.now()-started<1000,'native lock wait exceeded the invocation budget tolerance');assert.equal(peer.prepare("SELECT count(*) AS n FROM objects WHERE tenant='review'").get().n,0);}}
  finally{peer.exec('ROLLBACK');peer.close();}
  await store.put('review','metadata','recovered',{value:true});assert.equal((await store.get('review','metadata','recovered')).value,true);
});

test('bounded calls restore the legacy synchronous busy timeout after native lock failure',async(t)=>{
  const {raw,store}=fixture(t,{busyTimeoutMs:200});const peer=new DatabaseSync(raw.path);peer.exec('BEGIN IMMEDIATE');
  try{await assert.rejects(requestContext.run({deadlineAt:Date.now()+30},()=>store.put('review','metadata','bounded',{value:true})),{code:'DATABASE_TIMEOUT'});const started=performance.now();assert.throws(()=>raw.put('review','metadata','legacy',{value:true}),error=>error.code==='ERR_SQLITE_ERROR');assert.ok(performance.now()-started>=120,'legacy busy_timeout was shortened permanently');}
  finally{peer.exec('ROLLBACK');peer.close();}
});
