import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes,createHash } from 'node:crypto';
import { mkdirSync,mkdtempSync,rmSync,writeFileSync } from 'node:fs';
import { resolve,join,sep } from 'node:path';
import { PGlite } from '@electric-sql/pglite';
import { openAsyncSqliteStore } from '../src/product/async-store.mjs';
import { openSqliteArchivePort } from '../src/product/store.mjs';
import { openPostgresStore,openPostgresArchivePort,openPostgresBackupPort,restorePostgresSnapshot } from '../src/product/postgres-store.mjs';
import { migratePostgres } from '../src/product/migrations.mjs';
import { createJobService,createRoleJobService,createRoleMaintenanceSchedule } from '../src/product/jobs.mjs';
import { createTelemetry,instrumentStore } from '../src/product/telemetry.mjs';
import { createMaintenanceWorker } from '../src/product/worker.mjs';
import { createRuntimeOperations } from '../src/product/runtime-operations.mjs';
import { runKeyRotation } from '../scripts/key-rotation.mjs';

function sqlite(t){const root=resolve('.test-data');mkdirSync(root,{recursive:true});const dir=mkdtempSync(join(root,'maintenance-'));const path=join(dir,'store.db');const keys={encryptionKey:randomBytes(32),auditKey:randomBytes(32)};const store=openAsyncSqliteStore({path,...keys});t.after(async()=>{await store.close();assert.ok(resolve(dir).startsWith(root+sep));rmSync(dir,{recursive:true,force:true});});return {store,path,keys};}
async function postgres(t){const db=new PGlite();await db.waitReady;let tail=Promise.resolve();const queries=[];const pool={async connect(){let release;const gate=new Promise(done=>{release=done;});const prior=tail;tail=tail.then(()=>gate);await prior;return {query(input,values){queries.push(typeof input==='string'?input:input.text);if(typeof input==='string'&&values===undefined)return db.exec(input).then(rows=>rows.at(-1)??{rows:[]});return db.query(typeof input==='string'?input:input.text,typeof input==='string'?values:input.values);},release};}};await migratePostgres({pool,realm:'gateway'});await migratePostgres({pool,realm:'resource'});const keys={encryptionKey:randomBytes(32),auditKey:randomBytes(32)};const store=await openPostgresStore({pool,realm:'gateway',role:'worker',...keys,sqlFixture:true});t.after(async()=>{await store.close();await db.close();});return {db,pool,store,keys,queries};}

for(const backend of ['sqlite','postgres'])test(`${backend} durable maintenance races, future-page progress, fence renewal, expiry, DLQ and replay`,async(t)=>{
  const {store}=backend==='sqlite'?sqlite(t):await postgres(t);let clock=Date.now();const options={store,now:()=>clock,leaseMs:100,maxAttempts:2,baseDelayMs:10,random:()=>0};const a=createJobService({...options,ownerId:'worker-a'});const b=createJobService({...options,ownerId:'worker-b'});
  for(let i=0;i<105;i++)await a.enqueue('company',{id:`future-${String(i).padStart(3,'0')}`,kind:'retention',payload:{},runAt:clock+10000});
  const job=await a.enqueue('company',{id:'ready',kind:'retention',payload:{}});assert.equal((await a.enqueue('company',{id:'ready',kind:'retention',payload:{}})).id,job.id);
  await assert.rejects(a.enqueue('company',{id:'ready',kind:'backup',payload:{}}),{code:'JOB_IDEMPOTENCY_CONFLICT'});
  const race=await Promise.all([a.claim('company'),b.claim('company')]);assert.equal(race.flat().length,1);const stale=race.flat()[0];clock+=101;
  const fresh=(await b.claim('company'))[0];assert.ok(fresh.lease.fence>stale.lease.fence);await assert.rejects(a.complete(stale),{code:'LEASE_LOST'});
  await b.renew(fresh);const failed=await b.fail(fresh,new Error('sensitive should never persist'));assert.equal(failed.state,'dead');assert.equal(failed.error,'MAINTENANCE_HANDLER_FAILED');assert.equal((await b.status('company')).dead,1);
  await b.retryDead('company','ready');const retried=(await a.claim('company'))[0];await a.complete(retried,{cleaned:1});assert.equal((await a.status('company')).done,1);assert.equal((await a.status('company')).queued,105);
});

test('worker visits dormant tenants and system, persists heartbeat aggregates, retries an unacknowledged DLQ alarm once without recursion',async(t)=>{
  let worker;t.after(()=>worker?.close());const {store}=sqlite(t);const jobs=createJobService({store,ownerId:'worker',maxAttempts:1});await store.put('dormant','memory','kept',{text:'private'});let alerts=0;let visits=[];
  await jobs.enqueue('dormant',{kind:'retention',payload:{}});worker=createMaintenanceWorker({store,jobs,ownerId:'worker',handlers:{retention:async()=>{throw new Error('failure');}},schedule:async(tenant)=>{visits.push(tenant);},onAlert:async()=>{alerts++;if(alerts===1)throw new Error('receiver unavailable');}});
  await assert.rejects(worker.tick());await worker.tick();await worker.tick();assert.equal(alerts,2);assert.ok(visits.includes('dormant'));assert.ok(visits.includes('system'));const heartbeats=await store.workerStatus();assert.equal(heartbeats.items[0].queueSummary.dead,1);assert.equal((await jobs.deadAlerts('dormant')).length,0);
});

test('SQLite archive prefix preserves chain origin and next sequence without audit cipher rewrite',async(t)=>{
  let raw;t.after(()=>raw?.close());const {store,path}=sqlite(t);for(let i=0;i<3;i++)await store.appendAudit({tenantId:'company',actorId:'operator',event:'test.event'});raw=openSqliteArchivePort({path});const segment=raw.readArchiveSegment('company',{limit:2});const row=segment.rows.at(-1);raw.commitArchivedPrefix('company',{expectedBase:segment.base,checkpoint:{tenantId:'company',sequence:row.sequence,hash:row.hash},reference:{id:'locked'},signedManifest:{manifest:{keyIds:['legacy']},signature:'fixture'}});
  assert.equal((await store.verifyAudit('company')).sequence,3);assert.equal((await store.exportAudit('company')).base.sequence,2);assert.equal((await store.appendAudit({tenantId:'company',actorId:'operator',event:'after.archive'})).sequence,4);
});

test('PostgreSQL keyless role journals remain durable and cannot read application values; archive prefix is protected',async(t)=>{
  const {pool,store,db}=await postgres(t);await store.put('company','memory','secret',{text:'private'});await store.appendAudit({tenantId:'company',actorId:'operator',event:'test.event'});const telemetry=createTelemetry();t.after(()=>telemetry.close());const raw=instrumentStore(await openPostgresArchivePort({pool,realm:'gateway',sqlFixture:true}),telemetry);t.after(()=>raw.close());assert.equal(raw.get,undefined);assert.equal(raw.put,undefined);
  const jobs=createRoleJobService({store:raw,ownerId:'archive-worker',leaseMs:100});await jobs.enqueue('company',{id:'archive-one',kind:'audit-archive',payload:{}});await assert.rejects(jobs.enqueue('company',{kind:'backup',payload:{}}),{code:'ROLE_JOB_PAYLOAD_DENIED'});const claim=(await jobs.claim('company'))[0];await jobs.complete(claim,{archived:1});assert.equal((await jobs.status('company')).done,1);
  const page=await raw.readArchiveSegment('company');await raw.commitArchivedPrefix('company',{expectedBase:page.base,checkpoint:page.checkpoint,reference:{id:'locked'},signedManifest:{manifest:{keyIds:['legacy']},signature:'fixture'}});assert.equal((await store.verifyAudit('company')).sequence,1);assert.equal((await store.appendAudit({tenantId:'company',actorId:'operator',event:'after.archive'})).sequence,2);
  await db.exec('SET ROLE runtime_gateway_app');await assert.rejects(db.query('UPDATE runtime_gateway.audit_bases SET sequence=0'),/permission denied/);await assert.rejects(db.query('DELETE FROM runtime_gateway.archive_jobs'),/permission denied/);await db.exec('RESET ROLE');
});

test('PostgreSQL consistent encrypted snapshot restores only into empty target, authenticates keys, quarantines and revokes old grants',async(t)=>{
  const {pool,store,keys}=await postgres(t);await store.put('company','tasks','mission',{id:'mission',actorId:'agent',revoked:false});const backup=await openPostgresBackupPort({pool,realm:'gateway',sqlFixture:true});t.after(()=>backup.close());const snapshot=await backup.exportSnapshot('company');const expectedSha256=createHash('sha256').update(snapshot).digest('hex');
  await assert.rejects(restorePostgresSnapshot({pool,realm:'gateway',snapshot,expectedSha256,allowNewTarget:true,...keys}),{code:'RESTORE_DESTINATION_EXISTS'});
  const target=await postgres(t);await target.db.exec("DELETE FROM runtime_gateway.objects; DELETE FROM runtime_gateway.tenants");
  await assert.rejects(restorePostgresSnapshot({pool:target.pool,realm:'gateway',snapshot,expectedSha256,allowNewTarget:true,encryptionKey:randomBytes(32),auditKey:keys.auditKey}),{code:'STORE_INTEGRITY_ERROR'});
  const restored=await restorePostgresSnapshot({pool:target.pool,realm:'gateway',snapshot,expectedSha256,allowNewTarget:true,...keys});assert.equal(restored.quarantined,true);const opened=await openPostgresStore({pool:target.pool,realm:'gateway',...keys,sqlFixture:true});t.after(()=>opened.close());assert.equal((await opened.get('company','tasks','mission')).revoked,true);assert.equal((await opened.restoreStatus()).quarantined,true);await assert.rejects(opened.put('company','memory','blocked',{text:'blocked'}),{code:'WRITE_EPOCH_REJECTED'});
});

test('completed job payload expiry retains a durable authenticated deduplication tombstone',async(t)=>{
  const {store}=sqlite(t);const jobs=createJobService({store,ownerId:'worker',completedRetentionMs:5});await jobs.enqueue('company',{id:'once',kind:'retention',payload:{}});await jobs.complete((await jobs.claim('company'))[0]);await new Promise(done=>setTimeout(done,10));await store.purgeExpired(Date.now(),{tenantId:'company'});assert.equal((await jobs.status('company')).done,0);const repeated=await jobs.enqueue('company',{id:'once',kind:'retention',payload:{}});assert.equal(repeated.expired,true);assert.deepEqual(await jobs.claim('company'),[]);
});

test('SQLite realm freeze fences already-open old writers and retirement seal prevents epoch changes',async(t)=>{
  const {store,path,keys}=sqlite(t);await store.put('company','memory','note',{text:'private'});const next=randomBytes(32);const rotator=openAsyncSqliteStore({path,encryptionKey:next,auditKey:keys.auditKey,role:'rotator',keyring:{activeKeyId:'new',legacyKeyId:'old',keys:{old:keys.encryptionKey,new:next}}});
  let epoch=await rotator.freezeWrites({expectedVersion:(await rotator.keyEpoch()).version});await assert.rejects(store.put('company','memory','old',{text:'blocked'}),{code:'WRITE_EPOCH_REJECTED'});epoch=await rotator.activateKeyEpoch({expectedVersion:epoch.version,activeKeyId:'new'});let after='';do{after=(await rotator.rekeyRecords({after,limit:10})).next;}while(after);
  const seal=await rotator.beginKeyRetirement({expectedVersion:epoch.version,keyId:'old',referenceProofHash:'a'.repeat(64)});await assert.rejects(rotator.unfreezeWrites({expectedVersion:seal.version}),{code:'WRITE_EPOCH_CONFLICT'});const completed=await rotator.finishKeyRetirement({expectedVersion:seal.version,keyId:'old',referenceProofHash:'a'.repeat(64)});await rotator.unfreezeWrites({expectedVersion:completed.version});assert.equal((await store.keyEpoch()).healthy,false);assert.equal((await rotator.keyEpoch()).healthy,true);const identity={tenantId:'company',actorId:'operator',roles:['operator'],scopes:['runtime:operations']};const operations=createRuntimeOperations({store});assert.equal((await operations.status(identity)).ready,false);await assert.rejects(operations.gate(identity),{code:'KEY_EPOCH_UNAVAILABLE'});await assert.rejects(store.put('company','memory','old',{text:'still blocked'}),{code:'WRITE_EPOCH_REJECTED'});await rotator.close();
});

test('a stale PostgreSQL archive handler cannot commit a prefix after another journal owner reclaims it',async(t)=>{
  const {pool,store}=await postgres(t);await store.appendAudit({tenantId:'company',actorId:'operator',event:'test.event'});const raw=await openPostgresArchivePort({pool,realm:'gateway',sqlFixture:true});let clock=Date.now();const a=createRoleJobService({store:raw,ownerId:'one',leaseMs:100,now:()=>clock});const b=createRoleJobService({store:raw,ownerId:'two',leaseMs:100,now:()=>clock});await a.enqueue('company',{id:'archive',kind:'audit-archive',payload:{}});const stale=(await a.claim('company'))[0];clock+=101;await b.claim('company');const page=await raw.readArchiveSegment('company');
  await assert.rejects(raw.withMaintenanceLease(stale,()=>raw.commitArchivedPrefix('company',{expectedBase:page.base,checkpoint:page.checkpoint,reference:{id:'locked'},signedManifest:{manifest:{keyIds:['legacy']},signature:'fixture'}})),{code:'LEASE_LOST'});assert.equal((await store.exportAudit('company')).base,undefined);assert.equal((await store.verifyAudit('company')).sequence,1);await raw.close();
});

test('migration targets reject false directions and authority-bearing downgrades require explicit decommission',async(t)=>{
  const {pool,store}=await postgres(t);await assert.rejects(migratePostgres({pool,realm:'gateway',targetVersion:0}),{code:'INVALID_MIGRATION_TARGET'});
  await assert.rejects(migratePostgres({pool,realm:'gateway',direction:'down',targetVersion:1,allowDestructive:true}),{code:'MIGRATION_DOWN_REQUIRES_RESTORE'});
  await assert.rejects(migratePostgres({pool,realm:'gateway',direction:'down',targetVersion:0,allowDestructive:true}),{code:'MIGRATION_DOWN_REQUIRES_RESTORE'});assert.equal((await migratePostgres({pool,realm:'gateway',direction:'down',targetVersion:2,allowDestructive:true})).version,2);
  await store.close();await migratePostgres({pool,realm:'resource',direction:'down',targetVersion:1,allowDestructive:true});await assert.rejects(migratePostgres({pool,realm:'resource',direction:'down',targetVersion:2,allowDestructive:true}),{code:'INVALID_MIGRATION_DIRECTION'});
});

test('migration acquisition deadline releases late clients without issuing SQL',async()=>{
  let released=0;let sent=0;const pool={async connect(){await new Promise(done=>setTimeout(done,30));return {query(){sent++;return {rows:[]};},release(){released++;}};}};
  await assert.rejects(migratePostgres({pool,realm:'gateway',acquireTimeoutMs:5}),{code:'DATABASE_ACQUIRE_TIMEOUT'});await new Promise(done=>setTimeout(done,40));assert.equal(released,1);assert.equal(sent,0);
});

test('global inventory and pristine initialization remain correct under a non-bypass SECURITY DEFINER owner with forced RLS',async(t)=>{
  const {db,store}=await postgres(t);await store.claimLease('company-a','operation:active',{ownerId:'owner',ttlMs:30000});
  await db.exec("SELECT set_config('runtime.tenant_id','company-a',false);INSERT INTO runtime_gateway.archive_segments VALUES('company-a',1,'{}','{\"keyIds\":[\"old\"]}');INSERT INTO runtime_gateway.backup_jobs(tenant,id,job,state,due,owner,fence,expires) VALUES('raw-only','owner','{}','running',1,'raw',1,(extract(epoch FROM clock_timestamp())*1000)::bigint+30000);CREATE ROLE review_inventory_owner NOLOGIN NOSUPERUSER NOBYPASSRLS;GRANT USAGE ON SCHEMA runtime_gateway TO review_inventory_owner;GRANT SELECT ON ALL TABLES IN SCHEMA runtime_gateway TO review_inventory_owner;GRANT UPDATE ON runtime_gateway.key_epochs TO review_inventory_owner;ALTER FUNCTION runtime_gateway.active_lease_count() OWNER TO review_inventory_owner;ALTER FUNCTION runtime_gateway.retained_key_records(text,integer) OWNER TO review_inventory_owner;ALTER FUNCTION runtime_gateway.initialize_epoch(text) OWNER TO review_inventory_owner;");
  assert.equal(Number((await db.query('SELECT runtime_gateway.active_lease_count() AS n')).rows[0].n),2);
  const records=(await db.query("SELECT * FROM runtime_gateway.retained_key_records('',100)")).rows;assert.equal(records.length,1);assert.equal(records[0].tenant_id,'company-a');assert.equal((await db.query("SELECT current_setting('runtime.tenant_id') AS tenant")).rows[0].tenant,'company-a');
  await db.exec("DELETE FROM runtime_gateway.objects WHERE tenant='system' AND id='key-check';SELECT runtime_gateway.initialize_epoch('injected');");assert.equal((await db.query('SELECT active_id FROM runtime_gateway.key_epochs')).rows[0].active_id,'legacy');
  await db.exec("REVOKE SELECT ON runtime_gateway.backup_catalogues FROM review_inventory_owner");await assert.rejects(db.query("SELECT * FROM runtime_gateway.retained_key_records('',100)"),/permission denied/);assert.equal((await db.query("SELECT current_setting('runtime.tenant_id') AS tenant")).rows[0].tenant,'company-a');
});

test('raw purpose journal compacts completed payloads while preserving deduplication and fencing generation',async(t)=>{
  const {pool,db}=await postgres(t);const raw=await openPostgresArchivePort({pool,realm:'gateway',sqlFixture:true});let clock=Date.now();const jobs=createRoleJobService({store:raw,ownerId:'worker',now:()=>clock,completedRetentionMs:1});await jobs.enqueue('company',{id:'once',kind:'audit-archive',payload:{}});const claim=(await jobs.claim('company'))[0];await jobs.complete(claim,{privateReference:'retained-only-until-expiry'});clock+=2;assert.equal((await jobs.compact('company')).compacted,1);const again=await jobs.enqueue('company',{id:'once',kind:'audit-archive',payload:{}});assert.equal(again.expired,true);assert.equal(again.result,undefined);assert.equal(again.trace,undefined);assert.equal(Number((await db.query("SELECT fence FROM runtime_gateway.archive_jobs WHERE tenant='company' AND id='once'")).rows[0].fence),claim.lease.fence);assert.deepEqual(await jobs.claim('company'),[]);await raw.close();
});

test('rekey CLI activates the configured new codec before its encrypted requested audit and migrates real PostgreSQL rows',async(t)=>{
  const {pool,store,keys}=await postgres(t);await store.put('company','memory','private',{text:'retained'});const rotator=await openPostgresStore({pool,realm:'gateway',role:'rotator',...keys,sqlFixture:true});await rotator.freezeWrites({expectedVersion:(await rotator.keyEpoch()).version});await rotator.close();
  const root=resolve('.test-data');const directory=mkdtempSync(join(root,'rekey-cli-'));t.after(()=>{assert.ok(resolve(directory).startsWith(root+sep));rmSync(directory,{recursive:true,force:true});});const next=randomBytes(32);const ring={activeKeyId:'new',legacyKeyId:'old',keys:{old:keys.encryptionKey.toString('hex'),new:next.toString('hex')}};
  for(const [name,value]of Object.entries({'enc.key':next.toString('hex'),'audit.key':keys.auditKey.toString('hex'),'ring.json':JSON.stringify(ring),'ca.pem':'-----BEGIN CERTIFICATE-----\nfixture\n-----END CERTIFICATE-----','credentials.json':JSON.stringify({host:'db.invalid',port:5432,database:'runtime',user:'rotator',password:'fixture-only'})}))writeFileSync(join(directory,name),value,{mode:0o600});
  const config=join(directory,'config.json');writeFileSync(config,JSON.stringify({version:1,role:'rotator',realm:'gateway',storage:{backend:'postgres',encryptionKeyFile:'enc.key',auditKeyFile:'audit.key',keyringFile:'ring.json',postgres:{credentialsFile:'credentials.json',caFile:'ca.pem'}},worker:{timeoutMs:20000,leaseMs:30000},services:{}}),{mode:0o600});
  const result=await runKeyRotation({command:'rekey',options:{config,'key-id':'new'},storeFactory:(options)=>openPostgresStore({...options,pool,sqlFixture:true})});assert.equal(result.epoch.activeKeyId,'new');const reader=await openPostgresStore({pool,realm:'gateway',encryptionKey:next,auditKey:keys.auditKey,keyring:ring,sqlFixture:true});assert.equal((await reader.get('company','memory','private')).text,'retained');assert.deepEqual((await reader.queryAudit('system')).map(row=>row.event),['key.lifecycle.requested','key.lifecycle.completed']);await reader.close();
});

test('read-only PostgreSQL snapshot binds RLS without taking the business mutation lock or registering tenants',async(t)=>{
  const {pool,queries}=await postgres(t);const backup=await openPostgresBackupPort({pool,realm:'gateway',sqlFixture:true});queries.length=0;await backup.exportSnapshot('company');const begin=queries.findIndex(query=>query==='BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');assert.ok(begin>=0);const snapshot=queries.slice(begin);assert.ok(snapshot.some(query=>query.includes("set_config('runtime.tenant_id'")));assert.ok(!snapshot.some(query=>query.includes('pg_advisory_xact_lock')||query.includes('register_tenant')));await backup.close();
});


test('archive scheduling drains more than 500 rows at a fixed clock and stays idle at an unchanged empty prefix',async(t)=>{
  let worker;t.after(()=>worker?.close());const {pool,store}=await postgres(t);for(let i=0;i<507;i++)await store.appendAudit({tenantId:'company',actorId:'operator',event:'backlog.event'});
  const raw=await openPostgresArchivePort({pool,realm:'gateway',sqlFixture:true});t.after(()=>raw.close());const clock=Date.now();const jobs=createRoleJobService({store:raw,ownerId:'archive-drain',now:()=>clock});const schedule=createRoleMaintenanceSchedule({store:raw,jobs,role:'archive',now:()=>clock});let archived=0;
  worker=createMaintenanceWorker({store:raw,jobs,ownerId:'archive-drain',schedule,handlers:{'audit-archive':async(job)=>{const page=await raw.readArchiveSegment(job.tenantId,{limit:100});const tail=page.rows.at(-1);if(!tail)return {archived:0};await raw.commitArchivedPrefix(job.tenantId,{expectedBase:page.base,checkpoint:{tenantId:job.tenantId,sequence:tail.sequence,hash:tail.hash},reference:{id:job.id},signedManifest:{manifest:{id:job.id,keyIds:['legacy']},signature:'fixture'}});archived+=page.rows.length;return {archived:page.rows.length};}}});
  for(let i=0;i<6;i++)assert.equal((await worker.tick()).processed,1);assert.equal(archived,507);assert.equal((await raw.archiveStatus('company')).checkpoint.sequence,507);assert.equal((await worker.tick()).processed,0);assert.equal((await jobs.status('company')).done,6);
});

test('PostgreSQL old-codec readiness fails after cutover while new rotator activation and keyless readers remain valid',async(t)=>{
  const {pool,store,keys}=await postgres(t);await store.put('company','memory','private',{text:'retained'});const next=randomBytes(32);const rotator=await openPostgresStore({pool,realm:'gateway',role:'rotator',encryptionKey:next,auditKey:keys.auditKey,keyring:{activeKeyId:'new',legacyKeyId:'old',keys:{old:keys.encryptionKey,new:next}},sqlFixture:true});t.after(()=>rotator.close());
  assert.equal((await store.keyEpoch()).healthy,true);let epoch=await rotator.freezeWrites({expectedVersion:(await rotator.keyEpoch()).version});epoch=await rotator.activateKeyEpoch({expectedVersion:epoch.version,activeKeyId:'new'});await rotator.unfreezeWrites({expectedVersion:epoch.version});
  assert.equal((await store.keyEpoch()).healthy,false);assert.equal((await rotator.keyEpoch()).healthy,true);const identity={tenantId:'company',actorId:'operator',roles:['operator'],scopes:['runtime:operations']};const oldOperations=createRuntimeOperations({store});assert.equal((await oldOperations.status(identity)).ready,false);await assert.rejects(oldOperations.gate(identity),{code:'KEY_EPOCH_UNAVAILABLE'});assert.equal((await createRuntimeOperations({store:rotator}).status(identity)).ready,true);
  await assert.rejects(store.put('company','memory','old',{text:'fenced'}),{code:'WRITE_EPOCH_REJECTED'});await rotator.put('company','memory','new',{text:'writable'});for(const open of [openPostgresArchivePort,openPostgresBackupPort]){const keyless=await open({pool,realm:'gateway',sqlFixture:true});assert.equal((await keyless.keyEpoch()).healthy,true);await keyless.close();}
});
