import test from 'node:test';
import assert from 'node:assert/strict';
import { parseCapacityConfig,runArrivalCohort,capacityFatal,cohortConstraint,reconcileCapacityEffects,seededRandom } from '../src/product/capacity.mjs';
import { runCapacityMeasurement,capacityArguments } from '../scripts/capacity-acceptance.mjs';
import { createProductFixture,seedProductFixture,resourceEffects } from '../scripts/product-fixture.mjs';

const success=()=>({status:200,body:{state:'succeeded'}});
test('capacity plans require bounded twice-peak, monotonic saturation and explicit smoke qualification',()=>{
  const plan=parseCapacityConfig({version:1});assert.equal(plan.planningPeakRps,5);assert.equal(plan.planningBasis,'assumption');assert.equal(plan.sustainedMs,60000);assert.equal(plan.soakMs,120000);
  for(const change of [{sustainedMs:100},{soakMs:100},{saturationRates:[20,20]},{saturationRates:[5]},{documents:{count:65,bytes:1024}},{unexpected:true},{latencyTargets:{'/v1/actions':{p50Ms:2000,p95Ms:100,p99Ms:5000}}}])assert.throws(()=>parseCapacityConfig({version:1,...change}));
  assert.equal(parseCapacityConfig({version:1,mode:'smoke',sustainedMs:10,soakMs:10,saturationMs:10}).mode,'smoke');assert.throws(()=>capacityArguments(['--config','a','--out','b','--extra']));assert.equal(capacityArguments(['--config','a','--out','b']).config.endsWith('a'),true);
});
test('arrival scheduling accounts for every lag drop separately from issued request latency',async()=>{
  let clock=0;const report=await runArrivalCohort({rate:100,durationMs:30,maxInFlight:5,maxLagMs:5,drainMs:100},{invoke:async()=>success(),now:()=>clock,sleep:async(ms)=>{clock+=ms+50;}});
  assert.equal(report.counts.planned,3);assert.equal(report.counts.issued,1);assert.equal(report.counts.droppedLag,2);assert.equal(report.counts.droppedInFlight,0);assert.equal(report.endpoint.latencyMs.samples,1);assert.equal(report.lagMs.samples,3);assert.equal(cohortConstraint(report,{p50Ms:100,p95Ms:100,p99Ms:100}),'driver-scheduling-lag');
});
test('in-flight driver cap drops scheduled arrivals without queuing or retrying them',async()=>{
  let invocations=0;const report=await runArrivalCohort({rate:100,durationMs:40,maxInFlight:1,maxLagMs:1000,drainMs:200},{invoke:async()=>{invocations++;await new Promise(done=>setTimeout(done,70));return success();}});
  assert.equal(invocations,1);assert.equal(report.counts.planned,4);assert.equal(report.counts.issued,1);assert.equal(report.counts.droppedInFlight,3);assert.equal(report.statuses['200'],1);assert.equal(report.peakInFlight,1);
});
test('authority/deadline/quota mistakes stop issuance and never become a hardware capacity ceiling',async()=>{
  for(const [status,code]of [[401,'INVALID_TOKEN'],[403,'TASK_EXPIRED'],[429,'ROOT_QUOTA'],[504,'REQUEST_DEADLINE'],[503,'ZANII_RUNTIME_REVOCATION_ROLLBACK'],[503,'ZANII_RUNTIME_REVOCATION_INVALID'],[503,'ZANII_RUNTIME_CAPACITY'],[503,'ZANII_LEDGER_UNAVAILABLE'],[503,'ZANII_RUNTIME_EVIDENCE_UNACCEPTED'],[503,'ZANII_RECEIPT_INVALID'],[503,'ZANII_TRUSTED_PROOF_REQUIRED'],[503,'REQUIRED_COMPANION_UNAVAILABLE']])assert.equal(capacityFatal(status,code),true,code);assert.equal(capacityFatal(429,'CONCURRENCY_LIMIT'),false);
  let calls=0;const report=await runArrivalCohort({rate:100,durationMs:100,maxInFlight:5,maxLagMs:1000,drainMs:100},{invoke:async()=>{calls++;return {status:403,body:{error:{code:'TASK_EXPIRED'}}};}});assert.equal(calls,1);assert.equal(report.counts.aborted,9);assert.equal(report.fatal.code,'TASK_EXPIRED');assert.equal(cohortConstraint(report,{}),'authority-or-configuration');
  const integration=await runArrivalCohort({rate:100,durationMs:100,maxInFlight:5,maxLagMs:1000,drainMs:100},{invoke:async()=>({status:503,body:{error:{code:'ZANII_RUNTIME_REVOCATION_ROLLBACK'}}})});assert.equal(integration.counts.issued,1);assert.equal(integration.counts.aborted,9);assert.equal(cohortConstraint(integration,{}),'authority-or-configuration');
});
test('unsettled requests are explicit unverified drain outcomes, never successful missing effects',async()=>{
  let release;const gate=new Promise(done=>{release=done;});const report=await runArrivalCohort({rate:1,durationMs:1,maxInFlight:1,maxLagMs:1000,drainMs:5},{invoke:()=>gate});assert.equal(report.drained,false);assert.equal(report.counts.unresolved,1);assert.equal(report.statuses.unresolved,1);assert.equal(cohortConstraint(report,{}),'driver-drain-unverified');release(success());await new Promise(done=>setTimeout(done,0));assert.equal(report.events[0].status,0);assert.equal(report.events[0].latencyMs,null);
});
test('independent capacity effect recount rejects dropped, duplicate, wrong-document and missing-success effects',()=>{
  const events=[{index:0,outcome:'issued',status:200,state:'succeeded'},{index:1,outcome:'dropped-lag',status:0}];const expected=index=>({id:'operation-'+index,documentId:'doc-'+index});const effect={id:'operation-0',documentId:'doc-0',state:'succeeded',actorId:'agent',kind:'read'};assert.equal(reconcileCapacityEffects(events,[effect],expected).observed,1);
  for(const effects of [[],[effect,effect],[{...effect,id:'operation-1',documentId:'doc-1'}],[{...effect,documentId:'other'}]])assert.throws(()=>reconcileCapacityEffects(events,effects,expected),{code:'CAPACITY_EFFECT_MISMATCH'});const a=seededRandom(17);const b=seededRandom(17);assert.deepEqual(Array.from({length:8},a),Array.from({length:8},b));
  for(const [status,code]of [[429,'CONCURRENCY_LIMIT'],[429,'RATE_LIMITED'],[401,'AUTHENTICATION_REQUIRED'],[403,'SCOPE_DENIED'],[403,'ROLE_DENIED'],[403,'ACTOR_DENIED'],[403,'ACTION_DENIED']])assert.throws(()=>reconcileCapacityEffects([{index:0,outcome:'issued',status,code,state:null}],[effect],expected),{code:'CAPACITY_EFFECT_MISMATCH'});
  for(const [status,code]of [[202,null],[0,'TRANSPORT_ERROR'],[403,'TASK_EXPIRED']])assert.equal(reconcileCapacityEffects([{index:0,outcome:'issued',status,code,state:status===202?'unknown':null}],[effect],expected).effectsWithoutSuccessfulResponse,1);
  assert.throws(()=>reconcileCapacityEffects([{index:0,outcome:'issued',status:200,state:'succeeded'},{index:0,outcome:'issued',status:200,state:'succeeded'}],[effect],expected),{code:'CAPACITY_EFFECT_MISMATCH'});
});
test('short real TLS capacity smoke binds unique actions to independent effects and records actual local resource scope',async()=>{
  const report=await runCapacityMeasurement({version:1,mode:'smoke',planningPeakRps:1,warmupMs:0,sustainedMs:250,soakMs:250,saturationMs:250,saturationRates:[4],maxLagMs:1000,documents:{count:2,bytes:128},latencyTargets:{'/v1/actions':{p50Ms:5000,p95Ms:5000,p99Ms:5000}}},{implementation:async()=> 'a'.repeat(64)});
  assert.equal(report.status,'SMOKE_ONLY');assert.equal(report.qualification.productionAccepted,false);assert.equal(report.qualification.sustainedTwoTimesPlanningPeak,false);assert.equal(report.cohorts.length,3);const ids=new Set();for(const cohort of report.cohorts){assert.equal(cohort.counts.successful,1);assert.equal(cohort.effects.observed,1);assert.equal(cohort.effects.effectsWithoutSuccessfulResponse,0);assert.equal(cohort.dataset.contentBytes,256);assert.equal(cohort.resources.servicesIsolated,false);assert.ok(cohort.resources.peakRssBytes>0);assert.ok(cohort.resources.samples.at(-1).databaseBytes.gateway>0);assert.equal(cohort.endpoint.latencyMs.samples,1);assert.equal(cohort.ledger,null);for(const event of cohort.events){assert.equal(ids.has(event.id),false);ids.add(event.id);}}
});
test('a source change invalidates a completed smoke rather than inheriting another implementation claim',async()=>{
  let count=0;await assert.rejects(runCapacityMeasurement({version:1,mode:'smoke',planningPeakRps:1,warmupMs:0,sustainedMs:1,soakMs:1,saturationMs:1,saturationRates:[4],documents:{count:1,bytes:128},latencyTargets:{'/v1/actions':{p50Ms:5000,p95Ms:5000,p99Ms:5000}}},{implementation:async()=>String(++count).repeat(64)}),{code:'IMPLEMENTATION_CHANGED'});
});

test('full-feature smoke proves actual Runtime preflight and signed receipt deltas separately from core-only',async()=>{
  const report=await runCapacityMeasurement({version:1,mode:'smoke',featureProfile:'runtime-preflight-local-ledger',planningPeakRps:1,warmupMs:0,sustainedMs:250,soakMs:250,saturationMs:250,saturationRates:[4],maxLagMs:1000,documents:{count:1,bytes:128},latencyTargets:{'/v1/actions':{p50Ms:5000,p95Ms:5000,p99Ms:5000}}},{implementation:async()=> 'a'.repeat(64)});
  assert.equal(report.status,'SMOKE_ONLY');assert.equal(report.qualification.fullFeatureExercised,true);for(const cohort of report.cohorts){assert.equal(cohort.counts.successful,1);assert.equal(cohort.effects.observed,1);assert.equal(cohort.ledger.featureProof.runtimeVersion,'0.4.0');assert.equal(cohort.ledger.featureProof.runtimeCalls,1);assert.equal(cohort.ledger.featureProof.runtimeAuthorized,1);assert.equal(cohort.ledger.featureProof.intentReceipts,1);assert.equal(cohort.ledger.featureProof.resultReceipts,1);assert.equal(cohort.ledger.featureProof.acceptedReceipts,3);assert.equal(cohort.ledger.featureProof.liveCompanyValidated,false);}
});

test('two actual Runtime actions wait for local writer acknowledgement while health keeps pending evidence blocked',async(t)=>{
  const f=await createProductFixture({featureProfile:'runtime-preflight-local-ledger'});t.after(()=>f.close());await seedProductFixture(f,{taskId:'concurrent-runtime'});let enter;let release;let held=false;const ready=new Promise(done=>{enter=done;});const gate=new Promise(done=>{release=done;});
  f.ledgerFixture.afterReceipt(async(receipts)=>{if(!held&&receipts.some(receipt=>receipt.action==='action_intent')){held=true;enter();await gate;}});
  const invoke=id=>f.agent.call('/v1/actions',{taskId:'concurrent-runtime',action:{id,kind:'read',documentId:'guide'}});const first=invoke('runtime-concurrent-a');await ready;let secondSettled=false;const second=invoke('runtime-concurrent-b').finally(()=>{secondSettled=true;});
  try{const monitor=await f.client('operator',{tenantId:'platform',roles:['auditor'],scopes:'runtime:health'});const health=await monitor.call('/health/ready');assert.equal(health.body.zanii.blocked,true);await new Promise(done=>setTimeout(done,30));assert.equal(secondSettled,false);}finally{release();}
  const results=await Promise.all([first,second]);assert.deepEqual(results.map(value=>value.status),[200,200]);assert.equal((await resourceEffects(f.resourceStore)).length,2);assert.equal(f.ledgerFixture.status().acceptedReceipts,6);assert.equal(f.gateway.runtime.runtimePreflight.status().authorized,2);
});

test('a warmup authority failure returns a detailed INVALID artifact instead of losing its counts and effects',async()=>{
  const report=await runCapacityMeasurement({version:1,mode:'smoke',planningPeakRps:1,warmupMs:100,sustainedMs:1,soakMs:1,saturationMs:1,saturationRates:[4],documents:{count:1,bytes:128}},{implementation:async()=> 'a'.repeat(64),fixtureFactory:async(options)=>{const fixture=await createProductFixture(options);return {...fixture,agent:{async call(){return {status:403,body:{error:{code:'TASK_EXPIRED'}}};}}};}});
  assert.equal(report.status,'INVALID');assert.equal(report.invalidReason,'TASK_EXPIRED');assert.equal(report.cohorts.length,0);assert.equal(report.invalidWarmup.counts.issued,1);assert.equal(report.invalidWarmup.statuses['403'],1);assert.equal(report.invalidWarmup.effects.observed,0);assert.equal(report.invalidWarmup.events[0].code,'TASK_EXPIRED');assert.equal(report.firstFailingConstraint.kind,'warmup');assert.equal(JSON.parse(JSON.stringify(report)).sourceDigest,'a'.repeat(64));
});
