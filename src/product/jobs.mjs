import { randomUUID } from 'node:crypto';
import { AppError, identifier, positiveInteger } from '../protocol.mjs';
import { jobTraceContext,parseTraceparent } from './context.mjs';
import { storeHash, storeJson } from './storage-crypto.mjs';

export const MAINTENANCE_KINDS = Object.freeze(['receipt-recovery', 'audit-archive', 'backup', 'retention', 'object-cleanup', 'privacy-export', 'privacy-delete', 'key-rotation', 'alert-delivery']);
const fail = (code, status = 400) => { throw new AppError(status, code); };
const tenantOf = (identity) => { const tenant = typeof identity === 'string' ? identity : identity?.tenantId; identifier(tenant); return tenant; };
const cleanError = (error) => typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]{0,79}$/.test(error.code) ? error.code : 'MAINTENANCE_HANDLER_FAILED';

/** Safe maintenance work only. Job identifiers double as downstream idempotency keys. */
export function createJobService({ store, ownerId = randomUUID(), now = Date.now, maxAttempts = 5, leaseMs = 30000, baseDelayMs = 1000, maxDelayMs = 300000, completedRetentionMs = 86400000, random = Math.random }) {
  positiveInteger(completedRetentionMs,2592000000); identifier(ownerId); positiveInteger(maxAttempts, 100); positiveInteger(leaseMs, 3600000); positiveInteger(baseDelayMs, 3600000); positiveInteger(maxDelayMs, 86400000);
  const owned = async (claim) => {
    if (!claim?.lease || !claim?.job) fail('INVALID_JOB_CLAIM');
    await store.assertLease(claim.lease, { now: now() });
    const job = await store.get(claim.lease.tenantId, 'jobs', claim.job.id);
    if (!job || job.state !== 'running' || job.ownerId !== claim.lease.ownerId || job.fence !== claim.lease.fence) fail('JOB_CLAIM_LOST', 409);
    return job;
  };
  const service = {
    async enqueue(identity, input) {
      const tenant = tenantOf(identity); const { kind, payload = {}, runAt = now(), idempotencyKey, trace = jobTraceContext() } = input;
      if (!MAINTENANCE_KINDS.includes(kind) || !payload || typeof payload !== 'object' || Array.isArray(payload)) fail('INVALID_MAINTENANCE_JOB');
      storeJson(payload, 8192); storeJson(trace, 2048);if(trace!==null){identifier(trace.requestId);if(Object.keys(trace).some(key=>!['requestId','traceparent'].includes(key))||trace.traceparent!==undefined&&!parseTraceparent(trace.traceparent))fail('INVALID_TRACE_CONTEXT');} positiveInteger(runAt);
      if (idempotencyKey !== undefined) identifier(idempotencyKey);
      const id = input.id ?? (idempotencyKey ? storeHash(storeJson([kind, idempotencyKey])) : randomUUID()); identifier(id);
      const digest = storeHash(storeJson({ kind, payload }));
      return store.transaction(async () => {
        const existing = await store.get(tenant, 'jobs', id) ?? (store.getJobTombstone?await store.getJobTombstone(tenant,id):null);
        if (existing) { if (existing.digest !== digest) fail('JOB_IDEMPOTENCY_CONFLICT', 409); return existing; }
        const job = { version: 1, id, tenantId: tenant, kind, payload, digest, trace, state: 'queued', attempts: 0, maxAttempts, dueAt: runAt, createdAt: now(), updatedAt: now(), error: null };
        await store.put(tenant, 'jobs', id, job); return job;
      }, { tenantId: tenant });
    },
    async claim(tenant, { limit = 1, kinds = MAINTENANCE_KINDS } = {}) {
      tenant = tenantOf(tenant); positiveInteger(limit, 100); if (!Array.isArray(kinds)||!kinds.length||kinds.some(kind=>!MAINTENANCE_KINDS.includes(kind))) fail('INVALID_MAINTENANCE_KIND');
      return store.transaction(async () => {
        const candidates = await store.listDueJobs(tenant, { now: now(), limit, kinds }); const claims = [];
        for (const candidate of candidates) {
          const lease = await store.claimLease(tenant, `job:${candidate.id}`, { ownerId, ttlMs: leaseMs, now: now() }); if (!lease) continue;
          const current = await store.get(tenant, 'jobs', candidate.id);
          if (!current || !['queued', 'retry', 'running'].includes(current.state) || current.dueAt > now()) { await store.releaseLease(lease); continue; }
          if (current.attempts >= current.maxAttempts) { await store.put(tenant, 'jobs', current.id, { ...current, state: 'dead', error: 'JOB_ATTEMPTS_EXHAUSTED', updatedAt: now() }); await store.releaseLease(lease); continue; }
          const job = { ...current, state: 'running', attempts: current.attempts + 1, ownerId, fence: lease.fence, dueAt: lease.expiresAt, updatedAt: now() };
          await store.put(tenant, 'jobs', job.id, job); claims.push({ job, lease });
        }
        return claims;
      }, { tenantId: tenant });
    },
    async renew(claim) {
      return store.transaction(async () => {
        const job = await owned(claim); const lease = await store.renewLease(claim.lease, { ttlMs: leaseMs, now: now() });
        if (!lease) fail('JOB_CLAIM_LOST', 409);
        await store.put(job.tenantId, 'jobs', job.id, { ...job, dueAt: lease.expiresAt, updatedAt: now() }); claim.lease = lease; return lease;
      }, { tenantId: claim.lease.tenantId });
    },
    async complete(claim, result = null) {
      storeJson(result, 8192);
      return store.transaction(async () => { const job = await owned(claim); const next = { ...job, state: 'done', result, updatedAt: now(), dueAt: now() }; if(store.putJobTombstone)await store.putJobTombstone(job.tenantId,{version:1,id:job.id,tenantId:job.tenantId,kind:job.kind,digest:job.digest,state:'done',completedAt:now(),expired:true});await store.put(job.tenantId, 'jobs', job.id, next,{expiresAt:now()+completedRetentionMs}); await store.releaseLease(claim.lease); return next; }, { tenantId: claim.lease.tenantId });
    },
    async fail(claim, error, { retryable = true } = {}) {
      return store.transaction(async () => {
        const job = await owned(claim); const dead = !retryable || job.attempts >= job.maxAttempts;
        const sample = random(); if (!Number.isFinite(sample) || sample < 0 || sample >= 1) fail('INVALID_JOB_JITTER');
        const delay = Math.floor(Math.min(maxDelayMs, baseDelayMs * 2 ** Math.min(job.attempts - 1, 30)) * (0.5 + sample * 0.5));
        const next = { ...job, state: dead ? 'dead' : 'retry', dueAt: dead ? now() : now() + delay, error: cleanError(error), updatedAt: now() };
        await store.put(job.tenantId, 'jobs', job.id, next); await store.releaseLease(claim.lease); return next;
      }, { tenantId: claim.lease.tenantId });
    },
    list(identity, options = {}) { return store.list(tenantOf(identity), 'jobs', options); },
    async retryDead(identity, id) {
      const tenant = tenantOf(identity); identifier(id);
      return store.transaction(async () => { const job = await store.get(tenant, 'jobs', id); if (!job || job.state !== 'dead') fail('JOB_NOT_DEAD', 409); const next = { ...job, state: 'queued', attempts: 0, dueAt: now(), error: null, replayCount: (job.replayCount ?? 0) + 1, updatedAt: now() }; await store.put(tenant, 'jobs', id, next); return next; }, { tenantId: tenant });
    },
    async compact(identity,{limit=100}={}){return store.compactCompletedJobs?store.compactCompletedJobs(tenantOf(identity),{now:now(),limit}):{compacted:0};},
    status(identity) { return store.jobStatus(tenantOf(identity), { now: now() }); },
    async deadAlerts(tenant,{limit=100}={}){return store.listDeadJobs(tenantOf(tenant),{now:now(),limit});},
    async acknowledgeDeadAlert(tenant,id){tenant=tenantOf(tenant);return store.transaction(async()=>{const job=await store.get(tenant,'jobs',id);if(!job||job.state!=='dead')return false;await store.put(tenant,'jobs',id,{...job,alertedAt:now(),dueAt:Number.MAX_SAFE_INTEGER});return true;},{tenantId:tenant});},
    leaseMs,
  };
  return Object.freeze(service);
}

/** Purpose-limited plaintext operational metadata; this port cannot access application ciphertext. */
export function createRoleJobService({store,...options}){if(typeof store.maintenanceStore!=='function'||!['archive','backup'].includes(store.role))fail('ROLE_JOB_AUTHORITY_REQUIRED');const jobs=createJobService({store:store.maintenanceStore(),...options});const kind=store.role==='archive'?'audit-archive':'backup';return Object.freeze({...jobs,async enqueue(identity,input){if(input.kind!==kind||Object.keys(input.payload??{}).length)fail('ROLE_JOB_PAYLOAD_DENIED',403);return jobs.enqueue(identity,input);}});}

/** Archive progress follows the durable prefix, so a fixed clock never throttles a backlog. */
export function createRoleMaintenanceSchedule({store,jobs,role,now=Date.now}){
  if(!['archive','backup'].includes(role))fail('ROLE_JOB_AUTHORITY_REQUIRED');
  return async(tenant)=>{
    if(role==='backup')return jobs.enqueue(tenant,{kind:'backup',payload:{},idempotencyKey:`backup-${Math.floor(now()/86400000)}`});
    const page=await store.readArchiveSegment(tenant,{limit:1});if(!page.rows.length)return null;
    return jobs.enqueue(tenant,{kind:'audit-archive',payload:{},idempotencyKey:`archive-${page.base.sequence}-${page.base.hash}`});
  };
}
