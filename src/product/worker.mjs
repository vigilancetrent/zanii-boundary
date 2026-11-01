import { randomUUID } from 'node:crypto';
import { AppError, identifier, positiveInteger } from '../protocol.mjs';
import { MAINTENANCE_KINDS } from './jobs.mjs';
import { runJobContext } from './context.mjs';

/** This module has no executor/provider-dispatch dependency. Handlers are explicitly installed. */
/** @param {any} options */
export function createMaintenanceWorker({ store, jobs, handlers, ownerId = randomUUID(), timeoutMs = 20000, pollMs = 1000, batchSize = 10, onAlert = async () => {}, schedule = async () => {}, telemetry = undefined, onEvent=()=>true, loggingStatus=()=>null }) {
  identifier(ownerId); positiveInteger(timeoutMs, 3600000); positiveInteger(pollMs, 3600000); positiveInteger(batchSize, 100);
  for (const [kind, handler] of Object.entries(handlers)) if (!MAINTENANCE_KINDS.includes(kind) || typeof handler !== 'function') throw new AppError(400, 'INVALID_MAINTENANCE_HANDLER');
  let closing = false; let timer; let active; let last = null; let queueSummary; const controllers = new Set();
  const event=(value)=>{try{onEvent({at:new Date().toISOString(),level:value.state==='failed'||value.state==='error'?'error':'info',...value});}catch{/* Log failure is exposed through the configured sink status, never a business replay. */}};
  const heartbeat = async (state, error = null) => {const logging=loggingStatus();last = { version: 1, ownerId, state, at: Date.now(), error, ...(queueSummary?{queueSummary}:{}),...(logging?{logging:{required:logging.required,healthy:logging.healthy}}:{}) }; if(store.writeRoleHeartbeat)await store.writeRoleHeartbeat(last);else await store.put('system', 'metadata', `worker-${ownerId}`, last);event({event:'maintenance.worker',state,...(error?{code:error}:{})}); };
  const run = async (claim) => {
    const handler = handlers[claim.job.kind]; const controller = new AbortController(); controllers.add(controller); let renewal; let renewing = false;
    const timeout = setTimeout(() => controller.abort(new AppError(503, 'MAINTENANCE_TIMEOUT')), timeoutMs);
    const renew = async () => { if (renewing || controller.signal.aborted) return; renewing = true; try { await jobs.renew(claim); } catch (error) { controller.abort(error); } finally { renewing = false; } };
    renewal = setInterval(renew, Math.max(10, Math.floor(jobs.leaseMs / 3))); renewal.unref?.();
    try {
      if (claim.job.version !== 1 || !handler) throw new AppError(400, 'MAINTENANCE_HANDLER_UNAVAILABLE');
      await jobs.renew(claim);
      event({event:'maintenance.job',state:'started',kind:claim.job.kind,...(claim.job.trace??{})});
      const result = await Promise.race([
        runJobContext(claim.job.trace ?? { requestId: claim.job.id }, { timeoutMs }, () => { const invoke=()=>handler(claim.job,{signal:controller.signal,idempotencyKey:claim.job.id,lease:claim.lease});const work=()=>store.withMaintenanceLease?store.withMaintenanceLease(claim,invoke):invoke();return telemetry?telemetry.span('maintenance.job',{'runtime.job.kind':claim.job.kind,'runtime.job.attempt':claim.job.attempts},work):work(); }),
        new Promise((_, reject) => controller.signal.addEventListener('abort', () => reject(controller.signal.reason), { once: true })),
      ]);
      if (controller.signal.aborted) throw controller.signal.reason;
      await jobs.complete(claim, result ?? null);
      event({event:'maintenance.job',state:'succeeded',kind:claim.job.kind,...(claim.job.trace??{})});
    } catch (error) {
      event({event:'maintenance.job',state:'failed',kind:claim.job.kind,code:error instanceof AppError?error.code:'MAINTENANCE_HANDLER_FAILED',...(claim.job.trace??{})});
      try { await jobs.fail(claim, error, { retryable: !(error instanceof AppError) || error.status === 429 || error.status >= 500 }); }
      catch (failure) { if (!['LEASE_LOST', 'JOB_CLAIM_LOST'].includes(failure instanceof AppError?failure.code:'')) throw failure; }
    } finally { clearTimeout(timeout); clearInterval(renewal); controllers.delete(controller); }
  };
  const tick = async () => {
    if (closing) return { closed: true }; if (active) return active;
    active = (async () => {
      await heartbeat('running'); let after = ''; let processed = 0;let heartbeatBusy=false;let heartbeatPending=Promise.resolve();const heartbeatTimer=setInterval(()=>{if(heartbeatBusy)return;heartbeatBusy=true;heartbeatPending=(async()=>{try{await heartbeat('running');}catch{for(const controller of controllers)controller.abort(new AppError(503,'WORKER_HEARTBEAT_FAILED'));}finally{heartbeatBusy=false;}})();},Math.max(10,Math.min(10000,Math.floor(jobs.leaseMs/3))));heartbeatTimer.unref?.();try{
      queueSummary={queued:0,retry:0,running:0,dead:0,done:0,due:0,oldestDueAt:null};
      const visit = async (tenant) => { await jobs.compact(tenant,{limit:100});await schedule(tenant); for(let index=0;index<batchSize&&!closing;index++){const [claim]=await jobs.claim(tenant,{limit:1,kinds:Object.keys(handlers)});if(!claim)break;await run(claim);processed++;}
        for(const dead of await jobs.deadAlerts(tenant,{limit:100})){if(dead.kind!=='alert-delivery')await onAlert({type:'maintenance.dead',tenantId:tenant,jobId:dead.id,code:dead.error,idempotencyKey:`dead-${dead.id}-${dead.replayCount??0}`});await jobs.acknowledgeDeadAlert(tenant,dead.id);}
        const status=await jobs.status(tenant);for(const key of ['queued','retry','running','dead','done','due'])queueSummary[key]+=status[key];if(status.oldestDueAt!==null)queueSummary.oldestDueAt=Math.min(queueSummary.oldestDueAt??Infinity,status.oldestDueAt);
      };
      await visit('system');
      do { const page = await store.listTenants({ after, limit: 100 }); for (const tenant of page.items) { if (closing) break; if(tenant!=='system')await visit(tenant); } after = page.next; } while (after && !closing);
      clearInterval(heartbeatTimer);await heartbeatPending;await heartbeat('idle'); return { processed };}finally{clearInterval(heartbeatTimer);await heartbeatPending;}
    })().catch(async (error) => { await heartbeat('error', typeof error?.code === 'string' ? error.code : 'WORKER_FAILURE'); throw error; }).finally(() => { active = null; });
    return active;
  };
  return Object.freeze({ tick, start() { if (timer || closing) return; const loop = async () => { try { await tick(); } catch { /* Durable error heartbeat is consumed by readiness. */ } if (!closing) timer = setTimeout(loop, pollMs); }; timer = setTimeout(loop, 0); }, status: () => last, async close() { closing = true; clearTimeout(timer); for (const controller of controllers) controller.abort(new AppError(503, 'WORKER_SHUTDOWN')); if (active) await active.catch(() => {}); await heartbeat('stopped'); } });
}
