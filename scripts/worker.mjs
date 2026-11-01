import { pathToFileURL } from 'node:url';
import { AppError } from '../src/protocol.mjs';
import { loadOperationsConfig } from '../src/product/operations-config.mjs';
import { openPostgresStore } from '../src/product/postgres-store.mjs';
import { openAsyncSqliteStore } from '../src/product/async-store.mjs';
import { createRoleJobService,createRoleMaintenanceSchedule } from '../src/product/jobs.mjs';
import { createMaintenanceWorker } from '../src/product/worker.mjs';
import { createConfiguredOperations } from '../src/product/runtime-operations.mjs';
import { createConfiguredTelemetry,instrumentStore } from '../src/product/telemetry.mjs';
import { createConfiguredLogSink } from '../src/product/logging.mjs';

/** No HTTP issuer/signing material is loaded by a maintenance process. */
export async function startWorker(path,{once=false}={}){
  const {config,material}=await loadOperationsConfig(path);if(!['worker','archive','backup'].includes(config.role))throw new AppError(400,'USE_ROLE_MAINTENANCE_COMMAND');
  let store;let operations;let worker;let telemetry;let logSink;
  const close=async()=>{let failure;for(const service of [worker,operations,logSink,telemetry,store]){try{await service?.close();}catch(error){failure??=error;}}material.encryptionKey?.fill(0);material.auditKey?.fill(0);if(failure)throw failure;};
  try{
    if(config.telemetry)telemetry=await createConfiguredTelemetry(config.telemetry,{baseDirectory:material.baseDirectory});
    if(config.logging)logSink=await createConfiguredLogSink(config.logging,{baseDirectory:material.baseDirectory});
    store=config.storage.backend==='postgres'?await openPostgresStore({...config.storage.postgres,...material.postgres,realm:config.realm,role:config.role,encryptionKey:material.encryptionKey,auditKey:material.auditKey,keyring:material.keyring}):openAsyncSqliteStore({path:config.storage.path,encryptionKey:material.encryptionKey,auditKey:material.auditKey,keyring:material.keyring,role:'worker'});
    store=instrumentStore(store,telemetry);operations=await createConfiguredOperations({config,material,store,telemetry});
    const jobs=config.role==='worker'?operations.jobs:createRoleJobService({store,ownerId:config.worker.ownerId,leaseMs:config.worker.leaseMs});
    const roleSchedule=config.role==='worker'?operations.schedule:createRoleMaintenanceSchedule({store,jobs,role:config.role});
    const schedule=async(tenant)=>{const logs=logSink?.status();if(logs?.required&&!logs.healthy)throw new AppError(503,'LOG_SINK_UNAVAILABLE');return roleSchedule(tenant);};
    worker=createMaintenanceWorker({store,jobs,handlers:operations.handlers,ownerId:config.worker.ownerId,timeoutMs:config.worker.timeoutMs,pollMs:config.worker.pollIntervalMs,batchSize:config.worker.batchSize,schedule,onAlert:operations.onAlert??(async()=>{process.stderr.write(JSON.stringify({event:'maintenance.dead',role:config.role})+'\n');}),telemetry,onEvent:(record)=>logSink?.write(record),loggingStatus:()=>logSink?.status()});
    if(once){const result=await worker.tick();await close();return result;}
    worker.start();return {close,status:worker.status};
  }catch(error){await close().catch(()=>{});throw error;}
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
  let active;try{const [path,flag]=process.argv.slice(2);if(!path||flag&&flag!=='--once')throw new AppError(400,'WORKER_CONFIG_REQUIRED');active=await startWorker(path,{once:flag==='--once'});if(flag==='--once')process.stdout.write(JSON.stringify(active)+'\n');else for(const signal of ['SIGINT','SIGTERM'])process.once(signal,()=>{active.close().then(()=>{process.exitCode=0;},()=>{process.exitCode=1;});});}
  catch(error){process.stderr.write(JSON.stringify({error:error instanceof AppError?error.code:'WORKER_START_FAILED'})+'\n');process.exitCode=1;}
}
