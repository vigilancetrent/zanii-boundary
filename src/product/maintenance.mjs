import { AppError } from '../protocol.mjs';
import { MAINTENANCE_KINDS } from './jobs.mjs';

/** Compose only named safe maintenance handlers; business execution cannot be registered. */
export function createMaintenanceHandlers(handlers){
  const result={};for(const [kind,handler]of Object.entries(handlers)){if(!MAINTENANCE_KINDS.includes(kind)||typeof handler!=='function')throw new AppError(400,'INVALID_MAINTENANCE_HANDLER');result[kind]=async(job,context)=>{if(job.kind!==kind||job.version!==1)throw new AppError(400,'INVALID_MAINTENANCE_JOB');return handler(job,context);};}return Object.freeze(result);
}
