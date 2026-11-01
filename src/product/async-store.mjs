import { AsyncLocalStorage } from 'node:async_hooks';
import { openStore, OWNED_SQLITE_TRANSACTION,BOUNDED_SQLITE_CALL } from './store.mjs';
import { AppError } from '../protocol.mjs';
import { effectiveDeadline } from './context.mjs';

const wrappers = new WeakMap();

/** One queue protects every call, not just transactions, while an async owner holds SQLite. */
export function asAsyncStore(store) {
  if (!store || typeof store.get !== 'function') throw new AppError(400, 'INVALID_ASYNC_STORE');
  if (store.async === true) return store;
  if (wrappers.has(store)) return wrappers.get(store);
  const context = new AsyncLocalStorage(); let tail = Promise.resolve(); let closed = false; let closing;
  const bind = (tenantId) => {
    const owner = context.getStore();
    if (tenantId && owner.tenantId && owner.tenantId !== tenantId) throw new AppError(403, 'TENANT_TRANSACTION_MISMATCH');
    if (tenantId) owner.tenantId = tenantId;
  };
  const owned = (work) => {
    if (closed) return Promise.reject(new AppError(503, 'STORE_CLOSED'));
    const current = context.getStore();
    if (current?.active) return Date.now() >= current.deadlineAt ? Promise.reject(new AppError(503, 'DATABASE_TIMEOUT')) : Promise.resolve().then(work);
    let deadlineAt;
    try { deadlineAt = effectiveDeadline({ timeoutMs: store.transactionTimeoutMs ?? 5000 }); } catch (error) { return Promise.reject(error); }
    const owner = { active: true, deadlineAt }; let expired = false; let timer;
    const run = tail.then(() => { if (closed) throw new AppError(503, 'STORE_CLOSED'); if (expired || Date.now() >= deadlineAt) throw new AppError(503, 'DATABASE_ACQUIRE_TIMEOUT'); return context.run(owner, work); });
    tail = run.catch(() => {});
    const finished = run.finally(() => { owner.active = false; });
    return Promise.race([finished, new Promise((_, reject) => { timer = setTimeout(() => { expired = true; reject(new AppError(503, 'DATABASE_TIMEOUT')); }, Math.max(1, deadlineAt - Date.now())); timer.unref?.(); })]).finally(() => clearTimeout(timer));
  };
  const result = { async: true, backend: 'sqlite', shared: false, path: store.path };
  const rawCall=(work)=>{const deadlineAt=effectiveDeadline({deadlineAt:context.getStore().deadlineAt,timeoutMs:store.transactionTimeoutMs??5000});return store[BOUNDED_SQLITE_CALL]?store[BOUNDED_SQLITE_CALL](work,{deadlineAt}):work();};
  for (const [name, value] of Object.entries(store)) if (typeof value === 'function') {
    if(name==='withMaintenanceLease'){result[name]=value.bind(store);continue;}
    result[name] = (...args) => owned(() => {
      const tenant = ['get', 'put', 'list', 'delete', 'getOperation', 'transitionOperation', 'verifyAudit', 'checkpoint', 'queryAudit', 'exportAudit', 'pruneOperationResults', 'recoverUnknown', 'listOperations', 'claimLease', 'queryPlans', 'getJobTombstone', 'putJobTombstone', 'pruneSubjectOperationResults', 'listDueJobs', 'listDeadJobs', 'jobStatus', 'readArchiveSegment', 'commitArchivedPrefix', 'exportSnapshot'].includes(name) ? args[0]
        : ['reserveOperation', 'appendAudit', 'assertLease', 'renewLease', 'releaseLease'].includes(name) ? args[0]?.tenantId
        : name === 'purgeExpired' ? args[1]?.tenantId : undefined;
      if (name === 'purgeExpired' && !tenant && context.getStore().tenantId) throw new AppError(403, 'TENANT_TRANSACTION_MISMATCH');
      bind(tenant); return rawCall(()=>value.apply(store, args));
    });
  }
  result.transaction = (work, { tenantId = undefined } = {}) => owned(() => { bind(tenantId); return rawCall(()=>store[OWNED_SQLITE_TRANSACTION]
    ? store[OWNED_SQLITE_TRANSACTION](work, { deadlineAt: context.getStore().deadlineAt }) : store.transaction(work)); });
  result.close = () => closing ??= owned(async () => { await rawCall(()=>store.close()); closed = true; });
  const frozen = Object.freeze(result); wrappers.set(store, frozen); return frozen;
}

export function openAsyncSqliteStore(options) { return asAsyncStore(openStore(options)); }

export async function openConfiguredStore({ config, material }) {
  if (config.storage.backend === 'postgres') {
    const { openPostgresStore } = await import('./postgres-store.mjs');
    return openPostgresStore({ ...config.storage.postgres, ...material.postgres, realm: config.role,
      encryptionKey: material.encryptionKey, auditKey: material.auditKey, keyring: material.keyring });
  }
  return openAsyncSqliteStore({ path: config.storage.path, encryptionKey: material.encryptionKey, auditKey: material.auditKey,
    keyring: material.keyring, busyTimeoutMs: Math.min(config.limits.requestTimeoutMs, 1000), transactionTimeoutMs: config.limits.requestTimeoutMs });
}
