import { X509Certificate } from 'node:crypto';
import { z } from 'zod';
import { AppError, exactObject, identifier } from '../protocol.mjs';
import { asAsyncStore } from './async-store.mjs';
import { assertProductIdentity, hashCanonical } from './policy.mjs';
import { parseOperationsPolicy } from './operations-config.mjs';
import { privacyRequestKey } from './privacy.mjs';

function operator(identity, required) {
  assertProductIdentity(identity, ['operator']);
  if (identity.roles.includes('agent') || !identity.scopes?.includes(required)) throw new AppError(403, 'OPERATOR_SCOPE_DENIED');
}
const pagination = z.object({ limit: z.number().int().min(1).max(100).default(25), after: z.string().max(512).optional() }).strict();
const age = (timestamp, now) => Number.isSafeInteger(timestamp) && timestamp <= now && timestamp > 0 ? now - timestamp : null;

/** Read-only health is also an admission predicate. Required outages cannot be bypassed by calling the executor directly.
 * @param {any} options Trusted service ports, never request-selected implementations.
 */
export function createRuntimeOperations({ store, policy, jobs, privacy, privacyAccess, archive, backup, alerts, objects, workerStatus, roleStatus, localStatus, now = Date.now,
  observability, certificate, drain = () => false } = {}) {
  store = asAsyncStore(store); const settings = parseOperationsPolicy(policy);
  const required = (name) => settings[name]?.required ?? (name === 'worker' && settings.required);
  const emit = (name, value) => { if (typeof value === 'number' && Number.isFinite(value)) observability?.signal?.(name, Math.max(0, value)); else observability?.signalUnavailable?.(name); };
  /** @param {any} work @param {any} absent */
  const probe = async (work, absent = { configured: false, healthy: false }) => {
    if (!work) return absent;
    try { return await work(); } catch { return { configured: true, healthy: false, code: 'OPERATIONAL_DEPENDENCY_UNAVAILABLE' }; }
  };
  async function status(identity) {
    assertProductIdentity(identity);
    const [database, epoch, tenantQueue, heartbeat, archiveState, backupState, objectState, recovery, roles, local] = await Promise.all([
      probe(store.health && (() => store.health()), { healthy: true, backend: store.backend ?? 'sqlite' }),
      probe(store.keyEpoch && (() => store.keyEpoch()), { frozen: false, legacy: true }),
      probe(jobs?.status && (() => jobs.status(identity.tenantId))),
      probe(workerStatus && (() => workerStatus(identity.tenantId))),
      probe(archive?.status && (() => archive.status(identity))),
      probe(backup?.status && (() => backup.status(identity))),
      probe(objects && (async () => { if (!objects.status().ready) await objects.verifyBucketPolicy(); return objects.status(); })),
      probe(store.restoreStatus && (() => store.restoreStatus()), { quarantined: false, sourceFencePending: false, requiresReauthorization: false }),
      probe(roleStatus && (() => roleStatus()), {}),
      probe(localStatus && (() => localStatus()), { required: false, healthy: true }),
    ]);
    const time = now();
    const queue = identity.scopes?.includes('runtime:health') && !identity.scopes?.includes('runtime:invoke')
      ? heartbeat?.queueSummary ?? tenantQueue : tenantQueue;
    const heartbeatAgeMs = age(heartbeat?.at ?? heartbeat?.lastHeartbeatAt, time);
    const archiveAgeMs = age(archiveState?.lastArchivedAt ?? archiveState?.at, time);
    const backupAgeMs = age(backupState?.lastVerifiedAt ?? backupState?.at, time);
    const backupSnapshotAgeMs = age(backupState?.capturedAt ?? backupState?.lastSnapshotAt, time);
    const queuePending = queue?.queued === undefined ? undefined : queue.queued + queue.retry + queue.running;
    const queueDead = queue?.dead;
    const queueOldest = queue?.queued === undefined ? undefined : queue?.oldestDueAt == null ? 0 : Math.max(0, time - queue.oldestDueAt);
    emit('jobs_pending', queuePending); emit('jobs_dlq', queueDead);
    emit('jobs_oldest_age_seconds', queueOldest === undefined ? undefined : queueOldest / 1000);
    emit('worker_heartbeat_age_seconds', heartbeatAgeMs === null ? undefined : heartbeatAgeMs / 1000);
    emit('archive_age_seconds', archiveAgeMs === null ? undefined : archiveAgeMs / 1000);
    emit('backup_age_seconds', backupAgeMs === null || backupSnapshotAgeMs === null ? undefined : Math.max(backupAgeMs, backupSnapshotAgeMs) / 1000);
    if (backupSnapshotAgeMs !== null) emit('backup_snapshot_age_seconds', backupSnapshotAgeMs / 1000); else observability?.signalUnavailable?.('backup_snapshot_age_seconds');
    if (backupAgeMs !== null) emit('backup_verification_age_seconds', backupAgeMs / 1000); else observability?.signalUnavailable?.('backup_verification_age_seconds');
    emit('backup_max_age_seconds', (settings.backup?.maxAgeMs ?? 86400000) / 1000); emit('archive_max_age_seconds', (settings.archive?.maxAgeMs ?? 3600000) / 1000);
    for (const [field, metric] of [['total', 'db_pool_total'], ['idle', 'db_pool_idle'], ['waiting', 'db_pool_waiting'], ['maximum', 'db_pool_max']])
      emit(metric, database?.pool?.[field]);
    if (certificate) emit('certificate_expiry_seconds', (Date.parse(new X509Certificate(certificate).validTo) - time) / 1000);
    const workerHealthy = heartbeat?.healthy !== false && !['error', 'stopped'].includes(heartbeat?.state) && heartbeatAgeMs !== null
      && heartbeatAgeMs <= (settings.worker?.maxHeartbeatAgeMs ?? 60000)
      && Number.isSafeInteger(queueDead) && queueDead <= (settings.worker?.maxDeadLetters ?? 0)
      && Number.isSafeInteger(queuePending) && (queuePending === 0 || Number.isSafeInteger(queueOldest) && queueOldest <= (settings.worker?.maxPendingAgeMs ?? 300000));
    const roleHealthy = (role) => {
      const state = roles?.[role]; const elapsed = age(state?.at, time); const counts = state?.queueSummary;
      const healthy = ['idle', 'running'].includes(state?.state) && elapsed !== null && elapsed <= (settings.worker?.maxHeartbeatAgeMs ?? 60000)
        && counts?.dead === 0 && (counts?.oldestDueAt == null || time - counts.oldestDueAt <= (settings.worker?.maxPendingAgeMs ?? 300000));
      observability?.maintenanceStatus?.({ role, healthy, required: Boolean(required(role)), heartbeatAgeMs: elapsed, counts, oldestAgeMs: counts?.oldestDueAt == null ? null : Math.max(0, time - counts.oldestDueAt) });
      return healthy;
    };
    if (roleStatus) roleHealthy('worker');
    const archiveRoleHealthy = roleStatus ? roleHealthy('archive') : true;
    const backupRoleHealthy = roleStatus ? roleHealthy('backup') : true;
    const archiveHealthy = archiveRoleHealthy && archiveState?.healthy !== false && archiveAgeMs !== null && archiveAgeMs <= (settings.archive?.maxAgeMs ?? 3600000);
    const backupHealthy = backupRoleHealthy && backupState?.healthy !== false && backupAgeMs !== null && backupSnapshotAgeMs !== null
      && Math.max(backupAgeMs, backupSnapshotAgeMs) <= (settings.backup?.maxAgeMs ?? 86400000);
    const blockers = [];
    if (drain()) blockers.push('SERVER_DRAINING');
    if (database?.healthy === false) blockers.push('DATABASE_UNAVAILABLE');
    if (epoch?.healthy === false || epoch?.frozen) blockers.push('KEY_EPOCH_UNAVAILABLE');
    if (recovery?.healthy === false || recovery?.quarantined || recovery?.sourceFencePending) blockers.push('RESTORE_QUARANTINED');
    if (required('worker') && !workerHealthy) blockers.push('REQUIRED_WORKER_UNAVAILABLE');
    if (required('archive') && !archiveHealthy) blockers.push('REQUIRED_ARCHIVE_UNAVAILABLE');
    if (required('backup') && !backupHealthy) blockers.push('REQUIRED_BACKUP_UNAVAILABLE');
    if (objects && (objectState?.ready !== true || objectState?.dependency?.state === 'open')) blockers.push('OBJECT_STORAGE_UNAVAILABLE');
    if (local?.required && !local?.healthy) blockers.push('REQUIRED_LOG_SINK_UNAVAILABLE');
    if (objectState?.dependency) observability?.dependencyState?.({ name: 'object-storage', state: objectState.dependency.state });
    return { ready: blockers.length === 0, blockers, database, keyEpoch: { version: epoch?.version, frozen: Boolean(epoch?.frozen), healthy: epoch?.healthy !== false },
      recovery: { quarantined: Boolean(recovery?.quarantined), requiresReauthorization: Boolean(recovery?.requiresReauthorization), sourceFencePending: Boolean(recovery?.sourceFencePending) },
      worker: { required: Boolean(required('worker')), healthy: workerHealthy, heartbeatAgeMs, queue },
      archive: { required: Boolean(required('archive')), healthy: archiveHealthy, ageMs: archiveAgeMs },
      backup: { required: Boolean(required('backup')), healthy: backupHealthy, ageMs: backupAgeMs, snapshotAgeMs: backupSnapshotAgeMs },
      objects: { configured: Boolean(objects), healthy: objectState?.ready === true },
      local: { required: Boolean(local?.required), healthy: local?.healthy !== false },
      alerts: alerts ? { configured: true } : { configured: false } };
  }
  /** @param {any} identity @param {any} context */
  async function gate(identity, context = {}) {
    const access = privacyAccess ?? privacy?.assertAccessible;
    await access?.(identity.tenantId, { kind: 'actor', id: identity.actorId });
    if (context.action?.documentId) await access?.(identity.tenantId, { kind: 'document', id: context.action.documentId });
    const state = await status(identity);
    if (!state.ready) throw new AppError(503, state.blockers[0]);
  }
  async function route(path, method, identity, body) {
    if (path === '/v1/ops/status' && method === 'GET') {
      operator(identity, 'runtime:operations'); return { body: await status(identity) };
    }
    if (path === '/v1/ops/jobs/list' && method === 'POST') {
      operator(identity, 'runtime:operations'); if (!jobs) throw new AppError(503, 'JOBS_UNCONFIGURED');
      return { body: await jobs.list(identity, pagination.parse(body)) };
    }
    if (path === '/v1/ops/jobs/retry' && method === 'POST') {
      operator(identity, 'runtime:operations:retry'); exactObject(body, ['id']); identifier(body.id);
      if (!jobs) throw new AppError(503, 'JOBS_UNCONFIGURED');
      return { body: await jobs.retryDead(identity, body.id) };
    }
    if (path.startsWith('/v1/ops/privacy/') && method === 'POST') {
      if (!privacy) throw new AppError(503, 'PRIVACY_UNCONFIGURED');
      if (path === '/v1/ops/privacy/request') {
        exactObject(body, ['kind', 'subject'], ['id']);
        if (!['export', 'delete'].includes(body.kind)) throw new AppError(400, 'INVALID_PRIVACY_REQUEST');
        operator(identity, `runtime:privacy:${body.kind}`);
        return { httpStatus: 202, body: await privacy.request(identity, body) };
      }
      if (path === '/v1/ops/privacy/status') {
        operator(identity, 'runtime:privacy'); exactObject(body, ['id']); identifier(body.id);
        return { body: await privacy.status(identity, body.id) };
      }
      if (path === '/v1/ops/privacy/export') {
        operator(identity, 'runtime:privacy:export'); exactObject(body, ['id'], ['limit', 'after']); identifier(body.id);
        const options = pagination.parse({ ...(body.limit === undefined ? { limit: 10 } : { limit: body.limit }), ...(body.after ? { after: body.after } : {}) });
        if (options.limit > 10) throw new AppError(400, 'INVALID_EXPORT_PAGE');
        return { body: await privacy.exportPage(identity, body.id, options) };
      }
      if (path === '/v1/ops/privacy/holds') {
        operator(identity, 'runtime:privacy:hold'); exactObject(body, ['subject', 'reason'], ['id']); return { httpStatus: 201, body: await privacy.hold(identity, body) };
      }
      if (path === '/v1/ops/privacy/holds/release') {
        operator(identity, 'runtime:privacy:hold'); exactObject(body, ['id']); identifier(body.id);
        return { body: await privacy.releaseHold(identity, body.id) };
      }
      if (path === '/v1/ops/privacy/learning-reset') {
        operator(identity, 'runtime:privacy:rebuild'); exactObject(body, []); return { body: await privacy.resetLearning(identity) };
      }
    }
    throw new AppError(404, 'ROUTE_NOT_FOUND');
  }
  return Object.freeze({ jobs, privacy, gate, status, route, async close() { await alerts?.close?.(); await archive?.close?.(); await backup?.close?.(); } });
}

/** Only an authenticated prepared intent or sealed privacy request can authorize removal.
 * @param {any} options
 */
export function createObjectCleanupHandler({ store, objectStorage, privacy }) {
  const pointsTo = (value, reference, depth = 0) => {
    if (!value || typeof value !== 'object') return false;
    if (depth > 16) throw new AppError(503, 'REFERENCE_SCAN_CAPACITY');
    if (value.bucket === reference.bucket && value.key === reference.key && value.versionId === reference.versionId) return true;
    return Object.values(value).some((child) => pointsTo(child, reference, depth + 1));
  };
  return async (job) => {
    exactObject(job.payload, [], ['reference', 'intentId', 'privacyRequestId']);
    let { reference } = job.payload; const { intentId, privacyRequestId } = job.payload;
    if (Boolean(intentId) === Boolean(privacyRequestId)) throw new AppError(400, 'INVALID_OBJECT_CLEANUP');
    if (intentId) {
      identifier(intentId); const intent = await store.get(job.tenantId, 'object-intents', intentId);
      if (intent?.state === 'prepared') {
        if (!objectStorage.recoverUpload || !intent.upload) throw new AppError(503, 'OBJECT_UPLOAD_RECOVERY_REQUIRED');
        const recovered = await objectStorage.recoverUpload(intent.upload, { tenantId: job.tenantId });
        if (!recovered) throw new AppError(503, 'OBJECT_UPLOAD_RECOVERY_PENDING');
        await store.transaction(async () => {
          const current = await store.get(job.tenantId, 'object-intents', intentId);
          if (!current || current.state !== 'prepared' || hashCanonical(current.upload) !== hashCanonical(intent.upload)) throw new AppError(409, 'OBJECT_INTENT_CHANGED');
          await store.put(job.tenantId, 'object-intents', intentId, { ...current, state: 'uploaded', reference: recovered });
        }, { tenantId: job.tenantId }); reference = recovered;
      } else if (!reference) reference = intent?.reference;
    }
    if (!reference || typeof reference !== 'object' || reference.purpose !== 'document') throw new AppError(400, 'INVALID_OBJECT_CLEANUP');
    identifier(reference.id); identifier(job.tenantId);
    const sealed = await store.transaction(async () => {
      let intent;
      if (intentId) {
        identifier(intentId); intent = await store.get(job.tenantId, 'object-intents', intentId);
        if (!intent || !['uploaded', 'purging', 'deleted'].includes(intent.state) || hashCanonical(intent.reference) !== hashCanonical(reference)) throw new AppError(409, 'OBJECT_INTENT_NOT_ABANDONED');
        if (intent.state === 'deleted') return { alreadyDeleted: true };
      } else {
        identifier(privacyRequestId); const request = await store.get(job.tenantId, 'privacy', privacyRequestKey(privacyRequestId));
        if (!request || request.type !== 'request' || request.kind !== 'delete' || !['purging', 'cleanup-pending', 'done'].includes(request.state)) throw new AppError(409, 'PRIVACY_DELETION_NOT_SEALED');
      }
      for (const namespace of ['documents', 'deliveries', 'resource-operations']) {
        let after = ''; let pages = 0;
        do {
          if (++pages > 100) throw new AppError(503, 'REFERENCE_SCAN_CAPACITY');
          const page = await store.list(job.tenantId, namespace, { limit: 100, after });
          if (page.items.some((row) => pointsTo(row.value, reference))) throw new AppError(409, 'OBJECT_REFERENCE_STILL_LIVE');
          after = page.next;
        } while (after);
      }
      if (!privacy || !await privacy.canDeleteReference(job.tenantId, reference)) throw new AppError(409, 'OBJECT_DELETION_HELD');
      if (intentId) await store.put(job.tenantId, 'object-intents', intentId, { ...intent, state: 'purging' });
      return { alreadyDeleted: false, intent };
    }, { tenantId: job.tenantId });
    if (sealed.alreadyDeleted) return { removed: true };
    const result = await objectStorage.remove(reference, { tenantId: job.tenantId, id: reference.id, authorized: true });
    if (result?.removed !== true) throw new AppError(503, 'OBJECT_DELETION_UNCONFIRMED');
    if (privacyRequestId) await privacy.completeReference(job.tenantId, privacyRequestId, reference);
    if (intentId) await store.put(job.tenantId, 'object-intents', intentId, { ...sealed.intent, state: 'deleted' }, { expiresAt: Date.now() + 30 * 86400000 });
    return { removed: true };
  };
}

/** Shared by real HTTP and worker entrypoints; factories validate selected integrations before startup.
 * @param {any} options
 */
export async function createConfiguredOperations({ config, material, store, observability, telemetry, zanii, drain, ports = {} }) {
  const settings = config.operations ?? { services: config.services ?? {}, policy: config.policy };
  const services = settings.services ?? {}; const owned = []; const baseDirectory = material.baseDirectory ?? process.cwd();
  const result = { ...ports }; const role = config.role; const handlers = {}; const app = ['gateway', 'resource'].includes(role);
  const permitted = app ? ['privacy', ...(role === 'resource' ? ['objects'] : [])]
    : role === 'worker' ? ['objects', 'privacy', 'alerts', 'zanii', 'secrets'] : role === 'archive' ? ['archive', 'secrets'] : role === 'backup' ? ['backup', 'secrets'] : ['secrets'];
  if (Object.entries(services).some(([name, value]) => !permitted.includes(name) || !value || typeof value !== 'object' || Array.isArray(value))) throw new AppError(400, 'OPERATIONS_ROLE_CONFIGURATION_DENIED');
  try {
    if (services.secrets) {
      const { createConfiguredSecretProvider } = await import('./secret-provider.mjs');
      result.secrets ??= await createConfiguredSecretProvider(services.secrets, { baseDirectory }); owned.push(result.secrets);
    }
    if (role === 'archive') {
      if (!services.archive) throw new AppError(400, 'ARCHIVE_CONFIGURATION_REQUIRED');
      const { createConfiguredAuditArchive } = await import('./audit-archive.mjs');
      result.archive ??= await createConfiguredAuditArchive(services.archive, { store, baseDirectory }); owned.push(result.archive);
      handlers['audit-archive'] = (job) => { exactObject(job.payload, [], ['limit', 'through']); return result.archive.archive(job.tenantId, job.payload); };
      return { ...result, handlers, async close() { for (const service of owned.reverse()) await service?.close?.(); } };
    }
    if (role === 'backup') {
      if (!services.backup) throw new AppError(400, 'BACKUP_CONFIGURATION_REQUIRED');
      const { createConfiguredBackup } = await import('./backup.mjs');
      const { restorePostgresSnapshot } = await import('./postgres-store.mjs');
      result.backup ??= await createConfiguredBackup(services.backup, { store, baseDirectory, restoreSnapshot: restorePostgresSnapshot }); owned.push(result.backup);
      handlers.backup = (job) => { exactObject(job.payload, [], ['id']); return result.backup.backup(job.tenantId, { ...job.payload, id: job.payload.id ?? job.id }); };
      return { ...result, handlers, async close() { for (const service of owned.reverse()) await service?.close?.(); } };
    }
    if (role === 'worker' || Object.keys(services).length || config.operations) {
      const { createJobService } = await import('./jobs.mjs');
      result.jobs ??= createJobService({ store, ...(config.worker?.ownerId ? { ownerId: config.worker.ownerId } : {}), ...(config.worker?.leaseMs ? { leaseMs: config.worker.leaseMs } : {}) });
    }
    let privacyGuard;
    if (app || role === 'worker') {
      const { createPrivacyService } = await import('./privacy.mjs');
      const privacyPolicy = z.object({ retentionMs: z.record(z.string(), z.number().int().positive()).optional(), exportLifetimeMs: z.number().int().min(60000).max(86400000).optional() }).strict().parse(services.privacy ?? {});
      privacyGuard = result.privacy ?? createPrivacyService({ store, jobs: result.jobs, policy: privacyPolicy, realm: config.realm ?? config.role,
        readReference: (reference, context) => { if (!result.objects) throw new AppError(503, 'PRIVACY_OBJECT_SOURCE_UNAVAILABLE'); return result.objects.get(reference, context); },
        authorize: async (identity, action) => operator(identity, ({ 'privacy.export': 'runtime:privacy:export', 'privacy.delete': 'runtime:privacy:delete',
          'privacy.hold': 'runtime:privacy:hold', 'privacy.hold.release': 'runtime:privacy:hold', 'privacy.status': 'runtime:privacy', 'privacy.learning.reset': 'runtime:privacy:rebuild' })[action] ?? 'runtime:privacy:denied') });
      if (services.privacy) result.privacy = privacyGuard;
      result.privacyAccess = privacyGuard.assertAccessible;
      result.privacyRetentionStatus = privacyGuard.retentionStatus;
      result.privacyHold = privacyGuard.assertUnheld;
    }
    if (services.alerts) {
      const { createConfiguredAlertDelivery } = await import('./alerts.mjs');
      result.alerts ??= await createConfiguredAlertDelivery(services.alerts, { baseDirectory }); owned.push(result.alerts);
    }
    if (services.objects) {
      const { createConfiguredObjectStorage } = await import('../adapters/object-storage.mjs');
      result.objects ??= await createConfiguredObjectStorage(services.objects, { baseDirectory }); owned.push(result.objects);
    }
    if (services.zanii) {
      const { createConfiguredZaniiLedger } = await import('../adapters/zanii.mjs');
      zanii ??= await createConfiguredZaniiLedger({ store, config: services.zanii, baseDirectory }); owned.push(zanii);
    }
    if (!result.archive && store.archiveStatus) result.archive = { async status(identity) {
      const state = await store.archiveStatus(identity.tenantId);
      return { configured: state.configured, lastArchivedAt: state.signedManifest?.manifest?.createdAt, healthy: true };
    } };
    if (!result.backup && store.backupStatus) result.backup = { async status(identity) {
      const state = await store.backupStatus(identity.tenantId);
      return { configured: state.configured, lastVerifiedAt: state.lastSuccessAt, capturedAt: state.lastSnapshotAt, healthy: !state.truncated };
    } };
    let roleRun;
    result.roleStatus ??= store.workerStatus && (() => roleRun ??= (async () => {
      const page = await store.workerStatus({ limit: 100 }); const items = Array.isArray(page) ? page : page.items; const roles = {};
      for (const item of items ?? []) { const role = item.role ?? 'worker'; if (['worker', 'archive', 'backup'].includes(role) && (!roles[role] || item.at > roles[role].at)) roles[role] = item; }
      return roles;
    })().finally(() => { roleRun = null; }));
    result.workerStatus ??= result.roleStatus && (async () => (await result.roleStatus()).worker ?? { healthy: false });
    const runtime = createRuntimeOperations({ ...result, store, policy: settings.policy, observability, drain, certificate: material.tls?.cert });
    if (role === 'worker') {
      handlers.retention = async (job) => {
        exactObject(job.payload, []); const time = Date.now(); const before = time - (config.storage.retentionMs ?? 86400000);
        return store.transaction(async () => {
          if ((await privacyGuard.retentionStatus(job.tenantId)).held) return { held: true, expired: 0, operations: 0 };
          return { expired: await store.purgeExpired(time, { tenantId: job.tenantId, limit: 100 }),
            operations: await store.pruneOperationResults(job.tenantId, { before, limit: 100, now: time }), privacy: await privacyGuard.retain(job.tenantId, { limit: 100 }) };
        }, { tenantId: job.tenantId });
      };
      if (zanii) handlers['receipt-recovery'] = async (job) => {
        exactObject(job.payload, []); return { outcomes: await zanii.recover({ tenantId: job.tenantId, actorId: 'maintenance', roles: ['operator'] }) };
      };
      handlers['privacy-export'] = handlers['privacy-delete'] = (job) => privacyGuard.process(job);
      if (result.objects) handlers['object-cleanup'] = createObjectCleanupHandler({ store, objectStorage: result.objects, privacy: privacyGuard });
      if (result.alerts) handlers['alert-delivery'] = async (job) => { exactObject(job.payload, ['event']); return result.alerts.deliver(job.payload.event); };
    }
    async function schedule(tenantId) {
      identifier(tenantId); const bucket = Math.floor(Date.now() / 60000);
      await result.jobs.enqueue(tenantId, { kind: 'retention', payload: {}, idempotencyKey: `retention-${bucket}` });
      if (zanii) await result.jobs.enqueue(tenantId, { kind: 'receipt-recovery', payload: {}, idempotencyKey: `receipts-${bucket}` });
    }
    async function onAlert(alarm) {
      if (!result.alerts) return;
      const { createAlertEvent } = await import('./alerts.mjs');
      identifier(alarm.idempotencyKey);
      return store.transaction(async () => {
        const prior = await store.get(alarm.tenantId, 'incidents', alarm.idempotencyKey);
        const event = prior?.alert ?? createAlertEvent({ key: material.auditKey, tenantId: alarm.tenantId, id: alarm.idempotencyKey,
          kind: 'job-dead-letter', code: /^[A-Z][A-Z0-9_]{0,63}$/.test(alarm.code ?? '') ? alarm.code : 'MAINTENANCE_HANDLER_FAILED' });
        if (!prior) await store.put(alarm.tenantId, 'incidents', alarm.idempotencyKey, { alert: event, at: event.occurredAt }, { expiresAt: event.occurredAt + 30 * 86400000 });
        return result.jobs.enqueue(alarm.tenantId, { kind: 'alert-delivery', payload: { event }, idempotencyKey: alarm.idempotencyKey });
      }, { tenantId: alarm.tenantId });
    }
    return { ...runtime, ...result, handlers, schedule, onAlert, telemetry, zanii,
      async close() { for (const service of owned.reverse()) await service?.close?.(); } };
  } catch (error) { for (const service of owned.reverse()) await service?.close?.(); throw error; }
}
