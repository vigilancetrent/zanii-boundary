import { AppError, exactObject, identifier, positiveInteger } from '../protocol.mjs';
import { boundedText } from './detector.mjs';
import { assertProductIdentity } from './policy.mjs';
import { highestSensitivity, LABELS, sensitivity } from './profiles.mjs';

/** Memory is data with provenance, never a source of execution authority. */
export function createMemoryService({ store, policy, now = Date.now, maxEntries = 64, maxLifetimeMs = 86_400_000 }) {
  positiveInteger(maxEntries, 100); positiveInteger(maxLifetimeMs, 604_800_000);
  return Object.freeze({
    remember(identity, taskId, value) {
      assertProductIdentity(identity, ['agent', 'operator']);
      exactObject(value, ['id', 'text', 'sourceId', 'label', 'expiresAt']);
      const task = policy.getTask(identity, taskId);
      const id = identifier(value.id); const sourceId = identifier(value.sourceId);
      const text = boundedText(value.text); const label = sensitivity(value.label);
      if (Buffer.byteLength(text) > 8_192) throw new AppError(400, 'MEMORY_TOO_LARGE');
      const expiresAt = positiveInteger(value.expiresAt);
      if (expiresAt <= now() || expiresAt > Math.min(task.expiresAt, now() + maxLifetimeMs)) throw new AppError(403, 'MEMORY_LIFETIME');
      return store.transaction(() => {
        policy.getTask(identity, taskId);
        const existing = store.get(identity.tenantId, 'memory', id);
        if (existing && (existing.rootTaskId !== task.rootTaskId || existing.actorId !== identity.actorId)) throw new AppError(403, 'MEMORY_DENIED');
        const count = store.list(identity.tenantId, 'memory', { limit: 100 }).items.length;
        if (!existing && count >= maxEntries) throw new AppError(429, 'MEMORY_QUOTA');
        const flow = store.get(identity.tenantId, 'flows', task.rootTaskId);
        const memory = { id, tenantId: identity.tenantId, rootTaskId: task.rootTaskId,
          actorId: identity.actorId, text, sourceId, trust: 'untrusted',
          sourceDocumentIds: [...new Set([...(flow?.documentIds ?? []), ...(task.documentIds.includes(sourceId) ? [sourceId] : [])])],
          label: highestSensitivity('internal', label, flow?.label ?? 'public'), createdAt: now(), expiresAt };
        store.put(identity.tenantId, 'memory', id, memory, { expiresAt });
        store.appendAudit({ tenantId: identity.tenantId, actorId: identity.actorId, event: 'memory.written',
          target: id, data: { rootTaskId: task.rootTaskId, label: memory.label, trust: memory.trust }, at: now() });
        return structuredClone(memory);
      });
    },
    read(identity, taskId, id) {
      assertProductIdentity(identity, ['agent', 'operator']);
      const task = policy.getTask(identity, taskId);
      const value = store.get(identity.tenantId, 'memory', identifier(id));
      if (!value || value.rootTaskId !== task.rootTaskId || value.tenantId !== identity.tenantId) throw new AppError(404, 'MEMORY_NOT_FOUND');
      if (value.expiresAt <= now()) throw new AppError(404, 'MEMORY_NOT_FOUND');
      if (!Array.isArray(value.sourceDocumentIds) || !value.sourceDocumentIds.every((source) => task.documentIds.includes(source))
          || LABELS.indexOf(sensitivity(value.label)) > LABELS.indexOf(task.maxSensitivity)) throw new AppError(403, 'MEMORY_SCOPE_DENIED');
      store.transaction(() => {
        const root = policy.rootContext(identity, taskId);
        const prior = store.get(identity.tenantId, 'flows', task.rootTaskId);
        store.put(identity.tenantId, 'flows', task.rootTaskId, {
          label: highestSensitivity(value.label, prior?.label ?? 'public'),
          documentIds: [...new Set([...(prior?.documentIds ?? []), ...value.sourceDocumentIds])], updatedAt: now(),
        }, { expiresAt: root.expiresAt });
      });
      return structuredClone(value);
    },
    remove(identity, taskId, id) {
      const task = policy.getTask(assertProductIdentity(identity, ['agent', 'operator']), taskId);
      const value = store.get(identity.tenantId, 'memory', identifier(id));
      if (!value || value.rootTaskId !== task.rootTaskId || (value.actorId !== identity.actorId && !identity.roles.includes('operator'))) {
        throw new AppError(403, 'MEMORY_DENIED');
      }
      store.transaction(() => {
        policy.getTask(identity, taskId);
        store.delete(identity.tenantId, 'memory', id);
        store.appendAudit({ tenantId: identity.tenantId, actorId: identity.actorId, event: 'memory.deleted', target: id, at: now() });
      });
      return { deleted: true };
    },
  });
}
