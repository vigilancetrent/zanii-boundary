import { asAsyncStore } from './async-store.mjs';
import { AppError, exactObject, identifier, positiveInteger } from '../protocol.mjs';
import { boundedText } from './detector.mjs';
import { assertProductIdentity } from './policy.mjs';
import { highestSensitivity, LABELS, sensitivity } from './profiles.mjs';
/** Memory is data with provenance, never a source of execution authority. */
export function createMemoryService({ store, policy, assertAccessible = undefined, assertUnheld = undefined, now = Date.now, maxEntries = 64, maxLifetimeMs = 86400000 }) {
    store = asAsyncStore(store);
    positiveInteger(maxEntries, 100);
    positiveInteger(maxLifetimeMs, 604800000);
    const access = async (identity, sources = []) => {
        await assertAccessible?.(identity.tenantId, { kind: 'actor', id: identity.actorId });
        for (const id of sources) await assertAccessible?.(identity.tenantId, { kind: 'document', id });
    };
    return Object.freeze({
        async remember(identity, taskId, value) {
            assertProductIdentity(identity, ['agent', 'operator']);
            exactObject(value, ['id', 'text', 'sourceId', 'label', 'expiresAt']);
            const task = (await policy.getTask(identity, taskId));
            const id = identifier(value.id);
            const sourceId = identifier(value.sourceId);
            const text = boundedText(value.text);
            const label = sensitivity(value.label);
            if (Buffer.byteLength(text) > 8192)
                throw new AppError(400, 'MEMORY_TOO_LARGE');
            const expiresAt = positiveInteger(value.expiresAt);
            if (expiresAt <= now() || expiresAt > Math.min(task.expiresAt, now() + maxLifetimeMs))
                throw new AppError(403, 'MEMORY_LIFETIME');
            return (await store.transaction(async () => {
                (await policy.getTask(identity, taskId));
                const existing = (await store.get(identity.tenantId, 'memory', id));
                if (existing && (existing.rootTaskId !== task.rootTaskId || existing.actorId !== identity.actorId))
                    throw new AppError(403, 'MEMORY_DENIED');
                if (existing) await assertUnheld?.(identity.tenantId, { actorIds: [existing.actorId], documentIds: existing.sourceDocumentIds ?? [] });
                const count = (await store.list(identity.tenantId, 'memory', { limit: 100 })).items.length;
                if (!existing && count >= maxEntries)
                    throw new AppError(429, 'MEMORY_QUOTA');
                const flow = (await store.get(identity.tenantId, 'flows', task.rootTaskId));
                const memory = { id, tenantId: identity.tenantId, rootTaskId: task.rootTaskId,
                    actorId: identity.actorId, text, sourceId, trust: 'untrusted',
                    sourceDocumentIds: [...new Set([...(flow?.documentIds ?? []), ...(task.documentIds.includes(sourceId) ? [sourceId] : [])])],
                    label: highestSensitivity('internal', label, flow?.label ?? 'public'), createdAt: now(), expiresAt };
                await access(identity, memory.sourceDocumentIds);
                (await store.put(identity.tenantId, 'memory', id, memory, { expiresAt }));
                (await store.appendAudit({ tenantId: identity.tenantId, actorId: identity.actorId, event: 'memory.written',
                    target: id, data: { rootTaskId: task.rootTaskId, label: memory.label, trust: memory.trust }, at: now() }));
                return structuredClone(memory);
            }, { tenantId: identity.tenantId }));
        },
        async read(identity, taskId, id) {
            assertProductIdentity(identity, ['agent', 'operator']);
            const task = (await policy.getTask(identity, taskId));
            const value = (await store.get(identity.tenantId, 'memory', identifier(id)));
            if (!value || value.rootTaskId !== task.rootTaskId || value.tenantId !== identity.tenantId)
                throw new AppError(404, 'MEMORY_NOT_FOUND');
            if (value.expiresAt <= now())
                throw new AppError(404, 'MEMORY_NOT_FOUND');
            if (!Array.isArray(value.sourceDocumentIds) || !value.sourceDocumentIds.every((source) => task.documentIds.includes(source))
                || LABELS.indexOf(sensitivity(value.label)) > LABELS.indexOf(task.maxSensitivity))
                throw new AppError(403, 'MEMORY_SCOPE_DENIED');
            (await store.transaction(async () => {
                await access(identity, value.sourceDocumentIds);
                if (value.actorId) await assertAccessible?.(identity.tenantId, { kind: 'actor', id: value.actorId });
                const root = (await policy.rootContext(identity, taskId));
                const prior = (await store.get(identity.tenantId, 'flows', task.rootTaskId));
                (await store.put(identity.tenantId, 'flows', task.rootTaskId, {
                    label: highestSensitivity(value.label, prior?.label ?? 'public'),
                    documentIds: [...new Set([...(prior?.documentIds ?? []), ...value.sourceDocumentIds])], updatedAt: now(),
                }, { expiresAt: root.expiresAt }));
            }, { tenantId: identity.tenantId }));
            return structuredClone(value);
        },
        async remove(identity, taskId, id) {
            const task = (await policy.getTask(assertProductIdentity(identity, ['agent', 'operator']), taskId));
            const value = (await store.get(identity.tenantId, 'memory', identifier(id)));
            if (!value || value.rootTaskId !== task.rootTaskId || (value.actorId !== identity.actorId && !identity.roles.includes('operator'))) {
                throw new AppError(403, 'MEMORY_DENIED');
            }
            (await store.transaction(async () => {
                (await policy.getTask(identity, taskId));
                const current = await store.get(identity.tenantId, 'memory', id);
                if (!current || current.rootTaskId !== task.rootTaskId || (current.actorId !== identity.actorId && !identity.roles.includes('operator'))) throw new AppError(403, 'MEMORY_DENIED');
                await assertUnheld?.(identity.tenantId, { actorIds: [current.actorId].filter(Boolean), documentIds: current.sourceDocumentIds ?? [] });
                (await store.delete(identity.tenantId, 'memory', id));
                (await store.appendAudit({ tenantId: identity.tenantId, actorId: identity.actorId, event: 'memory.deleted', target: id, at: now() }));
            }, { tenantId: identity.tenantId }));
            return { deleted: true };
        },
    });
}
