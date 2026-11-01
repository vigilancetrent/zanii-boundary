import { randomUUID } from 'node:crypto';
import { asAsyncStore } from './async-store.mjs';
import { AppError, exactObject, identifier } from '../protocol.mjs';
import { assertProductIdentity, validateProductAction } from './policy.mjs';
import { detectContent } from './detector.mjs';
import { requestContext } from './transport.mjs';
/** Every invocation uses current policy. A durable reservation precedes every external effect. */
export function createProductExecutor({ store, policy, adapter, coverage, zanii, learning, companions, operationalGate, now = Date.now, requestTimeoutMs = 5000, ownerId = randomUUID() }) {
    store = asAsyncStore(store);
    identifier(ownerId);
    const audit = async (identity, event, target, data = {}) => (await store.appendAudit({ tenantId: identity.tenantId, actorId: identity.actorId, event, target, data, at: now() }));
    async function owned(identity, id) {
        assertProductIdentity(identity, ['agent', 'operator']);
        const operation = (await store.getOperation(identity.tenantId, identifier(id)));
        if (!operation)
            throw new AppError(404, 'OPERATION_NOT_FOUND');
        (await policy.getTask(identity, operation.taskId));
        // getTask permits operators to inspect; releasing content always requires actual task ownership.
        if ((await policy.getTask(identity, operation.taskId)).actorId !== identity.actorId)
            throw new AppError(403, 'ACTOR_DENIED');
        return operation;
    }
    const warning = async (identity, result) => {
        if (result?.kind !== 'read')
            return undefined;
        // The detector has a strict 16KiB input budget; larger/empty documents remain bounded and visibly partial.
        const text = result.content.slice(0, 4096) || ' ';
        const verdict = result.content.trim() ? (learning ? (await learning.detect(identity, text, { source: 'document' })) : detectContent(text, { source: 'document' }))
            : { suspicious: false, reasons: [], grantsAuthority: false, source: 'document' };
        if (verdict.suspicious && learning) {
            try {
                (await learning.quarantine(identity, { text: result.content.slice(0, 512), sourceId: result.documentId, sourceKind: 'document' }));
            }
            catch (error) {
                if (!(error instanceof AppError && [400, 429].includes(error.status)))
                    throw error;
            }
        }
        return { ...verdict, truncated: result.content.length > 4096 };
    };
    async function current(identity, taskId, action) {
        await operationalGate?.(identity, { taskId, action });
        const posture = await coverage.require();
        if (companions?.status && !companions.status().ready)
            throw new AppError(503, 'REQUIRED_COMPANION_UNAVAILABLE');
        const ledgerState=zanii?.authorizationStatus?await zanii.authorizationStatus({deadlineAt:Math.min(now()+requestTimeoutMs,requestContext.getStore()?.deadlineAt??Infinity)}):await zanii?.status?.();
        if (ledgerState?.blocked)
            throw new AppError(503, 'ZANII_RECOVERY_REQUIRED');
        const metadata = await adapter.metadata(identity, action);
        const decision = (await policy.authorize(identity, taskId, action, metadata));
        return { posture, metadata, decision };
    }
    function requireRelease(identity, decision) {
        assertProductIdentity(identity, ['agent', 'operator']);
        if (now() >= Math.min(decision.task.expiresAt, decision.rootExpiresAt)) throw new AppError(403, 'TASK_EXPIRED');
        if (now() >= (requestContext.getStore()?.deadlineAt ?? Infinity)) throw new AppError(504, 'REQUEST_DEADLINE');
    }
    const runtimePreflight = zanii?.runtimePreflight;
    async function preflight(identity, taskId, action, context, deadlineAt) {
        return runtimePreflight?.authorize({ identity, taskId, action, current: context, deadlineAt, authorize: () => current(identity, taskId, action) });
    }
    async function reply(identity, operation, metadata, decision, runtimeTicket = undefined) {
        requireRelease(identity, decision);
        requestContext.getStore()?.business?.(operation.action.kind, operation.status);
        if (operation.actionDigest !== decision.actionDigest)
            throw new AppError(409, 'OPERATION_CONFLICT');
        if (operation.status === 'succeeded') {
            if (operation.resultExpiredAt || operation.result?.resultExpired)
                return { status: 200, operationId: operation.id, state: operation.status, resultExpired: true };
            if (runtimePreflight && !runtimeTicket) runtimeTicket = await preflight(identity, operation.taskId, operation.action,
                await current(identity, operation.taskId, operation.action), requestContext.getStore()?.deadlineAt);
            if (operation.action.kind === 'read')
                (await policy.recordRead(identity, operation.taskId, metadata));
            const verdict = (await warning(identity, operation.result));
            // Slow classification/storage cannot extend permission to release a cached private result.
            const final = await current(identity, operation.taskId, operation.action);
            if (runtimeTicket) await runtimePreflight.assertCurrent(runtimeTicket);
            // Only database work belongs in this final authority snapshot. Provider metadata
            // and classification finish first; revocation serializes with this transaction.
            const releaseDecision = await store.transaction(async () => {
                if (operation.action.kind === 'read') await policy.recordRead(identity, operation.taskId, final.metadata);
                const latest = await policy.authorize(identity, operation.taskId, operation.action, final.metadata);
                if (operation.actionDigest !== latest.actionDigest) throw new AppError(409, 'OPERATION_CONFLICT');
                requireRelease(identity, latest);
                if (runtimeTicket) runtimePreflight.assertRelease(runtimeTicket);
                return latest;
            }, { tenantId: identity.tenantId });
            requireRelease(identity, releaseDecision);
            if (runtimeTicket) {
                runtimePreflight.assertReleaseFresh(runtimeTicket);
                const request = requestContext.getStore();
                if (request) { const previous = request.releaseGuard; request.releaseGuard = () => { previous?.(); requireRelease(identity, releaseDecision); runtimePreflight.assertReleaseFresh(runtimeTicket); }; }
            }
            return { status: 200, operationId: operation.id, state: operation.status, result: operation.result, ...(verdict ? { warning: verdict } : {}) };
        }
        return { status: operation.status === 'failed' ? 409 : 202, operationId: operation.id, state: operation.status };
    }
    return Object.freeze({
        async execute(identity, value) {
            const invocationDeadline = Math.min(now() + requestTimeoutMs, requestContext.getStore()?.deadlineAt ?? Infinity);
            exactObject(value, ['taskId', 'action']);
            identifier(value.taskId);
            const action = validateProductAction(value.action);
            let { posture, metadata, decision } = await current(identity, value.taskId, action);
            const prior = (await store.getOperation(identity.tenantId, action.id));
            if (prior) {
                if (prior.taskId !== value.taskId)
                    throw new AppError(409, 'OPERATION_CONFLICT');
                return (await reply(identity, prior, metadata, decision));
            }
            const runtimeTicket = await preflight(identity, value.taskId, action, { posture, metadata, decision }, invocationDeadline);
            const provider = await adapter.status(identity);
            // Metadata and revision must describe the same provider epoch, re-read under the pinned revision.
            metadata = await adapter.metadata(identity, action);
            decision = (await policy.authorize(identity, value.taskId, action, metadata));
            const approval = decision.requiresApproval ? (await store.get(identity.tenantId, 'approvals', action.approvalId ?? 'missing')) : null;
            let deadlineAt = Math.min(invocationDeadline, runtimeTicket?.deadlineAt ?? Infinity, identity.expiresAt ?? Infinity, decision.task.expiresAt, decision.rootExpiresAt, posture.expiresAt, approval?.expiresAt ?? Infinity);
            if (deadlineAt <= now())
                throw new AppError(403, 'ACTION_EXPIRED');
            const lease = await store.claimLease(identity.tenantId, `operation:${action.id}`, {
                ownerId: `${ownerId.slice(0, 64)}:${randomUUID()}`, ttlMs: Math.max(1, Math.ceil(deadlineAt - now())), now: now(),
            });
            if (!lease) return { status: 202, operationId: action.id, state: 'reserved' };
            let reserved;
            try {
                reserved = (await store.reserveOperation({ tenantId: identity.tenantId, taskId: value.taskId, rootTaskId: decision.rootTaskId,
                operationId: action.id, actionDigest: decision.actionDigest, action: decision.action, policyDigest: decision.policyDigest,
                toolVersion: decision.toolVersion, maxActions: decision.rootMaxActions, approvalId: action.approvalId,
                requiresApproval: decision.requiresApproval, now: now(), lease }));
            } catch (error) { await store.releaseLease(lease); if (error instanceof AppError && error.code === 'LEASE_LOST' && now() >= deadlineAt) throw new AppError(403, 'ACTION_EXPIRED'); throw error; }
            if (!reserved.created) {
                await store.releaseLease(lease);
                return (await reply(identity, reserved.operation, metadata, decision));
            }
            deadlineAt = Math.min(deadlineAt, lease.expiresAt);
            let dispatched = false;
            try {
                await store.assertLease(lease, { now: now() });
                if (companions?.authorize)
                    await companions.authorize(identity, decision, { deadlineAt });
                if (zanii && !adapter.recordsBeforeDispatch)
                    await zanii.record(identity, { target: `runtime.document.${action.kind}`, payload: { operationId: action.id, actionDigest: decision.actionDigest, policyDigest: decision.policyDigest } });
                if (runtimeTicket) await runtimePreflight.assertCurrent(runtimeTicket);
                const fresh = await current(identity, value.taskId, action);
                if (fresh.decision.actionDigest !== decision.actionDigest || fresh.decision.policyDigest !== decision.policyDigest)
                    throw new AppError(403, 'AUTHORITY_CHANGED');
                if (now() >= Math.min(deadlineAt, fresh.posture.expiresAt, identity.expiresAt ?? Infinity))
                    throw new AppError(403, 'ACTION_EXPIRED');
                // Conservative root taint is committed before release or dependent dispatch.
                if (action.kind === 'read')
                    (await policy.recordRead(identity, value.taskId, fresh.metadata));
                if (!adapter.managesDispatchBarrier) {
                    (await store.transitionOperation(identity.tenantId, action.id, 'dispatched', null, { lease }));
                    dispatched = true;
                }
                if (runtimeTicket) runtimePreflight.assertReleaseFresh(runtimeTicket);
                const result = await adapter.execute(identity, fresh.decision.action, { operationId: action.id, expectedVersion: provider.configurationVersion, deadlineAt,
                    grant: { taskId: value.taskId, rootTaskId: decision.rootTaskId, policyDigest: decision.policyDigest, actionDigest: decision.actionDigest, lease },
                    async beforeDispatch() {
                    if (runtimeTicket) await runtimePreflight.assertCurrent(runtimeTicket);
                    await store.assertLease(lease, { now: now() });
                        const final = await current(identity, value.taskId, action);
                        if (final.decision.actionDigest !== decision.actionDigest || final.decision.policyDigest !== decision.policyDigest)
                            throw new AppError(403, 'AUTHORITY_CHANGED');
                        if (now() >= Math.min(deadlineAt, final.posture.expiresAt, identity.expiresAt ?? Infinity))
                            throw new AppError(403, 'ACTION_EXPIRED');
                        if (runtimeTicket) runtimePreflight.assertRelease(runtimeTicket);
                        if (!dispatched) {
                            (await store.transitionOperation(identity.tenantId, action.id, 'dispatched', null, { lease }));
                            dispatched = true;
                        }
                        if (runtimeTicket) runtimePreflight.assertReleaseFresh(runtimeTicket);
                    } });
                (await store.transitionOperation(identity.tenantId, action.id, 'succeeded', result, { lease }));
                (await audit(identity, 'action.succeeded', action.id, { actionDigest: decision.actionDigest }));
                // Current policy is also required before returning potentially sensitive provider content.
                const release = await current(identity, value.taskId, action);
                return (await reply(identity, (await store.getOperation(identity.tenantId, action.id)), release.metadata, release.decision, runtimeTicket));
            }
            catch (error) {
                if (!dispatched && error instanceof AppError && error.code === 'LEASE_LOST' && now() >= deadlineAt) error = new AppError(403, 'ACTION_EXPIRED');
                const state = (await store.getOperation(identity.tenantId, action.id))?.status;
                if (state === 'succeeded')
                    throw error;
                if (['reserved', 'dispatched'].includes(state)) {
                    try { await store.transitionOperation(identity.tenantId, action.id, dispatched ? 'unknown' : 'failed', null, { lease }); }
                    catch (transitionError) {
                        // An expired owner cannot finalize the journal; recovery will mark it unknown.
                        if (!(transitionError instanceof AppError && transitionError.code === 'LEASE_LOST')) throw transitionError;
                    }
                }
                (await audit(identity, dispatched ? 'action.unknown' : 'action.failed', action.id, { code: error instanceof AppError ? error.code : 'PROVIDER_UNAVAILABLE' }));
                if (dispatched) {
                    requestContext.getStore()?.business?.(action.kind, 'unknown');
                    return { status: 202, operationId: action.id, state: 'unknown' };
                }
                throw error;
            } finally {
                await store.releaseLease(lease);
            }
        },
        async operation(identity, id) {
            const operation = (await owned(identity, id));
            const { metadata, decision } = await current(identity, operation.taskId, operation.action);
            return (await reply(identity, operation, metadata, decision));
        },
        async reconcile(identity, id) {
            let operation = (await owned(identity, id));
            const { metadata, decision } = await current(identity, operation.taskId, operation.action);
            if (operation.status !== 'unknown')
                return (await reply(identity, operation, metadata, decision));
            const deadlineAt = Math.min(now() + requestTimeoutMs, requestContext.getStore()?.deadlineAt ?? Infinity,
                identity.expiresAt ?? Infinity, decision.task.expiresAt, decision.rootExpiresAt);
            if (deadlineAt <= now()) throw new AppError(403, 'ACTION_EXPIRED');
            const lease = await store.claimLease(identity.tenantId, `operation:${id}`, {
                ownerId: `${ownerId.slice(0, 64)}:${randomUUID()}`, ttlMs: Math.max(1, Math.ceil(deadlineAt - now())), now: now(),
            });
            if (!lease) return { status: 202, operationId: id, state: 'unknown' };
            try {
                const observed = await adapter.observe(identity, id);
                await store.assertLease(lease, { now: now() });
                if (observed.state === 'succeeded' && observed.resultExpired)
                    await store.transitionOperation(identity.tenantId, id, 'succeeded', { operationId: id, state: 'succeeded', resultExpired: true }, { lease });
                else if (observed.state === 'succeeded') {
                    if (observed.result?.kind !== operation.action.kind || observed.result?.documentId !== operation.action.documentId
                        || operation.action.kind === 'share' && observed.result?.recipient !== operation.action.recipient)
                        throw new AppError(502, 'RESOURCE_SCOPE_MISMATCH');
                    await store.transitionOperation(identity.tenantId, id, 'succeeded', observed.result, { lease });
                } else if (observed.state === 'failed') await store.transitionOperation(identity.tenantId, id, 'failed', null, { lease });
                operation = await owned(identity, id);
                const fresh = await current(identity, operation.taskId, operation.action);
                return await reply(identity, operation, fresh.metadata, fresh.decision);
            } finally { await store.releaseLease(lease); }
        },
        async cancel(identity, id) {
            const operation = (await owned(identity, id));
            // An in-flight reserved operation may already be inside an external authorization call.
            // Task revocation is the supported cancellation barrier; never claim an effect was canceled.
            (await policy.revoke(identity, operation.taskId));
            return { canceled: false, dispatched: operation.status !== 'reserved', state: operation.status, taskRevoked: true };
        },
    });
}
