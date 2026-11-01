import { AppError, exactObject, identifier } from '../protocol.mjs';
import { assertProductIdentity, validateProductAction } from './policy.mjs';
import { detectContent } from './detector.mjs';
import { requestContext } from './transport.mjs';

/** Every invocation uses current policy. A durable reservation precedes every external effect. */
export function createProductExecutor({ store, policy, adapter, coverage, zanii, learning, companions, now = Date.now, requestTimeoutMs = 5000 }) {
  const audit = (identity, event, target, data = {}) => store.appendAudit({ tenantId: identity.tenantId, actorId: identity.actorId, event, target, data, at: now() });
  function owned(identity, id) {
    assertProductIdentity(identity, ['agent', 'operator']);
    const operation = store.getOperation(identity.tenantId, identifier(id));
    if (!operation) throw new AppError(404, 'OPERATION_NOT_FOUND');
    policy.getTask(identity, operation.taskId);
    // getTask permits operators to inspect; releasing content always requires actual task ownership.
    if (policy.getTask(identity, operation.taskId).actorId !== identity.actorId) throw new AppError(403, 'ACTOR_DENIED');
    return operation;
  }
  const warning = (identity, result) => {
    if (result?.kind !== 'read') return undefined;
    // The detector has a strict 16KiB input budget; larger/empty documents remain bounded and visibly partial.
    const text = result.content.slice(0, 4096) || ' ';
    const verdict = result.content.trim() ? (learning ? learning.detect(identity, text, { source: 'document' }) : detectContent(text, { source: 'document' }))
      : { suspicious: false, reasons: [], grantsAuthority: false, source: 'document' };
    if (verdict.suspicious && learning) {
      try { learning.quarantine(identity, { text: result.content.slice(0, 512), sourceId: result.documentId, sourceKind: 'document' }); }
      catch (error) { if (!(error instanceof AppError && [400, 429].includes(error.status))) throw error; }
    }
    return { ...verdict, truncated: result.content.length > 4096 };
  };
  async function current(identity, taskId, action) {
    const posture = await coverage.require();
    if (companions?.status && !companions.status().ready) throw new AppError(503, 'REQUIRED_COMPANION_UNAVAILABLE');
    if (zanii?.status?.()?.blocked) throw new AppError(503, 'ZANII_RECOVERY_REQUIRED');
    const metadata = await adapter.metadata(identity, action);
    const decision = policy.authorize(identity, taskId, action, metadata);
    return { posture, metadata, decision };
  }
  function reply(identity, operation, metadata, decision) {
    if (operation.actionDigest !== decision.actionDigest) throw new AppError(409, 'OPERATION_CONFLICT');
    if (operation.status === 'succeeded') {
      if (operation.resultExpiredAt || operation.result?.resultExpired) return { status: 200, operationId: operation.id, state: operation.status, resultExpired: true };
      if (operation.action.kind === 'read') policy.recordRead(identity, operation.taskId, metadata);
      const verdict = warning(identity, operation.result);
      return { status: 200, operationId: operation.id, state: operation.status, result: operation.result, ...(verdict ? { warning: verdict } : {}) };
    }
    return { status: operation.status === 'failed' ? 409 : 202, operationId: operation.id, state: operation.status };
  }
  return Object.freeze({
    async execute(identity, value) {
      const invocationDeadline = Math.min(now() + requestTimeoutMs, requestContext.getStore()?.deadlineAt ?? Infinity);
      exactObject(value, ['taskId', 'action']); identifier(value.taskId); const action = validateProductAction(value.action);
      let { posture, metadata, decision } = await current(identity, value.taskId, action);
      const prior = store.getOperation(identity.tenantId, action.id);
      if (prior) { if (prior.taskId !== value.taskId) throw new AppError(409, 'OPERATION_CONFLICT'); return reply(identity, prior, metadata, decision); }
      const provider = await adapter.status(identity);
      // Metadata and revision must describe the same provider epoch, re-read under the pinned revision.
      metadata = await adapter.metadata(identity, action); decision = policy.authorize(identity, value.taskId, action, metadata);
      const approval = decision.requiresApproval ? store.get(identity.tenantId, 'approvals', action.approvalId ?? 'missing') : null;
      const deadlineAt = Math.min(invocationDeadline, identity.expiresAt ?? Infinity, decision.task.expiresAt,
        decision.rootExpiresAt, posture.expiresAt, approval?.expiresAt ?? Infinity);
      if (deadlineAt <= now()) throw new AppError(403, 'ACTION_EXPIRED');
      const reserved = store.reserveOperation({ tenantId: identity.tenantId, taskId: value.taskId, rootTaskId: decision.rootTaskId,
        operationId: action.id, actionDigest: decision.actionDigest, action: decision.action, policyDigest: decision.policyDigest,
        toolVersion: decision.toolVersion, maxActions: decision.rootMaxActions, approvalId: action.approvalId,
        requiresApproval: decision.requiresApproval, now: now() });
      if (!reserved.created) return reply(identity, reserved.operation, metadata, decision);
      let dispatched = false;
      try {
        if (companions?.authorize) await companions.authorize(identity, decision, { deadlineAt });
        if (zanii && !adapter.recordsBeforeDispatch) await zanii.record(identity, { target: `runtime.document.${action.kind}`, payload: { operationId: action.id, actionDigest: decision.actionDigest, policyDigest: decision.policyDigest } });
        const fresh = await current(identity, value.taskId, action);
        if (fresh.decision.actionDigest !== decision.actionDigest || fresh.decision.policyDigest !== decision.policyDigest) throw new AppError(403, 'AUTHORITY_CHANGED');
        if (now() >= Math.min(deadlineAt, fresh.posture.expiresAt, identity.expiresAt ?? Infinity)) throw new AppError(403, 'ACTION_EXPIRED');
        // Conservative root taint is committed before release or dependent dispatch.
        if (action.kind === 'read') policy.recordRead(identity, value.taskId, fresh.metadata);
        if (!adapter.managesDispatchBarrier) { store.transitionOperation(identity.tenantId, action.id, 'dispatched'); dispatched = true; }
        const result = await adapter.execute(identity, fresh.decision.action, { operationId: action.id, expectedVersion: provider.configurationVersion, deadlineAt,
          grant: { taskId: value.taskId, rootTaskId: decision.rootTaskId, policyDigest: decision.policyDigest, actionDigest: decision.actionDigest },
          async beforeDispatch() {
            const final = await current(identity, value.taskId, action);
            if (final.decision.actionDigest !== decision.actionDigest || final.decision.policyDigest !== decision.policyDigest) throw new AppError(403, 'AUTHORITY_CHANGED');
            if (now() >= Math.min(deadlineAt, final.posture.expiresAt, identity.expiresAt ?? Infinity)) throw new AppError(403, 'ACTION_EXPIRED');
            if (!dispatched) { store.transitionOperation(identity.tenantId, action.id, 'dispatched'); dispatched = true; }
          } });
        store.transitionOperation(identity.tenantId, action.id, 'succeeded', result);
        audit(identity, 'action.succeeded', action.id, { actionDigest: decision.actionDigest });
        // Current policy is also required before returning potentially sensitive provider content.
        const release = await current(identity, value.taskId, action);
        return reply(identity, store.getOperation(identity.tenantId, action.id), release.metadata, release.decision);
      } catch (error) {
        const state = store.getOperation(identity.tenantId, action.id)?.status;
        if (state === 'succeeded') throw error;
        if (['reserved', 'dispatched'].includes(state)) store.transitionOperation(identity.tenantId, action.id, dispatched ? 'unknown' : 'failed');
        audit(identity, dispatched ? 'action.unknown' : 'action.failed', action.id, { code: error instanceof AppError ? error.code : 'PROVIDER_UNAVAILABLE' });
        if (dispatched) return { status: 202, operationId: action.id, state: 'unknown' };
        throw error;
      }
    },
    async operation(identity, id) {
      const operation = owned(identity, id); const { metadata, decision } = await current(identity, operation.taskId, operation.action);
      return reply(identity, operation, metadata, decision);
    },
    async reconcile(identity, id) {
      let operation = owned(identity, id); const { metadata, decision } = await current(identity, operation.taskId, operation.action);
      if (operation.status !== 'unknown') return reply(identity, operation, metadata, decision);
      const observed = await adapter.observe(identity, id);
      if (observed.state === 'succeeded' && observed.resultExpired) store.transitionOperation(identity.tenantId, id, 'succeeded', { operationId: id, state: 'succeeded', resultExpired: true });
      else if (observed.state === 'succeeded') {
        if (observed.result?.kind !== operation.action.kind || observed.result?.documentId !== operation.action.documentId
          || operation.action.kind === 'share' && observed.result?.recipient !== operation.action.recipient) throw new AppError(502, 'RESOURCE_SCOPE_MISMATCH');
        store.transitionOperation(identity.tenantId, id, 'succeeded', observed.result);
      } else if (observed.state === 'failed') store.transitionOperation(identity.tenantId, id, 'failed');
      operation = owned(identity, id);
      const fresh = await current(identity, operation.taskId, operation.action);
      return reply(identity, operation, fresh.metadata, fresh.decision);
    },
    async cancel(identity, id) {
      const operation = owned(identity, id);
      // An in-flight reserved operation may already be inside an external authorization call.
      // Task revocation is the supported cancellation barrier; never claim an effect was canceled.
      policy.revoke(identity, operation.taskId);
      return { canceled: false, dispatched: operation.status !== 'reserved', state: operation.status, taskRevoked: true };
    },
  });
}
