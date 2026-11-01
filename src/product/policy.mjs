import { asAsyncStore } from './async-store.mjs';
import { randomUUID } from 'node:crypto';
import canonicalize from 'canonicalize';
import { AppError, exactObject, identifier, positiveInteger, sha256 } from '../protocol.mjs';
import { getProfile, highestSensitivity, LABELS, PROFILES, sensitivity } from './profiles.mjs';
export const hashCanonical = (value) => sha256(canonicalize(value));
const denied = (code) => { throw new AppError(403, code); };
export function assertProductIdentity(identity, roles = []) {
    if (!identity || typeof identity !== 'object')
        denied('IDENTITY_REQUIRED');
    identifier(identity.actorId);
    identifier(identity.tenantId);
    if (identity.expiresAt !== undefined && (!Number.isSafeInteger(identity.expiresAt)
        || identity.expiresAt <= Date.now()))
        denied('IDENTITY_EXPIRED');
    if (!Array.isArray(identity.roles) || identity.roles.length > 16
        || !identity.roles.every((role) => typeof role === 'string'))
        denied('IDENTITY_REQUIRED');
    if (roles.length && !roles.some((role) => identity.roles.includes(role)))
        denied('ROLE_REQUIRED');
    return identity;
}
function list(value, allowed, minimum = 0) {
    if (!Array.isArray(value) || value.length < minimum || value.length > 64
        || Reflect.ownKeys(value).length !== value.length + 1)
        throw new AppError(400, 'INVALID_INPUT');
    const items = Array.from({ length: value.length }, (_, index) => {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor || !('value' in descriptor))
            throw new AppError(400, 'INVALID_INPUT');
        const item = identifier(descriptor.value);
        if (allowed && !allowed.includes(item))
            throw new AppError(400, 'INVALID_INPUT');
        return item;
    });
    if (new Set(items).size !== items.length)
        throw new AppError(400, 'INVALID_INPUT');
    return Object.freeze(items);
}
export function validateProductAction(value) {
    exactObject(value, ['id', 'kind', 'documentId'], ['recipient', 'toolVersion', 'approvalId', 'sourceRefs']);
    if (!['read', 'share'].includes(value.kind)
        || (value.kind === 'read' && Object.hasOwn(value, 'recipient'))
        || (value.kind === 'share' && !Object.hasOwn(value, 'recipient')))
        throw new AppError(400, 'INVALID_INPUT');
    return Object.freeze({
        id: identifier(value.id), kind: value.kind, documentId: identifier(value.documentId),
        ...(value.kind === 'share' ? { recipient: identifier(value.recipient) } : {}),
        ...(value.toolVersion === undefined ? {} : { toolVersion: identifier(value.toolVersion) }),
        ...(value.approvalId === undefined ? {} : { approvalId: identifier(value.approvalId) }),
        ...(value.sourceRefs === undefined ? {} : { sourceRefs: list(value.sourceRefs) }),
    });
}
export function validateResourceMetadata(value) {
    exactObject(value, ['documentId', 'tenantId', 'label', 'toolVersion'], ['allowedRecipients', 'allowedPurposes', 'recipientIsInternal']);
    if (value.recipientIsInternal !== undefined && typeof value.recipientIsInternal !== 'boolean') {
        throw new AppError(400, 'INVALID_INPUT');
    }
    return Object.freeze({
        documentId: identifier(value.documentId), tenantId: identifier(value.tenantId),
        label: sensitivity(value.label), toolVersion: identifier(value.toolVersion),
        ...(value.allowedRecipients === undefined ? {} : { allowedRecipients: list(value.allowedRecipients) }),
        ...(value.allowedPurposes === undefined ? {} : { allowedPurposes: list(value.allowedPurposes) }),
        recipientIsInternal: value.recipientIsInternal === true,
    });
}
/** Metadata is provided by a trusted resource adapter, never copied from an agent's arguments. */
export function createPolicyEngine({ store, now = Date.now }) {
    store = asAsyncStore(store);
    for (const name of ['get', 'put', 'list', 'delete', 'transaction', 'appendAudit']) {
        if (typeof store?.[name] !== 'function')
            throw new AppError(400, 'INVALID_STORE');
    }
    if (typeof now !== 'function')
        throw new AppError(400, 'INVALID_CONFIGURATION');
    const audit = async (identity, event, target, data = {}) => (await store.appendAudit({
        tenantId: identity.tenantId, actorId: identity.actorId, event, target, data, at: now(),
    }));
    async function load(identity, taskId, actorRequired = true) {
        assertProductIdentity(identity);
        identifier(taskId);
        const task = (await store.get(identity.tenantId, 'tasks', taskId));
        if (!task || task.tenantId !== identity.tenantId)
            denied('TASK_NOT_FOUND');
        if (actorRequired && task.actorId !== identity.actorId)
            denied('ACTOR_DENIED');
        const lineage = [];
        const seen = new Set();
        let current = task;
        while (current) {
            if (seen.has(current.id) || lineage.length >= 8 || current.tenantId !== identity.tenantId
                || current.version !== 1 || current.profileVersion !== getProfile(current.profile).version)
                denied('TASK_CORRUPT');
            if (current.revoked)
                denied('TASK_REVOKED');
            if (now() >= current.expiresAt)
                denied('TASK_EXPIRED');
            seen.add(current.id);
            lineage.push(current);
            if (!current.parentId)
                break;
            const child = current;
            current = (await store.get(identity.tenantId, 'tasks', current.parentId));
            if (!current)
                denied('TASK_PARENT_MISSING');
            if (!narrows(child, current))
                denied('DELEGATION_WIDENS_AUTHORITY');
        }
        if (lineage.at(-1).id !== task.rootTaskId)
            denied('TASK_CORRUPT');
        return { task, lineage };
    }
    function narrows(child, parent) {
        return child.profile === parent.profile && child.purpose === parent.purpose
            && child.expiresAt <= parent.expiresAt && child.maxActions <= parent.maxActions
            && LABELS.indexOf(child.maxSensitivity) <= LABELS.indexOf(parent.maxSensitivity)
            && child.documentIds.every((id) => parent.documentIds.includes(id))
            && child.recipients.every((id) => parent.recipients.includes(id))
            && child.allowedActions.every((kind) => parent.allowedActions.includes(kind))
            && parent.requireApprovalFor.every((kind) => !child.allowedActions.includes(kind) || child.requireApprovalFor.includes(kind));
    }
    function digest(lineage) {
        return hashCanonical({ version: 1, profiles: PROFILES, authority: lineage.map((task) => {
                const authority = { ...task };
                delete authority.createdAt;
                delete authority.createdBy;
                return authority;
            }) });
    }
    function makeTask(identity, value, parent) {
        exactObject(value, ['id', 'actorId', 'documentIds', 'expiresAt', 'maxActions', 'profile', 'purpose'], ['tenantId', 'recipients', 'allowedActions', 'requireApprovalFor', 'allowDelegation', 'maxSensitivity']);
        const profile = getProfile(value.profile);
        if (value.tenantId !== undefined && value.tenantId !== identity.tenantId)
            denied('TENANT_DENIED');
        if (!profile.purposes.includes(value.purpose))
            denied('PURPOSE_DENIED');
        const expiresAt = positiveInteger(value.expiresAt);
        if (expiresAt <= now() || expiresAt > now() + profile.taskLifetimeMs)
            denied('TASK_LIFETIME');
        const maxActions = positiveInteger(value.maxActions, profile.maxActions);
        const documentIds = list(value.documentIds, undefined, 1);
        const recipients = list(value.recipients ?? []);
        const allowedActions = list(value.allowedActions ?? ['read'], profile.actions, 1);
        const requireApprovalFor = list(value.requireApprovalFor ?? [], allowedActions);
        const maxSensitivity = sensitivity(value.maxSensitivity ?? profile.maxSensitivity);
        if (LABELS.indexOf(maxSensitivity) > LABELS.indexOf(profile.maxSensitivity))
            denied('SENSITIVITY_DENIED');
        if (value.allowDelegation !== undefined && typeof value.allowDelegation !== 'boolean')
            throw new AppError(400, 'INVALID_INPUT');
        const task = {
            version: 1, id: identifier(value.id), tenantId: identity.tenantId, actorId: identifier(value.actorId),
            documentIds, recipients, expiresAt, maxActions, profile: value.profile, profileVersion: profile.version,
            purpose: value.purpose, allowedActions, requireApprovalFor,
            allowDelegation: value.allowDelegation === true, maxSensitivity,
            parentId: parent?.id ?? null, rootTaskId: parent?.rootTaskId ?? value.id, revoked: false,
            createdAt: now(), createdBy: identity.actorId,
        };
        if (parent && !narrows(task, parent)) {
            denied('DELEGATION_WIDENS_AUTHORITY');
        }
        return Object.freeze(task);
    }
    async function taskAndDigest(identity, taskId, actorRequired = true) {
        const loaded = (await load(identity, taskId, actorRequired));
        return { ...loaded, policyDigest: digest(loaded.lineage) };
    }
    const engine = {
        authorityDigest: () => hashCanonical({ version: 1, profiles: PROFILES }),
        async getTask(identity, taskId) {
            const isObserver = identity?.roles?.some((role) => ['operator', 'auditor', 'approver'].includes(role));
            return structuredClone((await load(identity, taskId, !isObserver)).task);
        },
        async policyDigest(identity, taskId) { return (await taskAndDigest(identity, taskId)).policyDigest; },
        async rootContext(identity, taskId) {
            const root = (await load(identity, taskId)).lineage.at(-1);
            return Object.freeze({ rootTaskId: root.id, expiresAt: root.expiresAt, maxActions: root.maxActions });
        },
        async createTask(identity, value) {
            assertProductIdentity(identity, ['operator']);
            const task = makeTask(identity, value);
            return (await store.transaction(async () => {
                assertProductIdentity(identity, ['operator']);
                if ((await store.get(identity.tenantId, 'tasks', task.id)))
                    throw new AppError(409, 'TASK_EXISTS');
                (await store.put(identity.tenantId, 'tasks', task.id, task, { expiresAt: task.expiresAt }));
                (await audit(identity, 'task.created', task.id, { policyDigest: digest([task]) }));
                return structuredClone(task);
            }, { tenantId: identity.tenantId }));
        },
        async delegate(identity, parentId, value) {
            assertProductIdentity(identity, ['agent', 'operator']);
            const { task: parent, lineage } = (await load(identity, parentId));
            if (!parent.allowDelegation)
                denied('DELEGATION_DENIED');
            if (lineage.length >= 8)
                denied('DELEGATION_DEPTH');
            const task = makeTask(identity, value, parent);
            return (await store.transaction(async () => {
                (await load(identity, parentId));
                if ((await store.get(identity.tenantId, 'tasks', task.id)))
                    throw new AppError(409, 'TASK_EXISTS');
                (await store.put(identity.tenantId, 'tasks', task.id, task, { expiresAt: task.expiresAt }));
                (await audit(identity, 'task.delegated', task.id, { rootTaskId: task.rootTaskId }));
                return structuredClone(task);
            }, { tenantId: identity.tenantId }));
        },
        async authorize(identity, taskId, value, metadataValue) {
            assertProductIdentity(identity, ['agent', 'operator']);
            const { task, lineage, policyDigest } = (await taskAndDigest(identity, taskId));
            const metadata = validateResourceMetadata(metadataValue);
            const proposed = validateProductAction(value);
            if (metadata.tenantId !== identity.tenantId || metadata.documentId !== proposed.documentId)
                denied('RESOURCE_DENIED');
            if (!task.documentIds.includes(proposed.documentId) || !task.allowedActions.includes(proposed.kind))
                denied('ACTION_DENIED');
            if (proposed.toolVersion !== undefined && proposed.toolVersion !== metadata.toolVersion)
                denied('TOOL_VERSION_CHANGED');
            if (metadata.allowedPurposes && !metadata.allowedPurposes.includes(task.purpose))
                denied('PURPOSE_DENIED');
            if (LABELS.indexOf(metadata.label) > LABELS.indexOf(task.maxSensitivity))
                denied('SENSITIVITY_DENIED');
            const profile = getProfile(task.profile);
            const flow = (await store.get(identity.tenantId, 'flows', task.rootTaskId));
            const label = highestSensitivity(metadata.label, flow?.label ?? 'public');
            if (proposed.kind === 'share') {
                if (!task.recipients.includes(proposed.recipient)
                    || (metadata.allowedRecipients && !metadata.allowedRecipients.includes(proposed.recipient)))
                    denied('RECIPIENT_DENIED');
                if (!metadata.recipientIsInternal && !profile.externalShareLabels.includes(label))
                    denied('DATA_FLOW_DENIED');
            }
            const action = Object.freeze({ ...proposed, toolVersion: metadata.toolVersion });
            const semanticAction = { ...action };
            delete semanticAction.approvalId;
            return Object.freeze({
                task: structuredClone(task), rootTaskId: task.rootTaskId, action, policyDigest,
                actionDigest: hashCanonical({ taskId, tenantId: identity.tenantId, policyDigest, action: semanticAction }),
                requiresApproval: profile.approvalFor.includes(action.kind) || task.requireApprovalFor.includes(action.kind),
                labels: Object.freeze([label]), units: 1, toolVersion: metadata.toolVersion,
                rootMaxActions: lineage.at(-1).maxActions,
                rootExpiresAt: lineage.at(-1).expiresAt,
            });
        },
        async approve(identity, value) {
            assertProductIdentity(identity, ['operator', 'approver']);
            exactObject(value, ['taskId', 'action', 'toolVersion', 'expiresAt']);
            const { task, policyDigest } = (await taskAndDigest(identity, value.taskId, false));
            if (task.actorId === identity.actorId)
                denied('SELF_APPROVAL_DENIED');
            const action = validateProductAction(value.action);
            if (!task.allowedActions.includes(action.kind) || !task.documentIds.includes(action.documentId)
                || (action.kind === 'share' && !task.recipients.includes(action.recipient)))
                denied('ACTION_DENIED');
            const toolVersion = identifier(value.toolVersion);
            if (action.toolVersion !== undefined && action.toolVersion !== toolVersion)
                denied('TOOL_VERSION_CHANGED');
            const expiresAt = positiveInteger(value.expiresAt);
            if (expiresAt <= now() || expiresAt > Math.min(task.expiresAt, now() + getProfile(task.profile).approvalLifetimeMs))
                denied('APPROVAL_LIFETIME');
            const semanticAction = { ...action, toolVersion };
            delete semanticAction.approvalId;
            const approval = Object.freeze({
                id: randomUUID(), tenantId: identity.tenantId, taskId: task.id,
                actionDigest: hashCanonical({ taskId: task.id, tenantId: identity.tenantId, policyDigest, action: semanticAction }),
                policyDigest, toolVersion, expiresAt, used: false, approverId: identity.actorId,
            });
            (await store.transaction(async () => {
                assertProductIdentity(identity, ['operator', 'approver']);
                (await store.put(identity.tenantId, 'approvals', approval.id, approval, { expiresAt }));
                (await audit(identity, 'action.approved', task.id, { actionDigest: approval.actionDigest, approvalId: approval.id }));
            }, { tenantId: identity.tenantId }));
            return approval;
        },
        async revoke(identity, taskId) {
            assertProductIdentity(identity, ['agent', 'operator']);
            const operator = identity.roles.includes('operator');
            const { task } = (await load(identity, taskId, !operator));
            (await store.transaction(async () => {
                assertProductIdentity(identity, ['agent', 'operator']);
                (await store.put(identity.tenantId, 'tasks', task.id, { ...task, revoked: true }, { expiresAt: task.expiresAt }));
                (await audit(identity, 'task.revoked', task.id));
            }, { tenantId: identity.tenantId }));
            return { revoked: true, taskId };
        },
        async recordRead(identity, taskId, metadataValue) {
            const { task } = (await load(identity, taskId));
            const metadata = validateResourceMetadata(metadataValue);
            if (metadata.tenantId !== identity.tenantId || !task.documentIds.includes(metadata.documentId))
                denied('RESOURCE_DENIED');
            return (await store.transaction(async () => {
                const prior = (await store.get(identity.tenantId, 'flows', task.rootTaskId));
                const result = { label: highestSensitivity(prior?.label ?? 'public', metadata.label),
                    documentIds: [...new Set([...(prior?.documentIds ?? []), metadata.documentId])], updatedAt: now() };
                (await store.put(identity.tenantId, 'flows', task.rootTaskId, result, { expiresAt: (await load(identity, taskId)).lineage.at(-1).expiresAt }));
                return result;
            }, { tenantId: identity.tenantId }));
        },
    };
    return Object.freeze(engine);
}
