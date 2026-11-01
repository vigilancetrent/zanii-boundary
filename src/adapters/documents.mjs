import { asAsyncStore } from '../product/async-store.mjs';
import { requestContext } from '../product/context.mjs';
import { randomUUID, createHash } from 'node:crypto';
import { open, realpath, lstat } from 'node:fs/promises';
import { resolve, relative, isAbsolute } from 'node:path';
import { AppError, exactObject, identifier, positiveInteger } from '../protocol.mjs';
import { assertProductIdentity, hashCanonical, validateProductAction } from '../product/policy.mjs';
import { LABELS } from '../product/profiles.mjs';
const denied = (code, status = 403) => { throw new AppError(status, code); };
const ids = (values) => {
    if (!Array.isArray(values) || values.length > 64 || new Set(values).size !== values.length)
        denied('INVALID_DOCUMENT_METADATA', 400);
    return values.map(identifier);
};
/** Encrypted, tenant-scoped documents and a real internal delivery mailbox.
 * @param {any} options */
export function createDocumentService({ store, toolVersion = 'documents-v1', maxContentBytes = 32768, internalRecipients = [], importRoot, objectStorage, enqueueMaintenance, assertAccessible, assertUnheld, now = Date.now } = {}) {
    store = asAsyncStore(store);
    identifier(toolVersion);
    positiveInteger(maxContentBytes, 32768);
    const recipients = new Set(ids(internalRecipients));
    const configurationDigest = hashCanonical({ toolVersion, internalRecipients: [...recipients].sort(), maxContentBytes, objectStorage: Boolean(objectStorage) });
    const identityFor = (identity, roles = []) => assertProductIdentity(identity, roles);
    const access = async (identity, documentId) => {
        if (!assertAccessible) return;
        await assertAccessible(identity.tenantId, { kind: 'actor', id: identity.actorId });
        if (documentId) await assertAccessible(identity.tenantId, { kind: 'document', id: documentId });
    };
    async function state(tenant) {
        return store.transaction(async () => {
        let value = (await store.get(tenant, 'metadata', 'document-service'));
        if (!value || value.configurationDigest !== configurationDigest) {
            value = { resourceId: value?.resourceId ?? randomUUID(), configurationVersion: (value?.configurationVersion ?? 0) + 1, toolVersion, configurationDigest };
            (await store.put(tenant, 'metadata', 'document-service', value));
        }
        return { resourceId: value.resourceId, configurationVersion: value.configurationVersion, toolVersion };
        }, { tenantId: tenant });
    }
    async function current(identity, action) {
        identityFor(identity);
        const validated = validateProductAction(action);
        await access(identity, validated.documentId);
        const document = (await store.get(identity.tenantId, 'documents', validated.documentId));
        if (!document)
            denied('DOCUMENT_NOT_FOUND', 404);
        if (validated.toolVersion && validated.toolVersion !== toolVersion)
            denied('TOOL_VERSION_CHANGED', 409);
        return { action: validated, document };
    }
    async function metadata(identity, action) {
        const { action: checked, document } = (await current(identity, action));
        identityFor(identity);
        return { documentId: document.id, tenantId: identity.tenantId, label: document.label, toolVersion,
            allowedRecipients: document.allowedRecipients, allowedPurposes: document.allowedPurposes,
            recipientIsInternal: checked.kind === 'share' ? recipients.has(checked.recipient) : true };
    }
    const service = {
        async putDocument(identity, input) {
            identityFor(identity, ['operator']);
            exactObject(input, ['id', 'content', 'label', 'allowedRecipients'], ['allowedPurposes']);
            identifier(input.id);
            await access(identity, input.id);
            if (typeof input.content !== 'string' || Buffer.byteLength(input.content) > maxContentBytes || !LABELS.includes(input.label))
                denied('INVALID_DOCUMENT', 400);
            const document = { id: input.id, content: input.content, label: input.label, createdBy: identity.actorId, actorId: identity.actorId,
                allowedRecipients: ids(input.allowedRecipients), allowedPurposes: ids(input.allowedPurposes ?? []) };
            // Escaped controls can expand sixfold in JSON. Bound the persisted/wire form before accepting data.
            if (Buffer.byteLength(JSON.stringify(document)) > 48000)
                denied('DOCUMENT_ENCODING_TOO_LARGE', 400);
            if (document.allowedRecipients.some((recipient) => !recipients.has(recipient)))
                denied('RECIPIENT_NOT_REGISTERED', 400);
            let intentId; let previousDigest; let reference;
            if (objectStorage) {
                intentId = randomUUID();
                const upload = { id: document.id, purpose: 'document', bytes: Buffer.byteLength(document.content), plaintextSha256: createHash('sha256').update(document.content).digest('hex'), contentType: 'text/plain;charset=utf-8' };
                await store.transaction(async () => {
                    identityFor(identity, ['operator']);
                    await access(identity, input.id);
                    previousDigest = hashCanonical((await store.get(identity.tenantId, 'documents', document.id)) ?? null);
                    await store.put(identity.tenantId, 'object-intents', intentId, { id: intentId, documentId: document.id, actorId: identity.actorId, state: 'prepared', upload, expectedDigest: previousDigest, at: now() });
                }, { tenantId: identity.tenantId });
                // Provider I/O must never hold a database transaction or its lease.
                try {
                reference = await objectStorage.put({ tenantId: identity.tenantId, id: document.id, bytes: Buffer.from(document.content), purpose: 'document', contentType: upload.contentType });
                await store.transaction(async () => {
                    const intent = await store.get(identity.tenantId, 'object-intents', intentId);
                    if (!intent || intent.state !== 'prepared') denied('OBJECT_INTENT_SEALED', 409);
                    await store.put(identity.tenantId, 'object-intents', intentId, { ...intent, state: 'uploaded', reference, at: now() });
                }, { tenantId: identity.tenantId });
                } catch (error) { if (enqueueMaintenance) await enqueueMaintenance(identity, { kind: 'object-cleanup', payload: { intentId }, idempotencyKey: intentId }); throw error; }
                delete document.content;
                document.objectRef = reference;
            }
            try {
            return (await store.transaction(async () => {
                identityFor(identity, ['operator']);
                await access(identity, document.id);
                const previousDocument = await store.get(identity.tenantId, 'documents', document.id);
                if (objectStorage && hashCanonical(previousDocument ?? null) !== previousDigest) denied('DOCUMENT_VERSION_CHANGED', 409);
                if (assertUnheld) await assertUnheld(identity.tenantId, {
                    actorIds: [...new Set([identity.actorId, previousDocument?.createdBy, previousDocument?.actorId, previousDocument?.updatedBy].filter(Boolean))],
                    documentIds: [...new Set([document.id, ...(previousDocument?.sourceDocumentIds ?? [])])],
                });
                document.createdBy = previousDocument?.createdBy ?? previousDocument?.actorId ?? identity.actorId;
                if (intentId) {
                    const intent = await store.get(identity.tenantId, 'object-intents', intentId);
                    if (!intent || intent.state !== 'uploaded' || hashCanonical(intent.reference) !== hashCanonical(reference)) denied('OBJECT_INTENT_SEALED', 409);
                }
                const previous = (await state(identity.tenantId));
                const next = { ...previous, configurationVersion: previous.configurationVersion + 1, toolVersion };
                (await store.put(identity.tenantId, 'documents', document.id, document));
                (await store.put(identity.tenantId, 'metadata', 'document-service', { ...next, configurationDigest }));
                (await store.appendAudit({ tenantId: identity.tenantId, actorId: identity.actorId, event: 'document.put', target: document.id, data: { label: document.label, version: next.configurationVersion } }));
                if (intentId) await store.delete(identity.tenantId, 'object-intents', intentId);
                identityFor(identity, ['operator']);
                return { documentId: document.id, ...next };
            }, { tenantId: identity.tenantId }));
            } catch (error) {
                if (reference && enqueueMaintenance) await enqueueMaintenance(identity, { kind: 'object-cleanup', payload: { intentId }, idempotencyKey: intentId });
                throw error;
            }
        },
        metadata,
        /** @param {any} identity @param {any} action @param {any} context */
        async execute(identity, action, { operationId = action.id, expectedVersion, deadlineAt, admission } = {}) {
            identityFor(identity);
            identifier(operationId);
            // The authenticated resource route supplies a verified single-action grant.
            // These independent checks still run at the final effect boundary.
            positiveInteger(expectedVersion);
            positiveInteger(deadlineAt);
            const checked = validateProductAction(action);
            const digest = hashCanonical({ actorId: identity.actorId, tenantId: identity.tenantId, action: checked, expectedVersion });
            const inherited = requestContext.getStore();
            const effectDeadline = Math.min(deadlineAt, admission?.expiresAt ?? Infinity, identity.expiresAt ?? Infinity, inherited?.deadlineAt ?? Infinity);
            const assertGrant = () => {
                identityFor(identity);
                if (deadlineAt <= now()) denied('RESOURCE_GRANT_EXPIRED');
                if (admission && (!Number.isSafeInteger(admission.fence) || admission.fence < 1 || admission.expiresAt < deadlineAt || admission.expiresAt <= now())) denied('RESOURCE_LEASE_EXPIRED');
            };
            assertGrant();
            const preparedPrior = objectStorage ? await store.get(identity.tenantId, 'resource-operations', operationId) : null;
            const prepared = objectStorage && !preparedPrior ? (await current(identity, checked)).document : null;
            const priorRef = preparedPrior?.digest === digest && !preparedPrior.resultExpiredAt ? preparedPrior.result?.objectRef : null;
            const preparedContent = prepared?.objectRef ? new TextDecoder('utf-8', { fatal: true }).decode(await objectStorage.get(prepared.objectRef,
                { tenantId: identity.tenantId, id: prepared.id, purpose: 'document', deadlineAt: effectDeadline })) : priorRef ? new TextDecoder('utf-8', { fatal: true }).decode(await objectStorage.get(priorRef,
                { tenantId: identity.tenantId, id: priorRef.id, purpose: 'document', deadlineAt: effectDeadline })) : prepared?.content;
            assertGrant();
            return (await requestContext.run({ ...inherited, deadlineAt: effectDeadline }, () => store.transaction(async () => {
                const prior = (await store.get(identity.tenantId, 'resource-operations', operationId));
                assertGrant();
                if (prior?.fence && admission && admission.fence < prior.fence) denied('RESOURCE_FENCE_STALE');
                if (prior) {
                    if (prior.digest !== digest)
                        denied('OPERATION_CONFLICT', 409);
                    await access(identity, prior.result?.documentId ?? checked.documentId);
                    if (prior.resultExpiredAt) return { operationId, state: prior.state, resultExpired: true };
                    if (prior.result?.objectRef) {
                        if (!priorRef || hashCanonical(prior.result.objectRef) !== hashCanonical(priorRef)) denied('OPERATION_CHANGED', 409);
                        const result = { ...prior.result, content: preparedContent }; delete result.objectRef; return result;
                    }
                    return structuredClone(prior.result);
                }
                if ((await state(identity.tenantId)).configurationVersion !== expectedVersion)
                    denied('RESOURCE_VERSION_CHANGED', 409);
                const { document } = (await current(identity, checked));
                if (prepared && hashCanonical(document) !== hashCanonical(prepared)) denied('DOCUMENT_VERSION_CHANGED', 409);
                // Metadata/database waits must not extend a signed grant past its effect boundary.
                assertGrant();
                let result;
                if (checked.kind === 'share') {
                    if (!recipients.has(checked.recipient) || !document.allowedRecipients.includes(checked.recipient))
                        denied('RECIPIENT_DENIED');
                    const delivery = { operationId, documentId: document.id, recipient: checked.recipient, label: document.label,
                        ...(document.objectRef ? { objectRef: document.objectRef } : { content: document.content }), actorId: identity.actorId, committedAt: now() };
                    (await store.put(identity.tenantId, 'deliveries', operationId, delivery));
                    result = { kind: 'share', documentId: document.id, recipient: checked.recipient, deliveryId: operationId,
                        status: 'committed', channel: 'internal-mailbox' };
                }
                else
                    result = { kind: 'read', documentId: document.id, label: document.label, content: document.objectRef ? preparedContent : document.content };
                const storedResult = document.objectRef && checked.kind === 'read' ? { ...result, content: undefined, objectRef: document.objectRef } : result;
                if (storedResult.content === undefined) delete storedResult.content;
                (await store.put(identity.tenantId, 'resource-operations', operationId, { digest, actorId: identity.actorId, state: 'succeeded', result: storedResult, completedAt: now(), ...(admission ? { fence: admission.fence } : {}) }));
                (await store.appendAudit({ tenantId: identity.tenantId, actorId: identity.actorId, event: `document.${checked.kind}`, target: operationId,
                    data: { documentId: document.id, ...(checked.recipient ? { recipient: checked.recipient } : {}) } }));
                assertGrant();
                return result;
            }, { tenantId: identity.tenantId })));
        },
        async observe(identity, operationId) {
            identityFor(identity);
            identifier(operationId);
            const operation = (await store.get(identity.tenantId, 'resource-operations', operationId));
            if (operation && operation.actorId !== identity.actorId && !identity.roles.includes('operator') && !identity.roles.includes('auditor'))
                denied('OPERATION_DENIED');
            identityFor(identity);
            await access(identity, operation?.result?.documentId);
            if (operation?.result?.objectRef && !operation.resultExpiredAt) {
                if (!objectStorage) denied('OBJECT_STORAGE_UNAVAILABLE', 503);
                const content = new TextDecoder('utf-8', { fatal: true }).decode(await objectStorage.get(operation.result.objectRef,
                    { tenantId: identity.tenantId, id: operation.result.objectRef.id, purpose: 'document' }));
                return await store.transaction(async () => {
                    identityFor(identity);
                    await access(identity, operation.result.documentId);
                    if (hashCanonical((await store.get(identity.tenantId, 'resource-operations', operationId)) ?? null) !== hashCanonical(operation)) denied('OPERATION_CHANGED', 409);
                    const result = { ...operation.result, content }; delete result.objectRef;
                    return { operationId, state: operation.state, result };
                }, { tenantId: identity.tenantId });
            }
            return operation ? { operationId, state: operation.state, ...(operation.resultExpiredAt ? { resultExpired: true } : { result: operation.result }) } : { operationId, state: 'absent' };
        },
        // Trusted maintenance port. Tombstones retain the unique effect identity;
        // deleting them would make a repeated operation dispatch again.
        async pruneResults(tenantId, { before, limit = 50, after = '', now: at = Date.now() }) {
            identifier(tenantId);
            positiveInteger(before);
            positiveInteger(at);
            positiveInteger(limit, 100);
            if (before > at)
                denied('INVALID_RETENTION_BOUNDARY', 400);
            return (await store.transaction(async () => {
                const page = (await store.list(tenantId, 'resource-operations', { limit, after }));
                let pruned = 0;
                for (const { id, value } of page.items) {
                    if (value.state === 'succeeded' && value.completedAt <= before && !value.resultExpiredAt) {
                        (await store.put(tenantId, 'resource-operations', id, { ...value, result: null, resultExpiredAt: at }));
                        pruned++;
                    }
                }
                return { pruned, next: page.next };
            }, { tenantId: tenantId }));
        },
        async delivery(identity, deliveryId) {
            identityFor(identity);
            identifier(deliveryId);
            const delivery = (await store.get(identity.tenantId, 'deliveries', deliveryId));
            if (!delivery || delivery.recipient !== identity.actorId && !identity.roles.includes('operator'))
                denied('DELIVERY_DENIED');
            await access(identity, delivery.documentId);
            identityFor(identity);
            if (!delivery.objectRef) return delivery;
            if (!objectStorage) denied('OBJECT_STORAGE_UNAVAILABLE', 503);
            const content = new TextDecoder('utf-8', { fatal: true }).decode(await objectStorage.get(delivery.objectRef,
                { tenantId: identity.tenantId, id: delivery.documentId, purpose: 'document' }));
            return await store.transaction(async () => {
                identityFor(identity);
                await access(identity, delivery.documentId);
                if (hashCanonical((await store.get(identity.tenantId, 'deliveries', deliveryId)) ?? null) !== hashCanonical(delivery)) denied('DELIVERY_CHANGED', 409);
                const result = { ...delivery, content }; delete result.objectRef; return result;
            }, { tenantId: identity.tenantId });
        },
        async status(identity) {
            identityFor(identity);
            return { ...(await state(identity.tenantId)), healthy: true, persistence: objectStorage ? 'encrypted-versioned-object-store' : `encrypted-${store.backend}`, deliveryChannel: 'internal-mailbox', maxContentBytes };
        },
        async importFile(identity, { relativePath, ...document }) {
            identityFor(identity, ['operator']);
            if (!importRoot || typeof relativePath !== 'string' || isAbsolute(relativePath) || relativePath.includes('..') || relativePath.includes(':'))
                denied('IMPORT_PATH_DENIED');
            const root = await realpath(importRoot);
            const candidate = resolve(root, relativePath);
            const actual = await realpath(candidate);
            const subpath = relative(root, actual);
            if (!subpath || subpath.startsWith('..') || isAbsolute(subpath) || (await lstat(candidate)).isSymbolicLink())
                denied('IMPORT_PATH_DENIED');
            const handle = await open(actual, 'r');
            try {
                if (!(await handle.stat()).isFile() || (await handle.stat()).size > maxContentBytes)
                    denied('IMPORT_TOO_LARGE', 413);
                const bytes = Buffer.alloc(maxContentBytes + 1);
                const { bytesRead } = await handle.read(bytes);
                if (bytesRead > maxContentBytes)
                    denied('IMPORT_TOO_LARGE', 413);
                let content;
                try {
                    content = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, bytesRead));
                }
                catch {
                    denied('IMPORT_INVALID_UTF8', 400);
                }
                return (await service.putDocument(identity, { ...document, content }));
            }
            finally {
                await handle.close();
            }
        },
    };
    return Object.freeze(service);
}
