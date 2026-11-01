import { asAsyncStore } from './async-store.mjs';
import { createPublicKey, randomUUID } from 'node:crypto';
import { CompactSign, compactVerify } from 'jose';
import canonicalize from 'canonicalize';
import { AppError, exactObject, identifier, positiveInteger } from '../protocol.mjs';
import { assertProductIdentity, hashCanonical } from './policy.mjs';
import { boundedText, detectContent, evaluateDetector, normalizeExample, validateDetectorModel } from './detector.mjs';
const UPDATE_TYPE = 'agent-runtime-detector-update+jws';
const deny = (code) => { throw new AppError(403, code); };
export function redactLearningText(value) {
    const text = boundedText(value);
    const redacted = text
        .replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '[redacted-key]')
        .replace(/\bBearer\s+[A-Za-z0-9._~+/-]+=*/gi, 'Bearer [redacted]')
        .replace(/\b(?:sk|zk_live|zk_admin)[_-][A-Za-z0-9_-]{12,}\b/g, '[redacted-token]')
        .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[redacted-jwt]')
        .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[email]');
    if (Buffer.byteLength(redacted) > 1024)
        throw new AppError(400, 'LEARNING_TEXT_TOO_LARGE');
    return redacted;
}
/** Owner-side helper; the protected agent and learner must not receive this private key. */
export async function signDetectorUpdate(payload, privateKey) {
    return new CompactSign(Buffer.from(canonicalize(payload))).setProtectedHeader({ alg: 'EdDSA', typ: UPDATE_TYPE }).sign(privateKey);
}
/**
 * Tenant-local learning only proposes detector changes; it never writes task/approval policy.
 * @param {{store:any,trustKey:any,policyDigest:string|(()=>string),now?:()=>number,
 * assertAccessible?:any,assertUnheld?:any,retentionMs?:number,promotionLifetimeMs?:number,thresholds?:{minRecall:number,minPrecision:number,maxFalsePositiveRate:number}}} options
 */
export function createLearningService({ store, trustKey, policyDigest, assertAccessible, assertUnheld, now = Date.now, retentionMs = 604800000, promotionLifetimeMs = 900000, thresholds = { minRecall: 0.5, minPrecision: 0.8, maxFalsePositiveRate: 0.25 }, }) {
    store = asAsyncStore(store);
    if (!trustKey || (typeof policyDigest !== 'string' && typeof policyDigest !== 'function'))
        throw new AppError(400, 'INVALID_LEARNING_CONFIGURATION');
    let pinnedKey;
    try {
        if (trustKey?.type === 'private' || (typeof trustKey === 'string' && trustKey.includes('PRIVATE KEY')))
            throw new Error('Public key required');
        pinnedKey = trustKey?.type === 'public' ? trustKey : createPublicKey(trustKey);
        if (pinnedKey.asymmetricKeyType !== 'ed25519')
            throw new Error('Ed25519 required');
    }
    catch {
        throw new AppError(400, 'INVALID_LEARNING_CONFIGURATION');
    }
    positiveInteger(retentionMs, 2592000000);
    positiveInteger(promotionLifetimeMs, 3600000);
    exactObject(thresholds, ['minRecall', 'minPrecision', 'maxFalsePositiveRate']);
    for (const value of Object.values(thresholds))
        if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1)
            throw new AppError(400, 'INVALID_LEARNING_CONFIGURATION');
    const limits = Object.freeze({ ...thresholds });
    const authority = () => {
        const value = typeof policyDigest === 'function' ? policyDigest() : policyDigest;
        if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value))
            throw new AppError(400, 'INVALID_POLICY_DIGEST');
        return value;
    };
    authority();
    const audit = async (identity, event, target, data = {}) => (await store.appendAudit({
        tenantId: identity.tenantId, actorId: identity.actorId, event, target, data, at: now(),
    }));
    async function all(tenantId, namespace, maximum = 64) {
        const result = [];
        let after;
        const seen = new Set();
        do {
            const page = (await store.list(tenantId, namespace, { limit: Math.min(100, maximum), ...(after ? { after } : {}) }));
            for (const item of page.items)
                result.push(item.value);
            if (result.length > maximum || (page.next && seen.has(page.next)))
                throw new AppError(429, 'LEARNING_QUOTA');
            after = page.next;
            if (after)
                seen.add(after);
        } while (after);
        return result;
    }
    async function candidate(identity, id) {
        const value = (await store.get(identity.tenantId, 'learning-candidates', identifier(id)));
        if (!value || value.tenantId !== identity.tenantId)
            throw new AppError(404, 'CANDIDATE_NOT_FOUND');
        return value;
    }
    const service = {
        async quarantine(identity, value) {
            assertProductIdentity(identity, ['agent', 'operator']);
            exactObject(value, ['text', 'sourceId', 'sourceKind'], ['id']);
            if (!['document', 'tool', 'memory'].includes(value.sourceKind))
                throw new AppError(400, 'INVALID_SOURCE');
            const text = redactLearningText(value.text);
            const textDigest = hashCanonical(normalizeExample(text));
            return (await store.transaction(async () => {
                assertProductIdentity(identity, ['agent', 'operator']);
                const entries = (await all(identity.tenantId, 'learning-examples'));
                const duplicate = entries.find((entry) => entry.textDigest === textDigest);
                if (duplicate)
                    return { id: duplicate.id, status: duplicate.status, duplicate: true };
                if (entries.length >= 64 || entries.filter((entry) => entry.actorId === identity.actorId && entry.status === 'quarantined').length >= 32) {
                    throw new AppError(429, 'LEARNING_QUOTA');
                }
                const id = identifier(value.id ?? randomUUID());
                if ((await store.get(identity.tenantId, 'learning-examples', id)))
                    throw new AppError(409, 'EXAMPLE_EXISTS');
                const example = { id, tenantId: identity.tenantId, actorId: identity.actorId, text, textDigest,
                    sourceId: identifier(value.sourceId), sourceKind: value.sourceKind, status: 'quarantined', createdAt: now(), expiresAt: now() + retentionMs };
                (await store.put(identity.tenantId, 'learning-examples', id, example, { expiresAt: example.expiresAt }));
                (await audit(identity, 'learning.quarantined', id, { textDigest, sourceKind: example.sourceKind }));
                return { id, status: 'quarantined', duplicate: false };
            }, { tenantId: identity.tenantId }));
        },
        async review(identity, value) {
            assertProductIdentity(identity, ['operator', 'approver']);
            exactObject(value, ['id', 'label', 'split']);
            if (!['attack', 'benign'].includes(value.label) || !['train', 'holdout'].includes(value.split))
                throw new AppError(400, 'INVALID_LABEL');
            return (await store.transaction(async () => {
                assertProductIdentity(identity, ['operator', 'approver']);
                const example = (await store.get(identity.tenantId, 'learning-examples', identifier(value.id)));
                if (!example)
                    throw new AppError(404, 'EXAMPLE_NOT_FOUND');
                if (example.actorId === identity.actorId)
                    deny('SELF_REVIEW_DENIED');
                if (example.status !== 'quarantined')
                    throw new AppError(409, 'EXAMPLE_ALREADY_REVIEWED');
                const updated = { ...example, status: 'reviewed', label: value.label, split: value.split,
                    reviewedBy: identity.actorId, reviewedAt: now() };
                (await store.put(identity.tenantId, 'learning-examples', example.id, updated, { expiresAt: example.expiresAt }));
                (await audit(identity, 'learning.reviewed', example.id, { label: value.label, split: value.split, textDigest: example.textDigest }));
                return { id: example.id, label: updated.label, split: updated.split, status: updated.status };
            }, { tenantId: identity.tenantId }));
        },
        async train(identity, options = {}) {
            assertProductIdentity(identity, ['operator', 'learner']);
            exactObject(options, [], ['threshold']);
            const threshold = options.threshold ?? 0.65;
            return store.transaction(async () => {
            assertProductIdentity(identity, ['operator', 'learner']);
            if ((await all(identity.tenantId, 'learning-candidates', 32)).length >= 32)
                throw new AppError(429, 'CANDIDATE_QUOTA');
            const reviewed = (await all(identity.tenantId, 'learning-examples')).filter((example) => example.status === 'reviewed');
            const training = reviewed.filter((example) => example.split === 'train');
            const holdout = reviewed.filter((example) => example.split === 'holdout');
            if (training.length < 4 || training.length > 32 || holdout.length < 4
                || ['attack', 'benign'].some((label) => training.filter((entry) => entry.label === label).length < 2
                    || holdout.filter((entry) => entry.label === label).length < 2))
                throw new AppError(400, 'INSUFFICIENT_REVIEWED_DATA');
            const model = validateDetectorModel({ version: 1, threshold,
                examples: training.map(({ text, label }) => ({ text, label })) });
            const evaluation = evaluateDetector(model, holdout.map(({ text, label }) => ({ text, label })));
            const eligible = evaluation.recall >= limits.minRecall && evaluation.precision >= limits.minPrecision
                && evaluation.falsePositiveRate <= limits.maxFalsePositiveRate;
            const item = { id: randomUUID(), tenantId: identity.tenantId, model,
                modelDigest: hashCanonical(model), corpusDigest: hashCanonical(reviewed.map(({ id, textDigest, label, split }) => ({ id, textDigest, label, split }))),
                evaluation, evaluationDigest: hashCanonical(evaluation), policyDigest: authority(), thresholds: limits,
                exampleIds: reviewed.map((example) => example.id),
                eligible, status: 'candidate', createdBy: identity.actorId, createdAt: now(),
                expiresAt: Math.min(now() + retentionMs, ...reviewed.map((example) => example.expiresAt)) };
                (await store.put(identity.tenantId, 'learning-candidates', item.id, item, { expiresAt: item.expiresAt }));
                (await audit(identity, 'learning.trained', item.id, { modelDigest: item.modelDigest, eligible }));
            return structuredClone(item);
            }, { tenantId: identity.tenantId });
        },
        async stage(identity, id) {
            assertProductIdentity(identity, ['operator', 'learner']);
            const item = (await candidate(identity, id));
            if (item.policyDigest !== authority())
                deny('POLICY_CHANGED');
            (await store.transaction(async () => {
                assertProductIdentity(identity, ['operator', 'learner']);
                await candidate(identity, item.id);
                const active = (await store.get(identity.tenantId, 'learning-active', 'current')) ?? { activeId: null, previousIds: [] };
                (await store.put(identity.tenantId, 'learning-active', 'current', { ...active, shadowId: item.id }));
                (await audit(identity, 'learning.shadowed', item.id));
            }, { tenantId: identity.tenantId }));
            return { shadowId: item.id, eligible: item.eligible };
        },
        async getCandidate(identity, id) {
            assertProductIdentity(identity, ['operator', 'learner', 'approver']);
            return structuredClone((await candidate(identity, id)));
        },
        async prepareUpdate(identity, id, options = {}) {
            assertProductIdentity(identity, ['operator', 'approver']);
            exactObject(options, [], ['action', 'expiresAt']);
            const action = options.action ?? 'promote';
            if (!['promote', 'rollback'].includes(action))
                throw new AppError(400, 'INVALID_UPDATE');
            const item = (await candidate(identity, id));
            const expiresAt = positiveInteger(options.expiresAt ?? Math.min(now() + promotionLifetimeMs, item.expiresAt));
            if (expiresAt <= now() || expiresAt > Math.min(now() + promotionLifetimeMs, item.expiresAt))
                deny('UPDATE_EXPIRED');
            return { version: 1, id: randomUUID(), action, tenantId: identity.tenantId, candidateId: item.id,
                modelDigest: item.modelDigest, corpusDigest: item.corpusDigest, evaluationDigest: item.evaluationDigest,
                policyDigest: authority(), authorizedBy: identity.actorId, issuedAt: now(), expiresAt };
        },
        async applyUpdate(identity, compactJws) {
            assertProductIdentity(identity, ['operator', 'approver']);
            if (typeof compactJws !== 'string' || compactJws.length > 8192)
                throw new AppError(400, 'INVALID_UPDATE');
            let payload;
            try {
                const verified = await compactVerify(compactJws, pinnedKey, { algorithms: ['EdDSA'] });
                if (verified.protectedHeader.typ !== UPDATE_TYPE)
                    throw new Error('Type');
                payload = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(verified.payload));
            }
            catch {
                deny('INVALID_UPDATE_SIGNATURE');
            }
            exactObject(payload, ['version', 'id', 'action', 'tenantId', 'candidateId', 'modelDigest', 'corpusDigest',
                'evaluationDigest', 'policyDigest', 'authorizedBy', 'issuedAt', 'expiresAt']);
            if (payload.version !== 1 || !['promote', 'rollback'].includes(payload.action))
                deny('INVALID_UPDATE');
            identifier(payload.id);
            identifier(payload.candidateId);
            positiveInteger(payload.issuedAt);
            positiveInteger(payload.expiresAt);
            if (payload.tenantId !== identity.tenantId || payload.authorizedBy !== identity.actorId)
                deny('UPDATE_SUBJECT');
            if (payload.issuedAt > now() || payload.expiresAt <= now()
                || payload.expiresAt <= payload.issuedAt || payload.expiresAt - payload.issuedAt > promotionLifetimeMs)
                deny('UPDATE_EXPIRED');
            const item = (await candidate(identity, payload.candidateId));
            if (payload.expiresAt > item.expiresAt)
                deny('UPDATE_EXPIRED');
            if (!item.eligible)
                deny('CANDIDATE_FAILED_EVALUATION');
            if (item.createdBy === identity.actorId)
                deny('SELF_PROMOTION_DENIED');
            if (payload.modelDigest !== item.modelDigest || payload.corpusDigest !== item.corpusDigest
                || payload.evaluationDigest !== item.evaluationDigest)
                deny('UPDATE_DIGEST');
            if (payload.policyDigest !== authority() || item.policyDigest !== payload.policyDigest)
                deny('POLICY_CHANGED');
            return (await store.transaction(async () => {
                assertProductIdentity(identity, ['operator', 'approver']);
                await candidate(identity, item.id);
                if (payload.expiresAt <= now())
                    deny('UPDATE_EXPIRED');
                if ((await store.get(identity.tenantId, 'learning-promotions', payload.id)))
                    throw new AppError(409, 'UPDATE_REPLAY');
                const prior = (await store.get(identity.tenantId, 'learning-active', 'current')) ?? { activeId: null, previousIds: [] };
                if (payload.action === 'rollback' && !prior.previousIds.includes(item.id))
                    deny('ROLLBACK_UNKNOWN');
                const previousIds = [...new Set([...(prior.activeId ? [prior.activeId] : []), ...prior.previousIds])]
                    .filter((id) => id !== item.id).slice(0, 16);
                (await store.put(identity.tenantId, 'learning-active', 'current', { activeId: item.id, shadowId: null,
                    previousIds, policyDigest: payload.policyDigest, expiresAt: payload.expiresAt }));
                (await store.put(identity.tenantId, 'learning-promotions', payload.id, { ...payload, signature: compactJws }, { expiresAt: now() + retentionMs }));
                (await audit(identity, payload.action === 'rollback' ? 'learning.rolled-back' : 'learning.promoted', item.id, { modelDigest: item.modelDigest, policyDigest: payload.policyDigest }));
                return { activeId: item.id, action: payload.action, policyDigest: payload.policyDigest };
            }, { tenantId: identity.tenantId }));
        },
        async detect(identity, text, context = {}) {
            assertProductIdentity(identity, ['agent', 'operator', 'learner', 'auditor']);
            exactObject(context, [], ['source', 'task', 'proposedAction']);
            const current = (await store.get(identity.tenantId, 'learning-active', 'current'));
            let model;
            let state = 'baseline';
            if (current?.activeId) {
                if (current.policyDigest !== authority())
                    state = 'blocked-policy-change';
                else if (current.expiresAt <= now())
                    state = 'expired';
                else {
                    const item = (await store.get(identity.tenantId, 'learning-candidates', current.activeId));
                    if (item && item.modelDigest === hashCanonical(item.model) && item.policyDigest === authority()) {
                        model = validateDetectorModel(item.model);
                        state = 'active';
                    }
                    else
                        state = 'model-unavailable';
                }
            }
            const verdict = detectContent(text, { ...context, ...(model ? { model } : {}) });
            const shadow = current?.shadowId && (await store.get(identity.tenantId, 'learning-candidates', current.shadowId));
            const report = { ...verdict };
            const shadowReport = shadow && shadow.policyDigest === authority() ? { ...detectContent(text, { ...context, model: shadow.model }) } : null;
            if (!identity.roles.some((role) => ['operator', 'learner', 'auditor'].includes(role))) {
                delete report.learnedScore;
                if (shadowReport)
                    delete shadowReport.learnedScore;
            }
            return { ...report, adaptiveState: state, activeId: model ? current.activeId : null,
                shadow: shadowReport,
                authorityPolicyDigest: authority(), authorityChanged: false };
        },
        async discardExample(identity, id) {
            assertProductIdentity(identity, ['operator']);
            identifier(id);
            (await store.transaction(async () => {
                assertProductIdentity(identity, ['operator']);
                const source = await store.get(identity.tenantId, 'learning-examples', id);
                await assertUnheld?.(identity.tenantId, { actorIds: [source?.actorId].filter(Boolean), documentIds: source?.sourceKind === 'document' ? [source.sourceId] : [], models: true });
                const removed = (await all(identity.tenantId, 'learning-candidates', 32)).filter((item) => item.exampleIds.includes(id)).map((item) => item.id);
                for (const candidateId of removed)
                    (await store.delete(identity.tenantId, 'learning-candidates', candidateId));
                const current = (await store.get(identity.tenantId, 'learning-active', 'current'));
                if (current)
                    (await store.put(identity.tenantId, 'learning-active', 'current', {
                        ...current, activeId: removed.includes(current.activeId) ? null : current.activeId,
                        shadowId: removed.includes(current.shadowId) ? null : current.shadowId,
                        previousIds: current.previousIds.filter((candidateId) => !removed.includes(candidateId)),
                    }));
                (await store.delete(identity.tenantId, 'learning-examples', id));
                (await audit(identity, 'learning.example-deleted', id, { candidatesRemoved: removed.length }));
            }, { tenantId: identity.tenantId }));
            return { deleted: true };
        },
    };
    if (assertAccessible) {
        for (const [name, work] of Object.entries(service)) service[name] = async (identity, ...args) => store.transaction(async () => {
            await assertAccessible(identity.tenantId, { kind: 'actor', id: identity.actorId });
            const blocked = await store.get(identity.tenantId, 'metadata', 'privacy-learning-block');
            if (blocked && name === 'detect') return { ...detectContent(args[0], args[1] ?? {}), adaptiveState: 'blocked-privacy-cleanup',
                activeId: null, shadow: null, authorityPolicyDigest: authority(), authorityChanged: false };
            if (blocked && name !== 'discardExample') throw new AppError(503, 'PRIVACY_MODEL_REBUILD_REQUIRED');
            const examples = await all(identity.tenantId, 'learning-examples');
            for (const example of examples) {
                await assertAccessible(identity.tenantId, { kind: 'actor', id: example.actorId });
                if (example.sourceKind === 'document') await assertAccessible(identity.tenantId, { kind: 'document', id: example.sourceId });
            }
            if (name === 'quarantine' && args[0]?.sourceKind === 'document') await assertAccessible(identity.tenantId, { kind: 'document', id: args[0].sourceId });
            return work(identity, ...args);
        }, { tenantId: identity.tenantId });
    }
    return Object.freeze(service);
}
