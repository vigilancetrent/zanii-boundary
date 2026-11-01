import { createServer } from 'node:https';
import { createHash, createHmac, randomUUID } from 'node:crypto';
import { chmod, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { z } from 'zod';
import { AppError, exactObject, identifier } from '../protocol.mjs';
import { readJson, sendJson, sendError } from '../http.mjs';
import { createAuthenticator } from './auth.mjs';
import { asAsyncStore, openConfiguredStore } from './async-store.mjs';
import { createPolicyEngine, hashCanonical, assertProductIdentity } from './policy.mjs';
import { createMemoryService } from './memory.mjs';
import { createLearningService } from './learning.mjs';
import { createCoverageService, checkpointEvidence } from './coverage.mjs';
import { createProductExecutor } from './executor.mjs';
import { createObservability, routeTemplate } from './observability.mjs';
import { createConfiguredTelemetry, createTelemetry, instrumentStore } from './telemetry.mjs';
import { createSharedIdentityLimiter } from './rate-limits.mjs';
import { createConfiguredResourceAdapter, requestContext } from './transport.mjs';
import { createDocumentService } from '../adapters/documents.mjs';
import { createMcpAdapter } from '../adapters/mcp.mjs';
import { createA2aAdapter } from '../adapters/a2a.mjs';
import { createConfiguredZaniiLedger } from '../adapters/zanii.mjs';
import { createConfiguredCompanions } from '../adapters/companions.mjs';
import { createAuditEvidencePage } from './evidence.mjs';
import { createConfiguredOperations } from './runtime-operations.mjs';
import { createConfiguredLogSink } from './logging.mjs';
import { createSignalSampler } from './metrics-sources.mjs';
const documentsSchema = z.object({ toolVersion: z.string().default('documents-v1'), maxContentBytes: z.number().int().min(1).max(32768).default(32768),
    internalRecipients: z.array(z.string()).max(64).default([]), importRoot: z.string().optional() }).strict();
const learningSchema = z.object({ trustKeyFile: z.string(), required: z.boolean().default(false) }).strict();
const executionGrant = z.object({ task_id: z.string().min(1).max(128), policy_digest: z.string().regex(/^[a-f0-9]{64}$/),
    action_digest: z.string().regex(/^[a-f0-9]{64}$/), operation_id: z.string().min(1).max(128), resource_version: z.number().int().positive(),
    deadline_at: z.number().int().positive(), lease_owner: z.string().min(1).max(128).optional(), lease_fence: z.number().int().positive().optional(), lease_expires_at: z.number().int().positive().optional() }).passthrough();
const protocolsSchema = z.object({ mcp: z.object({ allowedOrigins: z.array(z.string().url()).max(32).default([]) }).strict().optional(),
    a2a: z.object({ publicUrl: z.string().url() }).strict().optional() }).strict();
function scope(identity, required, roles = []) {
    if (!identity.scopes.includes(required))
        throw new AppError(403, 'SCOPE_DENIED');
    if (roles.length && !roles.some((role) => identity.roles.includes(role)))
        throw new AppError(403, 'ROLE_DENIED');
}
function monitorScope(identity, required) {
    if (!identity.scopes.includes(required) && !identity.scopes.includes('runtime:audit')) throw new AppError(403, 'SCOPE_DENIED');
    if (!identity.roles.some((role) => ['operator', 'auditor'].includes(role))) throw new AppError(403, 'ROLE_DENIED');
}
const bearer = (req) => {
    const value = req.headers.authorization;
    if (typeof value !== 'string' || !/^Bearer [A-Za-z0-9_.-]+$/.test(value))
        throw new AppError(401, 'AUTHENTICATION_REQUIRED');
    return value.slice(7);
};
/** Same binary has distinct gateway and resource roles, each with its own pinned JWT audience.
 * @param {any} options Validated configuration/material and trusted adapter ports.
 */
export async function startProductServer({ config, material, store: suppliedStore, adapter: suppliedAdapter, zanii, companions, operations: suppliedOperations, logger } = {}) {
    let store = suppliedStore ? asAsyncStore(suppliedStore) : await openConfiguredStore({ config, material });
    let failed = true;
    let observability;
    let operations;
    let logSink;
    try {
        const baseDirectory = material.baseDirectory ?? process.cwd();
        if (config.logging) logSink = await createConfiguredLogSink(config.logging, { baseDirectory });
        const telemetry = config.telemetry ? await createConfiguredTelemetry(config.telemetry, { baseDirectory }) : createTelemetry({ serviceName: `runtime-${config.role}` });
        observability = createObservability({ ...config.limits, logger: logSink ? (line) => { logSink.write(line); logger?.(line); } : logger, pseudonymKey: material.auditKey, telemetry });
        store = instrumentStore(store, telemetry, observability.observeStore);
        const sampleSignals = createSignalSampler({ store, observability, telemetry, logSink, config, baseDirectory });
        const permitted = config.role === 'resource' ? ['documents'] : ['resource', 'learning', 'zanii', 'companions'];
        if (Object.keys(config.integrations).some((key) => !permitted.includes(key)))
            throw new AppError(400, 'UNKNOWN_INTEGRATION');
        if (!zanii && config.integrations.zanii)
            zanii = await createConfiguredZaniiLedger({ store, config: config.integrations.zanii, baseDirectory });
        const ledgerRequired = config.integrations.zanii?.required !== false;
        const actionLedger = ledgerRequired ? zanii : undefined;
        async function ledgerStatus() {
            let status;
            try { status = await zanii?.status(); }
            catch (error) {
                if (ledgerRequired) throw error;
                status = { configured: true, blocked: true, reason: 'ZANII_STATUS_UNAVAILABLE' };
            }
            if (actionLedger?.runtimePreflight) status = { ...status, runtime: await actionLedger.runtimePreflight.health() };
            return { ...(status ?? { configured: false, available: false }), requiredForActions: Boolean(zanii) && ledgerRequired,
                receiptPolicy: actionLedger ? 'required-before-effect' : 'local-journal-only',
                featureHealth: !zanii ? 'unconfigured' : status?.blocked || status?.runtime?.ready === false ? 'degraded' : 'not-probed' };
        }
        const companionTenantId = config.integrations.companions?.runtimeTenantId;
        if (companions || config.integrations.companions)
            identifier(companionTenantId);
        if (!companions && config.integrations.companions) {
            const settings = structuredClone(config.integrations.companions);
            delete settings.runtimeTenantId;
            // Only fixed bootstrap paths are resolved here; request bodies never enter this loader.
            if (typeof settings.agentRoot === 'string')
                settings.agentRoot = resolve(baseDirectory, settings.agentRoot);
            for (const service of ['register', 'passport', 'vault'])
                if (settings[service]) {
                    for (const [key, value] of Object.entries(settings[service]))
                        if (key.endsWith('File') && typeof value === 'string')
                            settings[service][key] = resolve(baseDirectory, value);
                }
            companions = createConfiguredCompanions(settings);
        }
        if (companions?.authorize) {
            const client = companions;
            companions = { ...client, authorize(identity, ...args) {
                    if (identity.tenantId !== companionTenantId)
                        throw new AppError(403, 'COMPANION_TENANT_DENIED');
                    return client.authorize(identity, ...args);
                } };
        }
        const protocolConfig = protocolsSchema.parse(config.protocols);
        const authenticate = createAuthenticator({ ...config.auth, jwks: material.jwks });
        const grantKeys = createLocalJWKSet(material.jwks);
        const policy = createPolicyEngine({ store });
        const coverage = createCoverageService({ config });
        let draining = false;
        operations = suppliedOperations ?? await createConfiguredOperations({ config, material, store, observability, telemetry, zanii, drain: () => draining,
            ports: { localStatus: () => logSink?.status() ?? { required: false, healthy: true } } });
        const memory = createMemoryService({ store, policy, assertAccessible: operations.privacyAccess ?? operations.privacy?.assertAccessible,
            assertUnheld: operations.privacyHold ?? operations.privacy?.assertUnheld });
        let learning;
        if (config.integrations.learning) {
            const options = learningSchema.parse(config.integrations.learning);
            learning = createLearningService({ store, trustKey: await readFile(resolve(baseDirectory, options.trustKeyFile), 'utf8'), policyDigest: policy.authorityDigest,
                assertAccessible: operations.privacyAccess ?? operations.privacy?.assertAccessible, assertUnheld: operations.privacyHold ?? operations.privacy?.assertUnheld });
        }
        const adapter = suppliedAdapter ?? (config.role === 'resource'
            ? createDocumentService({ store, objectStorage: operations.objects, enqueueMaintenance: operations.jobs?.enqueue,
                assertAccessible: operations.privacyAccess ?? operations.privacy?.assertAccessible, ...documentsSchema.parse(config.integrations.documents ?? {}),
                assertUnheld: operations.privacyHold ?? operations.privacy?.assertUnheld,
                ...(config.integrations.documents?.importRoot ? { importRoot: resolve(baseDirectory, config.integrations.documents.importRoot) } : {}) })
            : config.integrations.resource ? await createConfiguredResourceAdapter(config.integrations.resource, { ...config.limits, baseDirectory, ledger: actionLedger }) : null);
        const unavailable = { metadata() { throw new AppError(503, 'RESOURCE_UNCONFIGURED'); }, status() { throw new AppError(503, 'RESOURCE_UNCONFIGURED'); }, execute() { throw new AppError(503, 'RESOURCE_UNCONFIGURED'); }, observe() { throw new AppError(503, 'RESOURCE_UNCONFIGURED'); } };
        const executor = createProductExecutor({ store, policy, adapter: adapter ?? unavailable, coverage, zanii: actionLedger, learning, companions, operationalGate: operations.gate, requestTimeoutMs: config.limits.requestTimeoutMs });
        const mcp = protocolConfig.mcp ? createMcpAdapter({ store, execute: executor.execute, ...protocolConfig.mcp }) : null;
        const a2a = protocolConfig.a2a ? createA2aAdapter({ store, execute: executor.execute, cancel: executor.cancel, readOperation: executor.operation, retentionMs: config.storage.retentionMs, ...protocolConfig.a2a }) : null;
        const identityLimiter = createSharedIdentityLimiter({ store, ...config.limits });
        let maintenanceFailed = false;
        const touchedTenants = new Set();
        async function recover(tenantId) {
            if (touchedTenants.has(tenantId))
                return;
            if (touchedTenants.size >= 4096)
                throw new AppError(429, 'TENANT_CAPACITY');
            (await store.recoverUnknown(tenantId));
            touchedTenants.add(tenantId);
        }
        async function ready(identity) {
            const posture = await coverage.status();
            let resource = false;
            try {
                resource = Boolean((await adapter?.status(identity))?.healthy);
            }
            catch { /* Status reports unavailable dependency. */ }
            const audit = (await store.verifyAudit(identity.tenantId));
            const zaniiStatus = await ledgerStatus();
            const companionsStatus = companions?.status();
            const operational = await operations.status(identity);
            await sampleSignals({ containment: posture });
            return { ready: !draining && !maintenanceFailed && operational.ready && resource && posture.permitted && audit.ok !== false && (!ledgerRequired || !zaniiStatus.blocked && zaniiStatus.runtime?.ready !== false) && companionsStatus?.ready !== false,
                role: config.role, containment: posture, resource: resource ? 'available' : 'unavailable',
                learning: learning ? 'available' : 'unconfigured', zanii: zaniiStatus ?? { available: false },
                companions: companionsStatus ?? { configured: false }, operations: operational, maintenance: maintenanceFailed ? 'failed' : 'healthy', audit: audit.ok === false ? 'invalid' : 'verified', profile: config.profile };
        }
        async function resourceRoute(path, req, identity, body, token) {
            if (path === '/v1/resource/diagnostic' && req.method === 'POST') {
                scope(identity, 'resource:diagnostic');
                exactObject(body, []);
                // Fixed public canary exercises this authenticated backend TLS/socket route only.
                return { canary: 'agent-runtime-public-containment-canary-v1', transport: 'mtls', resourceRole: true };
            }
            if (path === '/v1/resource/status' && req.method === 'GET') {
                scope(identity, 'resource:status');
                return (await adapter.status(identity));
            }
            // A production resource also refuses company data until the shared host receipt is current.
            await coverage.require();
            await operations.gate(identity);
            if (path === '/v1/resource/metadata' && req.method === 'POST') {
                scope(identity, 'resource:metadata');
                exactObject(body, ['action']);
                return (await adapter.metadata(identity, body.action));
            }
            if (path === '/v1/resource/observe' && req.method === 'POST') {
                scope(identity, 'resource:observe');
                exactObject(body, ['operationId']);
                return (await adapter.observe(identity, body.operationId));
            }
            if (path === '/v1/resource/documents' && req.method === 'POST') {
                scope(identity, 'resource:admin', ['operator']);
                return (await adapter.putDocument(identity, body));
            }
            if (path === '/v1/resource/import' && req.method === 'POST') {
                scope(identity, 'resource:admin', ['operator']);
                return (await adapter.importFile(identity, body));
            }
            if (path === '/v1/resource/deliveries' && req.method === 'POST') {
                scope(identity, 'resource:read');
                exactObject(body, ['deliveryId']);
                return (await adapter.delivery(identity, body.deliveryId));
            }
            if (path === '/v1/resource/execute' && req.method === 'POST') {
                scope(identity, 'resource:execute');
                exactObject(body, ['action', 'operationId', 'expectedVersion', 'deadlineAt'], ['grant']);
                // Authenticator already checked issuer, audience, client cert and lifetime. Verify again to obtain only signed grant claims.
                const verified = await jwtVerify(token, grantKeys, { issuer: config.auth.issuer, audience: config.auth.audience, algorithms: config.auth.algorithms });
                const parsedGrant = executionGrant.safeParse(verified.payload);
                if (!parsedGrant.success)
                    throw new AppError(403, 'INVALID_RESOURCE_GRANT');
                const payload = parsedGrant.data;
                const metadata = (await adapter.metadata(identity, body.action));
                const semantic = { ...body.action, toolVersion: metadata.toolVersion };
                delete semantic.approvalId;
                const digest = hashCanonical({ taskId: payload.task_id, tenantId: identity.tenantId, policyDigest: payload.policy_digest, action: semantic });
                if (!/^[a-f0-9]{64}$/.test(payload.policy_digest) || payload.action_digest !== digest || payload.operation_id !== body.operationId
                    || payload.resource_version !== body.expectedVersion || payload.deadline_at !== body.deadlineAt || body.action.id !== body.operationId
                    || body.deadlineAt > identity.expiresAt || Date.now() >= body.deadlineAt)
                    throw new AppError(403, 'INVALID_RESOURCE_GRANT');
                const hasLease = payload.lease_owner !== undefined || payload.lease_fence !== undefined || payload.lease_expires_at !== undefined;
                if ((store.shared || hasLease) && (!payload.lease_owner || !payload.lease_fence || !payload.lease_expires_at
                    || payload.deadline_at > payload.lease_expires_at || Date.now() >= payload.lease_expires_at)) throw new AppError(403, 'INVALID_RESOURCE_LEASE');
                return (await adapter.execute(identity, body.action, { operationId: body.operationId, expectedVersion: body.expectedVersion, deadlineAt: body.deadlineAt,
                    ...(hasLease ? { admission: { ownerId: payload.lease_owner, fence: payload.lease_fence, expiresAt: payload.lease_expires_at } } : {}) }));
            }
            throw new AppError(404, 'ROUTE_NOT_FOUND');
        }
        async function route(path, req, identity, body, token) {
            if (path.startsWith('/v1/ops/')) return operations.route(path, req.method, identity, body);
            if (path === '/health/ready' && req.method === 'GET') {
                monitorScope(identity, 'runtime:health');
                const status = await ready(identity);
                return { httpStatus: status.ready ? 200 : 503, body: status };
            }
            if (config.role === 'resource')
                return { body: await resourceRoute(path, req, identity, body, token) };
            if (path.startsWith('/v1/tasks') || path.startsWith('/v1/memory') || path.startsWith('/v1/learning') || path.startsWith('/v1/operations') || ['/v1/actions', '/mcp', '/a2a'].includes(path))
                await (operations.privacyAccess ?? operations.privacy?.assertAccessible)?.(identity.tenantId, { kind: 'actor', id: identity.actorId });
            if (path === '/v1/diagnostic/read' && req.method === 'POST') {
                scope(identity, 'containment:probe', ['operator', 'auditor', 'agent']);
                exactObject(body, []);
                if (!adapter?.diagnostic)
                    throw new AppError(503, 'DIAGNOSTIC_UNAVAILABLE');
                return { body: await adapter.diagnostic(identity) };
            }
            if (path === '/v1/coverage' && req.method === 'GET') {
                scope(identity, 'runtime:audit', ['operator', 'auditor']);
                return { body: await coverage.status() };
            }
            if (path === '/v1/integrations/status' && req.method === 'GET') {
                scope(identity, 'runtime:audit', ['operator', 'auditor']);
                return { body: { companions: companions?.status() ?? { configured: false }, zanii: await ledgerStatus() } };
            }
            if (path === '/v1/zanii/recover' && req.method === 'POST') {
                scope(identity, 'runtime:integrations', ['operator']);
                exactObject(body, []);
                if (!zanii)
                    throw new AppError(503, 'ZANII_UNCONFIGURED');
                return { body: { outcomes: await zanii.recover(identity) } };
            }
            if (path === '/v1/zanii/proof' && req.method === 'POST') {
                scope(identity, 'runtime:audit', ['operator', 'auditor']);
                exactObject(body, ['hash']);
                if (!zanii)
                    throw new AppError(503, 'ZANII_UNCONFIGURED');
                if (typeof body.hash !== 'string' || !/^sha256:[a-f0-9]{64}$/.test(body.hash))
                    throw new AppError(400, 'INVALID_RECEIPT_HASH');
                return { body: await zanii.verifyProof(body.hash) };
            }
            const companionRoute = path.match(/^\/v1\/integrations\/(register|passport|vault)$/);
            if (companionRoute && req.method === 'POST') {
                scope(identity, 'runtime:integrations', ['operator']);
                exactObject(body, ['method', 'input']);
                await coverage.require();
                await operations.gate(identity);
                if (identity.tenantId !== companionTenantId)
                    throw new AppError(403, 'COMPANION_TENANT_DENIED');
                const client = companions?.[companionRoute[1]];
                if (!client)
                    throw new AppError(503, 'COMPANION_UNCONFIGURED');
                const methods = { register: ['verifyRegistration', 'getRegistration'], passport: ['challenge', 'verify', 'executeDirectoryRead'],
                    vault: ['createCase', 'getCase', 'declareUpload', 'putChunk', 'completeUpload'] };
                if (!methods[companionRoute[1]].includes(body.method))
                    throw new AppError(400, 'INVALID_COMPANION_METHOD');
                let result;
                if (body.method === 'getRegistration') {
                    exactObject(body.input, ['registrationId']);
                    result = await client.getRegistration(body.input.registrationId);
                }
                else if (body.method === 'getCase') {
                    exactObject(body.input, ['caseId']);
                    result = await client.getCase(body.input.caseId);
                }
                else if (body.method === 'declareUpload') {
                    exactObject(body.input, ['caseId', 'metadata', 'idempotencyKey']);
                    result = await client.declareUpload(body.input.caseId, body.input.metadata, body.input.idempotencyKey);
                }
                else if (body.method === 'putChunk') {
                    exactObject(body.input, ['uploadId', 'index', 'base64']);
                    if (typeof body.input.base64 !== 'string' || body.input.base64.length > 43692 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(body.input.base64))
                        throw new AppError(400, 'INVALID_CHUNK');
                    result = await client.putChunk(body.input.uploadId, body.input.index, Buffer.from(body.input.base64, 'base64'));
                }
                else if (body.method === 'completeUpload') {
                    exactObject(body.input, ['uploadId', 'sha256']);
                    result = await client.completeUpload(body.input.uploadId, body.input.sha256);
                }
                else
                    result = await client[body.method](body.input);
                (await store.appendAudit({ tenantId: identity.tenantId, actorId: identity.actorId, event: 'integration.invoked', target: companionRoute[1], data: { method: body.method } }));
                return { body: result };
            }
            if (path === '/v1/evidence' && ['GET', 'POST'].includes(req.method)) {
                scope(identity, 'runtime:audit', ['operator', 'auditor']);
                if (body !== undefined)
                    exactObject(body, [], ['after', 'limit', 'through']);
                return { body: (await createAuditEvidencePage({ store, tenantId: identity.tenantId, signingKey: material.signingKey, ...(body ?? {}) })) };
            }
            if (path === '/v1/checkpoint' && req.method === 'GET') {
                scope(identity, 'runtime:audit', ['operator', 'auditor']);
                return { body: (await checkpointEvidence({ store, identity, signingKey: material.signingKey })) };
            }
            if (path === '/v1/audit' && req.method === 'POST') {
                scope(identity, 'runtime:audit', ['operator', 'auditor']);
                exactObject(body, [], ['limit', 'after']);
                return { body: (await store.queryAudit(identity.tenantId, body)) };
            }
            if (path === '/v1/tasks' && req.method === 'POST') {
                scope(identity, 'runtime:admin', ['operator']);
                return { httpStatus: 201, body: (await policy.createTask(identity, body)) };
            }
            if (path === '/v1/tasks' && req.method === 'GET') {
                scope(identity, 'runtime:admin', ['operator']);
                return { body: (await store.list(identity.tenantId, 'tasks')) };
            }
            if (path === '/v1/tasks/list' && req.method === 'POST') {
                scope(identity, 'runtime:admin', ['operator']);
                exactObject(body, [], ['limit', 'after']);
                return { body: (await store.list(identity.tenantId, 'tasks', body)) };
            }
            let match = path.match(/^\/v1\/tasks\/([A-Za-z0-9._:@-]+)(?:\/(delegate|revoke))?$/);
            if (match) {
                scope(identity, match[2] ? 'runtime:invoke' : 'runtime:read', ['agent', 'operator', 'auditor', 'approver']);
                if (req.method === 'GET' && !match[2])
                    return { body: (await policy.getTask(identity, match[1])) };
                if (req.method === 'POST' && match[2] === 'delegate')
                    return { httpStatus: 201, body: (await policy.delegate(identity, match[1], body)) };
                if (req.method === 'POST' && match[2] === 'revoke') {
                    exactObject(body, []);
                    return { body: (await policy.revoke(identity, match[1])) };
                }
            }
            if (path === '/v1/approvals' && req.method === 'POST') {
                scope(identity, 'runtime:approve', ['operator', 'approver']);
                exactObject(body, ['taskId', 'action', 'expiresAt']);
                const metadata = await (adapter ?? unavailable).metadata(identity, body.action);
                return { httpStatus: 201, body: (await policy.approve(identity, { ...body, toolVersion: metadata.toolVersion })) };
            }
            if (path === '/v1/actions' && req.method === 'POST') {
                scope(identity, 'runtime:invoke', ['agent', 'operator']);
                const response = await executor.execute(identity, body);
                return { httpStatus: response.status, body: response };
            }
            match = path.match(/^\/v1\/operations\/([A-Za-z0-9._:@-]+)(?:\/(reconcile|cancel))?$/);
            if (match) {
                scope(identity, 'runtime:invoke', ['agent', 'operator']);
                let result;
                if (!match[2] && req.method === 'GET')
                    result = await executor.operation(identity, match[1]);
                else if (req.method === 'POST' && match[2]) {
                    exactObject(body, []);
                    result = await executor[match[2]](identity, match[1]);
                }
                if (result)
                    return { httpStatus: typeof result.status === 'number' ? result.status : 200, body: result };
            }
            if (path === '/v1/memory' && req.method === 'POST') {
                scope(identity, 'runtime:invoke', ['agent', 'operator']);
                exactObject(body, ['taskId', 'entry']);
                return { body: (await memory.remember(identity, body.taskId, body.entry)) };
            }
            if (path === '/v1/memory/read' && req.method === 'POST') {
                scope(identity, 'runtime:invoke', ['agent', 'operator']);
                exactObject(body, ['taskId', 'id']);
                return { body: (await memory.read(identity, body.taskId, body.id)) };
            }
            if (path === '/v1/memory/delete' && req.method === 'POST') {
                scope(identity, 'runtime:invoke', ['agent', 'operator']);
                exactObject(body, ['taskId', 'id']);
                return { body: (await memory.remove(identity, body.taskId, body.id)) };
            }
            if (path.startsWith('/v1/learning/') && req.method === 'POST') {
                scope(identity, 'runtime:learn');
                if (!learning)
                    throw new AppError(503, 'LEARNING_UNCONFIGURED');
                const method = path.slice('/v1/learning/'.length);
                if (['quarantine', 'review', 'train'].includes(method))
                    return { body: await learning[method](identity, body) };
                if (['shadow', 'candidate', 'delete'].includes(method)) {
                    exactObject(body, ['id']);
                    return { body: await learning[{ shadow: 'stage', candidate: 'getCandidate', delete: 'discardExample' }[method]](identity, body.id) };
                }
                if (method === 'prepare-update') {
                    exactObject(body, ['id'], ['action', 'expiresAt']);
                    const { id, ...options } = body;
                    return { body: (await learning.prepareUpdate(identity, id, options)) };
                }
                if (method === 'apply-update') {
                    exactObject(body, ['jws']);
                    return { body: await learning.applyUpdate(identity, body.jws) };
                }
                if (method === 'detect') {
                    exactObject(body, ['text'], ['context']);
                    return { body: (await learning.detect(identity, body.text, body.context)) };
                }
            }
            if (path === '/mcp' && mcp) {
                scope(identity, 'runtime:invoke', ['agent', 'operator']);
                const result = await mcp.handle({ method: req.method, headers: req.headers, body }, identity);
                return { httpStatus: result.status, headers: result.headers, body: result.body };
            }
            if (path === '/a2a' && a2a) {
                scope(identity, 'runtime:invoke', ['agent', 'operator']);
                const result = await a2a.handle({ method: req.method, body }, identity);
                return { httpStatus: result.status, headers: result.headers, body: result.body };
            }
            if (path === '/.well-known/agent-card.json' && a2a && req.method === 'GET') {
                scope(identity, 'runtime:read');
                return { body: a2a.agentCard() };
            }
            throw new AppError(404, 'ROUTE_NOT_FOUND');
        }
        const server = createServer({ ...material.tls, requestCert: true, rejectUnauthorized: true, minVersion: 'TLSv1.3', maxHeaderSize: 16384 }, (req, res) => {
            let context;
            let routeName = 'unmatched';
            let securityIdentity;
            let authenticated = false;
            let auditAttempted = false;
            const peerPseudonym = createHmac('sha256', material.auditKey).update(req.socket.remoteAddress ?? 'unknown').digest('hex').slice(0, 24);
            async function securityAudit(event, code, status) {
                auditAttempted = true;
                try { await store.appendAudit({ tenantId: securityIdentity?.tenantId ?? 'system', actorId: securityIdentity?.actorId ?? 'unauthenticated',
                    event, target: 'http', data: { requestId: context?.requestId ?? randomUUID(), peer: peerPseudonym, route: routeName,
                        method: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].includes(req.method) ? req.method : 'OTHER', code, status } }); }
                catch { throw new AppError(503, 'SECURITY_AUDIT_UNAVAILABLE'); }
            }
            Promise.resolve().then(async () => {
                context = { ...observability.begin(req), deadlineAt: Date.now() + config.limits.requestTimeoutMs };
                context.admit();
                const work = async () => {
                res.setHeader('traceparent', context.traceparent);
                const url = new URL(req.url, 'https://runtime.invalid');
                if (url.search || url.hash || req.url.startsWith('//') || decodeURIComponent(url.pathname) !== url.pathname)
                    throw new AppError(400, 'INVALID_ROUTE');
                const path = url.pathname;
                routeName = routeTemplate(path);
                if (path === '/health/live' && req.method === 'GET') {
                    sendJson(res, 200, { live: true }, { requestId: context.requestId });
                    return;
                }
                if (path === '/health/startup' && req.method === 'GET') {
                    sendJson(res, 200, { started: true }, { requestId: context.requestId }); return;
                }
                if (draining) throw new AppError(503, 'SERVER_DRAINING');
                const socket = /** @type {import('node:tls').TLSSocket} */ (req.socket);
                if (!socket.authorized)
                    throw new AppError(401, 'CLIENT_CERTIFICATE_REQUIRED');
                const peer = socket.getPeerCertificate();
                if (!peer.raw)
                    throw new AppError(401, 'CLIENT_CERTIFICATE_REQUIRED');
                const fingerprint = createHash('sha256').update(peer.raw).digest('base64url');
                const token = bearer(req);
                const identity = await authenticate.authenticate(token, { certificateFingerprint: fingerprint });
                securityIdentity = identity;
                authenticated = true;
                context.deadlineAt = Math.min(context.deadlineAt, identity.expiresAt);
                context.bindIdentity(identity);
                await securityAudit('authentication.succeeded', 'AUTHENTICATED', 200);
                if (store.shared) await identityLimiter.consume(identity);
                else observability.limit(`identity:${identity.tenantId}:${identity.actorId}`);
                (await recover(identity.tenantId));
                if (path === '/metrics' && req.method === 'GET') {
                    monitorScope(identity, 'runtime:metrics');
                    await operations.status(identity);
                    await sampleSignals({ containment: await coverage.status() });
                    const text = await observability.metricsText();
                    assertProductIdentity(identity);
                    if (Date.now() >= context.deadlineAt) throw new AppError(504, 'REQUEST_DEADLINE');
                    context.httpStatus?.(200);
                    res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4', 'cache-control': 'no-store' });
                    res.end(text);
                    return;
                }
                const body = ['POST', 'PUT', 'DELETE'].includes(req.method) ? await readJson(req, { maxBytes: Math.min(config.limits.bodyBytes, 65536), timeoutMs: config.limits.requestTimeoutMs }) : undefined;
                const result = await requestContext.run(context, () => route(path, req, identity, body, token));
                await securityAudit('security.request.completed', 'COMPLETED', result.httpStatus ?? 200);
                assertProductIdentity(identity);
                const releaseGuard = Reflect.get(context, 'releaseGuard'); if (typeof releaseGuard === 'function') releaseGuard();
                if (Date.now() >= context.deadlineAt) throw new AppError(504, 'REQUEST_DEADLINE');
                context.httpStatus?.(result.httpStatus ?? (result.body === undefined ? 202 : 200));
                for (const [name, value] of Object.entries(result.headers ?? {}))
                    if (/^(mcp-session-id|mcp-protocol-version|content-type)$/i.test(name))
                        res.setHeader(name, value);
                if (result.body === undefined) {
                    res.writeHead(result.httpStatus ?? 202);
                    res.end();
                }
                else
                    sendJson(res, result.httpStatus ?? 200, result.body, { requestId: context.requestId, maxBytes: path === '/v1/evidence' || path === '/v1/ops/privacy/export' ? 1048576 : path === '/mcp' ? 262144 : 65536 });
                };
                return context.run(() => requestContext.run(context, work));
            }).catch(async (error) => {
                let problem = error instanceof z.ZodError ? new AppError(400, 'INVALID_INPUT') : error;
                if (!auditAttempted || authenticated && problem?.code !== 'SECURITY_AUDIT_UNAVAILABLE') {
                    try { await securityAudit(authenticated ? 'security.request.failed' : 'authentication.failed',
                        /^[A-Z][A-Z0-9_]{0,63}$/.test(problem?.code ?? '') ? problem.code : 'INTERNAL_FAILURE', problem instanceof AppError ? problem.status : 500); }
                    catch (auditError) { problem = auditError; }
                }
                context?.httpStatus?.(problem instanceof AppError ? problem.status : 500);
                return sendError(res, problem, context?.requestId ?? randomUUID());
            }).finally(() => context?.finish(res.statusCode, routeName));
        });
        server.requestTimeout = config.limits.requestTimeoutMs;
        server.headersTimeout = config.limits.requestTimeoutMs;
        server.timeout = config.limits.requestTimeoutMs;
        server.keepAliveTimeout = 1000;
        server.maxHeadersCount = 32;
        server.on('timeout', (socket) => socket.destroy());
        await new Promise((resolve, reject) => {
            server.once('error', reject);
            const options = config.listen.socketPath ? { path: config.listen.socketPath } : { host: config.listen.host, port: config.listen.port };
            server.listen(options, () => { server.off('error', reject); resolve(); });
        });
        if (config.listen.socketPath && process.platform !== 'win32')
            await chmod(config.listen.socketPath, 0o660);
        let retentionCursor = '';
        let retentionRun = null;
        const resourceRetentionCursors = new Map();
        async function performRetention() {
            if (store.shared) return { healthy: true, boundedBatch: true, delegatedToWorker: true };
            const time = Date.now();
            const before = time - config.storage.retentionMs;
            try {
                const page = await store.listTenants({ limit: 8, ...(retentionCursor ? { after: retentionCursor } : {}) });
                retentionCursor = page.next ?? '';
                for (const tenant of page.items) {
                    await store.transaction(async () => {
                        if ((await operations.privacyRetentionStatus?.(tenant))?.held) return;
                        await store.purgeExpired(time, { tenantId: tenant, limit: 100 });
                        await store.pruneOperationResults(tenant, { before, limit: 100, now: time });
                        if (config.role === 'resource' && adapter?.pruneResults) {
                            const result = await adapter.pruneResults(tenant, { before, limit: 50, after: resourceRetentionCursors.get(tenant) ?? '', now: time });
                            resourceRetentionCursors.set(tenant, result.next ?? '');
                        }
                    }, { tenantId: tenant });
                }
                maintenanceFailed = false;
            }
            catch {
                maintenanceFailed = true;
            }
            return { healthy: !maintenanceFailed, boundedBatch: true };
        }
        function runRetention() {
            if (!retentionRun) retentionRun = performRetention().finally(() => { retentionRun = null; });
            return retentionRun;
        }
        const timer = setInterval(runRetention, Math.min(60000, config.storage.retentionMs));
        timer.unref();
        const address = server.address();
        let closed = false;
        failed = false;
        return { server, store, origin: typeof address === 'object' ? `https://${config.listen.host}:${address.port}` : null, socketPath: config.listen.socketPath,
            runtime: { policy, executor, memory, learning, coverage, adapter, operations, ready, runRetention, runtimePreflight: actionLedger?.runtimePreflight },
            async close() {
                if (closed)
                    return;
                closed = true;
                draining = true;
                clearInterval(timer);
                await new Promise((resolve) => {
                    const deadline = setTimeout(() => { server.closeAllConnections(); resolve(); }, config.limits.requestTimeoutMs);
                    deadline.unref();
                    server.close(() => { clearTimeout(deadline); resolve(); });
                    server.closeIdleConnections();
                });
                await retentionRun;
                await zanii?.close?.();
                await operations.close?.();
                await observability.close?.();
                await logSink?.close();
                if (!suppliedStore)
                    (await store.close());
            } };
    }
    finally {
        if (failed) {
            await operations?.close?.();
            await observability?.close();
            await logSink?.close();
            if (!suppliedStore) await store.close();
        }
    }
}
