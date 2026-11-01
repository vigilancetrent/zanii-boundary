import { createHash, createPublicKey, randomUUID } from 'node:crypto';
import { openSync, closeSync, lstatSync, fstatSync, readSync, constants } from 'node:fs';
import { z } from 'zod';
import { Runtime } from '@zanii/runtime';
import { verifyChain, scopeCovers, publicKeyFromDid, jcsHash } from '@zanii/core';
import { AppError, verifyEnvelope } from '../protocol.mjs';
import { assertProductIdentity, hashCanonical, validateProductAction } from '../product/policy.mjs';
import { requestContext } from '../product/context.mjs';
import { asAsyncStore } from '../product/async-store.mjs';

export const RUNTIME_PREFLIGHT_TOOL = 'boundary.authorization.preflight';
export const RUNTIME_REVOCATION_PURPOSE = 'boundary-runtime-revocations';
const digest = z.string().regex(/^sha256:[a-f0-9]{64}$/); const did = z.string().min(1).max(256);
export const runtimePreflightSchema = z.object({ version: z.literal(1), mode: z.literal('authorization-preflight-v1'), ownerDid: did,
  revocationSnapshotFile: z.string().min(1).max(4096), maxSnapshotAgeMs: z.number().int().min(1000).max(900000).default(60000),
  timeoutMs: z.number().int().min(100).max(10000).default(3000), maxConcurrency: z.number().int().min(1).max(64).default(4),
  maxArgumentBytes: z.number().int().min(256).max(4096).default(2048), maxDetailBytes: z.number().int().min(128).max(4096).default(1024),
}).strict();
const revocations = z.object({ version: z.literal(1), type: z.literal('zanii-boundary.runtime-revocations'), tenantId: z.string().min(1).max(128),
  agentDid: did, ownerDid: did, delegationDigest: digest, revision: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  issuedAt: z.number().int().positive(), expiresAt: z.number().int().positive(), revoked: z.array(digest).max(64) }).strict();
const fail = (code, status = 503) => { throw new AppError(status, code); };
const sha = (value) => createHash('sha256').update(value).digest('hex');

/** The final release guard has no await gap. Authority is a local bounded regular file, not a URL. */
export function readRuntimeAuthorityFile(path) {
  let fd;
  try {
    const before = lstatSync(path); if (!before.isFile() || before.isSymbolicLink() || before.size > 65536) fail('ZANII_RUNTIME_AUTHORITY_FILE_INVALID');
    fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); const stat = fstatSync(fd);
    if (!stat.isFile() || stat.dev !== before.dev || stat.ino !== before.ino || stat.size > 65536) fail('ZANII_RUNTIME_AUTHORITY_FILE_INVALID');
    const bytes = Buffer.alloc(65537); const size = readSync(fd, bytes, 0, bytes.length, 0); if (size > 65536) fail('ZANII_RUNTIME_AUTHORITY_FILE_INVALID');
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, size));
  } catch (error) { throw error instanceof AppError ? error : new AppError(503, 'ZANII_RUNTIME_AUTHORITY_FILE_INVALID'); }
  finally { if (fd !== undefined) closeSync(fd); }
}

/** Only proof metadata enters the external ledger; raw task/document/recipient data stays in company authority. */
function binding(identity, taskId, action, current) {
  return hashCanonical({ tenantId: identity.tenantId, actorId: identity.actorId, identityExpiresAt: identity.expiresAt,
    taskId, action, actionDigest: current.decision.actionDigest, policyDigest: current.decision.policyDigest,
    rootTaskId: current.decision.rootTaskId, toolVersion: current.decision.toolVersion,
    deployment: { profileDigest: current.posture.profileDigest ?? null, imageRef: current.posture.imageRef ?? null } });
}

/** Real Runtime is limited to one read-only authorization tool; shared company authority remains asynchronous.
 * @param {any} options */
export function createRuntimePreflight({ store, ledger, config, tenantId, agentDid, loadAuthority, loadAuthoritySync, now = Date.now }) {
  config = runtimePreflightSchema.parse(config); store = asAsyncStore(store);
  const owner = publicKeyFromDid(config.ownerDid); if (!owner || owner.length !== 32) fail('ZANII_RUNTIME_OWNER_INVALID');
  const publicKey = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), owner]), format: 'der', type: 'spki' });
  if (!ledger?.record || typeof loadAuthority !== 'function' || typeof loadAuthoritySync !== 'function') fail('ZANII_RUNTIME_CONFIGURATION_REQUIRED');
  const authorityId = `runtime-authority-${sha(`${tenantId}\0${agentDid}\0${config.ownerDid}`)}`;
  const tickets = new WeakMap(); const running = new Set(); let closed = false; let calls = 0; let authorized = 0; let rejected = 0;
  let authorityRevision = 0; let authorityExpiresAt = 0;
  const currentTime = (deadlineAt, signal) => { if (closed || signal?.aborted || now() >= deadlineAt) fail('ZANII_RUNTIME_DEADLINE', 504); };
  function bounded(work, deadlineAt, signal) {
    currentTime(deadlineAt, signal);
    return new Promise((resolve, reject) => {
      let settled = false; const finish = (error, value = undefined) => { if (settled) return; settled = true; clearTimeout(timer); signal?.removeEventListener('abort', abort); error ? reject(error) : resolve(value); };
      const abort = () => finish(new AppError(504, 'ZANII_RUNTIME_DEADLINE'));
      const timer = setTimeout(abort, Math.max(1, deadlineAt - now())); signal?.addEventListener('abort', abort, { once: true });
      Promise.resolve().then(work).then((value) => { try { currentTime(deadlineAt, signal); finish(null, value); } catch (error) { finish(error); } }, (error) => finish(error));
    });
  }
  function verifyAuthority(loaded, deadlineAt, signal) {
    currentTime(deadlineAt, signal);
    let snapshot;
    try { snapshot = revocations.parse(verifyEnvelope(loaded.revocations, publicKey, RUNTIME_REVOCATION_PURPOSE)); }
    catch { fail('ZANII_RUNTIME_REVOCATION_INVALID'); }
    const time = now();
    if (snapshot.tenantId !== tenantId || snapshot.agentDid !== agentDid || snapshot.ownerDid !== config.ownerDid
        || snapshot.issuedAt > time || snapshot.expiresAt <= time || snapshot.expiresAt <= snapshot.issuedAt
        || snapshot.expiresAt - snapshot.issuedAt > config.maxSnapshotAgeMs || time - snapshot.issuedAt > config.maxSnapshotAgeMs
        || new Set(snapshot.revoked).size !== snapshot.revoked.length || !Array.isArray(loaded.delegation) || loaded.delegation.length < 1 || loaded.delegation.length > 16
        || snapshot.delegationDigest !== jcsHash(loaded.delegation)) fail('ZANII_RUNTIME_REVOCATION_STALE');
    const revoked = new Set(snapshot.revoked); const chain = verifyChain(loaded.delegation, { agentId: agentDid, expectedRoot: config.ownerDid, revoked, at: new Date(time) });
    if (!chain.ok || !chain.effectiveScopes?.some((scope) => scopeCovers(scope, RUNTIME_PREFLIGHT_TOOL))) fail('ZANII_RUNTIME_DELEGATION_DENIED', 403);
    const snapshotDigest = hashCanonical(snapshot);
    currentTime(deadlineAt, signal);
    return { delegation: structuredClone(loaded.delegation), revoked, revision: snapshot.revision, digest: snapshotDigest,
      expiresAt: Math.min(snapshot.expiresAt, ...loaded.delegation.map((cert) => Date.parse(cert.exp))) };
  }
  async function authority(deadlineAt, signal) {
    const loaded = await bounded(loadAuthority, deadlineAt, signal); const value = verifyAuthority(loaded, deadlineAt, signal);
    await bounded(() => store.transaction(async () => {
      currentTime(deadlineAt, signal);
      const previous = await store.get(tenantId, 'metadata', authorityId);
      if (previous && (!Number.isSafeInteger(previous.revision) || previous.revision < 1 || !/^[a-f0-9]{64}$/.test(previous.digest ?? ''))) fail('ZANII_RUNTIME_AUTHORITY_STATE_INVALID');
      currentTime(deadlineAt, signal);
      if (previous && (value.revision < previous.revision || value.revision === previous.revision && value.digest !== previous.digest)) fail('ZANII_RUNTIME_REVOCATION_ROLLBACK');
      if (!previous || value.revision > previous.revision) await store.put(tenantId, 'metadata', authorityId, { revision: value.revision, digest: value.digest });
      currentTime(deadlineAt, signal);
    }, { tenantId }), deadlineAt, signal);
    currentTime(deadlineAt, signal); authorityRevision = Math.max(authorityRevision, value.revision); authorityExpiresAt = value.expiresAt; return value;
  }
  async function recheck(context, signal) {
    return requestContext.run({ ...(requestContext.getStore() ?? {}), deadlineAt: Math.min(context.deadlineAt, requestContext.getStore()?.deadlineAt ?? Infinity) }, async () => {
      currentTime(context.deadlineAt, signal); const first = await authority(context.deadlineAt, signal);
      const fresh = await bounded(context.authorize, context.deadlineAt, signal); currentTime(context.deadlineAt, signal);
      if (binding(context.identity, context.taskId, context.action, fresh) !== context.binding) fail('ZANII_RUNTIME_AUTHORITY_CHANGED', 403);
      const last = await authority(context.deadlineAt, signal); context.deadlineAt = Math.min(context.deadlineAt, first.expiresAt, last.expiresAt); context.authorityDigest = last.digest;
      currentTime(context.deadlineAt, signal);
      return last;
    });
  }
  const status = () => ({ configured: true, mode: config.mode, version: '0.4.0', calls, authorized, rejected, active: running.size,
    authorityRevision, authorityExpiresAt, authorityFresh: authorityExpiresAt > now(), preflightExecuted: calls > 0, businessExecution: false, liveCompanyValidated: false, closed });
  return Object.freeze({ status,
    async initialize() { await requestContext.run({ ...(requestContext.getStore() ?? {}), deadlineAt: now() + config.timeoutMs }, () => authority(now() + config.timeoutMs, undefined)); },
    async health() { try { await requestContext.run({ ...(requestContext.getStore() ?? {}), deadlineAt: Math.min(now() + config.timeoutMs, requestContext.getStore()?.deadlineAt ?? Infinity) }, () => authority(Math.min(now() + config.timeoutMs, requestContext.getStore()?.deadlineAt ?? Infinity), undefined)); return { ...status(), ready: true }; }
      catch (error) { return { ...status(), ready: false, code: error instanceof AppError ? error.code : 'ZANII_RUNTIME_AUTHORITY_UNAVAILABLE' }; } },
    async authorize({ identity, taskId, action, current, authorize, deadlineAt }) {
      assertProductIdentity(identity, ['agent', 'operator']); if (identity.tenantId !== tenantId) fail('ZANII_RUNTIME_TENANT_DENIED', 403);
      if (closed || running.size >= config.maxConcurrency) fail('ZANII_RUNTIME_CAPACITY');
      const controller = new AbortController(); let settle = () => {}; const entry = { controller, done: new Promise((resolve) => { settle = () => resolve(undefined); }) }; running.add(entry);
      const context = { identity, taskId, action: validateProductAction(action), authorize,
        binding: binding(identity, taskId, action, current), deadlineAt: Math.min(deadlineAt ?? Infinity, now() + config.timeoutMs,
          requestContext.getStore()?.deadlineAt ?? Infinity, identity.expiresAt, current.decision.task.expiresAt, current.decision.rootExpiresAt, current.posture.expiresAt) };
      let timer;
      try {
        currentTime(context.deadlineAt, controller.signal); timer = setTimeout(() => controller.abort(), Math.max(1, context.deadlineAt - now())); timer.unref();
        let snapshot = await recheck(context, controller.signal); context.deadlineAt = Math.min(context.deadlineAt, snapshot.expiresAt);
        const acceptances = []; let toolAuthorized = false; let recordError;
        const record = async (fields) => {
          try {
          snapshot = await recheck(context, controller.signal);
          if (fields.target !== RUNTIME_PREFLIGHT_TOOL || !['action_intent', 'action_result'].includes(fields.action) || acceptances.length >= 2) fail('ZANII_RUNTIME_RECORD_SCOPE_INVALID');
          const result = await bounded(() => ledger.record(identity, fields), context.deadlineAt, controller.signal);
          if (result.accepted !== true || result.delivery?.hash !== result.hash || !['accepted', 'duplicate'].includes(result.delivery?.status)) fail('ZANII_RUNTIME_EVIDENCE_UNACCEPTED');
          acceptances.push({ hash: result.hash, status: result.delivery.status }); snapshot = await recheck(context, controller.signal);
          return { hash: result.hash, delivery: { status: result.delivery.status, hash: result.hash } };
          } catch (error) { recordError = error; throw error; }
        };
        const runtime = new Runtime({ agentDid, record, recordAndConfirm: record }, {
          delegation: snapshot.delegation, ownerDid: config.ownerDid, revoked: () => snapshot.revoked, approvalMode: 'strict',
          agentId: agentDid, intentReceipts: true, maxActions: 1, maxArgumentBytes: config.maxArgumentBytes, maxDetailBytes: config.maxDetailBytes,
          runtimeHash: current.posture.profileDigest, manifestHash: jcsHash({ version: 1, tool: RUNTIME_PREFLIGHT_TOOL, revision: 'authorization-preflight-v1' }),
          tools: [{ name: RUNTIME_PREFLIGHT_TOOL, scope: RUNTIME_PREFLIGHT_TOOL, revision: 'authorization-preflight-v1', irreversible: false, risk: 'low',
            async run(args) {
              if (Object.keys(args).length !== 1 || args.binding !== context.binding) fail('ZANII_RUNTIME_ACTION_BINDING_DENIED', 403);
              snapshot = await recheck(context, controller.signal); toolAuthorized = true;
              return { ok: true, detail: { authorized: true, binding: context.binding, businessEffect: false } };
            } }],
        });
        runtime.addExecutionControl({ check(input) { if (closed || controller.signal.aborted || now() >= context.deadlineAt) return 'preflight deadline expired'; if (input.tool !== RUNTIME_PREFLIGHT_TOOL || Object.keys(input.args).length !== 1 || input.args.binding !== context.binding) return 'preflight action binding mismatch'; } });
        calls++;
        const report = await requestContext.run({ ...(requestContext.getStore() ?? {}), deadlineAt: context.deadlineAt }, () => runtime.executeWithEvidence(RUNTIME_PREFLIGHT_TOOL, { binding: context.binding }, { actionId: `preflight-${randomUUID()}`, confidence: 1,
          barrier: 'accepted', signal: controller.signal, timeoutMs: Math.max(1, context.deadlineAt - now()) }));
        if (recordError) throw recordError;
        await recheck(context, controller.signal);
        if (!toolAuthorized || !('stage' in report) || report.stage !== 'completed' || report.outcome !== 'succeeded' || report.evidence === 'failed'
            || !['accepted', 'duplicate'].includes(report.intentEvidence) || acceptances.length !== 2 || report.receiptHash !== acceptances[1].hash || report.providerReceipt) fail('ZANII_RUNTIME_PREFLIGHT_REJECTED', 403);
        const ticket = Object.freeze({ binding: context.binding, deadlineAt: context.deadlineAt }); tickets.set(ticket, context); authorized++; return ticket;
      } catch (error) { rejected++; throw error instanceof AppError ? error : new AppError(503, 'ZANII_RUNTIME_PREFLIGHT_UNAVAILABLE'); }
      finally { clearTimeout(timer); running.delete(entry); settle(); }
    },
    async assertCurrent(ticket) { const context = tickets.get(ticket); if (!context) fail('ZANII_RUNTIME_TICKET_INVALID', 403); await recheck(context, undefined); },
    assertRelease(ticket) { const context = tickets.get(ticket); if (!context) fail('ZANII_RUNTIME_TICKET_INVALID', 403); currentTime(context.deadlineAt, undefined); },
    assertReleaseFresh(ticket) { const context = tickets.get(ticket); if (!context) fail('ZANII_RUNTIME_TICKET_INVALID', 403);
      const value = verifyAuthority(loadAuthoritySync(), context.deadlineAt, undefined);
      if (value.revision < authorityRevision) fail('ZANII_RUNTIME_REVOCATION_ROLLBACK');
      if (value.digest !== context.authorityDigest) fail('ZANII_RUNTIME_AUTHORITY_CHANGED', 403);
      currentTime(Math.min(context.deadlineAt, value.expiresAt), undefined); },
    async close() { if (closed) return; closed = true; const active = [...running]; for (const entry of active) entry.controller.abort(); let timer;
      try { await Promise.race([Promise.allSettled(active.map((entry) => entry.done)), new Promise((_, reject) => { timer = setTimeout(() => reject(new AppError(503, 'ZANII_RUNTIME_DRAIN_TIMEOUT')), config.timeoutMs + 1000); timer.unref(); })]); }
      finally { clearTimeout(timer); } },
  });
}
