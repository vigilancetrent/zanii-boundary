import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { fork } from 'node:child_process';
import { AppError, exactObject, positiveInteger, randomToken, signEnvelope, validateCoverage, validateTask } from './protocol.mjs';
import { loopbackOrigin, requestJson } from './http.mjs';
import { startResource, validateResourceEvent, validateResourceState } from './resource.mjs';
import { MODES, startBroker } from './broker.mjs';
import { createClient } from './client.mjs';

function childEnvironment() {
  /** @type {NodeJS.ProcessEnv} */
  const result = {};
  for (const key of ['SystemRoot', 'WINDIR', 'PATH', 'Path', 'PATHEXT', 'TEMP', 'TMP']) {
    if (typeof process.env[key] === 'string') result[key] = process.env[key];
  }
  return result;
}

async function startChild(role, configuration) {
  let child;
  try {
    child = fork(new URL('./process.mjs', import.meta.url), [], { env: childEnvironment(), execArgv: [],
      windowsHide: true, stdio: ['ignore', 'pipe', 'pipe', 'ipc'] });
  } catch { throw new AppError(503, 'PROCESS_TRANSPORT_UNAVAILABLE'); }
  let closed = false;
  const close = async () => {
    if (closed) return;
    closed = true;
    if (!child.pid || child.exitCode !== null || child.signalCode !== null) return;
    await new Promise((resolve) => {
      const timer = setTimeout(() => { child.kill('SIGKILL'); resolve(); }, 1_000);
      child.once('exit', () => { clearTimeout(timer); resolve(); });
      if (child.connected) child.send({ type: 'close' }, () => {}); else child.kill();
    });
  };
  try {
    const origin = await new Promise((resolve, reject) => {
      let outputBytes = 0;
      let settled = false;
      let timer;
      const cleanup = () => { clearTimeout(timer); child.off('message', ready); child.off('spawn', send); child.off('exit', fail); };
      const fail = () => { if (!settled) { settled = true; cleanup(); reject(new AppError(503, 'PROCESS_TRANSPORT_UNAVAILABLE')); } };
      timer = setTimeout(fail, 5_000);
      const output = (chunk) => { outputBytes += chunk.length; if (outputBytes > 8_192) fail(); };
      child.stdout.on('data', output); child.stderr.on('data', output);
      child.once('error', fail); child.once('exit', fail);
      const ready = (message) => {
        try {
          exactObject(message, ['type', 'origin']);
          if (message.type !== 'ready') throw new Error('Ready');
          const value = loopbackOrigin(message.origin);
          if (!settled) { settled = true; cleanup(); resolve(value); }
        } catch { fail(); }
      };
      const send = () => child.send({ version: 1, role, configuration }, (error) => { if (error) fail(); });
      child.on('message', ready); child.once('spawn', send);
    });
    return { origin, close };
  } catch (error) { await close(); throw error; }
}

/** Trusted controller. Returned credential-bearing helpers must never be passed to an agent.
 * @param {{mode?:string,transport?:string,maxActions?:number,taskLifetimeMs?:number,coverageLifetimeMs?:number,providerTimeoutMs?:number,maxEvents?:number}} options
 */
export async function startHarness(options = {}) {
  exactObject(options, [], ['mode', 'transport', 'maxActions', 'taskLifetimeMs', 'coverageLifetimeMs', 'providerTimeoutMs', 'maxEvents']);
  const mode = options.mode ?? 'coverage-bound';
  const transport = options.transport ?? 'process';
  if (!MODES.includes(mode) || !['process', 'in-process'].includes(transport)) throw new AppError(400, 'INVALID_CONFIGURATION');
  const maxActions = positiveInteger(options.maxActions ?? 100, 10_000);
  const maxEvents = positiveInteger(options.maxEvents ?? Math.max(256, maxActions + 16), 20_000);
  const taskLifetimeMs = positiveInteger(options.taskLifetimeMs ?? 60_000, 900_000);
  const coverageLifetimeMs = positiveInteger(options.coverageLifetimeMs ?? 60_000, 900_000);
  const providerTimeoutMs = positiveInteger(options.providerTimeoutMs ?? 1_000, 2_000);
  const task = validateTask({ id: `task-${randomUUID()}`, actorId: 'agent-a', tenantId: 'tenant-a',
    documentIds: ['tenant-a-guide'], recipients: ['internal-team'], expiresAt: Date.now() + taskLifetimeMs, maxActions });
  const tokens = { resource: randomToken(), resourceControl: randomToken(), observer: randomToken(), legacy: randomToken(), client: randomToken(), brokerControl: randomToken() };
  const keys = generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ type: 'spki', format: 'pem' });
  let resource; let broker; let closed = false;
  const close = async () => { if (closed) return; closed = true; await broker?.close(); await resource?.close(); };
  try {
    const resourceConfig = { version: 1, resourceId: `resource-${randomUUID()}`, brokerToken: tokens.resource,
      controlToken: tokens.resourceControl, observerToken: tokens.observer, legacyToken: tokens.legacy, maxEvents };
    resource = await (transport === 'process' ? startChild('resource', resourceConfig) : startResource(resourceConfig));
    const state = async () => {
      const response = await requestJson(resource.origin, '/v1/status', { token: tokens.resource, validate: validateResourceState });
      if (response.status !== 200) throw new AppError(503, 'RESOURCE_UNAVAILABLE');
      return response.body;
    };
    const resourceAction = (action, token, extra = {}) => requestJson(resource.origin, '/v1/actions', {
      method: 'POST', token, body: { actorId: task.actorId, tenantId: task.tenantId, action, ...extra }, timeoutMs: 4_000,
    });
    let coverageEnvelope;
    /** @param {{issuedAt?:number,expiresAt?:number}} options */
    const evaluate = async ({ issuedAt, expiresAt } = {}) => {
      const before = await state();
      const probe = { id: `admission-${randomUUID()}`, kind: 'read', documentId: task.documentIds[0] };
      const authorized = await resourceAction(probe, tokens.resource);
      const direct = await resourceAction({ ...probe, id: `admission-${randomUUID()}` }, tokens.legacy);
      const wrong = await resourceAction({ ...probe, id: `admission-${randomUUID()}` }, randomToken());
      const after = await state();
      if (authorized.status !== 200 || ![401, 403].includes(direct.status) || ![401, 403].includes(wrong.status)
          || before.resourceId !== after.resourceId || before.configurationVersion !== after.configurationVersion) throw new AppError(409, 'ADMISSION_FAILED');
      const start = issuedAt ?? Date.now();
      const payload = validateCoverage({ version: 1, resourceId: after.resourceId, configurationVersion: after.configurationVersion,
        taskId: task.id, issuedAt: start, expiresAt: expiresAt ?? start + coverageLifetimeMs,
        checks: { authorizedRead: true, directDenied: true, wrongIdentityDenied: true } });
      return signEnvelope(payload, keys.privateKey);
    };
    coverageEnvelope = await evaluate();
    const brokerConfig = { version: 1, mode, resourceOrigin: resource.origin, resourceId: resourceConfig.resourceId,
      resourceToken: tokens.resource, clientToken: tokens.client, controlToken: tokens.brokerControl, task,
      publicKey, coverage: coverageEnvelope, providerTimeoutMs };
    broker = await (transport === 'process' ? startChild('broker', brokerConfig) : startBroker(brokerConfig));
    const actor = createClient({ origin: broker.origin, token: tokens.client, timeoutMs: 4_000 });
    const control = (path, body) => requestJson(broker.origin, path, { method: 'POST', token: tokens.brokerControl, body });
    return Object.freeze({
      mode, transport, brokerOrigin: broker.origin, resourceOrigin: resource.origin, task, publicKey,
      // Test/controller-only; reports must select public fields rather than serializing this object.
      clientToken: tokens.client,
      client: (action) => actor.execute(action),
      direct: (action) => resourceAction(action, tokens.legacy),
      state,
      async observe() {
        const events = []; const seen = new Set(); let total = 0; let configurationVersion = 0;
        do {
          const result = await requestJson(resource.origin, `/v1/observations?after=${events.length}&limit=32`, { token: tokens.observer });
          if (result.status !== 200) throw new AppError(503, 'OBSERVATION_UNAVAILABLE');
          exactObject(result.body, ['resourceId', 'configurationVersion', 'events', 'total']);
          if (result.body.resourceId !== resourceConfig.resourceId || !Number.isSafeInteger(result.body.total)
              || result.body.total < events.length || result.body.total > maxEvents || !Array.isArray(result.body.events)
              || result.body.events.length > 32 || (result.body.events.length === 0 && result.body.total > events.length)) throw new AppError(502, 'INVALID_OBSERVATION');
          positiveInteger(result.body.configurationVersion);
          for (const raw of result.body.events) {
            const event = validateResourceEvent(raw);
            if (event.configurationVersion > result.body.configurationVersion || seen.has(event.id)
                || events.length >= maxEvents || events.length >= result.body.total) throw new AppError(502, 'INVALID_OBSERVATION');
            seen.add(event.id);
            events.push(event);
          }
          total = result.body.total; configurationVersion = result.body.configurationVersion;
        } while (events.length < total);
        return { resourceId: resourceConfig.resourceId, configurationVersion, events, total };
      },
      async mutate(patch) {
        const result = await requestJson(resource.origin, '/v1/control', { method: 'POST', token: tokens.resourceControl, body: patch, validate: validateResourceState });
        if (result.status !== 200) throw new AppError(result.status, 'MUTATION_FAILED');
        return result.body;
      },
      revoke: () => control('/v1/control/revoke', {}),
      async refreshCoverage(options = {}) {
        exactObject(options, [], ['issuedAt', 'expiresAt']);
        const next = await evaluate(options);
        const result = await control('/v1/control/coverage', { envelope: next });
        if (result.status !== 200) throw new AppError(result.status, 'COVERAGE_REJECTED');
        coverageEnvelope = next; return structuredClone(next);
      },
      setCoverage: (envelope) => control('/v1/control/coverage', { envelope }),
      coverage: () => structuredClone(coverageEnvelope),
      closeResource: () => resource.close(), close,
    });
  } catch (error) { await close(); throw error; }
}
