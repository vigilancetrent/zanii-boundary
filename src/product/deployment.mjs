import { spawnSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { AppError, exactObject, positiveInteger, sha256, verifyEnvelope } from '../protocol.mjs';

export const CONTAINMENT_CHECKS = Object.freeze(['authenticated-action', 'container-controls', 'external-network',
  'cloud-metadata', 'backend-network', 'dns', 'secret-files', 'runtime-socket', 'socket-directory', 'child-inheritance']);

export const IMAGE_REFERENCE = /^[a-zA-Z0-9][a-zA-Z0-9._/:\-]*@sha256:[a-f0-9]{64}$/;
const fail = (code = 'UNSAFE_DEPLOYMENT') => { throw new AppError(400, code); };
const equal = (a, b) => JSON.stringify(a) === JSON.stringify(b);
const SECRET_FILES = Object.freeze({
  gateway_tls_key: '${RUNTIME_PKI_DIR:?}/gateway-key.pem', gateway_tls_cert: '${RUNTIME_PKI_DIR:?}/gateway-cert.pem',
  gateway_data_key: '${RUNTIME_SECRETS_DIR:?}/gateway-data.key', gateway_audit_key: '${RUNTIME_SECRETS_DIR:?}/gateway-audit.key',
  gateway_signing_key: '${RUNTIME_PKI_DIR:?}/gateway-signing-key.pem', containment_receipt: '${RUNTIME_CONTAINMENT_RECEIPT:?}', containment_trust: '${RUNTIME_CONTAINMENT_TRUST:?}',
  resource_tls_key: '${RUNTIME_PKI_DIR:?}/resource-key.pem', resource_tls_cert: '${RUNTIME_PKI_DIR:?}/resource-cert.pem',
  resource_data_key: '${RUNTIME_SECRETS_DIR:?}/resource-data.key', resource_audit_key: '${RUNTIME_SECRETS_DIR:?}/resource-audit.key', resource_signing_key: '${RUNTIME_PKI_DIR:?}/resource-signing-key.pem',
});

export function validateImageReference(value) {
  if (typeof value !== 'string' || value.length > 512 || !IMAGE_REFERENCE.test(value)) fail('PINNED_IMAGE_REQUIRED');
  return value;
}

/** Validate the actual Compose template; JSON syntax is valid YAML and needs no custom YAML parser. */
export function validateDeployment(profile, compose) {
  exactObject(profile, ['version', 'name', 'socketPath', 'identityFile', 'identityFiles', 'gatewayUser', 'resourceUser', 'agentUser', 'receiptLifetimeMs', 'checks']);
  if (profile.version !== 1 || profile.name !== 'linux-no-network-v1' || profile.socketPath !== '/run/runtime/gateway.sock'
      || profile.identityFile !== '/run/identity/agent.jwt' || !equal(profile.identityFiles, ['agent.jwt', 'agent-cert.pem', 'agent-key.pem', 'ca.pem'])
      || !equal(profile.checks, CONTAINMENT_CHECKS) || profile.gatewayUser !== '10001:2000'
      || profile.resourceUser !== '10002:2000' || profile.agentUser !== '10003:2000') fail();
  positiveInteger(profile.receiptLifetimeMs, 900_000);
  exactObject(compose, ['name', 'services', 'networks', 'secrets']);
  exactObject(compose.services, ['gateway', 'resource', 'agent']);
  exactObject(compose.networks, ['backend']); exactObject(compose.networks.backend, ['internal']);
  if (compose.networks.backend.internal !== true) fail();
  for (const [role, service] of Object.entries(compose.services)) {
    exactObject(service, ['image', 'user', 'command', 'read_only', 'cap_drop', 'security_opt', 'pids_limit', 'mem_limit', 'cpus', 'tmpfs', 'volumes', 'environment', 'stop_grace_period'],
      role === 'agent' ? ['network_mode', 'entrypoint', 'stdin_open'] : ['networks', 'secrets']);
    if (service.image !== '${RUNTIME_IMAGE:?Set a verified product image including @sha256 digest}'
        || service.user !== profile[`${role}User`] || service.read_only !== true || !equal(service.cap_drop, ['ALL'])
        || !equal(service.security_opt, ['no-new-privileges:true']) || typeof service.cpus !== 'number' || !Number.isFinite(service.cpus) || service.cpus <= 0 || service.cpus > 2
        || !/^(256|512)m$/.test(service.mem_limit) || !Number.isSafeInteger(service.pids_limit)
        || service.pids_limit < 1 || service.pids_limit > 128
        || !equal(service.tmpfs, ['/tmp:rw,noexec,nosuid,size=16m,mode=1770'])
        || !equal(service.environment, { NODE_ENV: 'production' })) fail();
    if (typeof service.stop_grace_period !== 'string' || !/^\d+s$/.test(service.stop_grace_period)
        || Number.parseInt(service.stop_grace_period, 10) < 1 || Number.parseInt(service.stop_grace_period, 10) > 30) fail();
    if (!Array.isArray(service.command) || !service.command.length || service.command.some((v) => typeof v !== 'string' || v.length > 256)) fail();
    if (!Array.isArray(service.volumes) || service.volumes.length > 8) fail();
    for (const mount of service.volumes) {
      exactObject(mount, ['type', 'source', 'target'], ['read_only']);
      if (mount.type !== 'bind' || typeof mount.source !== 'string' || !/^\$\{[A-Z_]+:\?\}(?:\/[a-zA-Z0-9._-]+)?$/.test(mount.source)
          || typeof mount.target !== 'string' || /docker\.sock|containerd|\/proc|\/sys|\/dev\//.test(mount.target)) fail();
      if (role === 'agent' && mount.read_only !== true) fail();
    }
    if (role === 'agent') {
      if (service.network_mode !== 'none' || service.stdin_open !== true || !equal(service.entrypoint, ['node']) || service.networks || service.secrets
          || service.volumes.length !== 2 || !equal(service.volumes.map((m) => [m.source, m.target]),
            [['${RUNTIME_SOCKET_DIR:?}', '/run/runtime'], ['${RUNTIME_AGENT_IDENTITY_DIR:?}', '/run/identity']])) fail();
      const command = ['scripts/agent-runner.mjs', '--socket', profile.socketPath, '--token-file', profile.identityFile,
        '--cert-file', '/run/identity/agent-cert.pem', '--key-file', '/run/identity/agent-key.pem', '--ca-file', '/run/identity/ca.pem'];
      if (!equal(service.command, command)) fail();
    } else {
      if (!equal(service.networks, ['backend']) || !equal(service.command, ['--config', `/run/config/${role}.json`])) fail();
      const expected = role === 'gateway'
        ? [['${RUNTIME_CONFIG_DIR:?}/gateway.json', '/run/config/gateway.json', true], ['${RUNTIME_SOCKET_DIR:?}', '/run/runtime', false], ['${RUNTIME_GATEWAY_DATA_DIR:?}', '/var/lib/runtime', false], ['${RUNTIME_PKI_DIR:?}/ca.pem', '/run/trust/ca.pem', true], ['${RUNTIME_PKI_DIR:?}/issuer-public.jwks.json', '/run/trust/issuer.jwks.json', true]]
        : [['${RUNTIME_CONFIG_DIR:?}/resource.json', '/run/config/resource.json', true], ['${RUNTIME_RESOURCE_DATA_DIR:?}', '/var/lib/runtime', false], ['${RUNTIME_DOCUMENT_DIR:?}', '/var/lib/documents', true], ['${RUNTIME_PKI_DIR:?}/ca.pem', '/run/trust/ca.pem', true], ['${RUNTIME_PKI_DIR:?}/broker-public.jwks.json', '/run/trust/broker.jwks.json', true]];
      if (!equal(service.volumes.map((m) => [m.source, m.target, m.read_only === true]), expected)) fail();
      const requiredSecrets = [...Object.keys(SECRET_FILES).filter((name) => name.startsWith(`${role}_`)),
        ...Object.keys(SECRET_FILES).filter((name) => name.startsWith('containment_'))];
      if (!equal(service.secrets, requiredSecrets)) fail();
    }
  }
  exactObject(compose.secrets, Object.keys(SECRET_FILES));
  for (const [name, item] of Object.entries(compose.secrets)) {
    exactObject(item, ['file']);
    if (item.file !== SECRET_FILES[name]) fail();
  }
  return { ok: true, status: 'static-verified', profileDigest: sha256(JSON.stringify({ profile, compose })),
    liveVerified: false, imageVerified: false };
}

export async function readDeploymentFiles(root = new URL('../../', import.meta.url)) {
  const profile = JSON.parse(await readFile(new URL('deploy/profile.json', root), 'utf8'));
  const compose = JSON.parse(await readFile(new URL('deploy/compose.yaml', root), 'utf8'));
  return { profile, compose, ...validateDeployment(profile, compose) };
}

/** No shell, bounded output/deadline, and no assistant/provider credentials inherited.
 * @param {string[]} args
 * @param {{input?:string,timeoutMs?:number,imageRef?:string}} options
 */
export function dockerCommand(args, { input, timeoutMs = 5_000, imageRef } = {}) {
  if (!Array.isArray(args) || args.some((arg) => typeof arg !== 'string' || arg.length > 32_768)) fail('INVALID_ARGUMENTS');
  positiveInteger(timeoutMs, 30_000);
  /** @type {NodeJS.ProcessEnv} */
  const env = {};
  for (const name of ['PATH', 'Path', 'SystemRoot', 'WINDIR', 'HOME', 'USERPROFILE', 'DOCKER_HOST', 'DOCKER_CONFIG',
    'DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH', 'RUNTIME_CONFIG_DIR', 'RUNTIME_SOCKET_DIR',
    'RUNTIME_GATEWAY_DATA_DIR', 'RUNTIME_RESOURCE_DATA_DIR', 'RUNTIME_PKI_DIR', 'RUNTIME_SECRETS_DIR',
    'RUNTIME_DOCUMENT_DIR', 'RUNTIME_AGENT_IDENTITY_DIR', 'RUNTIME_CONTAINMENT_RECEIPT', 'RUNTIME_CONTAINMENT_TRUST']) {
    if (typeof process.env[name] === 'string') env[name] = process.env[name];
  }
  if (imageRef) env.RUNTIME_IMAGE = validateImageReference(imageRef);
  try {
    const result = spawnSync('docker', args, { input, encoding: 'utf8', shell: false, windowsHide: true, timeout: timeoutMs, maxBuffer: 1_048_576, env });
    if (result.error || result.status !== 0) return { ok: false, reason: result.error && 'code' in result.error && typeof result.error.code === 'string' ? result.error.code : 'DOCKER_COMMAND_FAILED' };
    return { ok: true, stdout: result.stdout };
  } catch { return { ok: false, reason: 'DOCKER_COMMAND_UNAVAILABLE' }; }
}

export async function deploymentDoctor({ staticOnly = false, imageRef = process.env.RUNTIME_IMAGE } = {}) {
  const deployment = await readDeploymentFiles();
  if (staticOnly) return { status: 'static-verified', liveVerified: false, profileDigest: deployment.profileDigest,
    imageVerified: false, note: 'Template only; image provenance and host/container controls remain unverified.' };
  if (!imageRef) return { status: 'blocked', stage: 'image', reason: 'PINNED_IMAGE_REQUIRED', liveVerified: false, profileDigest: deployment.profileDigest };
  validateImageReference(imageRef);
  const result = dockerCommand(['info', '--format', '{{json .}}']);
  if (!result.ok) return { status: 'blocked', stage: 'engine', reason: result.reason, liveVerified: false, profileDigest: deployment.profileDigest };
  try {
    const info = JSON.parse(result.stdout);
    if (info.OSType !== 'linux') return { status: 'blocked', stage: 'engine', reason: 'LINUX_ENGINE_REQUIRED', liveVerified: false };
    return { status: 'live-unverified', liveVerified: false, profileDigest: deployment.profileDigest,
      engine: { serverVersion: info.ServerVersion, kernel: info.KernelVersion, osType: info.OSType },
      note: 'Run containment-check with a real authorized action before creating a live receipt.' };
  } catch { return { status: 'blocked', stage: 'engine', reason: 'INVALID_ENGINE_RESPONSE', liveVerified: false }; }
}

/** Signed observations remain dependent on an independently trusted evaluator and host.
 * @param {unknown} envelope
 * @param {any} pinnedPublicKey
 * @param {{profileDigest?:string,imageRef?:string,now?:number,maxAgeMs?:number}} expected
 */
export function verifyDeploymentReceipt(envelope, pinnedPublicKey, { profileDigest, imageRef, now = Date.now(), maxAgeMs = 900_000 } = {}) {
  try {
    const receipt = verifyEnvelope(envelope, pinnedPublicKey, 'containment');
    exactObject(receipt, ['version', 'profileDigest', 'runtimeDigest', 'imageRef', 'imageId', 'startedAt', 'completedAt', 'expiresAt', 'engine', 'checks']);
    if (receipt.version !== 1 || !/^[a-f0-9]{64}$/.test(receipt.profileDigest) || receipt.profileDigest !== profileDigest
        || !/^[a-f0-9]{64}$/.test(receipt.runtimeDigest) || !/^sha256:[a-f0-9]{64}$/.test(receipt.imageId)) fail();
    validateImageReference(receipt.imageRef);
    validateImageReference(imageRef);
    if (receipt.imageRef !== imageRef) fail();
    positiveInteger(receipt.startedAt); positiveInteger(receipt.completedAt); positiveInteger(receipt.expiresAt);
    positiveInteger(now); positiveInteger(maxAgeMs, 900_000);
    if (receipt.startedAt > receipt.completedAt || receipt.completedAt > now || now >= receipt.expiresAt
        || receipt.expiresAt - receipt.completedAt > 900_000 || now - receipt.completedAt > maxAgeMs) fail();
    exactObject(receipt.engine, ['serverVersion', 'kernel', 'osType']);
    if (receipt.engine.osType !== 'linux' || ['serverVersion', 'kernel'].some((name) => typeof receipt.engine[name] !== 'string'
        || !receipt.engine[name].length || receipt.engine[name].length > 256)) fail();
    exactObject(receipt.checks, CONTAINMENT_CHECKS);
    if (CONTAINMENT_CHECKS.some((name) => receipt.checks[name] !== true)) fail();
    return Object.freeze(receipt);
  } catch { throw new AppError(403, 'INVALID_DEPLOYMENT_RECEIPT'); }
}
