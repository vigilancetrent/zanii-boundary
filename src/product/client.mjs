import { readFileSync, lstatSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHttpsTransport } from '../adapters/transport.mjs';
import { AppError, identifier } from '../protocol.mjs';

/** File-backed identities can be rotated without restarting the agent. No automatic mutation retries.
 * @param {any} options */
export function createProductClient({ origin, socketPath, ca, cert, key, servername, token, tokenProvider,
  allowPrivateNetworks = false, timeoutMs = 10000, maxBytes = 65536 }) {
  if (token !== undefined && tokenProvider !== undefined || tokenProvider !== undefined && typeof tokenProvider !== 'function') throw new AppError(400, 'INVALID_CLIENT_IDENTITY');
  const transport = createHttpsTransport({ origin, socketPath, tls: { ca, cert, key, servername }, allowPrivateNetworks, timeoutMs, maxBytes });
  const material = (value) => (typeof value === 'string' || Buffer.isBuffer(value)) && Buffer.byteLength(value) > 0 && Buffer.byteLength(value) <= 65536;
  if (!(Array.isArray(ca) ? ca.length > 0 && ca.length <= 16 && ca.every(material) : material(ca)) || !material(cert) || !material(key)) throw new AppError(400, 'TLS_IDENTITY_REQUIRED');
  async function request(path, body, method = body === undefined ? 'GET' : 'POST') {
    const credential = tokenProvider ? await tokenProvider() : token;
    if (typeof credential !== 'string' || !/^[A-Za-z\d_.-]{1,16384}$/.test(credential)) throw new AppError(401, 'CLIENT_TOKEN_REQUIRED');
    return transport.request(path, { method, headers: { authorization: `Bearer ${credential}`, accept: 'application/json' }, ...(body === undefined ? {} : { body }) });
  }
  return Object.freeze({ request,
    execute: (taskId, action) => request('/v1/actions', { taskId, action }),
    operation: (id) => request(`/v1/operations/${identifier(id)}`),
    reconcile: (id) => request(`/v1/operations/${identifier(id)}/reconcile`, {}),
    createTask: (task) => request('/v1/tasks', task),
    approve: (value) => request('/v1/approvals', value),
    evidence: (cursor) => cursor === undefined ? request('/v1/evidence') : request('/v1/evidence', cursor),
    operationsStatus: () => request('/v1/ops/status'),
    maintenanceJobs: (page = {}) => request('/v1/ops/jobs/list', page),
    retryMaintenanceJob: (id) => request('/v1/ops/jobs/retry', { id: identifier(id) }),
    requestPrivacy: (value) => request('/v1/ops/privacy/request', value),
    privacyStatus: (id) => request('/v1/ops/privacy/status', { id: identifier(id) }),
    privacyExport: (id, page = {}) => request('/v1/ops/privacy/export', { id: identifier(id), ...page }),
    holdPrivacy: (value) => request('/v1/ops/privacy/holds', value),
    releasePrivacyHold: (id) => request('/v1/ops/privacy/holds/release', { id: identifier(id) }),
    resetPrivacyLearning: () => request('/v1/ops/privacy/learning-reset', {}),
  });
}

export function readIdentityFile(path, { secret = false, maxBytes = 65536 } = {}) {
  const full = resolve(path); const stat = lstatSync(full);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes || secret && process.platform !== 'win32' && (stat.mode & 0o077)) throw new AppError(400, 'UNSAFE_IDENTITY_FILE');
  return readFileSync(full, 'utf8');
}

/** @param {any} options */
export function createFileProductClient({ origin = 'https://gateway', socketPath, caFile, certFile, keyFile, tokenFile,
  servername, allowPrivateNetworks = false, timeoutMs = 10000, maxBytes = 65536 }) {
  return createProductClient({ origin, socketPath, ca: readIdentityFile(caFile), cert: readIdentityFile(certFile), key: readIdentityFile(keyFile, { secret: true }),
    tokenProvider: () => readIdentityFile(tokenFile, { secret: true, maxBytes: 16384 }).trim(), servername, allowPrivateNetworks, timeoutMs, maxBytes });
}
