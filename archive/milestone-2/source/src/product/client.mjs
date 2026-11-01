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
