import { readFileSync, lstatSync, existsSync, realpathSync, openSync, fstatSync, closeSync, constants } from 'node:fs';
import { resolve, relative, isAbsolute } from 'node:path';
import { AppError } from '../protocol.mjs';
import { createHttpsTransport } from './transport.mjs';

/** Explicit operator-provisioned file; reject credentials mounted into the agent's workspace. */
export function credentialFileProvider({ path, agentRoot }) {
  const full = resolve(path); const root = resolve(agentRoot); const rel = relative(root, full);
  if (!rel || (!rel.startsWith('..') && !isAbsolute(rel))) throw new AppError(400, 'CREDENTIAL_INSIDE_AGENT_ROOT');
  return () => {
    const physicalRel = relative(existsSync(root) ? realpathSync(root) : root, realpathSync(full));
    if (!physicalRel || (!physicalRel.startsWith('..') && !isAbsolute(physicalRel))) throw new AppError(403, 'CREDENTIAL_INSIDE_AGENT_ROOT');
    const stat = lstatSync(full);
    if (stat.isSymbolicLink() || !stat.isFile() || stat.size > 16384 || (process.platform !== 'win32' && (stat.mode & 0o077))) throw new AppError(403, 'UNSAFE_CREDENTIAL_FILE');
    let value; let fd;
    try {
      fd = openSync(full, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0)); const opened = fstatSync(fd);
      if (!opened.isFile() || opened.size > 16384 || (process.platform !== 'win32' && (opened.mode & 0o077))) throw new Error('unsafe file');
      value = JSON.parse(readFileSync(fd, 'utf8'));
    } catch { throw new AppError(403, 'INVALID_CREDENTIAL_FILE'); }
    finally { if (fd !== undefined) closeSync(fd); }
    return validCredential(value);
  };
}
export function validCredential(value) {
  if (!value || typeof value !== 'object' || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now()) throw new AppError(401, 'COMPANION_SESSION_EXPIRED');
  return value;
}
export function secret(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 16384 || /[\r\n;]/.test(value)) throw new AppError(401, 'INVALID_COMPANION_CREDENTIAL');
  return value;
}
export function companionTransport(options, paths) {
  const origin = new URL(options.origin);
  if (origin.protocol !== 'https:' || origin.origin !== options.origin || origin.username || origin.password) throw new AppError(400, 'INVALID_COMPANION_ORIGIN');
  const transport = options.request ? null : createHttpsTransport({ origin: options.origin, tls: options.tls,
    allowPrivateNetworks: options.allowPrivateNetworks ?? false, maxBytes: 65536, allowedPaths: paths });
  const request = options.request ?? transport.request;
  let last = 'pending'; let validUntil = 0;
  return {
    origin: origin.origin,
    async request(path, init, expected = [200]) {
      let response;
      try { response = await request(path, init); }
      catch (error) { last = 'failed'; throw error instanceof AppError ? error : new AppError(502, 'COMPANION_TRANSPORT_FAILED'); }
      if (!response || !expected.includes(response.status)) {
        last = 'failed'; throw new AppError(response?.status === 401 || response?.status === 403 ? 403 : 502, 'COMPANION_REQUEST_DENIED');
      }
      if (!response.body || typeof response.body !== 'object' || Buffer.byteLength(JSON.stringify(response.body)) > 65536) { last = 'failed'; throw new AppError(502, 'INVALID_COMPANION_RESPONSE'); }
      return response;
    },
    validated(expiresAt = Date.now() + 60000) { last = options.contractOnly || options.request ? 'contract-validated' : 'live-validated'; validUntil = Math.min(expiresAt, Date.now() + 60000); },
    fail(code) { last = 'failed'; throw new AppError(502, code); },
    state(configured = true) {
      const status = ['live-validated', 'contract-validated'].includes(last) && validUntil <= Date.now() ? 'pending' : last;
      return { configured, status: configured ? status : 'unconfigured', liveValidated: configured && status === 'live-validated',
        ...(validUntil ? { validationExpiresAt: validUntil } : {}) };
    },
  };
}
