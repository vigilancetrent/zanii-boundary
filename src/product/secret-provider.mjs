import { open, lstat, realpath } from 'node:fs/promises';
import { resolve, relative, isAbsolute } from 'node:path';
import { z } from 'zod';
import { AppError, exactObject, identifier } from '../protocol.mjs';
import { createHttpsTransport } from '../adapters/transport.mjs';

/** Configuration-owned files only; no ambient credentials or mutable symlink target.
 * @param {string} path @param {any} options */
export async function readProtectedFile(path, { baseDirectory = process.cwd(), secret = false, maxBytes = 65536, agentRoot } = {}) {
  const full = resolve(baseDirectory, path); const stat = await lstat(full);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes || secret && process.platform !== 'win32' && (stat.mode & 0o077)) throw new AppError(400, 'UNSAFE_SECRET_FILE');
  const physical = await realpath(full);
  if (agentRoot) {
    const root = await realpath(resolve(baseDirectory, agentRoot)); const rel = relative(root, physical);
    if (!rel || !rel.startsWith('..') && !isAbsolute(rel)) throw new AppError(400, 'SECRET_INSIDE_AGENT_ROOT');
  }
  const file = await open(physical, 'r');
  try {
    const actual = await file.stat();
    if (!actual.isFile() || actual.dev !== stat.dev || actual.ino !== stat.ino || actual.size > maxBytes || secret && process.platform !== 'win32' && (actual.mode & 0o077)) throw new AppError(400, 'UNSAFE_SECRET_FILE');
    const bytes = Buffer.alloc(maxBytes + 1); const { bytesRead } = await file.read(bytes);
    if (bytesRead > maxBytes) throw new AppError(413, 'SECRET_FILE_TOO_LARGE');
    return bytes.subarray(0, bytesRead);
  } finally { await file.close(); }
}

export async function readProtectedJson(path, options) {
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await readProtectedFile(path, options))); }
  catch (error) { throw error instanceof AppError ? error : new AppError(400, 'INVALID_SECRET_FILE'); }
}

export async function readKeyFile(path, options = {}) {
  const text = (await readProtectedFile(path, { ...options, secret: true, maxBytes: 256 })).toString('utf8').trim();
  if (!/^[a-f\d]{64}$/i.test(text)) throw new AppError(400, 'INVALID_ENCRYPTION_KEY');
  return Buffer.from(text, 'hex');
}

function liveValue(value) {
  exactObject(value, ['value', 'expiresAt']);
  const serialized = JSON.stringify(value.value);
  if (typeof serialized !== 'string' || !Number.isSafeInteger(value.expiresAt) || value.expiresAt <= Date.now() || Buffer.byteLength(serialized) > 32768) throw new AppError(503, 'SECRET_EXPIRED');
  return { value: structuredClone(value.value), expiresAt: value.expiresAt };
}

/** Vault KV v2 documented GET /v1/:mount/data/:path, not a generic secret URL proxy. */
export async function createConfiguredSecretProvider(raw, { baseDirectory = process.cwd() } = {}) {
  const path = z.string().min(1).max(4096); const names = z.record(z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/), path);
  const schema = z.discriminatedUnion('type', [
    z.object({ type: z.literal('file'), files: names, agentRoot: path.optional() }).strict(),
    z.object({ type: z.literal('vault-kv2'), origin: z.string().url(), mount: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/), paths: names,
      tokenFile: path, caFile: path, certFile: path, keyFile: path, agentRoot: path.optional(),
      allowPrivateNetworks: z.boolean().default(false), timeoutMs: z.number().int().min(100).max(30000).default(5000) }).strict(),
  ]);
  let config; try { config = schema.parse(raw); } catch { throw new AppError(400, 'INVALID_SECRET_PROVIDER'); }
  let transport; let closed = false;
  if (config.type === 'vault-kv2') {
    for (const value of Object.values(config.paths)) if (!/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(value)) throw new AppError(400, 'INVALID_SECRET_PATH');
    transport = createHttpsTransport({ origin: config.origin, tls: {
      ca: await readProtectedFile(config.caFile, { baseDirectory }), cert: await readProtectedFile(config.certFile, { baseDirectory }),
      key: await readProtectedFile(config.keyFile, { baseDirectory, secret: true, agentRoot: config.agentRoot }),
    }, allowPrivateNetworks: config.allowPrivateNetworks, timeoutMs: config.timeoutMs, dependencyName: 'secrets',
    allowedMethods: ['GET'], allowedPaths: [`/v1/${config.mount}/data`] });
  }
  return Object.freeze({
    async get(name) {
      if (closed) throw new AppError(503, 'SECRET_PROVIDER_CLOSED');
      identifier(name);
      if (config.type === 'file') {
        if (!Object.hasOwn(config.files, name)) throw new AppError(404, 'SECRET_NOT_CONFIGURED');
        return liveValue(await readProtectedJson(config.files[name], { baseDirectory, secret: true, agentRoot: config.agentRoot }));
      }
      if (!Object.hasOwn(config.paths, name)) throw new AppError(404, 'SECRET_NOT_CONFIGURED');
      const token = (await readProtectedFile(config.tokenFile, { baseDirectory, secret: true, agentRoot: config.agentRoot, maxBytes: 4096 })).toString('utf8').trim();
      if (!/^[A-Za-z0-9._-]{8,4096}$/.test(token)) throw new AppError(400, 'INVALID_SECRET_TOKEN');
      const response = await transport.request(`/v1/${config.mount}/data/${config.paths[name]}`, { headers: { 'x-vault-token': token } });
      const body = response.body;
      if (response.status !== 200 || !body?.data?.metadata || body.data.metadata.destroyed !== false
        || body.data.metadata.deletion_time !== '' || !Number.isSafeInteger(body.data.metadata.version) || body.data.metadata.version < 1) throw new AppError(503, 'SECRET_PROVIDER_DENIED');
      return { ...liveValue(body.data.data), version: body.data.metadata.version };
    },
    status: () => ({ configured: true, kind: config.type, ambientCredentials: false, closed }),
    close: () => { closed = true; },
  });
}
