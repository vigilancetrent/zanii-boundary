import https from 'node:https';
import { lookup } from 'node:dns';
import { isIP } from 'node:net';
import { createSecureContext } from 'node:tls';
import { AppError, positiveInteger } from '../protocol.mjs';
import { effectiveDeadline, remainingBudget, requestContext, withSpan } from '../product/context.mjs';
import { createDependencyPolicy } from '../product/resilience.mjs';

const fail = (code, status = 502) => new AppError(status, code);
function privateAddress(address) {
  const value = address.toLowerCase();
  if (value.includes(':')) {
    // Refuse mapped, compatible and transition addresses: their embedded IPv4
    // destination must never evade the IPv4 policy.
    return value === '::' || value === '::1' || value.startsWith('fc') || value.startsWith('fd')
      || value.startsWith('fe8') || value.startsWith('fe9') || value.startsWith('fea') || value.startsWith('feb')
      || value.startsWith('ff') || value.startsWith('2001:db8:') || !/^[23]/.test(value)
      || value.includes('.') || value.startsWith('::ffff:') || value.startsWith('2002:') || value.startsWith('2001:0:');
  }
  const [a, b, c] = value.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31
    || a === 192 && [0, 168].includes(b) || a === 198 && [18, 19].includes(b)
    || a === 198 && b === 51 && c === 100 || a === 203 && b === 0 && c === 113
    || a === 100 && b >= 64 && b <= 127 || a >= 224;
}
function forbiddenMetadata(address) {
  return address.startsWith('169.254.') || ['168.63.129.16', '100.100.100.200', 'fd00:ec2::254'].includes(address);
}

export function assertNetworkDestination(address, { allowPrivateNetworks = false } = {}) {
  if (typeof address !== 'string') throw fail('NETWORK_DESTINATION_DENIED', 400);
  let normalized = address.toLowerCase();
  if (isIP(normalized) === 6) {
    try { normalized = new URL(`https://[${normalized}]/`).hostname.slice(1, -1); }
    catch { throw fail('NETWORK_DESTINATION_DENIED', 400); }
  }
  if (!isIP(normalized) || forbiddenMetadata(normalized) || !allowPrivateNetworks && privateAddress(normalized)
      || normalized.includes(':') && (normalized.startsWith('::') && !['::', '::1'].includes(normalized)
        || normalized.startsWith('64:ff9b:') || normalized.startsWith('2002:')
        || normalized.startsWith('2001:0:') || normalized.startsWith('2001::') || normalized.startsWith('ff'))) throw fail('NETWORK_DESTINATION_DENIED', 400);
}

/** Reused by configured SDK HTTP agents so they cannot bypass native transport DNS policy. */
export function createPinnedLookup({ allowPrivateNetworks = false } = {}) {
  return (hostname, options, callback) => {
    lookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
      if (error) return callback(fail('DNS_LOOKUP_FAILED'));
      try {
        if (!addresses.length) throw fail('DNS_LOOKUP_FAILED');
        for (const { address } of addresses) assertNetworkDestination(address, { allowPrivateNetworks });
      } catch (invalid) { callback(invalid); return; }
      if (options.all) callback(null, addresses); else callback(null, addresses[0].address, addresses[0].family);
    });
  };
}

/** Fixed-origin, bounded HTTPS. Configuration is exclusively operator-owned.
 * @param {any} options */
export function createHttpsTransport({ origin, tls = {}, allowPrivateNetworks = false, timeoutMs = 10000,
  connectTimeoutMs = 3000, readTimeoutMs = 3000, maxBytes = 65536,
  allowedPaths, allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'], socketPath,
  dependencyName = 'provider', resilience = {}, onDependencyState } = {}) {
  let base; try { base = new URL(origin); } catch { throw fail('INVALID_TRUSTED_ORIGIN', 400); }
  if (base.protocol !== 'https:' || base.username || base.password || base.pathname !== '/' || base.search || base.hash
      || /metadata|instance-data/i.test(base.hostname)) throw fail('INVALID_TRUSTED_ORIGIN', 400);
  for (const value of [timeoutMs, connectTimeoutMs, readTimeoutMs, maxBytes]) positiveInteger(value, 16 * 1024 * 1024);
  if (tls.rejectUnauthorized === false) throw fail('TLS_VERIFICATION_REQUIRED', 400);
  try { createSecureContext({ ca: tls.ca, cert: tls.cert, key: tls.key }); }
  catch { throw fail('INVALID_TRANSPORT_TLS', 400); }
  allowedMethods = Object.freeze([...allowedMethods]);
  if (allowedPaths) allowedPaths = Object.freeze([...allowedPaths]);
  const host = base.hostname.replace(/^\[|\]$/g, '');
  if (isIP(host)) assertNetworkDestination(host, { allowPrivateNetworks });
  const checkedLookup = createPinnedLookup({ allowPrivateNetworks });
  const dependency = createDependencyPolicy({ ...resilience, name: dependencyName, timeoutMs, onState(value) {
    onDependencyState?.(value); requestContext.getStore()?.dependency?.(value);
  } });
  const resultOnFailure = Symbol('http-result');
  /** @param {string} path @param {any} options */
  function prepare(path, { method = 'GET', headers = {}, body } = {}) {
    if (typeof path !== 'string' || path.length > 4096 || !path.startsWith('/') || path.startsWith('//') || /[\\\r\n\0]/.test(path)) throw fail('INVALID_TRANSPORT_PATH', 400);
    const target = new URL(path, base);
    if (target.origin !== base.origin || target.hash || !allowedMethods.includes(method)
        || allowedPaths && !allowedPaths.some((prefix) => target.pathname === prefix || target.pathname.startsWith(`${prefix}/`))) throw fail('TRANSPORT_ROUTE_DENIED', 400);
    /** @type {Record<string,string>} */
    const cleanHeaders = {};
    const entries = Object.entries(headers); let headerBytes = 0;
    if (entries.length > 32) throw fail('INVALID_TRANSPORT_HEADERS', 400);
    for (const [name, value] of entries) {
      if (!/^[!#$%&'*+.^_`|~\w-]+$/.test(name) || typeof value !== 'string' || /[\r\n\0]/.test(value)
          || ['host', 'content-length', 'connection', 'transfer-encoding', 'upgrade', 'proxy-authorization'].includes(name.toLowerCase())) throw fail('INVALID_TRANSPORT_HEADERS', 400);
      cleanHeaders[name] = value;
      headerBytes += Buffer.byteLength(name) + Buffer.byteLength(value);
    }
    if (headerBytes > 16384) throw fail('INVALID_TRANSPORT_HEADERS', 400);
    let bytes;
    try { bytes = body === undefined ? undefined : Buffer.from(typeof body === 'string' || body instanceof Uint8Array ? body : JSON.stringify(body)); }
    catch { throw fail('INVALID_TRANSPORT_BODY', 400); }
    if (bytes && bytes.length > maxBytes) throw fail('REQUEST_TOO_LARGE', 413);
    if (bytes && !Object.keys(cleanHeaders).some((name) => name.toLowerCase() === 'content-type')) cleanHeaders['content-type'] = 'application/json';
    return { target, method, cleanHeaders, bytes };
  }
  async function raw({ target, method, cleanHeaders, bytes }, deadlineAt, signal) {
    const deadline = effectiveDeadline({ deadlineAt, timeoutMs }); const remaining = remainingBudget(deadline);
    if (signal?.aborted) throw fail('TRANSPORT_DEADLINE', 504);
    return new Promise((resolve, reject) => {
      let settled = false; let connectTimer; let totalTimer;
      const abort = () => req.destroy(fail('TRANSPORT_DEADLINE', 504));
      const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(connectTimer); clearTimeout(totalTimer); signal?.removeEventListener('abort', abort); error ? reject(error) : resolve(value); };
      const req = https.request(target, { method, headers: cleanHeaders, agent: false, lookup: checkedLookup,
        ...(socketPath ? { socketPath } : {}), ca: tls.ca, cert: tls.cert, key: tls.key,
        servername: tls.servername, rejectUnauthorized: true }, (res) => {
        clearTimeout(connectTimer);
        const chunks = []; let size = 0;
        res.setTimeout(readTimeoutMs, () => req.destroy(fail('TRANSPORT_READ_TIMEOUT', 504)));
        if (res.statusCode >= 300 && res.statusCode < 400) { res.resume(); req.destroy(fail('TRANSPORT_REDIRECT_DENIED')); return; }
        if (res.headers['content-encoding'] && res.headers['content-encoding'] !== 'identity') { res.resume(); req.destroy(fail('TRANSPORT_ENCODING_DENIED')); return; }
        res.on('data', (chunk) => { size += chunk.length; if (size > maxBytes) req.destroy(fail('RESPONSE_TOO_LARGE')); else chunks.push(chunk); });
        res.on('error', () => finish(fail('TRANSPORT_RESPONSE_FAILED')));
        res.on('end', () => finish(null, { status: res.statusCode, headers: res.headers, bytes: Buffer.concat(chunks) }));
      });
      req.on('socket', (socket) => socket.once('secureConnect', () => {
        clearTimeout(connectTimer);
        req.setTimeout(readTimeoutMs, () => req.destroy(fail('TRANSPORT_READ_TIMEOUT', 504)));
      }));
      req.on('error', (error) => finish(error instanceof AppError ? error : fail('TRANSPORT_FAILED')));
      signal?.addEventListener('abort', abort, { once: true });
      connectTimer = setTimeout(() => req.destroy(fail('TRANSPORT_CONNECT_TIMEOUT', 504)), Math.min(connectTimeoutMs, remaining));
      totalTimer = setTimeout(() => req.destroy(fail('TRANSPORT_DEADLINE', 504)), remaining);
      // This is also the SDK/companion barrier: no I/O starts after an inherited invocation expires.
      if (Date.now() >= deadline) req.destroy(fail('TRANSPORT_DEADLINE', 504)); else req.end(bytes);
    });
  }
  async function dispatch(path, options = {}) {
    const method = options.method ?? 'GET';
    if (options.retrySafe !== undefined && typeof options.retrySafe !== 'boolean') throw fail('INVALID_RETRY_POLICY', 400);
    if (options.retrySafe && !['GET', 'HEAD'].includes(method)) throw fail('MUTATION_RETRY_DENIED', 400);
    const prepared = prepare(path, options);
    const deadlineAt = effectiveDeadline({ deadlineAt: options.deadlineAt, timeoutMs });
    try {
      return await dependency.execute(({ deadlineAt: attemptDeadline, signal }) => withSpan('http.provider', {
        'runtime.dependency': dependencyName, 'http.request.method': method,
      }, async () => {
        const context = requestContext.getStore();
        const cleanHeaders = { ...prepared.cleanHeaders, ...(context?.traceparent ? { traceparent: context.traceparent } : {}) };
        const result = await raw({ ...prepared, cleanHeaders }, attemptDeadline, signal);
        if (result.status >= 500 || result.status === 429) {
          const error = fail('DEPENDENCY_HTTP_FAILURE', result.status); error[resultOnFailure] = result; throw error;
        }
        return result;
      }), { deadlineAt, retrySafe: options.retrySafe === true });
    } catch (error) {
      if (error?.[resultOnFailure]) return error[resultOnFailure];
      throw error;
    }
  }
  return Object.freeze({
    origin: base.origin,
    dependencyStatus: dependency.status,
    async request(path, options) {
      const result = await dispatch(path, options); let body = null;
      if (result.bytes.length) { try { body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result.bytes)); } catch { throw fail('INVALID_PROVIDER_JSON'); } }
      return { status: result.status, headers: result.headers, body };
    },
    async fetch(input, init = {}) {
      const url = new URL(typeof input === 'string' ? input : input.url);
      if (url.origin !== base.origin) throw fail('TRANSPORT_ROUTE_DENIED', 400);
      const result = await dispatch(`${url.pathname}${url.search}`, { ...init, headers: Object.fromEntries(new Headers(init.headers).entries()) });
      return new Response([204, 205, 304].includes(result.status) ? null : result.bytes,
        { status: result.status, headers: Object.fromEntries(Object.entries(result.headers).filter(([name]) => !['set-cookie', 'authorization'].includes(name)).map(([name, value]) => [name, Array.isArray(value) ? value.join(', ') : String(value)])) });
    },
  });
}
