import https from 'node:https';
import { lookup } from 'node:dns';
import { isIP } from 'node:net';
import { AppError, positiveInteger } from '../protocol.mjs';

const fail = (code, status = 502) => new AppError(status, code);
function privateAddress(address) {
  const value = address.toLowerCase();
  if (value.includes(':')) {
    // Refuse mapped, compatible and transition addresses: their embedded IPv4
    // destination must never evade the IPv4 policy.
    return value === '::' || value === '::1' || value.startsWith('fc') || value.startsWith('fd')
      || value.startsWith('fe8') || value.startsWith('fe9') || value.startsWith('fea') || value.startsWith('feb')
      || value.includes('.') || value.startsWith('::ffff:') || value.startsWith('2002:') || value.startsWith('2001:0:');
  }
  const [a, b] = value.split('.').map(Number);
  return a === 0 || a === 10 || a === 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31
    || a === 192 && b === 168 || a === 100 && b >= 64 && b <= 127 || a >= 224;
}
function forbiddenMetadata(address) {
  return ['169.254.169.254', '169.254.170.2', '100.100.100.200', 'fd00:ec2::254'].includes(address.toLowerCase());
}

/** Fixed-origin, bounded HTTPS. Configuration is exclusively operator-owned.
 * @param {any} options */
export function createHttpsTransport({ origin, tls = {}, allowPrivateNetworks = false, timeoutMs = 10000,
  connectTimeoutMs = 3000, readTimeoutMs = 3000, maxBytes = 65536,
  allowedPaths, allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'], socketPath } = {}) {
  const base = new URL(origin);
  if (base.protocol !== 'https:' || base.username || base.password || base.pathname !== '/' || base.search || base.hash
      || /metadata|instance-data/i.test(base.hostname)) throw fail('INVALID_TRUSTED_ORIGIN', 400);
  for (const value of [timeoutMs, connectTimeoutMs, readTimeoutMs, maxBytes]) positiveInteger(value, 16 * 1024 * 1024);
  if (tls.rejectUnauthorized === false) throw fail('TLS_VERIFICATION_REQUIRED', 400);
  const addressAllowed = (address) => {
    const normalized = address.toLowerCase();
    if (normalized.includes(':') && (normalized.includes('.') || normalized.startsWith('::ffff:')
        || normalized.startsWith('2002:') || normalized.startsWith('2001:0:'))) return false;
    return !forbiddenMetadata(normalized) && (allowPrivateNetworks || !privateAddress(normalized));
  };
  const host = base.hostname.replace(/^\[|\]$/g, '');
  if (isIP(host) && !addressAllowed(host)) throw fail('NETWORK_DESTINATION_DENIED', 400);
  const checkedLookup = (hostname, options, callback) => {
    lookup(hostname, { all: true, verbatim: true }, (error, addresses) => {
      if (error) return callback(fail('DNS_LOOKUP_FAILED'));
      if (!addresses.length || addresses.some(({ address }) => !addressAllowed(address))) return callback(fail('NETWORK_DESTINATION_DENIED'));
      // This validated result is used directly by the socket, avoiding a second DNS lookup.
      if (options.all) callback(null, addresses); else callback(null, addresses[0].address, addresses[0].family);
    });
  };
  /** @param {string} path @param {any} options */
  async function raw(path, { method = 'GET', headers = {}, body, deadlineAt } = {}) {
    if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || /[\\\r\n\0]/.test(path)) throw fail('INVALID_TRANSPORT_PATH', 400);
    const target = new URL(path, base);
    if (target.origin !== base.origin || target.hash || !allowedMethods.includes(method)
        || allowedPaths && !allowedPaths.some((prefix) => target.pathname === prefix || target.pathname.startsWith(`${prefix}/`))) throw fail('TRANSPORT_ROUTE_DENIED', 400);
    /** @type {Record<string,string>} */
    const cleanHeaders = {};
    for (const [name, value] of Object.entries(headers)) {
      if (!/^[!#$%&'*+.^_`|~\w-]+$/.test(name) || typeof value !== 'string' || /[\r\n\0]/.test(value)
          || ['host', 'content-length', 'connection', 'transfer-encoding', 'upgrade', 'proxy-authorization'].includes(name.toLowerCase())) throw fail('INVALID_TRANSPORT_HEADERS', 400);
      cleanHeaders[name] = value;
    }
    const bytes = body === undefined ? undefined : Buffer.from(typeof body === 'string' || body instanceof Uint8Array ? body : JSON.stringify(body));
    if (bytes && bytes.length > maxBytes) throw fail('REQUEST_TOO_LARGE', 413);
    if (bytes && !Object.keys(cleanHeaders).some((name) => name.toLowerCase() === 'content-type')) cleanHeaders['content-type'] = 'application/json';
    const remaining = deadlineAt === undefined ? timeoutMs : Math.min(timeoutMs, deadlineAt - Date.now());
    if (!Number.isFinite(remaining) || remaining <= 0) throw fail('TRANSPORT_DEADLINE', 504);
    return new Promise((resolve, reject) => {
      let settled = false; let connectTimer; let totalTimer;
      const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(connectTimer); clearTimeout(totalTimer); error ? reject(error) : resolve(value); };
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
      connectTimer = setTimeout(() => req.destroy(fail('TRANSPORT_CONNECT_TIMEOUT', 504)), Math.min(connectTimeoutMs, remaining));
      totalTimer = setTimeout(() => req.destroy(fail('TRANSPORT_DEADLINE', 504)), remaining);
      req.end(bytes);
    });
  }
  return Object.freeze({
    origin: base.origin,
    async request(path, options) {
      const result = await raw(path, options); let body = null;
      if (result.bytes.length) { try { body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(result.bytes)); } catch { throw fail('INVALID_PROVIDER_JSON'); } }
      return { status: result.status, headers: result.headers, body };
    },
    async fetch(input, init = {}) {
      const url = new URL(typeof input === 'string' ? input : input.url);
      if (url.origin !== base.origin) throw fail('TRANSPORT_ROUTE_DENIED', 400);
      const result = await raw(`${url.pathname}${url.search}`, { ...init, headers: Object.fromEntries(new Headers(init.headers).entries()) });
      return new Response([204, 205, 304].includes(result.status) ? null : result.bytes,
        { status: result.status, headers: Object.fromEntries(Object.entries(result.headers).filter(([name]) => !['set-cookie', 'authorization'].includes(name)).map(([name, value]) => [name, Array.isArray(value) ? value.join(', ') : String(value)])) });
    },
  });
}
