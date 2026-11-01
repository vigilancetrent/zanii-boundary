import { randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { AppError, MAX_JSON_BYTES, positiveInteger, tokenMatches } from './protocol.mjs';

const JSON_HEADERS = Object.freeze({
  'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
  'x-content-type-options': 'nosniff', 'x-frame-options': 'DENY',
  'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
});

/** Only harness-owned numeric loopback origins are supported by this research client.
 * @param {unknown} value
 */
export function loopbackOrigin(value) {
  try {
    if (typeof value !== 'string') throw new Error('Origin');
    const parsed = new URL(value);
    if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1'
        || !parsed.port || parsed.username || parsed.password || parsed.pathname !== '/'
        || parsed.search || parsed.hash || value.replace(/\/$/, '') !== parsed.origin) throw new Error('Origin');
    return parsed.origin;
  } catch { throw new AppError(400, 'INVALID_ORIGIN'); }
}

/** @param {import('node:http').IncomingMessage} request @param {string} expected */
export function requireBearer(request, expected) {
  const header = request.headers.authorization;
  if (typeof header !== 'string' || !header.startsWith('Bearer ')
      || !tokenMatches(header.slice(7), expected)) throw new AppError(401, 'AUTHENTICATION_REQUIRED');
}

/** Parse a bounded JSON object. No compressed bodies, arrays or implicit text decoding.
 * @param {import('node:http').IncomingMessage} request
 * @param {{maxBytes?:number,timeoutMs?:number}} options
 */
export async function readJson(request, { maxBytes = MAX_JSON_BYTES, timeoutMs = 2_000 } = {}) {
  positiveInteger(maxBytes, MAX_JSON_BYTES); positiveInteger(timeoutMs, 60_000);
  const contentType = request.headers['content-type'];
  if (typeof contentType !== 'string' || !/^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(contentType)
      || request.headers['content-encoding']) throw new AppError(415, 'JSON_REQUIRED');
  const length = request.headers['content-length'];
  if (length !== undefined && (!/^\d+$/.test(String(length)) || Number(length) > maxBytes)) throw new AppError(413, 'BODY_TOO_LARGE');
  const bytes = await /** @type {Promise<Buffer>} */ (new Promise((resolve, reject) => {
    /** @type {Buffer[]} */
    const chunks = [];
    let size = 0;
    const timer = setTimeout(() => finish(new AppError(408, 'REQUEST_TIMEOUT')), timeoutMs);
    function cleanup() {
      clearTimeout(timer);
      request.off('data', data); request.off('end', end);
      request.off('error', error); request.off('aborted', aborted);
    }
    function finish(failure, value) {
      cleanup();
      if (failure) { request.resume(); reject(failure); } else resolve(value);
    }
    function data(chunk) {
      size += chunk.length;
      if (size > maxBytes) { finish(new AppError(413, 'BODY_TOO_LARGE')); return; }
      chunks.push(Buffer.from(chunk));
    }
    function end() { finish(null, Buffer.concat(chunks, size)); }
    function error() { finish(new AppError(400, 'INVALID_BODY')); }
    function aborted() { finish(new AppError(400, 'INVALID_BODY')); }
    request.on('data', data); request.once('end', end);
    request.once('error', error); request.once('aborted', aborted);
  }));
  try {
    const body = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('Object');
    return body;
  } catch { throw new AppError(400, 'INVALID_JSON'); }
}

/** @param {import('node:http').ServerResponse} response @param {number} status @param {unknown} body
 * @param {{requestId?:string,maxBytes?:number}} options
 */
export function sendJson(response, status, body, { requestId = randomUUID(), maxBytes = MAX_JSON_BYTES } = {}) {
  if (response.writableEnded || response.destroyed) return;
  let bytes;
  try { bytes = Buffer.from(JSON.stringify(body), 'utf8'); }
  catch { throw new AppError(500, 'INVALID_RESPONSE'); }
  if (bytes.length > maxBytes) throw new AppError(500, 'RESPONSE_TOO_LARGE');
  response.writeHead(status, { ...JSON_HEADERS, 'x-request-id': requestId, 'content-length': bytes.length,
    ...(status === 429 ? { 'retry-after': '1' } : {}), ...(status >= 400 ? { connection: 'close' } : {}) });
  response.end(bytes);
}

/** @param {import('node:http').ServerResponse} response @param {unknown} error @param {string} requestId */
export function sendError(response, error, requestId = randomUUID()) {
  if (response.headersSent) { response.destroy(); return; }
  const known = error instanceof AppError && Number.isInteger(error.status) && error.status >= 400 && error.status <= 599;
  sendJson(response, known ? error.status : 500, { error: { code: known ? error.code : 'INTERNAL_ERROR', requestId } }, { requestId });
}

/** Start on an ephemeral loopback port; cleanup closes active connections as well as the listener.
 * @param {(request:import('node:http').IncomingMessage,response:import('node:http').ServerResponse,context:{requestId:string})=>unknown} handler
 * @param {{requestTimeoutMs?:number,handlerTimeoutMs?:number}} options
 */
export async function listenLoopback(handler, { requestTimeoutMs = 5_000, handlerTimeoutMs = 5_000 } = {}) {
  positiveInteger(requestTimeoutMs, 60_000); positiveInteger(handlerTimeoutMs, 60_000);
  const server = createServer((request, response) => {
    const requestId = randomUUID();
    const timer = setTimeout(() => sendError(response, new AppError(504, 'HANDLER_TIMEOUT'), requestId), handlerTimeoutMs);
    response.once('close', () => clearTimeout(timer));
    Promise.resolve().then(() => handler(request, response, { requestId }))
      .catch((error) => sendError(response, error, requestId));
  });
  server.requestTimeout = requestTimeoutMs;
  server.headersTimeout = requestTimeoutMs;
  server.timeout = requestTimeoutMs;
  server.keepAliveTimeout = 1_000;
  server.maxHeadersCount = 32;
  server.on('timeout', (socket) => socket.destroy());
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { server.off('error', reject); resolve(undefined); });
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Listener did not start');
  let closed = false;
  return {
    origin: `http://127.0.0.1:${address.port}`, server,
    async close() {
      if (closed) return;
      closed = true;
      server.closeAllConnections();
      await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve(undefined)));
    },
  };
}

/** HTTP status is returned; transport, schema and bounded-read failures throw without retrying.
 * @param {string} originValue
 * @param {string} path
 * @param {{method?:string,token?:string,body?:unknown,timeoutMs?:number,maxBytes?:number,validate?:(value:any)=>any}} options
 */
export async function requestJson(originValue, path, { method = 'GET', token, body, timeoutMs = 2_000, maxBytes = MAX_JSON_BYTES, validate } = {}) {
  const origin = loopbackOrigin(originValue);
  positiveInteger(timeoutMs, 60_000); positiveInteger(maxBytes, MAX_JSON_BYTES);
  if (typeof path !== 'string' || !path.startsWith('/') || path.startsWith('//') || path.length > 1_024
      || !['GET', 'POST', 'PUT', 'DELETE'].includes(method)) throw new AppError(400, 'INVALID_REQUEST');
  const url = new URL(path, origin);
  if (url.origin !== origin || url.hash || url.username || url.password) throw new AppError(400, 'INVALID_REQUEST');
  if (token !== undefined && (typeof token !== 'string' || token.length > 256 || /[\r\n]/.test(token))) throw new AppError(400, 'INVALID_REQUEST');
  const encoded = body === undefined ? undefined : JSON.stringify(body);
  if (encoded !== undefined && Buffer.byteLength(encoded) > MAX_JSON_BYTES) throw new AppError(400, 'BODY_TOO_LARGE');
  try {
    const response = await fetch(url, {
      method, redirect: 'manual', signal: AbortSignal.timeout(timeoutMs),
      headers: { accept: 'application/json', ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
        ...(encoded === undefined ? {} : { 'content-type': 'application/json' }) },
      ...(encoded === undefined ? {} : { body: encoded }),
    });
    if (response.status >= 300 && response.status < 400) { await response.body?.cancel(); throw new AppError(502, 'DOWNSTREAM_REDIRECT'); }
    if (!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type') ?? '')) {
      await response.body?.cancel(); throw new AppError(502, 'INVALID_DOWNSTREAM');
    }
    const chunks = [];
    let size = 0;
    if (response.body) for await (const chunk of response.body) {
      size += chunk.length;
      if (size > maxBytes) throw new AppError(502, 'DOWNSTREAM_TOO_LARGE');
      chunks.push(Buffer.from(chunk));
    }
    let parsed;
    try { parsed = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks, size))); }
    catch { throw new AppError(502, 'INVALID_DOWNSTREAM'); }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new AppError(502, 'INVALID_DOWNSTREAM');
    if (validate) {
      try { parsed = validate(parsed); } catch { throw new AppError(502, 'INVALID_DOWNSTREAM'); }
    }
    return { status: response.status, body: parsed, headers: response.headers };
  } catch (error) {
    if (error instanceof AppError) throw error;
    throw new AppError(503, 'DEPENDENCY_UNAVAILABLE');
  }
}
