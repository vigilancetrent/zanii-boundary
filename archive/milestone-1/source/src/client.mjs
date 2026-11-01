import { loopbackOrigin, requestJson } from './http.mjs';
import { AppError, tokenMatches, validateAction } from './protocol.mjs';

/** Convenience integration only; authorization remains at the external broker/resource. */
export function createClient({ origin, token, timeoutMs = 3_000 }) {
  const fixedOrigin = loopbackOrigin(origin);
  if (typeof token !== 'string' || !tokenMatches(token, token)) throw new AppError(400, 'INVALID_CONFIGURATION');
  return Object.freeze({ execute(action) { return requestJson(fixedOrigin, '/v1/actions', {
    method: 'POST', token, body: validateAction(action), timeoutMs,
  }); } });
}
