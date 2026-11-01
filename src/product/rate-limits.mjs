import { AppError, positiveInteger } from '../protocol.mjs';
import { asAsyncStore } from './async-store.mjs';
import { assertProductIdentity, hashCanonical } from './policy.mjs';

/** The authoritative counter is shared by replicas, and never stores raw actor identifiers. */
export function createSharedIdentityLimiter({ store, rateWindowMs, rateRequests, now = Date.now }) {
  store = asAsyncStore(store);
  positiveInteger(rateWindowMs, 3600000); positiveInteger(rateRequests, 100000);
  return Object.freeze({
    async consume(identity) {
      assertProductIdentity(identity);
      const key = hashCanonical({ kind: 'identity', actorId: identity.actorId });
      return store.transaction(async () => {
        const time = now();
        const previous = await store.get(identity.tenantId, 'rate-limits', key);
        const current = previous?.until > time ? previous : { count: 0, until: time + rateWindowMs };
        if (current.count >= rateRequests) throw new AppError(429, 'RATE_LIMITED');
        const next = { count: current.count + 1, until: current.until };
        await store.put(identity.tenantId, 'rate-limits', key, next, { expiresAt: next.until });
        return { remaining: rateRequests - next.count, resetsAt: next.until };
      }, { tenantId: identity.tenantId });
    },
  });
}
