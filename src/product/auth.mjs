import { createLocalJWKSet, jwtVerify } from 'jose';
import { z } from 'zod';
import { timingSafeEqual } from 'node:crypto';
import { AppError } from '../protocol.mjs';

const ROLE = z.enum(['agent', 'operator', 'approver', 'auditor', 'learner']);
const claims = z.object({
  sub: z.string().min(1).max(128), tenant_id: z.string().min(1).max(128),
  roles: z.array(ROLE).max(5), scope: z.string().max(2048).optional(),
  iat: z.number().int().positive(), exp: z.number().int().positive(), jti: z.string().min(1).max(128),
  cnf: z.object({ 'x5t#S256': z.string().regex(/^[A-Za-z0-9_-]{43}$/) }).strict().optional(),
}).passthrough();

/** The issuer owns roles; actor requests cannot supply or expand them. */
export function createAuthenticator({ issuer, audience, jwks, algorithms = ['EdDSA'], maxLifetimeSeconds = 900,
  clockTolerance = 0, requireSenderBinding = true }) {
  if (typeof issuer !== 'string' || !issuer || typeof audience !== 'string' || !audience
      || !Array.isArray(algorithms) || !algorithms.length || algorithms.some((v) => !['EdDSA', 'ES256'].includes(v))
      || !Number.isInteger(maxLifetimeSeconds) || maxLifetimeSeconds < 1 || maxLifetimeSeconds > 3600
      || !Number.isInteger(clockTolerance) || clockTolerance < 0 || clockTolerance > 30) throw new AppError(400, 'INVALID_AUTH_CONFIGURATION');
  let keys;
  try {
    if (!jwks || !Array.isArray(jwks.keys) || !jwks.keys.length || jwks.keys.length > 16
        || jwks.keys.some((key) => key.d || key.k || key.p || key.q)) throw new Error('Public keys only');
    keys = createLocalJWKSet(structuredClone(jwks));
  } catch { throw new AppError(400, 'INVALID_AUTH_CONFIGURATION'); }
  const permittedAlgorithms = Object.freeze([...algorithms]);
  return Object.freeze({
    /** @param {string} token @param {{certificateFingerprint?:string}} options */
    async authenticate(token, { certificateFingerprint } = {}) {
      try {
        if (typeof token !== 'string' || token.length > 16_384) throw new Error('Token');
        const { payload } = await jwtVerify(token, keys, { issuer, audience, algorithms: [...permittedAlgorithms], clockTolerance,
          requiredClaims: ['exp', 'iat', 'sub', 'tenant_id', 'jti'], maxTokenAge: maxLifetimeSeconds });
        const value = claims.parse(payload);
        if (value.exp <= value.iat || value.exp - value.iat > maxLifetimeSeconds) throw new Error('Lifetime');
        if (requireSenderBinding || value.cnf) {
          const expected = value.cnf?.['x5t#S256'];
          if (typeof certificateFingerprint !== 'string' || !expected) throw new Error('Sender binding');
          const a = Buffer.from(expected); const b = Buffer.from(certificateFingerprint);
          if (a.length !== b.length || !timingSafeEqual(a, b)) throw new Error('Sender binding');
        }
        const scopes = (value.scope ?? '').split(' ').filter(Boolean);
        return Object.freeze({ actorId: value.sub, subject: value.sub, tenantId: value.tenant_id,
          roles: Object.freeze([...new Set(value.roles)]), scopes: Object.freeze([...new Set(scopes)]),
          expiresAt: value.exp * 1000, tokenId: value.jti });
      } catch { throw new AppError(401, 'INVALID_ACCESS_TOKEN'); }
    },
  });
}

export function requireRole(identity, role) {
  ROLE.parse(role);
  if (!identity || !Array.isArray(identity.roles) || !identity.roles.includes(role)) throw new AppError(403, 'ROLE_DENIED');
  return identity;
}
