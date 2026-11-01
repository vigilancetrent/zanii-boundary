import { z } from 'zod';
import { AppError } from '../protocol.mjs';
import { companionTransport, secret, validCredential } from './companion-common.mjs';
export { credentialFileProvider } from './companion-common.mjs';

const querySchema = z.object({ registrationId: z.uuid(), recordVersion: z.number().int().positive(), canonicalRecordHash: z.string().regex(/^[a-f0-9]{64}$/), projectionHash: z.string().regex(/^[a-f0-9]{64}$/).optional() }).strict();
const assurance = z.object({ schemaVersion: z.literal(1), asOf: z.iso.datetime({ offset: true }), refreshedAt: z.iso.datetime({ offset: true }),
  freshness: z.enum(['fresh', 'stale']), freshnessExpiresAt: z.iso.datetime({ offset: true }), status: z.enum(['verified', 'not_verified']),
  reason: z.enum(['not_published', 'version_or_hash_mismatch', 'stale_public_projection', 'current_public_projection_match']), evidenceBasis: z.literal('self_declared'), wording: z.string().max(4096),
  registrationId: z.uuid().optional(), recordVersion: z.number().int().positive().optional(), canonicalRecordHash: z.string().regex(/^[a-f0-9]{64}$/).optional(), projectionHash: z.string().regex(/^[a-f0-9]{64}$/).optional() }).strict();

/** Contract source: 01/apps/api/src/projections/projection.controller.ts and auth/auth.guard.ts. */
export function createRegisterClient(options) {
  const channel = companionTransport(options, ['/v1/public', '/v1/registrations'], 'register');
  return Object.freeze({
    capabilities: () => ({ service: 'register', assuranceOnly: true, dispatchPermit: false, protectedSessionConfigured: typeof options.credentials === 'function', ...channel.state() }),
    async verifyRegistration(value) {
      const { registrationId, ...query } = querySchema.parse(value);
      const path = `/v1/public/registrations/${registrationId}/verification?${new URLSearchParams(Object.entries(query).map(([k, v]) => [k, String(v)]))}`;
      const response = await channel.request(path, { method: 'GET' });
      const parsed = assurance.safeParse(response.body);
      if (!parsed.success) channel.fail('INVALID_REGISTER_RESPONSE');
      if (parsed.data.registrationId && parsed.data.registrationId !== registrationId) channel.fail('REGISTER_BINDING_MISMATCH');
      if (parsed.data.status === 'verified' && (parsed.data.recordVersion !== query.recordVersion || parsed.data.canonicalRecordHash !== query.canonicalRecordHash
          || (query.projectionHash && parsed.data.projectionHash !== query.projectionHash))) channel.fail('REGISTER_BINDING_MISMATCH');
      channel.validated(Date.parse(parsed.data.freshnessExpiresAt));
      const stale = Date.parse(parsed.data.freshnessExpiresAt) <= Date.now() || parsed.data.freshness === 'stale';
      return { ...parsed.data, ...(stale ? { freshness: 'stale', status: 'not_verified', reason: 'stale_public_projection' } : {}), dispatchPermit: false };
    },
    async getRegistration(registrationId) {
      z.uuid().parse(registrationId);
      if (typeof options.credentials !== 'function') throw new AppError(503, 'REGISTER_SESSION_UNCONFIGURED');
      const credentials = validCredential(await options.credentials());
      // Session cookie is the existing Register API's actual protected authentication mechanism.
      const response = await channel.request(`/v1/registrations/${registrationId}`, { method: 'GET', headers: { Cookie: `register_access=${secret(credentials.session)}` } });
      const record = z.object({ id: z.uuid(), tenant_id: z.uuid(), state: z.string().max(64), version: z.number().int().positive(), display_name: z.string().max(200), purpose: z.string().max(4096) }).safeParse(response.body);
      if (!record.success || record.data.id !== registrationId || (options.tenantId && record.data.tenant_id !== options.tenantId)) channel.fail('INVALID_REGISTER_RECORD');
      return { registrationId, record: record.data, dispatchPermit: false };
    },
    async validateLive(input) { if (!input) return channel.state(); await this.verifyRegistration(input); return channel.state(); },
  });
}
