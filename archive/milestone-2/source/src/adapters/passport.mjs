import { createHash, randomUUID } from 'node:crypto';
import { SignJWT, importJWK } from 'jose';
import { z } from 'zod';
import { AppError } from '../protocol.mjs';
import { companionTransport, secret, validCredential } from './companion-common.mjs';

const digest = z.string().regex(/^sha256:[A-Za-z0-9_-]{43}$/);
const challengeInput = z.object({ audience: z.string().min(1).max(256), requestDigest: digest, expectedPassportId: z.uuid().optional() }).strict();
const challengeResult = challengeInput.extend({ id: z.string().regex(/^[A-Za-z0-9_-]{43}$/), tenantId: z.uuid(), expiresAt: z.iso.datetime({ offset: true }), presentationFormat: z.literal('m2m'), requestedClaims: z.record(z.string(), z.unknown()) }).strict();
const outcome = z.enum(['pass', 'fail', 'not_verified', 'stale', 'unavailable', 'last_known', 'not_requested']);
const verification = z.object({ resultVersion: z.literal('1.0.0'), passportId: z.uuid().nullable(), decision: z.enum(['verified', 'not_verified']), asOf: z.iso.datetime({ offset: true }), offline: z.boolean(), dispatchPermit: z.literal(false),
  outcomes: z.object({ organisation: outcome, agent: outcome, presentation: outcome, mandateCredential: outcome, mandateScope: outcome, relyingPartyPolicy: outcome, executionEvidence: outcome }).strict(),
  components: z.array(z.object({ type: z.enum(['organisation_attestation', 'agent_binding', 'mandate_credential', 'presentation', 'status', 'executor']), status: outcome,
    observedAt: z.iso.datetime({ offset: true }), validUntil: z.iso.datetime({ offset: true }).optional(), reasons: z.array(z.string().max(4096)).max(20) }).strict()).max(10),
  reasons: z.array(z.object({ code: z.string().regex(/^[A-Z][A-Z0-9_]{1,80}$/), component: z.enum(['organisation', 'agent', 'presentation', 'mandate_credential', 'mandate_scope', 'relying_party', 'executor', 'status']), message: z.string().max(300) }).strict()).max(50) }).strict();
const executeInput = z.object({ tenantId: z.uuid(), passportId: z.uuid(), entryId: z.string().min(1).max(256), operationId: z.uuid(), expiresAt: z.iso.datetime({ offset: true }) }).strict();

/** Wire proof matches 02/src/server/modules/enforcement/workload.ts (JOSE, not Mandate SDK). */
export async function createPassportWorkloadProof({ privateKey, publicJwk, passportId, url, body, now = Date.now }) {
  if (!privateKey || publicJwk?.kty !== 'OKP' || publicJwk.crv !== 'Ed25519' || publicJwk.d) throw new AppError(400, 'INVALID_WORKLOAD_PUBLIC_KEY');
  const key = typeof privateKey === 'object' && privateKey.kty ? await importJWK(privateKey, 'EdDSA') : privateKey;
  return new SignJWT({ htm: 'POST', htu: url, iat: Math.floor(now() / 1000), jti: randomUUID(), passport_id: z.uuid().parse(passportId),
    request_digest: `sha256:${createHash('sha256').update(body).digest('base64url')}` })
    .setProtectedHeader({ typ: 'dpop+jwt', alg: 'EdDSA', jwk: publicJwk }).sign(key);
}
export function createPassportClient(options) {
  const channel = companionTransport(options, ['/v1/challenges', '/v1/verify', '/v1/pep']);
  return Object.freeze({
    capabilities: () => ({ service: 'passport', verificationDispatchPermit: false, directoryPep: true,
      viewerConfigured: typeof options.viewerCredentials === 'function', workloadConfigured: typeof options.workloadCredentials === 'function',
      ...channel.state(typeof options.viewerCredentials === 'function' || typeof options.workloadCredentials === 'function') }),
    async challenge(input) {
      const body = challengeInput.parse(input);
      if (typeof options.viewerCredentials !== 'function') throw new AppError(503, 'PASSPORT_VIEWER_UNCONFIGURED');
      const credentials = validCredential(await options.viewerCredentials());
      const response = await channel.request('/v1/challenges', { method: 'POST', headers: { Authorization: `Bearer ${secret(credentials.accessToken)}` }, body }, [200, 201]);
      const parsed = challengeResult.safeParse(response.body);
      if (!parsed.success || parsed.data.audience !== body.audience || parsed.data.requestDigest !== body.requestDigest
          || parsed.data.expectedPassportId !== body.expectedPassportId || Date.parse(parsed.data.expiresAt) <= Date.now()
          || (options.tenantId && parsed.data.tenantId !== options.tenantId)) channel.fail('INVALID_PASSPORT_CHALLENGE');
      return parsed.data;
    },
    async verify(input) {
      const body = z.object({ tenantId: z.uuid(), challengeId: z.string().regex(/^[A-Za-z0-9_-]{43}$/), passport: z.unknown() }).strict().parse(input);
      if (options.tenantId && body.tenantId !== options.tenantId) throw new AppError(403, 'COMPANION_TENANT_DENIED');
      const response = await channel.request('/v1/verify', { method: 'POST', body });
      const parsed = verification.safeParse(response.body);
      if (!parsed.success) channel.fail('INVALID_PASSPORT_VERIFICATION');
      channel.validated(); return parsed.data;
    },
    async executeDirectoryRead(input) {
      const value = executeInput.parse(input);
      if (options.tenantId && value.tenantId !== options.tenantId) throw new AppError(403, 'COMPANION_TENANT_DENIED');
      if (Date.parse(value.expiresAt) <= Date.now() || Date.parse(value.expiresAt) > Date.now() + 300000) throw new AppError(400, 'INVALID_OPERATION_EXPIRY');
      if (typeof options.workloadCredentials !== 'function') throw new AppError(503, 'PASSPORT_WORKLOAD_UNCONFIGURED');
      const credentials = validCredential(await options.workloadCredentials());
      const path = `/v1/pep/${value.tenantId}/${value.passportId}/directory-entries/${encodeURIComponent(value.entryId)}`;
      const body = JSON.stringify({ operationId: value.operationId, expiresAt: value.expiresAt });
      const proof = await createPassportWorkloadProof({ ...credentials, passportId: value.passportId, url: `${channel.origin}${path}`, body });
      const response = await channel.request(path, { method: 'POST', headers: { DPoP: proof, 'Content-Type': 'application/json' }, body }, [200, 202]);
      const parsed = z.object({ operationId: z.uuid(), status: z.enum(['reserving', 'reserved', 'held', 'dispatching', 'dispatched', 'committing', 'committed', 'unknown', 'failed', 'cancelled']),
        executorState: z.enum(['not_started', 'pending', 'sent', 'confirmed', 'unknown']), executionEvidenceVerified: z.boolean(), dispatchPermit: z.literal(false), result: z.unknown().optional() }).strict().safeParse(response.body);
      if (!parsed.success) channel.fail('INVALID_PASSPORT_EXECUTION');
      const result = parsed.data;
      if (result.operationId !== value.operationId || (response.status === 200 && (result.status !== 'committed' || result.executionEvidenceVerified !== true || result.executorState !== 'confirmed'))
          || (response.status === 202 && (result.status === 'committed' || result.executionEvidenceVerified))) channel.fail('INVALID_PASSPORT_EXECUTION');
      channel.validated(credentials.expiresAt);
      return { status: response.status, state: result.status, operationId: value.operationId, ...(response.status === 200 ? { result: result.result } : {}) };
    },
    async validateLive(input) { if (!input) return channel.state(typeof options.viewerCredentials === 'function' || typeof options.workloadCredentials === 'function'); await this.verify(input); return channel.state(); },
  });
}
