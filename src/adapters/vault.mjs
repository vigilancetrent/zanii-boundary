import { createHash } from 'node:crypto';
import { z } from 'zod';
import { AppError } from '../protocol.mjs';
import { companionTransport, secret, validCredential } from './companion-common.mjs';

const date = z.iso.datetime({ offset: true });
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const sha = z.string().regex(/^[a-f0-9]{64}$/);
const caseInput = z.object({ title: z.string().min(3).max(200), incidentType: z.enum(['wrong_payment', 'data_disclosure', 'unsuitable_output', 'other']),
  severity: z.enum(['low', 'medium', 'high', 'critical']), occurredAt: date.optional(), detectedAt: date.optional(),
  jurisdiction: z.record(z.string(), z.unknown()).optional(), retentionClass: z.string().min(1).max(128),
  confidentiality: z.enum(['internal', 'confidential', 'personal', 'financial', 'potentially_privileged']),
  coverage: z.object({ configuredCapturePaths: z.array(z.string().max(512)).max(1000).optional(), offGatewayActivity: z.enum(['yes', 'no', 'unknown']).optional(),
    missingSequences: z.array(z.unknown()).max(1000).optional(), unavailableSources: z.array(z.unknown()).max(1000).optional(), contradictions: z.array(z.unknown()).max(1000).optional(),
    clockIssues: z.array(z.unknown()).max(1000).optional(), unknowns: z.array(z.string().max(512)).max(1000).optional(), limitations: z.string().max(4096).optional() }).strict().optional() }).strict();
const clock = z.object({ timestamp: date, clockQuality: z.enum(['trusted_timestamp', 'synchronised', 'source_asserted', 'unsynchronised', 'unknown', 'unavailable']),
  precisionMilliseconds: z.number().int().nonnegative().optional(), clockEvidenceId: z.string().max(256).optional() }).strict();
const uploadInput = z.object({ expectedSize: z.number().int().min(0).max(16777216), chunkSize: z.number().int().min(1024).max(32768).default(32768),
  filename: z.string().min(1).max(512).regex(/^[^\x00-\x1F]+$/), mediaType: z.string().min(1).max(128).regex(/^[A-Za-z0-9!#$&^_.+-]+\/[A-Za-z0-9!#$&^_.+-]+$/),
  provenance: z.enum(['gateway_observed', 'sdk_reported', 'external_attested', 'investigator_added']), sourceId: z.string().min(1).max(256), sourceTime: clock,
  sourceMetadata: z.record(z.string(), z.unknown()).optional(), acquisition: z.object({ method: z.string().max(128), capturePath: z.string().max(512), actorEvidenceId: z.string().max(256).optional(), requestId: z.string().max(128).optional() }).strict() }).strict();
const uploadResult = z.object({ uploadId: z.uuid(), chunkSize: z.number().int().min(1024).max(32768), chunkCount: z.number().int().min(0).max(16384),
  receivedBytes: z.number().int().min(0).max(16777216), state: z.enum(['created', 'uploading', 'complete']), evidenceId: z.uuid().nullable().optional() }).strict();

/** Actual multipart workflow: 03/apps/api/src/routes/{cases,evidence}.ts and services/evidence.ts. */
export function createVaultClient(options) {
  const channel = companionTransport(options, ['/v1/vault'], 'vault');
  const configured = () => typeof options.credentials === 'function';
  async function auth(write) {
    if (!configured()) throw new AppError(503, 'VAULT_SESSION_UNCONFIGURED');
    const credentials = validCredential(await options.credentials());
    return { Cookie: `vault_session=${secret(credentials.session)}`, ...(write ? { 'X-CSRF-Token': secret(credentials.csrfToken), Origin: channel.origin } : {}) };
  }
  function caseView(body) {
    const parsed = z.object({ id: z.uuid(), tenantId: z.uuid(), state: z.string().min(1).max(64), version: z.number().int().positive() }).passthrough().safeParse(body);
    if (!parsed.success || (options.tenantId && parsed.data.tenantId !== options.tenantId)) channel.fail('INVALID_VAULT_CASE');
    return { caseId: parsed.data.id, tenantId: parsed.data.tenantId, state: parsed.data.state, version: parsed.data.version };
  }
  return Object.freeze({
    capabilities: () => ({ service: 'vault', uploadWorkflow: 'declare-chunks-complete', maxUploadBytes: 16777216, ...channel.state(configured()) }),
    async createCase(input) {
      const body = caseInput.parse(input);
      const response = await channel.request('/v1/vault/cases', { method: 'POST', headers: await auth(true), body }, [200, 201]);
      return caseView(response.body);
    },
    async getCase(caseId) {
      z.uuid().parse(caseId);
      const response = await channel.request(`/v1/vault/cases/${caseId}`, { method: 'GET', headers: await auth(false) });
      const result = caseView(response.body);
      if (result.caseId !== caseId) channel.fail('VAULT_CASE_BINDING_MISMATCH');
      channel.validated(); return result;
    },
    async declareUpload(caseId, input, idempotencyKey) {
      z.uuid().parse(caseId); z.string().min(8).max(128).regex(/^[ -~]+$/).parse(idempotencyKey);
      const body = uploadInput.parse(input);
      const response = await channel.request(`/v1/vault/cases/${caseId}/uploads`, { method: 'POST', headers: { ...await auth(true), 'Idempotency-Key': idempotencyKey }, body }, [200, 201]);
      const parsed = uploadResult.safeParse(response.body);
      if (!parsed.success || parsed.data.chunkSize !== body.chunkSize || parsed.data.chunkCount !== Math.ceil(body.expectedSize / body.chunkSize)) channel.fail('INVALID_VAULT_UPLOAD');
      return parsed.data;
    },
    async putChunk(uploadId, index, bytes) {
      z.uuid().parse(uploadId); z.number().int().min(0).max(1000000).parse(index);
      if (!(bytes instanceof Uint8Array) || bytes.byteLength > 32768) throw new AppError(400, 'INVALID_VAULT_CHUNK');
      bytes = Buffer.from(bytes);
      const digest = hash(bytes);
      const response = await channel.request(`/v1/vault/uploads/${uploadId}/chunks/${index}`, { method: 'PUT', headers: { ...await auth(true), 'Content-Type': 'application/octet-stream', 'X-Chunk-SHA256': digest }, body: bytes });
      const parsed = z.object({ index: z.number().int(), digest: sha, received: z.boolean(), duplicate: z.boolean() }).strict().safeParse(response.body);
      if (!parsed.success || parsed.data.index !== index || parsed.data.digest !== digest || (!parsed.data.received && !parsed.data.duplicate)) channel.fail('INVALID_VAULT_CHUNK_RECEIPT');
      return parsed.data;
    },
    async completeUpload(uploadId, finalSha256) {
      z.uuid().parse(uploadId); sha.parse(finalSha256);
      const response = await channel.request(`/v1/vault/uploads/${uploadId}/complete`, { method: 'POST', headers: await auth(true), body: { finalSha256 } });
      const parsed = z.object({ schemaVersion: z.literal('difc-evidence-vault/v1'), evidenceId: z.uuid(), tenantId: z.uuid(), caseId: z.uuid(), sha256: sha,
        byteLength: z.number().int().nonnegative(), scanState: z.string().max(128) }).passthrough().safeParse(response.body);
      if (!parsed.success || parsed.data.sha256 !== finalSha256 || (options.tenantId && parsed.data.tenantId !== options.tenantId)) channel.fail('INVALID_VAULT_EVIDENCE');
      return { evidenceId: parsed.data.evidenceId, tenantId: parsed.data.tenantId, caseId: parsed.data.caseId, sha256: parsed.data.sha256,
        byteLength: parsed.data.byteLength, scanState: parsed.data.scanState };
    },
    async uploadEvidence(caseId, metadata, bytes, idempotencyKey) {
      if (!(bytes instanceof Uint8Array) || bytes.byteLength > 16777216) throw new AppError(400, 'INVALID_VAULT_EVIDENCE_BYTES');
      bytes = Buffer.from(bytes);
      const upload = await this.declareUpload(caseId, { ...metadata, expectedSize: bytes.byteLength }, idempotencyKey);
      for (let index = 0; index < upload.chunkCount; index += 1) await this.putChunk(upload.uploadId, index, bytes.subarray(index * upload.chunkSize, (index + 1) * upload.chunkSize));
      const evidence = await this.completeUpload(upload.uploadId, hash(bytes));
      if (evidence.caseId !== caseId || evidence.byteLength !== bytes.byteLength) channel.fail('VAULT_EVIDENCE_BINDING_MISMATCH');
      return evidence;
    },
    async validateLive(input) { if (!input) return channel.state(configured()); await this.getCase(input.caseId); return channel.state(configured()); },
  });
}
