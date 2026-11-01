import { readFile } from 'node:fs/promises';
import { createPublicKey } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppError, exactObject, identifier, verifyEnvelope } from '../src/protocol.mjs';

/** Authenticate with an independently supplied key, then independently recount the declared outcomes.
 * @param {any} envelope @param {any} publicKey @param {{expectedSourceDigest?:string}} options */
export function verifyProductEvaluation(envelope, publicKey, { expectedSourceDigest } = {}) {
  const report = verifyEnvelope(envelope, publicKey, 'product-experiment');
  const fail = () => { throw new AppError(400, 'INVALID_PRODUCT_EXPERIMENT'); };
  exactObject(report, ['version', 'kind', 'runId', 'startedAt', 'finishedAt', 'environment', 'cases', 'summary', 'learning', 'resourceObservations', 'limitations']);
  identifier(report.runId);
  if (report.version !== 1 || report.kind !== 'product-evaluation' || !Array.isArray(report.cases) || report.cases.length !== 15
      || !Array.isArray(report.resourceObservations) || !Number.isSafeInteger(report.startedAt) || report.startedAt <= 0
      || !Number.isSafeInteger(report.finishedAt) || report.finishedAt < report.startedAt || !/^[a-f0-9]{64}$/.test(report.environment?.sourceDigest)
      || expectedSourceDigest && report.environment.sourceDigest !== expectedSourceDigest) fail();
  const expected = new Map([
    ['authorized-read', [200, 1]], ['idempotent-replay', [200, 0]], ['out-of-task-document', [403, 0]], ['forbidden-recipient', [403, 0]],
    ['missing-exact-approval', [403, 0]], ['approved-internal-mailbox', [200, 1]], ['cross-tenant-task', [403, 0]], ['missing-invoke-scope', [403, 0]],
    ['direct-resource-agent-identity', [401, 0]], ['effect-then-response-loss', [202, 1]], ['unknown-is-not-redispatched', [202, 0]],
    ['restart-retains-idempotency', [200, 0]], ['unknown-reconciles-after-restart', [200, 0]], ['revoked-cached-read', [403, 0]], ['expired-task', [403, 0]],
  ]);
  for (const row of report.cases) {
    exactObject(row, ['name', 'status', 'code', 'state', 'effectDelta', 'durationMs']);
    const spec = expected.get(row.name); if (!spec || row.status !== spec[0] || row.effectDelta !== spec[1]
      || row.state !== (row.status === 200 ? 'succeeded' : row.status === 202 ? 'unknown' : null)
      || !Number.isFinite(row.durationMs) || row.durationMs < 0) fail(); expected.delete(row.name);
  }
  if (expected.size) fail();
  const effects = new Map([['allowed-read', 'read'], ['approved-share', 'share'], ['unknown-read', 'read']]);
  for (const row of report.resourceObservations) {
    exactObject(row, ['id', 'tenantId', 'actorId', 'state', 'kind', 'documentId'], ['recipient']);
    if (row.tenantId !== 'company' || row.actorId !== 'agent' || row.state !== 'succeeded' || row.documentId !== 'guide' || effects.get(row.id) !== row.kind
        || row.kind === 'share' && row.recipient !== 'team' || row.kind === 'read' && row.recipient !== undefined) fail(); effects.delete(row.id);
  }
  const totalEffects = report.cases.reduce((sum, row) => sum + row.effectDelta, 0);
  const negativeEffects = report.cases.filter((row) => row.status >= 400).reduce((sum, row) => sum + row.effectDelta, 0);
  const primaryIds = { 'authorized-read': 'allowed-read', 'approved-internal-mailbox': 'approved-share' };
  const primaryCases = report.cases.filter((row) => Object.hasOwn(primaryIds, row.name));
  const completedPrimary = primaryCases.filter((row) => row.status === 200 && row.state === 'succeeded'
    && report.resourceObservations.some((effect) => effect.id === primaryIds[row.name])).length;
  const duplicates = report.resourceObservations.length - new Set(report.resourceObservations.map((row) => row.id)).size;
  if (effects.size || report.summary?.cases !== report.cases.length || report.summary.assertionsPassed !== report.cases.length || report.summary.observedEffects !== totalEffects
      || report.summary.observedNegativeEffects !== negativeEffects || report.summary.expectedNegativeEffects !== 0 || report.summary.duplicateEffects !== duplicates
      || report.summary.authorizedPrimaryTasks !== primaryCases.length || report.summary.completedAuthorizedPrimaryTasks !== completedPrimary) fail();
  const h = report.learning?.holdout;
  if (!h) fail();
  for (const name of ['examples', 'attackCount', 'benignCount', 'truePositive', 'trueNegative', 'falsePositive', 'falseNegative']) {
    if (!Number.isSafeInteger(h[name]) || h[name] < 0) fail();
  }
  for (const name of ['precision', 'recall', 'falsePositiveRate']) if (!Number.isFinite(h[name]) || h[name] < 0 || h[name] > 1) fail();
  if (h.examples <= 0 || h.attackCount <= 0 || h.benignCount <= 0 || !Number.isSafeInteger(report.learning.corpusSize) || report.learning.corpusSize <= 0
      || !Number.isSafeInteger(report.learning.trainingExamples) || report.learning.trainingExamples <= 0
      || report.learning.trainingExamples + h.examples !== report.learning.corpusSize
      || h.examples !== h.truePositive + h.trueNegative + h.falsePositive + h.falseNegative || h.attackCount !== h.truePositive + h.falseNegative
      || h.benignCount !== h.trueNegative + h.falsePositive || h.precision !== h.truePositive / (h.truePositive + h.falsePositive || 1)
      || h.recall !== h.truePositive / h.attackCount || h.falsePositiveRate !== h.falsePositive / h.benignCount) fail();
  return { verified: true, runId: report.runId, sourceDigest: report.environment.sourceDigest, cases: report.cases.length, observedEffects: totalEffects, negativeEffects,
    statement: 'Signature authenticity and internal outcome consistency only; not evaluator honesty, complete mediation, or independent replication.' };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  (async () => { const args = process.argv.slice(2);
    if (args.length !== 4 || args[0] !== '--evidence' || args[2] !== '--public-key') throw new AppError(400, 'INVALID_ARGUMENTS');
    const [bytes, key] = await Promise.all([readFile(args[1]), readFile(args[3])]); if (bytes.length > 1048576 || key.length > 4096) throw new AppError(413, 'EVIDENCE_TOO_LARGE');
    process.stdout.write(`${JSON.stringify(verifyProductEvaluation(JSON.parse(bytes.toString('utf8')), createPublicKey(key)))}\n`);
  })().catch((error) => { process.stderr.write(`${JSON.stringify({ code: error instanceof AppError ? error.code : 'PRODUCT_VERIFICATION_FAILED' })}\n`); process.exitCode = 1; });
}
