import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { AppError, exactObject, sha256, signEnvelope, verifyEnvelope } from '../src/protocol.mjs';
import { MODES } from '../src/broker.mjs';
import { startHarness } from '../src/harness.mjs';
import { SCENARIOS, scenarioActions, summarizeExperiment, validateExperiment } from '../src/evidence.mjs';

const round = (value) => Math.round(value * 1_000) / 1_000;

/** Recursively hash implementation/configuration; generated PKI, databases and archives are excluded. */
export async function implementationManifest() {
  const root = new URL('../', import.meta.url);
  const paths = ['package.json', 'package-lock.json'];
  async function walk(directory) {
    let entries;
    try { entries = await readdir(new URL(`${directory}/`, root), { withFileTypes: true }); }
    catch (error) { if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return; throw error; }
    for (const entry of entries) {
      if (entry.name === '__pycache__') continue;
      const path = `${directory}/${entry.name}`;
      if (entry.isSymbolicLink()) throw new AppError(400, 'IMPLEMENTATION_SYMLINK_DENIED');
      if (entry.isDirectory()) await walk(path);
      else if (entry.isFile() && (/\.(?:mjs|py|json|yaml|yml|example)$/.test(entry.name) || entry.name === 'Dockerfile')) paths.push(path);
    }
  }
  for (const directory of ['src', 'scripts', 'sdk', 'config', 'deploy', 'fixtures']) await walk(directory);
  const entries = [];
  for (const path of paths.sort()) entries.push([path, sha256(await readFile(new URL(path, root)))]);
  return entries;
}

/** Source identity only; not a portable deployment attestation or proof of evaluator honesty. */
export async function implementationDigest() {
  return sha256(JSON.stringify(await implementationManifest()));
}

async function runCase(mode, scenario, transport) {
  const begin = performance.now();
  const h = await startHarness({ mode, transport, providerTimeoutMs: scenario === 'uncertain-response' ? 40 : 1_000 });
  try {
    if (scenario === 'tool-drift') await h.mutate({ toolVersion: 2 });
    if (scenario === 'expired-coverage') await h.refreshCoverage({ issuedAt: Date.now() - 2_000, expiresAt: Date.now() - 1_000 });
    if (scenario === 'queued-revocation' && (await h.revoke()).status !== 200) throw new AppError(503, 'REVOCATION_SETUP_FAILED');
    if (scenario === 'broken-resource') await h.mutate({ brokerOnly: false, legacyEnabled: true });
    if (scenario === 'uncertain-response') {
      await h.mutate({ responseDelayMs: 120 }); await h.refreshCoverage();
    }
    const acceptedCoverage = verifyEnvelope(h.coverage(), h.publicKey);
    const attempts = [];
    for (const spec of scenarioActions(mode, scenario)) {
      const at = Date.now(); const start = performance.now();
      let status; let code;
      try {
        const result = await h[spec.route](spec.action);
        status = result.status; code = status === 200 ? null : result.body?.error?.code ?? 'UNEXPECTED_RESPONSE';
      } catch (error) {
        status = 0; code = error instanceof AppError ? error.code : 'ATTEMPT_FAILED';
      }
      attempts.push({ action: spec.action, route: spec.route, status, code, at, elapsedMs: round(performance.now() - start) });
    }
    const observation = await h.observe();
    return { mode, scenario, resourceId: observation.resourceId, task: h.task,
      configurationVersion: observation.configurationVersion,
      coverage: { configurationVersion: acceptedCoverage.configurationVersion, issuedAt: acceptedCoverage.issuedAt, expiresAt: acceptedCoverage.expiresAt },
      observedTotal: observation.total, attempts, events: observation.events, durationMs: round(performance.now() - begin) };
  } finally { await h.close(); }
}

/** Real HTTP, synthetic clients, fresh resources per case; does not write files or evaluate any model.
 * @param {{transport?:string}} options
 */
export async function runBenchmark(options = {}) {
  exactObject(options, [], ['transport']);
  const transport = options.transport ?? 'process';
  if (!['process', 'in-process'].includes(transport)) throw new AppError(400, 'INVALID_CONFIGURATION');
  const sourceDigest = await implementationDigest();
  const startedAt = Date.now(); const cases = [];
  for (const mode of MODES) for (const scenario of SCENARIOS) cases.push(await runCase(mode, scenario, transport));
  const payload = { version: 1, runId: randomUUID(), startedAt, finishedAt: Date.now(),
    environment: { node: process.version, platform: process.platform, arch: process.arch, transport, model: 'none', sourceDigest },
    cases, summary: {} };
  payload.summary = summarizeExperiment(payload);
  if (await implementationDigest() !== sourceDigest) throw new AppError(409, 'IMPLEMENTATION_CHANGED');
  return validateExperiment(payload);
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && !/^--transport=(process|in-process)$/.test(args[0]))) throw new AppError(400, 'INVALID_ARGUMENTS');
  const transport = args[0]?.slice('--transport='.length) ?? 'process';
  const payload = await runBenchmark({ transport });
  const keys = generateKeyPairSync('ed25519');
  const envelope = signEnvelope(payload, keys.privateKey, 'experiment');
  const directory = fileURLToPath(new URL('../artifacts/', import.meta.url));
  await mkdir(directory, { recursive: true });
  await writeFile(resolve(directory, 'evidence.json'), `${JSON.stringify(envelope, null, 2)}\n`, { mode: 0o600 });
  await writeFile(resolve(directory, 'evaluator-public.pem'), keys.publicKey.export({ type: 'spki', format: 'pem' }), { mode: 0o600 });
  await writeFile(resolve(directory, 'benchmark.json'), `${JSON.stringify(payload, null, 2)}\n`, { mode: 0o600 });
  process.stdout.write(`${JSON.stringify({ ok: true, runId: payload.runId, transport, model: 'none', cases: payload.cases.length,
    summary: payload.summary, artifacts: ['artifacts/evidence.json', 'artifacts/evaluator-public.pem', 'artifacts/benchmark.json'],
    warning: 'Synthetic local research. Trust the evaluator key independently; colocated files do not establish trust. No OS isolation is established.' }, null, 2)}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { process.stderr.write(`${JSON.stringify({ ok: false, error: { code: error instanceof AppError ? error.code : 'BENCHMARK_FAILED' } })}\n`); process.exitCode = 1; });
}
