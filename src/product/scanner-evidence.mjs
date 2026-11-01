import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve, dirname, relative } from 'node:path';
import { z } from 'zod';
import { AppError, signEnvelope, verifyEnvelope } from '../protocol.mjs';
import { readOperationsFile } from './operations-config.mjs';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fail = (code, status = 503) => { throw new AppError(status, code); };
const hex = z.string().regex(/^[a-f\d]{64}$/);
const ids = ['codeql-javascript-typescript', 'codeql-python', 'trivy-image', 'trivy-source', 'trivy-database'];
const steps = ['native-sbom', 'codeql-version', 'codeql-create-javascript-typescript', 'codeql-analyze-javascript-typescript', 'codeql-create-python', 'codeql-analyze-python', 'trivy-version', 'trivy-image', 'trivy-source'];
const schema = z.object({ version: z.literal(1), purpose: z.literal('native-security-scanner-execution'), runId: z.string().regex(/^[A-Za-z\d_-]{1,128}$/),
  sourceDigest: hex, lockSha256: hex, requirementsSha256: hex, runtimeSbomSha256: hex,
  imageConfigDigest: z.string().regex(/^sha256:[a-f\d]{64}$/), imageManifestDigest: z.string().regex(/^sha256:[a-f\d]{64}$/),
  startedAt: z.number().int().positive(), completedAt: z.number().int().positive(), codeqlVersion: z.string().min(1).max(128), trivyVersion: z.literal('0.76.1'),
  inputs: z.array(z.object({ path: z.string().min(1).max(512), sha256: hex }).strict()).length(6),
  reports: z.array(z.object({ id: z.enum(ids), sha256: hex }).strict()).length(5),
  invocations: z.array(z.object({ id: z.enum(steps), argumentsSha256: hex, startedAt: z.number().int().positive(), completedAt: z.number().int().positive(), exitCode: z.literal(0) }).strict()).length(9),
}).strict();

/** Imported reports require an explicitly pinned producer key and expected run, never local re-signing. */
export async function verifyScannerExecution({ root, envelope, publicKey, runId, sourceDigest, now = Date.now(), maxAgeMs = 900000 }) {
  if (!Number.isSafeInteger(now) || !Number.isSafeInteger(maxAgeMs) || maxAgeMs < 1 || maxAgeMs > 900000) fail('SCANNER_PRODUCER_SCOPE_INVALID');
  const { boundedBytes, SOURCE_SCAN_INPUTS } = await import('./security-delivery.mjs');
  let value;
  try { value = schema.parse(verifyEnvelope(envelope, createPublicKey(publicKey), 'security-scanner-execution')); }
  catch { fail('SCANNER_PRODUCER_SIGNATURE_INVALID'); }
  if (value.runId !== runId || value.sourceDigest !== sourceDigest || value.startedAt > value.completedAt || value.completedAt > now + 1000 || now - value.completedAt > maxAgeMs
      || value.completedAt - value.startedAt > 1200000 || new Set(value.reports.map((row) => row.id)).size !== ids.length
      || new Set(value.invocations.map((row) => row.id)).size !== steps.length || value.invocations.some((row) => row.startedAt < value.startedAt || row.completedAt < row.startedAt || row.completedAt > value.completedAt)) fail('SCANNER_PRODUCER_SCOPE_INVALID');
  const expected = new Map(); for (const name of SOURCE_SCAN_INPUTS) expected.set(name, hash(await boundedBytes(resolve(root, name))));
  if (new Set(value.inputs.map((row) => row.path)).size !== 6 || value.inputs.some((row) => expected.get(row.path) !== row.sha256)
      || value.lockSha256 !== expected.get('package-lock.json') || value.requirementsSha256 !== expected.get('requirements-ci.txt')
      || value.runtimeSbomSha256 !== hash(await boundedBytes(resolve(root, 'artifacts/runtime-sbom.cdx.json')))) fail('SCANNER_PRODUCER_SCOPE_INVALID');
  return value;
}

/** Installed Node packages in the image must contain the native production SBOM inventory. */
export function validateImagePackageCoverage(report, sbom) {
  const expected = new Set((sbom.components ?? []).map((row) => `${row.group ? row.group + '/' : ''}${row.name}@${row.version}`));
  const packages = report.Results?.filter((row) => row.Class === 'lang-pkgs' && ['node-pkg', 'npm'].includes(row.Type)).flatMap((row) => row.Packages ?? []) ?? [];
  const actual = new Set(packages.map((row) => `${row.Name}@${row.Version}`));
  if (!expected.size || [...expected].some((name) => !actual.has(name))) fail('IMAGE_PACKAGE_INVENTORY_REQUIRED');
  return { runtimeSbomPackages: expected.size, observedNodePackages: actual.size, productionInventoryCovered: true };
}

/** The only signing path executes fixed native commands into a newly created private run directory.
 * There is intentionally no API that signs caller-supplied existing scanner reports.
 * @param {any} options */
export async function produceScannerExecution({ root = process.cwd(), producerKey, producerRunId, codeql, codeqlVersion, platform = 'linux/amd64' } = {}) {
  const delivery = await import('./security-delivery.mjs'); root = await delivery.canonicalSecurityRoot(root);
  if (!/^[A-Za-z\d_-]{1,128}$/.test(producerRunId ?? '') || !producerKey || !codeql || !codeqlVersion) fail('SCANNER_PRODUCER_CONFIGURATION_REQUIRED');
  const key = createPrivateKey(await readOperationsFile(resolve(root, producerKey), { secret: true, maxBytes: 16384 })); if (key.asymmetricKeyType !== 'ed25519') fail('SCANNER_PRODUCER_KEY_REQUIRED');
  const { implementationDigest } = await import('../../scripts/benchmark.mjs'); const sourceDigest = await implementationDigest(); const startedAt = Date.now(); const deadlineAt = startedAt + 1200000;
  const directory = resolve(root, 'artifacts/private/security', `producer-${producerRunId}`); await mkdir(dirname(directory), { recursive: true, mode: 0o700 }); await mkdir(directory, { mode: 0o700 });
  const invocations = [];
  const execute = async (id, binary, args, timeoutMs = 300000) => {
    const start = Date.now(); if (start >= deadlineAt) fail('SCANNER_PRODUCER_DEADLINE');
    const result = await delivery.runSecurityTool(binary, args, { cwd: directory, timeoutMs: Math.min(timeoutMs, deadlineAt - start) });
    if (result.code !== 0) throw Object.assign(new AppError(503, 'NATIVE_SCANNER_EXECUTION_FAILED'), { toolExitCode: result.code, toolSignal: result.signal });
    invocations.push({ id, argumentsSha256: hash(JSON.stringify(args)), startedAt: start, completedAt: Date.now(), exitCode: 0 }); return result;
  };
  const userConfig = resolve(directory, 'empty-user.npmrc'), globalConfig = resolve(directory, 'empty-global.npmrc');
  await writeFile(userConfig, '', { flag: 'wx', mode: 0o600 }); await writeFile(globalConfig, '', { flag: 'wx', mode: 0o600 });
  const sbom = await execute('native-sbom', process.execPath, [await delivery.resolveNpmCli(), '--prefix', root, '--userconfig', userConfig, '--globalconfig', globalConfig, '--cache', resolve(directory, 'npm-cache'), '--registry', 'https://registry.npmjs.org', 'sbom', '--sbom-format=cyclonedx', '--omit=dev']);
  delivery.validateNativeSbom(JSON.parse(sbom.stdout.toString())); if (!(await delivery.scanSecrets({ root, content: sbom.stdout.toString() })).accepted) fail('PUBLIC_SBOM_CONTAINS_SECRET');
  await delivery.writePublicSecurityArtifact(root, 'artifacts/runtime-sbom.cdx.json', sbom.stdout);
  const version = await execute('codeql-version', codeql, ['version', '--format=json']); let observedVersion;
  try { observedVersion = JSON.parse(version.stdout.toString()).version; } catch { fail('CODEQL_VERSION_UNVERIFIED'); }
  if (observedVersion !== codeqlVersion) fail('CODEQL_VERSION_UNVERIFIED');
  const codeRoot = resolve(directory, 'source'); await mkdir(codeRoot, { mode: 0o700 });
  for (const name of (await delivery.securitySourceFiles(root)).filter((name) => /^(?:src|scripts|sdk)\//.test(name) && /\.(?:mjs|py)$/.test(name)).concat(['package.json', 'package-lock.json'])) {
    const destination = resolve(codeRoot, name); await mkdir(dirname(destination), { recursive: true, mode: 0o700 }); await writeFile(destination, await delivery.boundedBytes(resolve(root, name)), { flag: 'wx', mode: 0o600 });
  }
  const reports = []; const paths = {};
  for (const language of ['javascript-typescript', 'python']) {
    const database = resolve(directory, `db-${language}`); const output = resolve(directory, `${language}.sarif`);
    await execute(`codeql-create-${language}`, codeql, ['database', 'create', database, `--language=${language}`, `--source-root=${codeRoot}`, '--build-mode=none', '--threads=2']);
    const pack = language === 'python' ? 'python' : 'javascript';
    await execute(`codeql-analyze-${language}`, codeql, ['database', 'analyze', database, `codeql/${pack}-queries:codeql-suites/${pack}-security-extended.qls`, '--format=sarifv2.1.0', `--output=${output}`, '--threads=2']);
    delivery.validateCodeqlSarif(await delivery.boundedJson(output)); reports.push({ id: `codeql-${language}`, sha256: hash(await delivery.boundedBytes(output)) }); paths[language] = relative(root, output);
  }
  const trivy = await execute('trivy-version', 'trivy', ['--version']); if (!/^Version:\s*0\.76\.1\s*$/m.test(trivy.stdout.toString())) fail('TRIVY_VERSION_UNVERIFIED');
  const baseBytes = await delivery.boundedBytes(resolve(root, 'artifacts/private/security/base-index.json'), { maxBytes: 1048576 }); const base = delivery.validateBaseIndex(JSON.parse(baseBytes.toString()), { rawBytes: baseBytes, platform });
  const metadata = await delivery.boundedJson(resolve(root, 'artifacts/private/security/build-metadata.json'));
  const { inspectOciArchive } = await import('./oci-evidence.mjs'); const image = await inspectOciArchive(resolve(root, 'artifacts/private/security/runtime.oci.tar'), { expectedDigest: metadata['containerimage.digest'], sourceDigest, baseIndexDigest: base.indexDigest, baseManifestDigest: base.manifestDigest, platform });
  const staged = resolve(directory, 'inputs'); await mkdir(staged, { mode: 0o700 }); const inputs = [];
  for (const name of delivery.SOURCE_SCAN_INPUTS) { const content = await delivery.boundedBytes(resolve(root, name)); const destination = resolve(staged, name); await mkdir(dirname(destination), { recursive: true, mode: 0o700 }); await writeFile(destination, content, { flag: 'wx', mode: 0o600 }); inputs.push({ path: name, sha256: hash(content) }); }
  const cache = resolve(directory, 'trivy-cache'); const config = resolve(directory, 'trivy.yaml'); await writeFile(config, '{}\n', { flag: 'wx', mode: 0o600 });
  const common = ['--config', config, '--cache-dir', cache];
  const scanFlags = ['--skip-version-check', '--timeout', '2m', '--ignorefile', '', '--ignore-unfixed=false', '--severity', 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL', '--format', 'json'];
  const imagePath = resolve(directory, 'image.json'), sourcePath = resolve(directory, 'dependencies.json');
  await execute('trivy-image', 'trivy', [...common, 'image', ...scanFlags, '--scanners', 'vuln', '--input', resolve(root, 'artifacts/private/security/runtime.oci.tar'), '--output', imagePath], 150000);
  await execute('trivy-source', 'trivy', [...common, 'fs', ...scanFlags, '--scanners', 'vuln,misconfig', '--include-non-failures', '--include-dev-deps', '--file-patterns', 'pip:requirements-ci\\.txt', '--output', sourcePath, staged], 150000);
  const databasePath = resolve(cache, 'db/metadata.json'); const db = await delivery.boundedJson(databasePath);
  const imageReport = await delivery.boundedJson(imagePath); delivery.validateTrivyReport(imageReport, db, { expectedConfigDigest: image.imageConfigDigest }); validateImagePackageCoverage(imageReport, await delivery.boundedJson(resolve(root, 'artifacts/runtime-sbom.cdx.json')));
  const source = await delivery.boundedJson(sourcePath); delivery.validateTrivyReport(source, db, { artifactType: 'filesystem' }); delivery.validateSourceDependencyCoverage(source, await delivery.boundedJson(resolve(root, 'package-lock.json')), (await delivery.boundedBytes(resolve(root, 'requirements-ci.txt'))).toString());
  for (const [id, path] of [['trivy-image', imagePath], ['trivy-source', sourcePath], ['trivy-database', databasePath]]) reports.push({ id, sha256: hash(await delivery.boundedBytes(path)) });
  if (Date.now() >= deadlineAt || sourceDigest !== await implementationDigest()) fail('IMPLEMENTATION_CHANGED');
  const manifest = schema.parse({ version: 1, purpose: 'native-security-scanner-execution', runId: producerRunId, sourceDigest,
    lockSha256: hash(await delivery.boundedBytes(resolve(root, 'package-lock.json'))), requirementsSha256: hash(await delivery.boundedBytes(resolve(root, 'requirements-ci.txt'))), runtimeSbomSha256: hash(await delivery.boundedBytes(resolve(root, 'artifacts/runtime-sbom.cdx.json'))),
    imageConfigDigest: image.imageConfigDigest, imageManifestDigest: image.imageManifestDigest, startedAt, completedAt: Date.now(), codeqlVersion, trivyVersion: '0.76.1', inputs, reports, invocations });
  const output = resolve(directory, 'execution.json'); await writeFile(output, JSON.stringify(signEnvelope(manifest, key, 'security-scanner-execution')) + '\n', { flag: 'wx', mode: 0o600 });
  return { producerManifest: relative(root, output), producerRunId, sarif: [paths['javascript-typescript'], paths.python], imageReport: relative(root, imagePath), sourceDependencyReport: relative(root, sourcePath), databaseMetadata: relative(root, databasePath), sourceDigest, independentBuilderTrust: false };
}
