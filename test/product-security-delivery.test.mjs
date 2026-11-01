import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdir, mkdtemp, writeFile, readFile, rm } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { parse } from 'yaml';
import { validateLockedDependencies, validateWorkflow, validateAdvisoryReport, validateNativeSbom, validateCodeqlSarif, validateTrivyReport, validateBaseIndex,
  verifyDeliveryPolicy, securitySourceFiles, scanSecrets, PUBLIC_SECURITY_ARTIFACTS, validateSourceDependencyCoverage, boundedJson, writePublicSecurityArtifact, stageSecurityScanInputs, SOURCE_SCAN_INPUTS, buildSecurityImage, collectSecurityReport } from '../src/product/security-delivery.mjs';
import { inspectOciArchive } from '../src/product/oci-evidence.mjs';
import { implementationManifest } from '../scripts/benchmark.mjs';
import { parseSecurityArguments } from '../scripts/security-report.mjs';
import { signEnvelope } from '../src/protocol.mjs';
import { verifyScannerExecution, validateImagePackageCoverage } from '../src/product/scanner-evidence.mjs';
import * as boundary from '@zanii/boundary';
import * as boundaryClient from '@zanii/boundary/client';
import * as boundaryEvidence from '@zanii/boundary/evidence';
import * as researchClient from '@zanii/boundary/research/client';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const digest = (bytes) => `sha256:${hash(bytes)}`;
const bytes = (value) => Buffer.from(JSON.stringify(value));

test('Boundary package self-imports expose the TLS product API and isolate explicit research aliases', async () => {
  assert.equal(boundary.createProductClient, boundaryClient.createProductClient);
  assert.equal(boundary.createClient, undefined); assert.equal(typeof researchClient.createClient, 'function');
  assert.equal(typeof boundaryEvidence.verifyAuditEvidence, 'function');
  assert.equal(boundaryEvidence.verifyEvidence, undefined);
  const alias = await import('@zanii/boundary/product/client'); assert.equal(alias.createProductClient, boundary.createProductClient);
  assert.throws(() => boundary.createProductClient({ origin: 'http://127.0.0.1:8443', token: 'fixture' }), { code: 'INVALID_TRUSTED_ORIGIN' });
  assert.throws(() => boundary.createProductClient({ origin: 'https://gateway', token: 'fixture' }), { code: 'TLS_IDENTITY_REQUIRED' });
});
async function fixture(t) {
  const base = resolve('.test-data'); await mkdir(base, { recursive: true }); const directory = await mkdtemp(join(base, 'security-delivery-'));
  t.after(async () => { assert.ok(directory.startsWith(base)); await rm(directory, { recursive: true, force: true }); }); return directory;
}
function tar(entries) {
  const parts = [];
  for (const [name, content, type = '0'] of entries) {
    const header = Buffer.alloc(512); header.write(name, 0, 100); header.write('0000644\0', 100); header.write('0000000\0', 108); header.write('0000000\0', 116);
    header.write(content.length.toString(8).padStart(11, '0') + '\0', 124); header.write('00000000000\0', 136); header.fill(32, 148, 156); header.write(type, 156); header.write('ustar\0', 257);
    const checksum = [...header].reduce((sum, value) => sum + value, 0); header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148);
    parts.push(header, content, Buffer.alloc((512 - content.length % 512) % 512));
  }
  return Buffer.concat([...parts, Buffer.alloc(1024)]);
}
function oci({ sourceDigest = hash('source'), material = digest('base-platform'), subjectForeign = false } = {}) {
  const blobs = new Map(); const add = (value, mediaType) => { const data = Buffer.isBuffer(value) ? value : bytes(value); const id = digest(data); blobs.set(`blobs/sha256/${id.slice(7)}`, data); return { mediaType, digest: id, size: data.length }; };
  const config = add({ os: 'linux', architecture: 'amd64', config: { Labels: { 'ai.zinii.source-digest': sourceDigest } } }, 'application/vnd.oci.image.config.v1+json');
  const layer = add(Buffer.from('contract-layer-bytes-not-a-real-container'), 'application/vnd.oci.image.layer.v1.tar+gzip');
  const image = add({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json', config, layers: [layer] }, 'application/vnd.oci.image.manifest.v1+json');
  const statement = add({ _type: 'https://in-toto.io/Statement/v1', predicateType: 'https://slsa.dev/provenance/v1',
    subject: [{ name: 'contract-runtime', digest: { sha256: subjectForeign ? 'f'.repeat(64) : image.digest.slice(7) } }],
    predicate: { buildDefinition: { resolvedDependencies: [{ uri: 'pkg:docker/node@24.19.0-bookworm-slim', digest: { sha256: material.slice(7) } }] } } }, 'application/vnd.in-toto+json');
  const empty = add({}, 'application/vnd.oci.empty.v1+json');
  const attestation = add({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.manifest.v1+json', config: empty, layers: [statement] }, 'application/vnd.oci.image.manifest.v1+json');
  const index = bytes({ schemaVersion: 2, manifests: [{ ...image, platform: { os: 'linux', architecture: 'amd64' } }, { ...attestation, platform: { os: 'unknown', architecture: 'unknown' } }] });
  const entries = [['oci-layout', bytes({ imageLayoutVersion: '1.0.0' })], ['index.json', index], ...blobs.entries()];
  return { archive: tar(entries), entries, options: { expectedDigest: digest(index), sourceDigest, baseIndexDigest: digest('base-index'), baseManifestDigest: digest('base-platform'), platform: 'linux/amd64' }, configDigest: config.digest, imageDigest: image.digest };
}

test('delivery locks, action pins, container source allowlist and artifact whitelist reject deliberate weakening', async () => {
  assert.equal((await verifyDeliveryPolicy()).workflow.explicitPublicArtifacts, true);
  const pkg = JSON.parse(await readFile('package.json')); const lock = JSON.parse(await readFile('package-lock.json'));
  const weak = structuredClone(pkg); weak.devDependencies.eslint = '^9.39.5'; assert.throws(() => validateLockedDependencies(weak, lock), { code: 'UNLOCKED_DIRECT_DEPENDENCY' });
  const modified = structuredClone(lock); delete modified.packages['node_modules/eslint'].integrity; assert.throws(() => validateLockedDependencies(pkg, modified), { code: 'DEPENDENCY_PROVENANCE_REQUIRED' });
  const workflow = parse(await readFile('.github/workflows/product.yml', 'utf8'));
  const mutable = structuredClone(workflow); mutable.jobs.verify.steps[0].uses = 'actions/checkout@v4'; assert.throws(() => validateWorkflow(mutable), { code: 'UNPINNED_CI_ACTION' });
  const upload = structuredClone(workflow); upload.jobs.verify.steps.at(-1).with.path = 'artifacts/**'; assert.throws(() => validateWorkflow(upload), { code: 'PUBLIC_ARTIFACT_WHITELIST_REQUIRED' });
  const transient = structuredClone(workflow); transient.jobs.verify.steps.push({ run: 'npm install --no-save scanner' }); assert.throws(() => validateWorkflow(transient), { code: 'UNSAFE_DELIVERY_WORKFLOW' });
  const publish = structuredClone(workflow); publish.jobs.verify.steps.push({ run: 'docker push registry.example/runtime' }); assert.throws(() => validateWorkflow(publish), { code: 'UNSAFE_DELIVERY_WORKFLOW' });
  const privileged = structuredClone(workflow); privileged.jobs.verify.permissions = { contents: 'write' }; assert.throws(() => validateWorkflow(privileged), { code: 'CI_WRITE_PERMISSION_DENIED' });
  assert.deepEqual(PUBLIC_SECURITY_ARTIFACTS, ['artifacts/security-delivery.json', 'artifacts/runtime-sbom.cdx.json']);
});

test('source manifest includes migration, delivery and monitoring inputs while source scans exclude private/generated trees', async (t) => {
  const paths = (await implementationManifest()).map(([path]) => path);
  for (const path of ['migrations/postgres/002_maintenance.up.sql', 'migrations/sqlite/003_maintenance.up.sql', '.github/workflows/product.yml', '.github/gitleaks.toml', '.github/trivy.yaml', 'requirements-ci.txt', '.dockerignore',
    'monitoring/grafana/grafana.ini', 'monitoring/prometheus.yaml', 'monitoring/dashboard.json', 'monitoring/receiver.json.example']) assert.ok(paths.includes(path), path);
  assert.equal(paths.some((path) => /(^|\/)(artifacts|archive|node_modules)(\/|$)/.test(path)), false);
  const directory = await fixture(t); await mkdir(join(directory, 'src')); await mkdir(join(directory, 'artifacts')); await mkdir(join(directory, 'archive'));
  await writeFile(join(directory, 'src', 'safe.mjs'), 'export const safe = true;'); await writeFile(join(directory, 'artifacts', 'private.json'), '{}'); await writeFile(join(directory, 'archive', 'old.mjs'), 'private');
  assert.deepEqual(await securitySourceFiles(directory), ['src/safe.mjs']);
});

test('actual pinned Secretlint detects synthetic credentials and never returns matched bytes in public counts', async () => {
  const key = 'AKIA' + 'QWERTYUIOPASDFGHJ'; const secret = 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0';
  const result = await scanSecrets({ content: `aws_access_key_id = "${key}"; aws_secret_access_key = "${secret}";` });
  assert.equal(result.accepted, false); assert.ok(result.findings > 0); assert.equal(JSON.stringify(result).includes(key), false); assert.equal(JSON.stringify(result).includes(secret), false);
  assert.equal((await scanSecrets({ content: 'export const harmless = true;' })).accepted, true);
});

test('fresh advisory/SARIF/image gates reject incomplete execution, hidden findings, unknown risk and stale databases', () => {
  const empty = { auditReportVersion: 2, vulnerabilities: {}, metadata: { vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 } } };
  assert.equal(validateAdvisoryReport(empty).accepted, true);
  assert.throws(() => validateAdvisoryReport({ error: { code: 'ENOTCACHED' } }), { code: 'ADVISORY_DATABASE_UNAVAILABLE' });
  const hidden = structuredClone(empty); hidden.vulnerabilities.hidden = { name: 'hidden', severity: 'high', via: [] }; assert.throws(() => validateAdvisoryReport(hidden), { code: 'INVALID_ADVISORY_REPORT' });
  const sarif = { version: '2.1.0', runs: [{ tool: { driver: { name: 'CodeQL', rules: [{ id: 'js/fixture', properties: { 'security-severity': '8.0' } }] } }, invocations: [{ executionSuccessful: true }], results: [] }] };
  assert.equal(validateCodeqlSarif(sarif).accepted, true); const finding = structuredClone(sarif); finding.runs[0].results.push({ ruleId: 'js/fixture', level: 'warning' }); assert.equal(validateCodeqlSarif(finding).accepted, false);
  const unscanned = structuredClone(sarif); unscanned.runs[0].tool.driver.rules = []; assert.throws(() => validateCodeqlSarif(unscanned), { code: 'SAST_EXECUTED_SUITE_REQUIRED' });
  delete finding.runs[0].invocations; assert.throws(() => validateCodeqlSarif(finding), { code: 'SAST_EXECUTION_INCOMPLETE' });
  const time = Date.now(); const database = { UpdatedAt: new Date(time - 1000).toISOString(), NextUpdate: new Date(time + 10000).toISOString() };
  const image = { SchemaVersion: 2, CreatedAt: new Date(time).toISOString(), ArtifactType: 'container_image', Metadata: { ImageID: digest('config') }, Results: [{ Target: 'Debian contract fixture', Class: 'os-pkgs', Type: 'debian', Packages: [{ Name: 'base', Version: '1' }], Vulnerabilities: [] }, { Target: 'Node contract fixture', Class: 'lang-pkgs', Type: 'node-pkg', Packages: [{ Name: 'fixture', Version: '1.0.0' }] }] };
  assert.equal(validateTrivyReport(image, database, { expectedConfigDigest: digest('config'), now: time }).accepted, true);
  assert.throws(() => validateTrivyReport(image, { ...database, NextUpdate: new Date(time - 1).toISOString() }, { now: time }), { code: 'IMAGE_ADVISORY_DATABASE_STALE' });
  assert.throws(() => validateTrivyReport(image, database, { expectedConfigDigest: digest('foreign'), now: time }), { code: 'IMAGE_SCAN_IDENTITY_MISMATCH' });
  assert.throws(() => validateTrivyReport({ ...image, Results: [{ Target: 'unscanned' }] }, database, { now: time }), { code: 'IMAGE_SCAN_COVERAGE_REQUIRED' });
  assert.equal(validateImagePackageCoverage(image, { components: [{ name: 'fixture', version: '1.0.0' }] }).productionInventoryCovered, true);
  assert.throws(() => validateImagePackageCoverage(image, { components: [{ name: 'omitted', version: '1.0.0' }] }), { code: 'IMAGE_PACKAGE_INVENTORY_REQUIRED' });
  assert.throws(() => validateTrivyReport({ ...image, CreatedAt: new Date(time - 86400001).toISOString() }, database, { now: time }), { code: 'SCANNER_REPORT_STALE' });
  image.Results[0].Vulnerabilities.push({ VulnerabilityID: 'CONTRACT-UNKNOWN', Severity: 'UNKNOWN' }); assert.equal(validateTrivyReport(image, database, { now: time }).accepted, false);
  assert.throws(() => validateNativeSbom({ components: [] }), { code: 'INVALID_NATIVE_SBOM' });
});

test('base image pins bind exact index bytes and one real platform descriptor including CLI newline handling', () => {
  const index = { schemaVersion: 2, manifests: [{ digest: digest('platform-child'), platform: { os: 'linux', architecture: 'amd64' } }] }; const raw = bytes(index);
  const reference = `docker.io/library/node:24.19.0-bookworm-slim@${digest(raw)}`;
  assert.equal(validateBaseIndex(index, { reference, rawBytes: raw }).manifestDigest, digest('platform-child'));
  assert.equal(validateBaseIndex(index, { reference, rawBytes: Buffer.concat([raw, Buffer.from('\n')]) }).manifestDigest, digest('platform-child'));
  assert.throws(() => validateBaseIndex(index, { reference, rawBytes: bytes({ schemaVersion: 2 }) }), { code: 'BASE_INDEX_DIGEST_MISMATCH' });
  assert.throws(() => validateBaseIndex(index, { reference, rawBytes: raw, platform: 'linux/arm64' }), { code: 'BASE_PLATFORM_MANIFEST_REQUIRED' });
});

test('OCI contract verifier binds every blob, provenance subject, base material, config and source without extracting paths', async (t) => {
  const directory = await fixture(t); const valid = oci(); const path = join(directory, 'runtime.oci.tar'); await writeFile(path, valid.archive);
  const result = await inspectOciArchive(path, valid.options); assert.equal(result.imageConfigDigest, valid.configDigest); assert.equal(result.imageManifestDigest, valid.imageDigest); assert.equal(result.independentlyTrustedBuilder, false);
  await assert.rejects(inspectOciArchive(path, { ...valid.options, deadlineAt: Date.now() - 1 }), { code: 'OCI_EVIDENCE_DEADLINE' });
  await assert.rejects(inspectOciArchive(path, { ...valid.options, sourceDigest: hash('foreign-source') }), { code: 'INVALID_OCI_EVIDENCE' });
  await assert.rejects(inspectOciArchive(path, { ...valid.options, expectedDigest: digest('foreign-image') }), { code: 'INVALID_OCI_EVIDENCE' });
  const foreign = oci({ material: digest('foreign-base') }); await writeFile(path, foreign.archive); await assert.rejects(inspectOciArchive(path, foreign.options), { code: 'INVALID_OCI_EVIDENCE' });
  const subject = oci({ subjectForeign: true }); await writeFile(path, subject.archive); await assert.rejects(inspectOciArchive(path, subject.options), { code: 'INVALID_OCI_EVIDENCE' });
  const changed = Buffer.from(valid.archive); const offset = changed.indexOf(Buffer.from('contract-layer-bytes')); changed[offset] ^= 1; await writeFile(path, changed); await assert.rejects(inspectOciArchive(path, valid.options), { code: 'INVALID_OCI_EVIDENCE' });
  await writeFile(path, tar([['../escape', Buffer.from('private')]])); await assert.rejects(inspectOciArchive(path, valid.options), { code: 'INVALID_OCI_EVIDENCE' });
  await writeFile(path, tar([['index.json', Buffer.alloc(0), '2']])); await assert.rejects(inspectOciArchive(path, valid.options), { code: 'INVALID_OCI_EVIDENCE' });
});

test('scan coverage rejects omitted dev packages and public outputs reject private routes and oversized inputs', async (t) => {
  const report = { Results: [{ Target: 'package-lock.json', Type: 'npm', Packages: [{ Name: 'fixture', Version: '1.0.0' }] }, { Target: 'requirements-ci.txt', Type: 'pip', Packages: [{ Name: 'pki', Version: '1.2.3' }] }, { Target: 'deploy/Dockerfile', Class: 'config', Type: 'dockerfile', Misconfigurations: [{ ID: 'contract', Status: 'PASS', Severity: 'LOW' }] }] };
  const lock = { packages: { '': {}, 'node_modules/fixture': { version: '1.0.0', dev: true } } }; const requirements = `pki==1.2.3 --hash=sha256:${'a'.repeat(64)}`;
  assert.equal(validateSourceDependencyCoverage(report, lock, requirements).developmentDependenciesIncluded, true);
  const hidden = structuredClone(report); hidden.Results[0].Packages = []; assert.throws(() => validateSourceDependencyCoverage(hidden, lock, requirements), { code: 'SOURCE_DEPENDENCY_COVERAGE_REQUIRED' });
  const directory = await fixture(t); await writePublicSecurityArtifact(directory, 'artifacts/security-delivery.json', '{"status":"BLOCKED"}');
  assert.deepEqual(await boundedJson(join(directory, 'artifacts/security-delivery.json')), { status: 'BLOCKED' });
  await assert.rejects(boundedJson(join(directory, 'artifacts/security-delivery.json'), { maxBytes: 1 }), { code: 'UNSAFE_SECURITY_INPUT' });
  await assert.rejects(writePublicSecurityArtifact(directory, 'artifacts/private/secrets.json', '{}'), { code: 'PUBLIC_ARTIFACT_WHITELIST_REQUIRED' });
  for (const name of SOURCE_SCAN_INPUTS) { await mkdir(resolve(directory, name, '..'), { recursive: true }); await writeFile(join(directory, name), '{}'); }
  const stage = await stageSecurityScanInputs(directory); assert.equal(stage.files.length, 6); assert.equal(stage.privateDataTraversed, false);
  await assert.rejects(buildSecurityImage({ root: directory }), { code: 'FOREIGN_SECURITY_ROOT' });
  await assert.rejects(collectSecurityReport({ root: directory }), { code: 'FOREIGN_SECURITY_ROOT' });
  await assert.rejects(readFile(join(directory, stage.directory, 'artifacts/private/secrets.json')), { code: 'ENOENT' });
  await assert.rejects(stageSecurityScanInputs(directory), { code: 'EEXIST' });
});

test('pinned scanner producer contract rejects foreign keys/runs, duplicate languages, stale evidence and changed sources', async (t) => {
  const directory = await fixture(t); const key = generateKeyPairSync('ed25519'); const foreign = generateKeyPairSync('ed25519');
  for (const name of SOURCE_SCAN_INPUTS) { await mkdir(resolve(directory, name, '..'), { recursive: true }); await writeFile(join(directory, name), '{}'); }
  await mkdir(join(directory, 'artifacts')); await writeFile(join(directory, 'artifacts/runtime-sbom.cdx.json'), '{}');
  const now = Date.now(); const reports = ['codeql-javascript-typescript', 'codeql-python', 'trivy-image', 'trivy-source', 'trivy-database'];
  const steps = ['native-sbom', 'codeql-version', 'codeql-create-javascript-typescript', 'codeql-analyze-javascript-typescript', 'codeql-create-python', 'codeql-analyze-python', 'trivy-version', 'trivy-image', 'trivy-source'];
  const manifest = { version: 1, purpose: 'native-security-scanner-execution', runId: 'contract-run', sourceDigest: hash('source'), lockSha256: hash('{}'), requirementsSha256: hash('{}'), runtimeSbomSha256: hash('{}'), imageConfigDigest: digest('config'), imageManifestDigest: digest('image'), startedAt: now - 1000, completedAt: now - 1, codeqlVersion: 'contract-not-a-native-run', trivyVersion: '0.76.1', inputs: SOURCE_SCAN_INPUTS.map((path) => ({ path, sha256: hash('{}') })), reports: reports.map((id) => ({ id, sha256: hash(id) })), invocations: steps.map((id) => ({ id, argumentsSha256: hash(id), startedAt: now - 500, completedAt: now - 5, exitCode: 0 })) };
  const options = { root: directory, publicKey: key.publicKey.export({ type: 'spki', format: 'pem' }), runId: manifest.runId, sourceDigest: manifest.sourceDigest, now };
  const signed = (value) => signEnvelope(value, key.privateKey, 'security-scanner-execution');
  assert.equal((await verifyScannerExecution({ ...options, envelope: signed(manifest) })).runId, manifest.runId);
  await assert.rejects(verifyScannerExecution({ ...options, publicKey: foreign.publicKey.export({ type: 'spki', format: 'pem' }), envelope: signed(manifest) }), { code: 'SCANNER_PRODUCER_SIGNATURE_INVALID' });
  await assert.rejects(verifyScannerExecution({ ...options, runId: 'foreign-run', envelope: signed(manifest) }), { code: 'SCANNER_PRODUCER_SCOPE_INVALID' });
  const duplicate = structuredClone(manifest); duplicate.reports[1] = duplicate.reports[0]; await assert.rejects(verifyScannerExecution({ ...options, envelope: signed(duplicate) }), { code: 'SCANNER_PRODUCER_SCOPE_INVALID' });
  await assert.rejects(verifyScannerExecution({ ...options, now: now + 900001, envelope: signed(manifest) }), { code: 'SCANNER_PRODUCER_SCOPE_INVALID' });
  await writeFile(join(directory, 'package-lock.json'), '{"changed":true}'); await assert.rejects(verifyScannerExecution({ ...options, envelope: signed(manifest) }), { code: 'SCANNER_PRODUCER_SCOPE_INVALID' });
});

test('security CLI has fixed operations and refuses publication, shell options and duplicate output routes', () => {
  assert.equal(parseSecurityArguments(['report', '--sarif', 'one.sarif', '--sarif', 'two.sarif']).options.sarif.length, 2);
  for (const args of [['publish'], ['build', '--push', 'true'], ['report', '--output', 'one', '--output', 'two'], ['report', '--sarif']]) assert.throws(() => parseSecurityArguments(args), { code: args[0] === 'publish' || args.length % 2 === 0 ? 'INVALID_SECURITY_COMMAND' : 'INVALID_SECURITY_ARGUMENTS' });
});
