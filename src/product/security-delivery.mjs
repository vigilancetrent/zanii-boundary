import { createHash, randomUUID } from 'node:crypto';
import { readFile, readdir, lstat, mkdir, writeFile, rename, rm, open, realpath } from 'node:fs/promises';
import { constants } from 'node:fs';
import { resolve, relative, isAbsolute, join } from 'node:path';
import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import { AppError } from '../protocol.mjs';
import { inspectOciArchive } from './oci-evidence.mjs';

export const DELIVERY_BASE_IMAGE = 'docker.io/library/node:24.19.0-bookworm-slim@sha256:a9f5f7c91a432850b2a8a7797adf5eadb6c733ceed61167806cee7ea7fbc29df';
export const DELIVERY_BUILDKIT_IMAGE = 'docker.io/moby/buildkit:buildx-stable-1@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8';
export const DELIVERY_GITLEAKS_IMAGE = 'ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb';
export const PUBLIC_SECURITY_ARTIFACTS = Object.freeze(['artifacts/security-delivery.json', 'artifacts/runtime-sbom.cdx.json']);
export const SOURCE_SCAN_INPUTS = Object.freeze(['package.json', 'package-lock.json', 'requirements-ci.txt', 'deploy/Dockerfile', '.github/workflows/product.yml', '.github/dependabot.yml']);
export const IMAGE_CONTEXT_PATTERNS = Object.freeze(['**', '!package.json', '!package-lock.json', '!src/', '!src/**/', '!src/**/*.mjs', '!scripts/', '!scripts/**/', '!scripts/**/*.mjs', '!migrations/', '!migrations/**/', '!migrations/**/*.sql', '**/node_modules', '**/__pycache__', 'artifacts', 'archive', '.secrets', '.data', '.test-data', '.npm-cache', '.cache', '.security', '.git', '**/.env', '**/.env.*', '**/*.pem', '**/*.key', '**/*.sqlite*', '**/*.db', '**/*.db-*', '**/*.snapshot', '**/*.pending', '**/*.oci.tar']);
export const LOCKED_DEVELOPMENT_TOOLS = Object.freeze({ typescript: '6.0.3', eslint: '10.14.0', '@types/node': '26.6.6', secretlint: '13.1.0', '@secretlint/secretlint-rule-preset-recommend': '13.1.0' });
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const fail = (code, status = 400) => { throw new AppError(status, code); };
const toolFailure = (code, result) => { throw Object.assign(new AppError(503, code), { toolExitCode: result.code, toolSignal: result.signal }); };
const safeInteger = (n) => Number.isSafeInteger(n) && n >= 0;
const digestPattern = /^sha256:[a-f\d]{64}$/;
const sourceRoots = ['src', 'scripts', 'sdk', 'config', 'deploy', 'fixtures', 'test', 'docs', 'paper', 'migrations', 'monitoring', '.github'];
const privateDirectory = /(?:^|\/)(?:artifacts|archive|node_modules|__pycache__|\.git|\.npm-cache|\.cache|\.test-data|\.secrets|\.data|\.security)(?:\/|$)/;

export async function canonicalSecurityRoot(root) {
  const actual = await realpath(root); const expected = await realpath(fileURLToPath(new URL('../../', import.meta.url)));
  if ((process.platform === 'win32' ? actual.toLowerCase() !== expected.toLowerCase() : actual !== expected)) fail('FOREIGN_SECURITY_ROOT');
  return actual;
}

export async function boundedBytes(path, { maxBytes = 32 * 1024 * 1024 } = {}) {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 32 * 1024 * 1024) fail('UNSAFE_SECURITY_INPUT');
  const stat = await lstat(path); if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxBytes) fail('UNSAFE_SECURITY_INPUT');
  const file = await open(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const actual = await file.stat(); if (!actual.isFile() || actual.ino !== stat.ino || actual.dev !== stat.dev || actual.size !== stat.size) fail('UNSAFE_SECURITY_INPUT');
    const chunks = []; let size = 0;
    for await (const chunk of file.createReadStream({ autoClose: false })) { size += chunk.length; if (size > maxBytes) fail('UNSAFE_SECURITY_INPUT'); chunks.push(chunk); }
    return Buffer.concat(chunks);
  } finally { await file.close(); }
}

export async function boundedJson(path, options = {}) {
  const bytes = await boundedBytes(path, options);
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch (error) { throw error instanceof AppError ? error : new AppError(400, 'INVALID_SECURITY_JSON'); }
}

/** Public artifacts are a fixed two-file surface; a pre-existing link is never followed. */
export async function writePublicSecurityArtifact(root, name, content) {
  const destination = resolve(root, name); const path = relative(root, destination).replaceAll('\\', '/');
  if (!PUBLIC_SECURITY_ARTIFACTS.includes(path) || isAbsolute(path)) fail('PUBLIC_ARTIFACT_WHITELIST_REQUIRED');
  const directory = resolve(root, 'artifacts'); await mkdir(directory, { recursive: true, mode: 0o700 });
  const parent = await lstat(directory); if (!parent.isDirectory() || parent.isSymbolicLink()) fail('UNSAFE_SECURITY_OUTPUT');
  try { const stat = await lstat(destination); if (!stat.isFile() || stat.isSymbolicLink()) fail('UNSAFE_SECURITY_OUTPUT'); }
  catch (error) { if (!(error instanceof Error && 'code' in error && error.code === 'ENOENT')) throw error; }
  const temporary = join(directory, `.security-${randomUUID()}.pending`);
  try { await writeFile(temporary, content, { flag: 'wx', mode: 0o600 }); await rename(temporary, destination); }
  finally { await rm(temporary, { force: true }); }
}

/** Staging makes the scanner's filesystem scope explicit, rather than scanning the workspace. */
export async function stageSecurityScanInputs(root = process.cwd()) {
  const directory = resolve(root, 'artifacts/private/security/source-input'); await mkdir(resolve(root, 'artifacts/private/security'), { recursive: true, mode: 0o700 });
  await mkdir(directory, { mode: 0o700 }); const files = [];
  for (const name of SOURCE_SCAN_INPUTS) {
    const content = await boundedBytes(resolve(root, name)); const destination = resolve(directory, name);
    await mkdir(resolve(destination, '..'), { recursive: true, mode: 0o700 }); await writeFile(destination, content, { flag: 'wx', mode: 0o600 });
    files.push({ path: name, sha256: sha(content) });
  }
  return { directory: 'artifacts/private/security/source-input', files, privateDataTraversed: false };
}

export async function securitySourceFiles(root = process.cwd()) {
  const files = [];
  async function walk(directory) {
    let entries; try { entries = await readdir(resolve(root, directory), { withFileTypes: true }); }
    catch (error) { if (error instanceof Error && 'code' in error && error.code === 'ENOENT') return; throw error; }
    for (const entry of entries) {
      const name = `${directory}/${entry.name}`; if (privateDirectory.test(name)) continue;
      if (entry.isSymbolicLink()) fail('SECURITY_SOURCE_SYMLINK_DENIED');
      if (entry.isDirectory()) await walk(name);
      else if (entry.isFile() && (/\.(?:mjs|py|json|yaml|yml|sql|md|sh|toml|conf|rules|rego|example|tmpl|tpl|txt|ini|cfg|nft|service|alloy)$/.test(name) || entry.name === 'Dockerfile')) files.push(name);
    }
  }
  for (const directory of sourceRoots) await walk(directory);
  for (const entry of await readdir(root, { withFileTypes: true })) if (entry.isFile() && (entry.name.endsWith('.md') || ['package.json', 'package-lock.json', '.dockerignore', '.secretlintrc.json', 'requirements-ci.txt'].includes(entry.name))) files.push(entry.name);
  return files.sort();
}

export function validateLockedDependencies(pkg, lock) {
  if (lock.lockfileVersion !== 3 || !lock.packages?.['']) fail('LOCKFILE_REQUIRED');
  let packages = 0;
  for (const category of ['dependencies', 'devDependencies']) {
    for (const [name, version] of Object.entries(pkg[category] ?? {})) {
      if (typeof version !== 'string' || !/^\d+\.\d+\.\d+(?:-[A-Za-z\d.-]+)?$/.test(version)
          || lock.packages[''][category]?.[name] !== version || lock.packages[`node_modules/${name}`]?.version !== version) fail('UNLOCKED_DIRECT_DEPENDENCY');
    }
  }
  for (const [name, version] of Object.entries(LOCKED_DEVELOPMENT_TOOLS)) if (pkg.devDependencies?.[name] !== version) fail('LOCKED_SECURITY_TOOL_REQUIRED');
  for (const [path, entry] of Object.entries(lock.packages)) {
    if (!path) continue; packages++;
    let url; try { url = new URL(entry.resolved); } catch { fail('DEPENDENCY_PROVENANCE_REQUIRED'); }
    if (entry.link || url.protocol !== 'https:' || url.hostname !== 'registry.npmjs.org' || url.username || url.password || url.search || url.hash
        || !/^sha(?:256|384|512)-[A-Za-z\d+/]+=*$/.test(entry.integrity ?? '') || typeof entry.version !== 'string') fail('DEPENDENCY_PROVENANCE_REQUIRED');
  }
  return { packages, directVersionsLocked: true, transitiveIntegrity: true, installScriptsRequired: false };
}

export function validateWorkflow(workflow) {
  if (!workflow?.jobs || workflow.permissions?.contents !== 'read') fail('INVALID_SECURITY_WORKFLOW');
  for (const permissions of [workflow.permissions, ...Object.values(workflow.jobs).map((job) => job.permissions).filter(Boolean)]) {
    if (!permissions || typeof permissions !== 'object' || Object.values(permissions).some((value) => !['read', 'none'].includes(value))) fail('CI_WRITE_PERMISSION_DENIED');
  }
  let actions = 0;
  for (const job of Object.values(workflow.jobs)) for (const step of job.steps ?? []) {
    if (step.uses) { if (!/^[A-Za-z\d_.-]+\/[A-Za-z\d_.-]+(?:\/[A-Za-z\d_./-]+)?@[a-f\d]{40}$/.test(step.uses)) fail('UNPINNED_CI_ACTION'); actions++; }
    if (step.run && (/npm\s+install[^\n]*(?:--no-save|--package-lock=false)/.test(step.run) || /docker\s+(?:push|login)\b|--push\b/.test(step.run))) fail('UNSAFE_DELIVERY_WORKFLOW');
    if (step.uses?.startsWith('actions/upload-artifact@')) {
      const files = String(step.with?.path ?? '').split(/\r?\n/).map((name) => name.trim()).filter(Boolean);
      if (!files.length || files.some((name) => !PUBLIC_SECURITY_ARTIFACTS.includes(name))) fail('PUBLIC_ARTIFACT_WHITELIST_REQUIRED');
    }
  }
  if (!actions) fail('CI_ACTIONS_REQUIRED'); return { pinnedActions: actions, explicitPublicArtifacts: true };
}

/** @param {any} index @param {any} options */
export function validateBaseIndex(index, { reference = DELIVERY_BASE_IMAGE, platform = 'linux/amd64', rawBytes } = {}) {
  if (!/^docker\.io\/library\/node:\d+\.\d+\.\d+-bookworm-slim@sha256:[a-f\d]{64}$/.test(reference) || !['linux/amd64', 'linux/arm64'].includes(platform)) fail('INVALID_BASE_IMAGE');
  const expected = reference.slice(reference.indexOf('@') + 1);
  const bytes = rawBytes && Buffer.from(rawBytes);
  const matches = bytes && (`sha256:${sha(bytes)}` === expected || bytes.at(-1) === 10 && `sha256:${sha(bytes.subarray(0, bytes.at(-2) === 13 ? -2 : -1))}` === expected);
  if (!matches || index.schemaVersion !== 2 || !Array.isArray(index.manifests)) fail('BASE_INDEX_DIGEST_MISMATCH');
  const [os, architecture] = platform.split('/'); const selected = index.manifests.filter((m) => m.platform?.os === os && m.platform?.architecture === architecture);
  if (selected.length !== 1 || !digestPattern.test(selected[0].digest)) fail('BASE_PLATFORM_MANIFEST_REQUIRED');
  return { reference, indexDigest: expected, platform, manifestDigest: selected[0].digest };
}

export function validateAdvisoryReport(value) {
  if (value.error || value.auditReportVersion !== 2 || !value.metadata?.vulnerabilities || !value.vulnerabilities || typeof value.vulnerabilities !== 'object') fail('ADVISORY_DATABASE_UNAVAILABLE', 503);
  const counts = value.metadata.vulnerabilities;
  if (['info', 'low', 'moderate', 'high', 'critical', 'total'].some((key) => !safeInteger(counts[key]))) fail('INVALID_ADVISORY_REPORT');
  if (counts.total !== counts.info + counts.low + counts.moderate + counts.high + counts.critical) fail('INVALID_ADVISORY_REPORT');
  const observed = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  for (const entry of Object.values(value.vulnerabilities)) { if (!entry || !Object.hasOwn(observed, entry.severity) || typeof entry.name !== 'string' || !Array.isArray(entry.via)) fail('INVALID_ADVISORY_REPORT'); observed[entry.severity]++; }
  if (Object.entries(observed).some(([severity, count]) => counts[severity] !== count)) fail('INVALID_ADVISORY_REPORT');
  return { findings: counts.total, high: counts.high, critical: counts.critical, accepted: counts.high + counts.critical === 0, scope: 'fresh npm advisory response including development dependencies' };
}

export function validateNativeSbom(value) {
  if (value.bomFormat !== 'CycloneDX' || !/^1\.[4-9]$/.test(value.specVersion ?? '') || !Array.isArray(value.components) || !value.components.length
      || !Array.isArray(value.dependencies) || !value.metadata?.component) fail('INVALID_NATIVE_SBOM');
  for (const component of value.components) if (typeof component.name !== 'string' || !component.name || typeof component.version !== 'string'
      || typeof component['bom-ref'] !== 'string' || !component['bom-ref'] || component.purl && !/^pkg:npm\//.test(component.purl)) fail('INVALID_NATIVE_SBOM');
  return { components: value.components.length, format: 'CycloneDX', nativeGenerator: 'npm sbom', developmentDependenciesOmitted: true };
}

export function validateCodeqlSarif(value) {
  if (value.version !== '2.1.0' || !Array.isArray(value.runs) || !value.runs.length) fail('INVALID_SAST_REPORT');
  let findings = 0; let high = 0;
  for (const run of value.runs) {
    if (!/CodeQL/i.test(run.tool?.driver?.name ?? '') || !Array.isArray(run.results) || !Array.isArray(run.tool.driver.rules) || !run.tool.driver.rules.length
        || !run.tool.driver.rules.some((rule) => Number.isFinite(Number(rule.properties?.['security-severity'])))) fail('SAST_EXECUTED_SUITE_REQUIRED', 503);
    if (!Array.isArray(run.invocations) || !run.invocations.length || run.invocations.some((entry) => entry.executionSuccessful !== true)) fail('SAST_EXECUTION_INCOMPLETE', 503);
    const rules = new Map(run.tool.driver.rules.map((rule) => [rule.id, rule]));
    for (const result of run.results) {
      if (typeof result.ruleId !== 'string' || !rules.has(result.ruleId) || (result.suppressions?.length ?? 0) > 0 || result.baselineState === 'absent') fail('SAST_FINDING_NOT_EVALUATED');
      findings++; const rule = rules.get(result.ruleId); const severity = Number(rule.properties?.['security-severity']);
      if (!Number.isFinite(severity) || severity < 0 || severity > 10) fail('SAST_SEVERITY_UNVERIFIED');
      if (result.level === 'error' || Number.isFinite(severity) && severity >= 7) high++;
    }
  }
  return { findings, high, accepted: high === 0, scanner: 'CodeQL', runs: value.runs.length };
}

/** @param {any} value @param {any} database @param {any} options */
export function validateTrivyReport(value, database, { now = Date.now(), maxDatabaseAgeMs = 86400000, expectedConfigDigest, artifactType = 'container_image' } = {}) {
  const updated = Date.parse(database?.UpdatedAt); const next = Date.parse(database?.NextUpdate);
  if (!Number.isFinite(updated) || !Number.isFinite(next) || updated > now + 60000 || now - updated > maxDatabaseAgeMs || next <= now) fail('IMAGE_ADVISORY_DATABASE_STALE', 503);
  const createdAt = Date.parse(value.CreatedAt);
  if (!Number.isFinite(createdAt) || createdAt < updated || createdAt > now + 60000 || now - createdAt > maxDatabaseAgeMs) fail('SCANNER_REPORT_STALE', 503);
  if (!['container_image', 'filesystem'].includes(artifactType) || value.SchemaVersion !== 2 || !Array.isArray(value.Results) || !value.Results.length || value.ArtifactType !== artifactType
      || artifactType === 'container_image' && (!digestPattern.test(value.Metadata?.ImageID ?? '') || expectedConfigDigest && value.Metadata.ImageID !== expectedConfigDigest)) fail('IMAGE_SCAN_IDENTITY_MISMATCH');
  if (artifactType === 'container_image' && (!value.Results.some((row) => row.Class === 'os-pkgs' && row.Type === 'debian' && row.Packages?.length > 0)
      || !value.Results.some((row) => row.Class === 'lang-pkgs' && ['node-pkg', 'npm'].includes(row.Type) && row.Packages?.length > 0))) fail('IMAGE_SCAN_COVERAGE_REQUIRED', 503);
  let findings = 0; let high = 0; let unknown = 0; let misconfigurations = 0;
  for (const result of value.Results) {
    if (typeof result.Target !== 'string' || !result.Target) fail('INVALID_IMAGE_SCAN');
    for (const finding of result.Vulnerabilities ?? []) {
      if (typeof finding.VulnerabilityID !== 'string' || !['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(finding.Severity)) fail('INVALID_IMAGE_SCAN');
      findings++; if (['HIGH', 'CRITICAL'].includes(finding.Severity)) high++; if (finding.Severity === 'UNKNOWN') unknown++;
    }
    for (const finding of result.Misconfigurations ?? []) {
      if (typeof finding.ID !== 'string' || !['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(finding.Severity) || !['FAIL', 'PASS', 'EXCEPTION'].includes(finding.Status)) fail('INVALID_IMAGE_SCAN');
      if (finding.Status === 'PASS') continue;
      if (finding.Status === 'EXCEPTION') fail('SCANNER_SUPPRESSED_FINDING_DENIED');
      misconfigurations++; if (['HIGH', 'CRITICAL'].includes(finding.Severity)) high++; if (finding.Severity === 'UNKNOWN') unknown++;
    }
  }
  return { findings, misconfigurations, high, unknown, accepted: high + unknown === 0, scanner: 'Trivy', ...(artifactType === 'container_image' ? { imageConfigDigest: value.Metadata.ImageID } : {}), reportCreatedAt: createdAt, databaseUpdatedAt: updated };
}

/** A successful scan must actually include every locked Node and Python CI package. */
export function validateSourceDependencyCoverage(value, lock, requirements) {
  const npm = value.Results?.filter((entry) => /(?:^|\/)package-lock\.json$/.test(entry.Target ?? '') && entry.Type === 'npm');
  const pip = value.Results?.filter((entry) => /(?:^|\/)requirements-ci\.txt$/.test(entry.Target ?? '') && entry.Type === 'pip');
  if (npm?.length !== 1 || pip?.length !== 1 || !Array.isArray(npm[0].Packages) || !Array.isArray(pip[0].Packages)
      || !value.Results?.some((row) => row.Class === 'config' && row.Type === 'dockerfile' && /(?:^|\/)deploy\/Dockerfile$/.test(row.Target ?? '') && row.Misconfigurations?.length > 0)) fail('SOURCE_DEPENDENCY_COVERAGE_REQUIRED', 503);
  const expected = new Set(Object.entries(lock.packages ?? {}).filter(([path]) => path).map(([path, entry]) => `${entry.name ?? path.split('node_modules/').at(-1)}@${entry.version}`));
  const observed = new Set(npm[0].Packages.map((entry) => `${entry.Name}@${entry.Version}`));
  const python = new Set(requirements.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#')).map((line) => {
    const match = /^([A-Za-z\d_.-]+)==(\d+\.\d+(?:\.\d+)?) --hash=sha256:[a-f\d]{64}$/.exec(line); if (!match) fail('HASHED_PYTHON_LOCK_REQUIRED'); return `${match[1].toLowerCase().replaceAll('_', '-')}@${match[2]}`;
  }));
  const observedPython = new Set(pip[0].Packages.map((entry) => `${entry.Name.toLowerCase().replaceAll('_', '-')}@${entry.Version}`));
  if (!expected.size || !python.size || expected.size !== observed.size || [...expected].some((entry) => !observed.has(entry))
      || python.size !== observedPython.size || [...python].some((entry) => !observedPython.has(entry))) fail('SOURCE_DEPENDENCY_COVERAGE_REQUIRED', 503);
  return { nodePackages: expected.size, pythonCiPackages: python.size, developmentDependenciesIncluded: true, exactLockedGraph: true };
}

/** Actual Secretlint public API; formatter output is never included in a public report.
 * @param {any} options */
export async function scanSecrets({ root = process.cwd(), files, content } = {}) {
  if (createRequire(import.meta.url)('secretlint/package.json').version !== LOCKED_DEVELOPMENT_TOOLS.secretlint) fail('SECRET_SCANNER_VERSION_MISMATCH', 503);
  const { runSecretLint } = await import('secretlint');
  const config = { rules: [{ id: '@secretlint/secretlint-rule-preset-recommend' }] };
  const result = await runSecretLint({ cliOptions: content === undefined
    ? { cwd: root, filePathOrGlobList: files ?? await securitySourceFiles(root), noGlob: true, respectGitignore: false }
    : { cwd: root, stdinContent: content, stdinFileName: 'src/security-contract-fixture.mjs' },
  engineOptions: { cwd: root, formatter: 'json', configFileJSON: config, color: false, maskSecrets: true } });
  let rows; try { rows = JSON.parse(result.stdout ?? '[]'); } catch { fail('SECRET_SCANNER_OUTPUT_INVALID', 503); }
  if (result.stderr || !Array.isArray(rows)) fail('SECRET_SCANNER_UNAVAILABLE', 503);
  const findings = rows.reduce((count, row) => count + (Array.isArray(row.messages) ? row.messages.length : 0), 0);
  if (result.exitStatus !== (findings ? 1 : 0)) fail('SECRET_SCANNER_OUTPUT_INVALID', 503);
  return { scanner: 'Secretlint', version: '13.1.0', toolExitCode: result.exitStatus, files: rows.length, findings, accepted: findings === 0, scope: content === undefined ? 'explicit source whitelist; generated PKI/private data excluded' : 'explicit supplied text; no filesystem traversal' };
}

/** No shell, no provider credentials, bounded output and an explicit deadline. */
export async function runSecurityTool(command, args, { cwd = process.cwd(), timeoutMs = 60000, maxBytes = 32 * 1024 * 1024 } = {}) {
  return new Promise((resolveResult, reject) => {
    const allowed = ['PATH', 'Path', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP']; const env = Object.fromEntries(allowed.filter((name) => process.env[name]).map((name) => [name, process.env[name]]));
    env.HOME = resolve(cwd, '.tool-home'); env.USERPROFILE = env.HOME;
    env.DOCKER_CONFIG = resolve(cwd, 'artifacts/private/security/docker-config'); env.TRIVY_CACHE_DIR = resolve(cwd, 'artifacts/private/security/trivy-cache');
    let child;
    try { child = spawn(command, args, { cwd, env, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }); }
    catch { reject(new AppError(503, 'SECURITY_TOOL_UNAVAILABLE')); return; }
    let bytes = 0; const output = []; const errors = []; let settled = false;
    const finish = (error, value) => { if (settled) return; settled = true; clearTimeout(timer); error ? reject(error) : resolveResult(value); };
    const timer = setTimeout(() => { child.kill('SIGKILL'); finish(new AppError(503, 'SECURITY_TOOL_DEADLINE')); }, timeoutMs);
    const append = (target, chunk) => { bytes += chunk.length; if (bytes > maxBytes) { child.kill('SIGKILL'); finish(new AppError(413, 'SECURITY_TOOL_OUTPUT_LIMIT')); } else target.push(chunk); };
    child.stdout.on('data', (chunk) => append(output, chunk)); child.stderr.on('data', (chunk) => append(errors, chunk));
    child.on('error', () => finish(new AppError(503, 'SECURITY_TOOL_UNAVAILABLE')));
    child.on('close', (code, signal) => finish(null, { code, signal, stdout: Buffer.concat(output), stderr: Buffer.concat(errors) }));
  });
}

export async function verifyDeliveryPolicy(root = process.cwd()) {
  const pkg = await boundedJson(resolve(root, 'package.json')); const lock = await boundedJson(resolve(root, 'package-lock.json'));
  const dependencies = validateLockedDependencies(pkg, lock);
  const workflow = validateWorkflow(parse(await readFile(resolve(root, '.github/workflows/product.yml'), 'utf8')));
  const dockerfile = await readFile(resolve(root, 'deploy/Dockerfile'), 'utf8'); const ignore = await readFile(resolve(root, '.dockerignore'), 'utf8');
  const patterns = ignore.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#'));
  if (!dockerfile.includes(`ARG NODE_IMAGE=${DELIVERY_BASE_IMAGE}`) || !/COPY migrations \.\/migrations/.test(dockerfile) || !/npm ci --omit=dev --ignore-scripts/.test(dockerfile)
      || !/USER 10001:2000/.test(dockerfile) || JSON.stringify(patterns) !== JSON.stringify(IMAGE_CONTEXT_PATTERNS)
      || dockerfile.split(/\r?\n/).filter((line) => /^FROM\b/i.test(line)).join() !== 'FROM ${NODE_IMAGE}' || /^ADD\b/im.test(dockerfile)) fail('UNSAFE_CONTAINER_CONTEXT');
  return { dependencies, workflow, dockerContext: 'explicit executable-input allowlist', baseImage: DELIVERY_BASE_IMAGE, imageBuilt: false };
}

export async function resolveNpmCli() {
  const candidates = [resolve(process.execPath, '../node_modules/npm/bin/npm-cli.js'), resolve(process.execPath, '../../lib/node_modules/npm/bin/npm-cli.js')];
  for (const path of candidates) { try { if ((await lstat(path)).isFile()) return path; } catch { /* Try the next fixed Node installation layout. */ } }
  fail('NPM_CLI_UNAVAILABLE', 503);
}

/** Actual local BuildKit OCI export. No registry login, push or publication occurs.
 * @param {any} options */
export async function buildSecurityImage({ root = process.cwd(), platform = 'linux/amd64' } = {}) {
  root = await canonicalSecurityRoot(root);
  if (!['linux/amd64', 'linux/arm64'].includes(platform)) fail('INVALID_BUILD_PLATFORM');
  const directory = resolve(root, 'artifacts/private/security'); await mkdir(directory, { recursive: true, mode: 0o700 }); await mkdir(join(directory, 'docker-config'), { recursive: true, mode: 0o700 });
  const { implementationDigest } = await import('../../scripts/benchmark.mjs'); const sourceDigest = await implementationDigest();
  const inspect = await runSecurityTool('docker', ['buildx', 'imagetools', 'inspect', DELIVERY_BASE_IMAGE, '--raw'], { cwd: root });
  if (inspect.code !== 0) toolFailure('BASE_IMAGE_INSPECTION_UNAVAILABLE', inspect);
  let index; try { index = JSON.parse(inspect.stdout.toString()); } catch { fail('BASE_INDEX_DIGEST_MISMATCH'); }
  const base = validateBaseIndex(index, { rawBytes: inspect.stdout, platform }); await writeFile(join(directory, 'base-index.json'), inspect.stdout, { mode: 0o600 });
  const builder = `zinii-security-${randomUUID().slice(0, 8)}`; let created = false;
  try {
    const setup = await runSecurityTool('docker', ['buildx', 'create', '--name', builder, '--driver', 'docker-container', '--driver-opt', `image=${DELIVERY_BUILDKIT_IMAGE}`], { cwd: root });
    if (setup.code !== 0) toolFailure('PINNED_BUILDER_UNAVAILABLE', setup); created = true;
    const build = await runSecurityTool('docker', ['buildx', 'build', '--builder', builder, '--platform', platform, '--pull', '--provenance=mode=max,version=v1',
      '--metadata-file', join(directory, 'build-metadata.json'), '--output', `type=oci,dest=${join(directory, 'runtime.oci.tar')}`,
      '--build-arg', `NODE_IMAGE=${DELIVERY_BASE_IMAGE}`, '--build-arg', `SOURCE_DIGEST=${sourceDigest}`, '--file', 'deploy/Dockerfile', '.'], { cwd: root, timeoutMs: 600000 });
    if (build.code !== 0) toolFailure('IMAGE_BUILD_UNAVAILABLE', build);
    const metadata = await boundedJson(join(directory, 'build-metadata.json'));
    const evidence = await inspectOciArchive(join(directory, 'runtime.oci.tar'), { expectedDigest: metadata['containerimage.digest'], sourceDigest,
      baseIndexDigest: base.indexDigest, baseManifestDigest: base.manifestDigest, platform });
    if (await implementationDigest() !== sourceDigest) fail('IMPLEMENTATION_CHANGED');
    await writeFile(join(directory, 'build-evidence.json'), JSON.stringify({ version: 1, createdAt: Date.now(), sourceDigest, base, evidence, registryPublished: false }), { mode: 0o600 });
    return { ...evidence, buildExitCode: build.code, baseImage: DELIVERY_BASE_IMAGE, builderImage: DELIVERY_BUILDKIT_IMAGE, registryPublished: false };
  } finally { if (created) { const cleanup = await runSecurityTool('docker', ['buildx', 'rm', '--force', builder], { cwd: root }); if (cleanup.code !== 0) fail('BUILDER_CLEANUP_REQUIRED', 503); } }
}

/** Only this standalone project's repository may be inspected; a parent monorepo is not implicitly authorized. */
export async function scanProjectHistory(root = process.cwd()) {
  let git; try { git = await lstat(resolve(root, '.git')); } catch { fail('GIT_HISTORY_UNAVAILABLE', 503); }
  if (!git.isDirectory() && !git.isFile() || git.isSymbolicLink()) fail('GIT_HISTORY_SCOPE_UNVERIFIED', 503);
  const scope = await runSecurityTool('git', ['rev-parse', '--show-toplevel'], { cwd: root });
  const canonical = (path) => process.platform === 'win32' ? resolve(path).toLowerCase() : resolve(path);
  if (scope.code !== 0 || canonical(scope.stdout.toString().trim()) !== canonical(root)) fail('GIT_HISTORY_SCOPE_UNVERIFIED', 503);
  const directory = resolve(root, 'artifacts/private/security'); const output = join(directory, 'history'); await mkdir(output, { recursive: true, mode: 0o700 });
  const tool = await runSecurityTool('docker', ['run', '--rm', '--platform=linux/amd64', '--network=none', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges:true', '--pids-limit=64', '--memory=512m',
    '--user', `${process.getuid?.() ?? 1000}:${process.getgid?.() ?? 1000}`, '--mount', `type=bind,src=${resolve(root)},dst=/repo,readonly`, '--mount', `type=bind,src=${output},dst=/out`,
    DELIVERY_GITLEAKS_IMAGE, 'git', '/repo', '--config=/repo/.github/gitleaks.toml', '--redact=100', '--report-format=json', '--report-path=/out/gitleaks.json', '--exit-code=1', '--no-banner',
    `--log-opts=${['--all', '--', ...sourceRoots, 'package.json', 'package-lock.json', '.dockerignore', '.secretlintrc.json', 'requirements-ci.txt', ':(top,glob)*.md'].join(' ')}`], { cwd: root, timeoutMs: 300000 });
  if (![0, 1].includes(tool.code)) toolFailure('HISTORY_SCANNER_UNAVAILABLE', tool);
  const rows = await boundedJson(join(output, 'gitleaks.json')); if (!Array.isArray(rows) || tool.code !== (rows.length ? 1 : 0)) fail('INVALID_HISTORY_SCAN');
  return { scanner: 'Gitleaks', image: DELIVERY_GITLEAKS_IMAGE, findings: rows.length, accepted: rows.length === 0, toolExitCode: tool.code, scope: 'this standalone repository; declared source paths; private/generated directories excluded' };
}

/** @param {any} options */
export async function collectSecurityReport({ root = process.cwd(), output = 'artifacts/security-delivery.json', sarif = [], imageReport, sourceDependencyReport, databaseMetadata, ociArchive, buildMetadata, baseIndex, platform = 'linux/amd64', producerManifest, producerPublicKey, producerRunId } = {}) {
  root = await canonicalSecurityRoot(root);
  const startedAt = Date.now(); const runId = randomUUID(); const checks = [];
  const { implementationDigest } = await import('../../scripts/benchmark.mjs'); const sourceDigest = await implementationDigest();
  const privateRoot = resolve(root, 'artifacts/private/security'); await mkdir(privateRoot, { recursive: true, mode: 0o700 });
  await mkdir(join(privateRoot, 'docker-config'), { recursive: true, mode: 0o700 });
  const capture = async (name, work) => { try { const result = await work(); checks.push({ name, status: result.accepted === false ? 'FAIL' : 'PASS', result }); }
    catch (error) { const details = error instanceof AppError && 'toolExitCode' in error ? { toolExitCode: error.toolExitCode, ...('toolSignal' in error && typeof error.toolSignal === 'string' && /^SIG[A-Z]+$/.test(error.toolSignal) ? { toolSignal: error.toolSignal } : {}) } : {};
      checks.push({ name, status: error instanceof AppError && error.status < 500 ? 'FAIL' : 'BLOCKED', code: error instanceof AppError ? error.code : 'SECURITY_CHECK_UNAVAILABLE', ...details }); } };
  let producer;
  await capture('trusted-scanner-execution', async () => {
    if (!producerManifest || !producerPublicKey || !producerRunId) fail('TRUSTED_SCANNER_PRODUCER_REQUIRED', 503);
    const { verifyScannerExecution } = await import('./scanner-evidence.mjs');
    producer = await verifyScannerExecution({ root, envelope: await boundedJson(resolve(root, producerManifest)), publicKey: await boundedBytes(resolve(root, producerPublicKey), { maxBytes: 16384 }), runId: producerRunId, sourceDigest });
    return { verified: true, runId: producer.runId, sourceDigest, completedAt: producer.completedAt, signerTrust: 'explicit caller-pinned producer key; independent CI identity not implied' };
  });
  await capture('locked-delivery-policy', () => verifyDeliveryPolicy(root));
  await capture('distributed-deployment-policy', async () => {
    const { readDistributedDeploymentFiles } = await import('./distributed-deployment.mjs');
    const { status, liveVerified, imageVerified, profileDigest, poolBudget } = await readDistributedDeploymentFiles(pathToFileURL(resolve(root, 'deploy/distributed') + '/'));
    return { status, liveVerified, imageVerified, profileDigest, poolBudget };
  });
  await capture('monitoring-policy', async () => (await import('./monitoring.mjs')).validateMonitoringBundle({ root }));
  await capture('source-secrets', () => scanSecrets({ root }));
  await capture('project-history-secrets', () => scanProjectHistory(root));
  const npmArgs = ['--userconfig', join(privateRoot, 'empty-user.npmrc'), '--globalconfig', join(privateRoot, 'empty-global.npmrc'), '--cache', join(privateRoot, 'npm-cache'), '--registry', 'https://registry.npmjs.org'];
  await writeFile(join(privateRoot, 'empty-user.npmrc'), '', { mode: 0o600 }); await writeFile(join(privateRoot, 'empty-global.npmrc'), '', { mode: 0o600 });
  await capture('native-runtime-sbom', async () => {
    if (producerManifest) {
      if (!producer) fail('TRUSTED_SCANNER_PRODUCER_REQUIRED', 503);
      const bytes = await boundedBytes(resolve(root, 'artifacts/runtime-sbom.cdx.json')); const result = validateNativeSbom(JSON.parse(bytes.toString()));
      if (sha(bytes) !== producer.runtimeSbomSha256 || !(await scanSecrets({ root, content: bytes.toString() })).accepted) fail('SCANNER_REPORT_BINDING_MISMATCH');
      return { ...result, toolExitCode: 0, sha256: sha(bytes), producerRunId: producer.runId };
    }
    const tool = await runSecurityTool(process.execPath, [await resolveNpmCli(), ...npmArgs, 'sbom', '--sbom-format=cyclonedx', '--omit=dev'], { cwd: root });
    if (tool.code !== 0) toolFailure('NATIVE_SBOM_UNAVAILABLE', tool); let value; try { value = JSON.parse(tool.stdout.toString()); } catch { fail('INVALID_NATIVE_SBOM'); }
    const result = validateNativeSbom(value); const secretCheck = await scanSecrets({ root, content: tool.stdout.toString() }); if (!secretCheck.accepted) fail('PUBLIC_SBOM_CONTAINS_SECRET');
    await writePublicSecurityArtifact(root, 'artifacts/runtime-sbom.cdx.json', tool.stdout); return { ...result, toolExitCode: tool.code, sha256: sha(tool.stdout) };
  });
  await capture('fresh-dependency-advisories', async () => {
    const tool = await runSecurityTool(process.execPath, [await resolveNpmCli(), ...npmArgs, 'audit', '--json', '--fetch-timeout=10000', '--fetch-retries=0'], { cwd: root, timeoutMs: 20000 });
    let value; try { value = JSON.parse(tool.stdout.toString()); } catch { fail('ADVISORY_DATABASE_UNAVAILABLE', 503); }
    if (![0, 1].includes(tool.code) || tool.code !== 0 && !value.vulnerabilities) toolFailure('ADVISORY_DATABASE_UNAVAILABLE', tool);
    const result = validateAdvisoryReport(value); await writeFile(join(privateRoot, 'npm-audit.json'), tool.stdout, { mode: 0o600 }); return { ...result, toolExitCode: tool.code, collectedAt: Date.now(), sha256: sha(tool.stdout) };
  });
  const boundReport = async (id, path) => {
    if (!producer || !path) fail('TRUSTED_SCANNER_PRODUCER_REQUIRED', 503);
    const record = producer.reports.find((row) => row.id === id); const bytes = await boundedBytes(resolve(root, path));
    if (!record || record.sha256 !== sha(bytes)) fail('SCANNER_REPORT_BINDING_MISMATCH');
    return JSON.parse(bytes.toString('utf8'));
  };
  await capture('codeql-sast', async () => {
    if (sarif.length !== 2 || new Set(sarif.map((path) => resolve(root, path))).size !== 2) fail('CODEQL_LANGUAGES_REQUIRED', 503);
    const reports = []; for (const [index, language] of ['javascript-typescript', 'python'].entries()) reports.push(validateCodeqlSarif(await boundReport(`codeql-${language}`, sarif[index])));
    return { scanner: 'CodeQL', files: reports.length, findings: reports.reduce((n, report) => n + report.findings, 0), high: reports.reduce((n, report) => n + report.high, 0), accepted: reports.every((report) => report.accepted) };
  });
  let imageEvidence;
  await capture('oci-build-provenance', async () => {
    if (!ociArchive || !buildMetadata || !baseIndex) fail('OCI_BUILD_PROVENANCE_REQUIRED', 503);
    const metadata = await boundedJson(resolve(root, buildMetadata)); const indexBytes = await boundedBytes(resolve(root, baseIndex), { maxBytes: 1048576 });
    const base = validateBaseIndex(JSON.parse(indexBytes.toString()), { rawBytes: indexBytes, platform });
    imageEvidence = await inspectOciArchive(resolve(root, ociArchive), { expectedDigest: metadata['containerimage.digest'], sourceDigest, baseIndexDigest: base.indexDigest, baseManifestDigest: base.manifestDigest, platform });
    return imageEvidence;
  });
  await capture('fresh-image-vulnerabilities', async () => {
    if (!imageReport || !databaseMetadata || !imageEvidence) fail('BUILT_IMAGE_SCAN_REQUIRED', 503);
    if (!producer || producer.imageConfigDigest !== imageEvidence.imageConfigDigest || producer.imageManifestDigest !== imageEvidence.imageManifestDigest) fail('SCANNER_REPORT_BINDING_MISMATCH');
    const value = await boundReport('trivy-image', imageReport); const { validateImagePackageCoverage } = await import('./scanner-evidence.mjs');
    const coverage = validateImagePackageCoverage(value, await boundedJson(resolve(root, 'artifacts/runtime-sbom.cdx.json')));
    return { ...validateTrivyReport(value, await boundReport('trivy-database', databaseMetadata), { expectedConfigDigest: imageEvidence.imageConfigDigest }), coverage };
  });
  await capture('fresh-source-dependency-advisories', async () => {
    if (!sourceDependencyReport || !databaseMetadata) fail('PYTHON_DEPENDENCY_SCAN_REQUIRED', 503);
    const value = await boundReport('trivy-source', sourceDependencyReport);
    const coverage = validateSourceDependencyCoverage(value, await boundedJson(resolve(root, 'package-lock.json')), (await boundedBytes(resolve(root, 'requirements-ci.txt'), { maxBytes: 1048576 })).toString());
    return { ...validateTrivyReport(value, await boundReport('trivy-database', databaseMetadata), { artifactType: 'filesystem' }), coverage, scope: 'entire locked Node graph including dev; hashed CI PKI tool requirements; product Python SDK is stdlib-only' };
  });
  const finalDigest = await implementationDigest(); if (finalDigest !== sourceDigest) checks.push({ name: 'frozen-source', status: 'FAIL', code: 'IMPLEMENTATION_CHANGED' });
  const report = { version: 1, purpose: 'agent-runtime-security-delivery', runId, sourceDigest, startedAt, finishedAt: Date.now(),
    status: checks.some((entry) => entry.status === 'FAIL') ? 'FAIL' : checks.some((entry) => entry.status === 'BLOCKED') ? 'BLOCKED' : 'PASS', checks,
    claims: { productionReady: false, imagePublished: false, historyScanned: checks.find((entry) => entry.name === 'project-history-secrets')?.status === 'PASS', independentBuilderTrust: false } };
  await writePublicSecurityArtifact(root, output, JSON.stringify(report, null, 2) + '\n'); return report;
}
