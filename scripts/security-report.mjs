import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { AppError } from '../src/protocol.mjs';
import { buildSecurityImage, collectSecurityReport, verifyDeliveryPolicy, scanSecrets, stageSecurityScanInputs } from '../src/product/security-delivery.mjs';
import { produceScannerExecution } from '../src/product/scanner-evidence.mjs';

export function parseSecurityArguments(args) {
  const [command = 'report', ...rest] = args; const options = { sarif: [] };
  if (!['report', 'policy', 'secrets', 'build', 'stage', 'produce'].includes(command) || rest.length % 2) throw new AppError(400, 'INVALID_SECURITY_COMMAND');
  const names = { '--output': 'output', '--sarif': 'sarif', '--image-report': 'imageReport', '--source-dependency-report': 'sourceDependencyReport', '--database-metadata': 'databaseMetadata', '--oci-archive': 'ociArchive', '--build-metadata': 'buildMetadata', '--base-index': 'baseIndex', '--platform': 'platform', '--producer-manifest': 'producerManifest', '--producer-public-key': 'producerPublicKey', '--producer-run-id': 'producerRunId', '--producer-key': 'producerKey', '--codeql': 'codeql', '--codeql-version': 'codeqlVersion' };
  for (let index = 0; index < rest.length; index += 2) {
    const name = names[rest[index]]; const value = rest[index + 1];
    if (!name || !value || name !== 'sarif' && Object.hasOwn(options, name)) throw new AppError(400, 'INVALID_SECURITY_ARGUMENTS');
    if (name === 'sarif') options.sarif.push(value); else options[name] = value;
  }
  const allowed = command === 'report' ? Object.values(names).filter((name) => !['producerKey', 'codeql', 'codeqlVersion'].includes(name)) : command === 'build' ? ['platform'] : command === 'produce' ? ['producerKey', 'producerRunId', 'codeql', 'codeqlVersion', 'platform'] : [];
  if (Object.keys(options).some((name) => name !== 'sarif' && !allowed.includes(name)) || command !== 'report' && options.sarif.length) throw new AppError(400, 'INVALID_SECURITY_ARGUMENTS');
  return { command, options };
}
export async function runSecurityCommand({ command, options }) {
  if (command === 'policy') return { status: 'PASS', result: await verifyDeliveryPolicy() };
  if (command === 'secrets') { const result = await scanSecrets(); return { status: result.accepted ? 'PASS' : 'FAIL', result }; }
  if (command === 'stage') return { status: 'PASS', result: await stageSecurityScanInputs() };
  if (command === 'produce') return { status: 'PASS', result: await produceScannerExecution(options) };
  if (command === 'build') return { status: 'PASS', result: await buildSecurityImage(options) };
  return collectSecurityReport(options);
}
if (import.meta.url === pathToFileURL(resolve(process.argv[1] ?? '')).href) {
  try { const result = await runSecurityCommand(parseSecurityArguments(process.argv.slice(2))); process.stdout.write(JSON.stringify(result) + '\n'); if (result.status !== 'PASS') process.exitCode = 1; }
  catch (error) { process.stderr.write(JSON.stringify({ status: error instanceof AppError && error.status < 500 ? 'FAIL' : 'BLOCKED', code: error instanceof AppError ? error.code : 'SECURITY_DELIVERY_UNAVAILABLE' }) + '\n'); process.exitCode = 1; }
}
