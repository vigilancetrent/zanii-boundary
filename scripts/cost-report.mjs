import { mkdir, lstat, writeFile, rename, rm } from 'node:fs/promises';
import { resolve, dirname, relative } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { AppError } from '../src/protocol.mjs';
import { readOperationsFile } from '../src/product/operations-config.mjs';
import { readDistributedDeploymentFiles } from '../src/product/distributed-deployment.mjs';
import { estimateCost, deploymentCostInventory, capacityCostObservations, COST_COMPONENTS } from '../src/product/cost-report.mjs';
import { implementationDigest } from './benchmark.mjs';

const configSchema = z.object({ version: z.literal(1), currency: z.string().regex(/^[A-Z]{3}$/), minorDigits: z.number().int().min(0).max(6),
  requiredComponents: z.array(z.enum(COST_COMPONENTS)).min(1).max(8), quotesFile: z.string().min(1).max(4096).nullable(), usageFile: z.string().min(1).max(4096).nullable(),
  budgetFile: z.string().min(1).max(4096).nullable(), capacityFile: z.string().min(1).max(4096).nullable(),
  maxQuoteAgeMs: z.number().int().min(1000).max(31622400000).default(2678400000), maxUsageAgeMs: z.number().int().min(1000).max(31622400000).default(86400000) }).strict();
const fail = (code) => { throw new AppError(400, code); };
export function parseCostArguments(args) {
  const values = {};
  if (args.length < 2 || args.length % 2) fail('COST_CONFIG_REQUIRED');
  for (let index = 0; index < args.length; index += 2) { const name = args[index]; if (!['--config', '--out'].includes(name) || values[name] || !args[index + 1]) fail('INVALID_COST_ARGUMENTS'); values[name] = args[index + 1]; }
  if (!values['--config']) fail('COST_CONFIG_REQUIRED'); return values;
}
async function readJson(path, secret = false) { try { return JSON.parse(await readOperationsFile(path, { secret, maxBytes: 1048576 })); } catch (error) { if (error instanceof AppError) throw error; fail('INVALID_COST_JSON'); } }
/** @param {any} args */
export async function runCostReport(args) {
  const configPath = resolve(args['--config']); const directory = dirname(configPath); const config = configSchema.parse(await readJson(configPath));
  const sourceDigest = await implementationDigest(); const deployment = await readDistributedDeploymentFiles();
  const quotes = config.quotesFile ? await readJson(resolve(directory, config.quotesFile), true) : [];
  const usage = config.usageFile ? await readJson(resolve(directory, config.usageFile)) : null;
  const billingObservation = config.budgetFile ? await readJson(resolve(directory, config.budgetFile), true) : null;
  /** @type {any} */ const report = estimateCost({ version: 1, sourceDigest, currency: config.currency, minorDigits: config.minorDigits, requiredComponents: config.requiredComponents,
    quotes, usage, maxQuoteAgeMs: config.maxQuoteAgeMs, maxUsageAgeMs: config.maxUsageAgeMs }, { billingObservation });
  report.deploymentInventory = deploymentCostInventory(deployment.profile, deployment.compose);
  if (config.capacityFile) {
    const { boundedBytes } = await import('../src/product/security-delivery.mjs'); const bytes = await boundedBytes(resolve(directory, config.capacityFile), { maxBytes: 33554432 });
    report.capacityObservations = { ...capacityCostObservations(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), { sourceDigest }), evidenceDigest: createHash('sha256').update(bytes).digest('hex') };
  }
  if (await implementationDigest() !== sourceDigest) throw new AppError(409, 'IMPLEMENTATION_CHANGED');
  if (args['--out']) {
    const output = resolve(args['--out']); const privateRoot = resolve('artifacts/private/cost'); const path = relative(privateRoot, output);
    if (!path || path.startsWith('..') || !/^[A-Za-z0-9_.-]+\.json$/.test(path)) fail('PRIVATE_COST_OUTPUT_REQUIRED');
    await mkdir(privateRoot, { recursive: true, mode: 0o700 });
    for (const check of [resolve('artifacts'), resolve('artifacts/private'), privateRoot]) { const stat = await lstat(check); if (!stat.isDirectory() || stat.isSymbolicLink()) fail('UNSAFE_COST_OUTPUT'); }
    const temporary = resolve(privateRoot, `.cost-${randomUUID()}.pending`);
    try { await writeFile(temporary, JSON.stringify(report, null, 2) + '\n', { flag: 'wx', mode: 0o600 }); await rename(temporary, output); } finally { await rm(temporary, { force: true }); }
  }
  return report;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { const report = await runCostReport(parseCostArguments(process.argv.slice(2))); process.stdout.write(JSON.stringify(report) + '\n'); if (report.status !== 'ESTIMATED') process.exitCode = 2; }
  catch (error) { process.stderr.write(JSON.stringify({ status: 'BLOCKED', code: error instanceof AppError ? error.code : 'COST_INPUT_UNAVAILABLE', totalMinor: null }) + '\n'); process.exitCode = 2; }
}
