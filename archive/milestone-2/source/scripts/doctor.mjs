import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { AppError } from '../src/protocol.mjs';
import { deploymentDoctor } from '../src/product/deployment.mjs';

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  (async () => {
    if (args.length > 1 || (args.length === 1 && args[0] !== '--static')) throw new AppError(400, 'INVALID_ARGUMENTS');
    const result = await deploymentDoctor({ staticOnly: args[0] === '--static' });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (!args.includes('--static') && !result.liveVerified) process.exitCode = 2;
  })().catch((error) => { process.stderr.write(`${JSON.stringify({ status: 'blocked', code: error instanceof AppError ? error.code : 'DOCTOR_FAILED' })}\n`); process.exitCode = 2; });
}
