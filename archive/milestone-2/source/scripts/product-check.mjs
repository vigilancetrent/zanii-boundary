import { readFile, readdir } from 'node:fs/promises';
import { SourceTextModule } from 'node:vm';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { implementationDigest, implementationManifest } from './benchmark.mjs';

/** Dependency-free syntax and narrowly named forbidden-pattern checks; not a full SAST/type checker. */
export async function checkProductSource() {
  const root = new URL('../', import.meta.url); const paths = (await implementationManifest()).map(([path]) => path).filter((path) => path.endsWith('.mjs'));
  for (const entry of await readdir(new URL('test/', root))) if (entry.endsWith('.mjs')) paths.push(`test/${entry}`);
  const rules = [/\beval\s*\(/, /\bnew\s+Function\s*\(/, /rejectUnauthorized\s*:\s*false/, /\bconsole\.(?:log|debug)\s*\(/, /\bdebugger\s*;/];
  for (const path of paths) {
    const source = await readFile(new URL(path, root), 'utf8');
    new SourceTextModule(source, { identifier: path });
    if (path.startsWith('src/') && rules.some((rule) => rule.test(source))) throw new Error(`Forbidden source pattern: ${path}`);
  }
  return { syntaxModules: paths.length, narrowSourceRules: rules.length, sourceDigest: await implementationDigest(),
    scope: 'ES module parsing plus explicit forbidden patterns. Does not establish type safety, dependency freshness, or absence of vulnerabilities.' };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) throw new Error('Unexpected source-check arguments');
  checkProductSource().then((result) => process.stdout.write(`${JSON.stringify(result)}\n`)).catch((error) => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
