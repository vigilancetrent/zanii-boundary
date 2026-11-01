import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { implementationManifest } from './benchmark.mjs';

// RUNTIME_TOOLING_ROOT is an explicit development-only installation path, never a runtime dependency.
const root = resolve(process.env.RUNTIME_TOOLING_ROOT ?? 'node_modules');
const selected = process.argv.slice(2);
if (selected.length !== 1 || !['lint', 'typecheck'].includes(selected[0])) throw new Error('Expected lint or typecheck');
try {
  if (selected[0] === 'lint') {
    const { ESLint } = await import(pathToFileURL(resolve(root, 'eslint/lib/api.js')).href);
    const engine = new ESLint({ overrideConfigFile: true, overrideConfig: { rules: { 'no-unused-vars': 'error', 'no-eval': 'error', 'no-debugger': 'error' } } });
    const results = await engine.lintFiles(['src/**/*.mjs', 'scripts/**/*.mjs']);
    const errors = results.reduce((sum, row) => sum + row.errorCount, 0); const warnings = results.reduce((sum, row) => sum + row.warningCount, 0);
    process.stdout.write(`${JSON.stringify({ check: 'basic-eslint', files: results.length, errors, warnings })}\n`);
    if (errors || warnings) { process.stderr.write(await (await engine.loadFormatter('stylish')).format(results)); process.exitCode = 1; }
  } else {
    const { default: ts } = await import(pathToFileURL(resolve(root, 'typescript/lib/typescript.js')).href);
    const paths = (await implementationManifest()).map(([path]) => path).filter((path) => path.endsWith('.mjs'));
    const program = ts.createProgram(paths, { noEmit: true, allowJs: true, checkJs: true, noImplicitAny: false, strictNullChecks: false,
      target: ts.ScriptTarget.ES2023, module: ts.ModuleKind.NodeNext, moduleResolution: ts.ModuleResolutionKind.NodeNext,
      types: ['node'], typeRoots: [resolve(root, '@types')], skipLibCheck: true });
    const diagnostics = ts.getPreEmitDiagnostics(program);
    process.stdout.write(`${JSON.stringify({ check: 'non-strict-checkJs', files: paths.length, diagnostics: diagnostics.length })}\n`);
    if (diagnostics.length) { process.stderr.write(ts.formatDiagnosticsWithColorAndContext(diagnostics, { getCanonicalFileName: (file) => file, getCurrentDirectory: () => process.cwd(), getNewLine: () => '\n' })); process.exitCode = 1; }
  }
} catch { process.stderr.write('PRODUCT_DEVELOPMENT_TOOLING_UNAVAILABLE\n'); process.exitCode = 1; }
