import { closeSync, fsyncSync, openSync, writeSync } from 'node:fs';
import { createInterface } from 'node:readline';
import { createReadStream } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadProductConfig } from '../src/product/config.mjs';
import { openStore, restoreStore } from '../src/product/store.mjs';
import { createAuditEvidencePage, verifyAuditEvidence } from '../src/product/evidence.mjs';
import { readIdentityFile } from '../src/product/client.mjs';
import { AppError } from '../src/protocol.mjs';
import { createDocumentService } from '../src/adapters/documents.mjs';

export function parseOperationsArguments(args) {
  const [command, ...rest] = args; const allowed = new Set(['config', 'tenant', 'output', 'backup', 'destination', 'expected-sha256', 'public-key', 'input', 'before', 'checkpoint', 'after']);
  if (!['backup', 'restore', 'audit-export', 'audit-verify', 'retention'].includes(command)) throw new Error('INVALID_OPERATIONS_COMMAND');
  const options = {};
  for (let i = 0; i < rest.length; i += 2) {
    const name = rest[i].slice(2);
    if (!rest[i].startsWith('--') || !allowed.has(name) || !rest[i + 1] || options[name]) throw new Error('INVALID_OPERATIONS_ARGUMENTS');
    options[name] = rest[i + 1];
  }
  return { command, options };
}

export async function runOperations({ command, options }) {
  const required = (name) => { if (!options[name]) throw new Error('MISSING_OPERATIONS_ARGUMENT'); return options[name]; };
  if (command === 'audit-verify') {
    // Lines are bounded before JSON parsing; total export is bounded by the product DB ceiling.
    const input = createReadStream(required('input'), { highWaterMark: 65536 });
    let pending = 0;
    input.on('data', (chunk) => {
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      let start = 0; let newline;
      while ((newline = bytes.indexOf(10, start)) !== -1) {
        pending += newline - start;
        if (pending > 1048576) { input.destroy(new AppError(413, 'EVIDENCE_LINE_TOO_LARGE')); return; }
        pending = 0; start = newline + 1;
      }
      pending += bytes.length - start;
      if (pending > 1048576) input.destroy(new AppError(413, 'EVIDENCE_LINE_TOO_LARGE'));
    });
    const lines = createInterface({ input, crlfDelay: Infinity }); const pages = []; let total = 0;
    for await (const line of lines) {
      total += Buffer.byteLength(line);
      if (Buffer.byteLength(line) > 1048576 || total > 256 * 1024 * 1024) { input.destroy(); throw new Error('EVIDENCE_TOO_LARGE'); }
      pages.push(JSON.parse(line));
    }
    const expectedCheckpoint = JSON.parse(readIdentityFile(required('checkpoint'), { maxBytes: 4096 }));
    return verifyAuditEvidence(pages, { publicKey: readIdentityFile(required('public-key')), tenantId: required('tenant'), expectedCheckpoint });
  }
  const { config, material } = await loadProductConfig(required('config'));
  const keys = { encryptionKey: material.encryptionKey, auditKey: material.auditKey };
  if (command === 'restore') {
    const expectedSha256 = required('expected-sha256');
    if (!/^[a-f\d]{64}$/.test(expectedSha256)) throw new Error('INVALID_EXPECTED_BACKUP_HASH');
    const start = performance.now();
    const restored = restoreStore({ backupPath: required('backup'), path: required('destination'), ...keys, expectedSha256 });
    try { return { restored: true, audit: restored.verifyAudit(required('tenant')), elapsedMs: performance.now() - start }; }
    finally { restored.close(); }
  }
  const store = openStore({ path: config.storage.path, ...keys });
  try {
    if (command === 'backup') return store.backup(required('output'));
    if (command === 'retention') {
      const before = Number(required('before')); if (!Number.isSafeInteger(before) || before <= 0) throw new Error('INVALID_RETENTION_CUTOFF');
      return { objectsRemoved: store.purgeExpired(Date.now(), { limit: 100 }),
        operations: store.pruneOperationResults(required('tenant'), { before, limit: 100 }),
        ...(config.role === 'resource' ? { provider: createDocumentService({ store }).pruneResults(required('tenant'), { before, limit: 50, after: options.after ?? '' }) } : {}) };
    }
    const fd = openSync(required('output'), 'wx', 0o600); let after = 0; let through; let pages = 0;
    try {
      do {
        const page = createAuditEvidencePage({ store, tenantId: required('tenant'), signingKey: material.signingKey, after, through });
        through ??= page.manifest.checkpoint.sequence;
        const bytes = Buffer.from(`${JSON.stringify(page)}\n`); let offset = 0;
        while (offset < bytes.length) offset += writeSync(fd, bytes, offset);
        pages += 1; after = page.manifest.next;
      } while (after !== null);
      fsyncSync(fd);
    } finally { closeSync(fd); }
    return { exported: true, pages, sequence: through, encrypted: true };
  } finally { store.close(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { process.stdout.write(`${JSON.stringify(await runOperations(parseOperationsArguments(process.argv.slice(2))))}\n`); }
  catch (error) { process.stderr.write(`${JSON.stringify({ code: error instanceof AppError ? error.code : 'OPERATIONS_FAILED' })}\n`); process.exitCode = 1; }
}
