import { open, lstat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { AppError } from '../protocol.mjs';

const fail = () => { throw new AppError(400, 'INVALID_OCI_EVIDENCE'); };
const hex = (text) => typeof text === 'string' && /^[a-f\d]{64}$/.test(text);
const text = (bytes) => bytes.toString('utf8').replace(/\0.*$/s, '');
const json = (bytes) => { try { const value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); if (!value || typeof value !== 'object' || Array.isArray(value)) fail(); return value; } catch { fail(); } };

/** Reads a standard uncompressed OCI tar without extracting paths, links or layer contents.
 * Every blob is hashed, including binary layers; only bounded JSON is retained in memory.
 * @param {string} path @param {any} options */
export async function inspectOciArchive(path, { expectedDigest, sourceDigest, baseIndexDigest, baseManifestDigest, platform = 'linux/amd64', maxArchiveBytes = 1073741824, timeoutMs = 120000, deadlineAt } = {}) {
  if (![expectedDigest, baseIndexDigest, baseManifestDigest].every((value) => /^sha256:[a-f\d]{64}$/.test(value ?? '')) || !hex(sourceDigest)
      || !['linux/amd64', 'linux/arm64'].includes(platform) || !Number.isSafeInteger(maxArchiveBytes) || maxArchiveBytes < 1024 || maxArchiveBytes > 2147483648
      || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 300000 || deadlineAt !== undefined && !Number.isSafeInteger(deadlineAt)) fail();
  const deadline = Math.min(Date.now() + timeoutMs, deadlineAt ?? Infinity);
  const assertTime = () => { if (Date.now() >= deadline) throw new AppError(503, 'OCI_EVIDENCE_DEADLINE'); };
  assertTime();
  const stat = await lstat(path); if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxArchiveBytes || stat.size % 512) fail();
  const file = await open(path, 'r'); const archiveHash = createHash('sha256'); let position = 0; let capturedBytes = 0;
  const entries = new Map(); let terminated = false;
  const read = async (length) => {
    assertTime(); const output = Buffer.alloc(length); let offset = 0;
    while (offset < length) { const part = await file.read(output, offset, length - offset, position + offset); assertTime(); if (!part.bytesRead) fail(); offset += part.bytesRead; }
    position += length; archiveHash.update(output); return output;
  };
  try {
    const actual = await file.stat(); if (actual.dev !== stat.dev || actual.ino !== stat.ino || actual.size !== stat.size) fail();
    while (position < stat.size) {
      const header = await read(512);
      if (header.every((byte) => byte === 0)) {
        if (stat.size - position < 512) fail();
        while (position < stat.size) if (!(await read(Math.min(65536, stat.size - position))).every((byte) => byte === 0)) fail();
        terminated = true; break;
      }
      let checksum = 0; for (let index = 0; index < 512; index++) checksum += index >= 148 && index < 156 ? 32 : header[index];
      const declaredChecksum = Number.parseInt(text(header.subarray(148, 156)).trim(), 8);
      const sizeText = text(header.subarray(124, 136)).trim(); const size = /^[0-7]+$/.test(sizeText) ? Number.parseInt(sizeText, 8) : NaN;
      let name = [text(header.subarray(345, 500)), text(header.subarray(0, 100))].filter(Boolean).join('/').replace(/^\.\//, '');
      const type = header[156]; const directory = type === 53;
      if (directory) name = name.replace(/\/$/, '');
      if (checksum !== declaredChecksum || !Number.isSafeInteger(size) || size < 0 || size > stat.size - position || ![0, 48, 53].includes(type) || entries.size >= 10000
          || !/^(?:oci-layout|index\.json|blobs\/?|blobs\/sha256\/?|blobs\/sha256\/[a-f\d]{64})$/.test(name) || entries.has(name)) fail();
      if (directory && size !== 0) fail();
      const hash = createHash('sha256'); const chunks = []; let remaining = size; let capture = size <= 16 * 1024 * 1024;
      while (remaining) { const bytes = await read(Math.min(65536, remaining)); hash.update(bytes); remaining -= bytes.length; if (capture) chunks.push(bytes); }
      const valueDigest = `sha256:${hash.digest('hex')}`;
      if (name.startsWith('blobs/sha256/') && valueDigest !== `sha256:${name.slice('blobs/sha256/'.length)}`) fail();
      let bytes = capture ? Buffer.concat(chunks) : null;
      if (bytes && !['index.json', 'oci-layout'].includes(name) && !/^\s*[\[{]/.test(bytes.subarray(0, 32).toString('utf8'))) bytes = null;
      capturedBytes += bytes?.length ?? 0; if (capturedBytes > 32 * 1024 * 1024) fail();
      entries.set(name, { size, digest: valueDigest, bytes });
      const padding = (512 - size % 512) % 512; if (padding && !(await read(padding)).every((byte) => byte === 0)) fail();
    }
    if (!terminated || !entries.get('index.json')?.bytes || !entries.get('oci-layout')?.bytes || json(entries.get('oci-layout').bytes).imageLayoutVersion !== '1.0.0') fail();
  } finally { await file.close(); }
  const root = entries.get('index.json'); const index = json(root.bytes);
  if (index.schemaVersion !== 2 || !Array.isArray(index.manifests) || !index.manifests.length) fail();
  const visited = new Set([root.digest]); const images = []; const statements = [];
  function descriptor(value) {
    if (!/^sha256:[a-f\d]{64}$/.test(value?.digest ?? '') || !Number.isSafeInteger(value.size) || value.size < 0) fail();
    const entry = entries.get(`blobs/sha256/${value.digest.slice(7)}`); if (!entry || entry.size !== value.size) fail(); return entry;
  }
  function visit(value) {
    assertTime();
    const entry = descriptor(value); if (visited.has(value.digest)) return; visited.add(value.digest); if (visited.size > 256 || !entry.bytes) fail();
    const manifest = json(entry.bytes);
    if (manifest.schemaVersion !== 2) fail();
    if (Array.isArray(manifest.manifests)) { for (const child of manifest.manifests) visit(child); return; }
    if (!manifest.config || !Array.isArray(manifest.layers)) fail();
    const configBytes = descriptor(manifest.config).bytes; if (!configBytes) fail(); const config = json(configBytes);
    if (`${config.os}/${config.architecture}` === platform) images.push({ digest: value.digest, configDigest: manifest.config.digest, config });
    for (const layer of manifest.layers) {
      const data = descriptor(layer);
      if (layer.mediaType === 'application/vnd.in-toto+json') { if (!data.bytes) fail(); statements.push(json(data.bytes)); }
    }
  }
  for (const value of index.manifests) visit(value);
  if (!visited.has(expectedDigest) || images.length !== 1) fail();
  const image = images[0]; if (image.config.config?.Labels?.['ai.zinii.source-digest'] !== sourceDigest) fail();
  const provenance = statements.filter((statement) => ['https://slsa.dev/provenance/v0.2', 'https://slsa.dev/provenance/v1'].includes(statement.predicateType)
    && ['https://in-toto.io/Statement/v0.1', 'https://in-toto.io/Statement/v1'].includes(statement._type)
    && Array.isArray(statement.subject) && statement.subject.some((subject) => `sha256:${subject.digest?.sha256}` === image.digest));
  if (provenance.length !== 1) fail();
  const predicate = provenance[0].predicate; if (!predicate || typeof predicate !== 'object') fail(); const materials = predicate.materials ?? predicate.buildDefinition?.resolvedDependencies;
  if (!Array.isArray(materials) || !materials.some((material) => typeof material.uri === 'string' && material.uri.startsWith('pkg:docker/')
      && [baseIndexDigest, baseManifestDigest].includes(`sha256:${material.digest?.sha256}`))) fail();
  assertTime(); return { verified: true, archiveSha256: archiveHash.digest('hex'), buildDigest: expectedDigest, imageManifestDigest: image.digest,
    imageConfigDigest: image.configDigest, platform, sourceDigest, baseIndexDigest, baseManifestDigest,
    provenanceType: provenance[0].predicateType, attestationsBoundToImage: true, independentlyTrustedBuilder: false };
}
