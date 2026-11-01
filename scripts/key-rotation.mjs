import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { randomUUID } from 'node:crypto';
import { AppError, identifier } from '../src/protocol.mjs';
import { loadOperationsConfig, readOperationsFile } from '../src/product/operations-config.mjs';
import { openPostgresStore } from '../src/product/postgres-store.mjs';
import { createKeyLifecycle, createRetainedKeyVerifier, createConfiguredSourceFenceVerifier, privacyInventoryDigest } from '../src/product/key-lifecycle.mjs';

export function parseKeyArguments(args) {
  const [command, ...rest] = args; const options = {};
  if (!['freeze', 'drain-status', 'rekey', 'retirement-proof', 'unfreeze', 'release-restore'].includes(command) || rest.length % 2) throw new AppError(400, 'INVALID_KEY_COMMAND');
  for (let index = 0; index < rest.length; index += 2) {
    const name = rest[index].slice(2);
    if (!rest[index].startsWith('--') || !['config', 'key-id', 'limit', 'restore-sha256'].includes(name) || !rest[index + 1] || Object.hasOwn(options, name)) throw new AppError(400, 'INVALID_KEY_ARGUMENTS');
    options[name] = rest[index + 1];
  }
  return { command, options };
}
/** No destructive provider deletion command: a proof is explicitly labelled not retired.
 * @param {any} request */
export async function runKeyRotation({ command, options, signal, storeFactory = openPostgresStore }) {
  if (typeof options.config !== 'string') throw new AppError(400, 'KEY_CONFIGURATION_REQUIRED');
  const { config, material } = await loadOperationsConfig(options.config); let store;
  try {
    if (config.role !== 'rotator' || config.storage.backend !== 'postgres') throw new AppError(400, 'SEPARATE_POSTGRES_ROTATOR_REQUIRED');
    if (command === 'rekey' && (!material.keyring || material.keyring.activeKeyId !== options['key-id'])) throw new AppError(400, 'REKEY_ACTIVE_CODEC_REQUIRED');
    store = await storeFactory({ ...config.storage.postgres, ...material.postgres, realm: config.realm, role: 'rotator',
      encryptionKey: material.encryptionKey, auditKey: material.auditKey, keyring: material.keyring });
    const keys = config.keyVerification ?? {};
    const read = (name) => keys[name] ? readOperationsFile(keys[name], { baseDirectory: material.baseDirectory }) : undefined;
    const lifecycle = createKeyLifecycle({ store, signal, deadlineAt: Date.now() + config.worker.timeoutMs,
      verifyRetainedRecord: createRetainedKeyVerifier({ archivePublicKey: await read('archivePublicKeyFile'), backupPublicKey: await read('backupPublicKeyFile'), realm: config.realm }) });
    const requestId = randomUUID();
    const requested = () => store.appendAudit({ tenantId: 'system', actorId: 'key-rotator', event: 'key.lifecycle.requested', target: config.realm, data: { command, requestId } });
    if (command !== 'rekey') await requested();
    let result;
    if (command === 'freeze') result = await lifecycle.freeze();
    else if (command === 'drain-status') result = await lifecycle.drained();
    else if (command === 'rekey') result = await lifecycle.rotate({ activeKeyId: identifier(options['key-id']), limit: options.limit === undefined ? 100 : Number(options.limit), onActivated: requested });
    else if (command === 'retirement-proof') result = { ...await lifecycle.retirementProof(identifier(options['key-id'])), retired: false, providerDeletion: 'not-requested' };
    else if (command === 'unfreeze') result = await lifecycle.unfreeze();
    else if (command === 'release-restore') {
      const state = await store.restoreStatus(); const epoch = await store.keyEpoch(); const digest = options['restore-sha256'];
      if (!state.quarantined || !/^[a-f0-9]{64}$/.test(digest ?? '') || digest !== state.restoreSha256 || !config.recovery?.fenceVerifier) throw new AppError(409, 'RESTORE_RELEASE_EVIDENCE_REQUIRED');
      const verify = await createConfiguredSourceFenceVerifier(config.recovery.fenceVerifier, { baseDirectory: material.baseDirectory });
      const targetPrivacyDigest = await privacyInventoryDigest({ store, realm: config.realm, deadlineAt: Date.now() + config.worker.timeoutMs });
      const evidence = await verify({ realm: config.realm, restoreSha256: digest, epoch: epoch.version, targetPrivacyDigest });
      if (!evidence.verified) throw new AppError(503, 'SOURCE_FENCE_UNVERIFIED');
      if (await privacyInventoryDigest({ store, realm: config.realm, deadlineAt: Date.now() + config.worker.timeoutMs }) !== targetPrivacyDigest) throw new AppError(409, 'PRIVACY_INVENTORY_CHANGED');
      await store.appendAudit({ tenantId: 'system', actorId: 'key-rotator', event: 'recovery.source-fence.verified', target: config.realm, data: { requestId, evidenceDigest: evidence.evidenceDigest, targetPrivacyDigest } });
      result = await store.releaseRestoreQuarantine({ expectedVersion: epoch.version, expectedRestoreSha256: digest, sourceFenceVerified: true });
    } else throw new AppError(400, 'INVALID_KEY_COMMAND');
    await store.appendAudit({ tenantId: 'system', actorId: 'key-rotator', event: 'key.lifecycle.completed', target: config.realm, data: { command, requestId } });
    return result;
  } finally { await store?.close(); material.encryptionKey?.fill(0); material.auditKey?.fill(0); }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const controller = new AbortController(); const stop = () => controller.abort();
  for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, stop);
  try { process.stdout.write(`${JSON.stringify({ status: 'PASS', result: await runKeyRotation({ ...parseKeyArguments(process.argv.slice(2)), signal: controller.signal }) })}\n`); }
  catch (error) { process.stderr.write(`${JSON.stringify({ status: 'BLOCKED', code: error instanceof AppError ? error.code : 'KEY_LIFECYCLE_FAILED' })}\n`); process.exitCode = 1; }
  finally { for (const signal of ['SIGINT', 'SIGTERM']) process.off(signal, stop); }
}
