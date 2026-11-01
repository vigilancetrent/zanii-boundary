import { randomUUID } from 'node:crypto';
import { open, realpath, lstat } from 'node:fs/promises';
import { resolve, relative, isAbsolute } from 'node:path';
import { AppError, exactObject, identifier, positiveInteger } from '../protocol.mjs';
import { assertProductIdentity, hashCanonical, validateProductAction } from '../product/policy.mjs';
import { LABELS } from '../product/profiles.mjs';

const denied = (code, status = 403) => { throw new AppError(status, code); };
const ids = (values) => {
  if (!Array.isArray(values) || values.length > 64 || new Set(values).size !== values.length) denied('INVALID_DOCUMENT_METADATA', 400);
  return values.map(identifier);
};

/** Encrypted, tenant-scoped documents and a real internal delivery mailbox.
 * @param {any} options */
export function createDocumentService({ store, toolVersion = 'documents-v1', maxContentBytes = 32768,
  internalRecipients = [], importRoot, now = Date.now } = {}) {
  identifier(toolVersion); positiveInteger(maxContentBytes, 32768);
  const recipients = new Set(ids(internalRecipients));
  const configurationDigest = hashCanonical({ toolVersion, internalRecipients: [...recipients].sort(), maxContentBytes });
  const identityFor = (identity, roles = []) => assertProductIdentity(identity, roles);
  function state(tenant) {
    let value = store.get(tenant, 'metadata', 'document-service');
    if (!value || value.configurationDigest !== configurationDigest) {
      value = { resourceId: value?.resourceId ?? randomUUID(), configurationVersion: (value?.configurationVersion ?? 0) + 1, toolVersion, configurationDigest };
      store.put(tenant, 'metadata', 'document-service', value);
    }
    return { resourceId: value.resourceId, configurationVersion: value.configurationVersion, toolVersion };
  }
  function current(identity, action) {
    identityFor(identity); const validated = validateProductAction(action);
    const document = store.get(identity.tenantId, 'documents', validated.documentId);
    if (!document) denied('DOCUMENT_NOT_FOUND', 404);
    if (validated.toolVersion && validated.toolVersion !== toolVersion) denied('TOOL_VERSION_CHANGED', 409);
    return { action: validated, document };
  }
  function metadata(identity, action) {
    const { action: checked, document } = current(identity, action);
    return { documentId: document.id, tenantId: identity.tenantId, label: document.label, toolVersion,
      allowedRecipients: document.allowedRecipients, allowedPurposes: document.allowedPurposes,
      recipientIsInternal: checked.kind === 'share' ? recipients.has(checked.recipient) : true };
  }
  const service = {
    putDocument(identity, input) {
      identityFor(identity, ['operator']);
      exactObject(input, ['id', 'content', 'label', 'allowedRecipients'], ['allowedPurposes']);
      identifier(input.id);
      if (typeof input.content !== 'string' || Buffer.byteLength(input.content) > maxContentBytes || !LABELS.includes(input.label)) denied('INVALID_DOCUMENT', 400);
      const document = { id: input.id, content: input.content, label: input.label,
        allowedRecipients: ids(input.allowedRecipients), allowedPurposes: ids(input.allowedPurposes ?? []) };
      // Escaped controls can expand sixfold in JSON. Bound the persisted/wire form before accepting data.
      if (Buffer.byteLength(JSON.stringify(document)) > 48000) denied('DOCUMENT_ENCODING_TOO_LARGE', 400);
      if (document.allowedRecipients.some((recipient) => !recipients.has(recipient))) denied('RECIPIENT_NOT_REGISTERED', 400);
      return store.transaction(() => {
        const previous = state(identity.tenantId);
        const next = { ...previous, configurationVersion: previous.configurationVersion + 1, toolVersion };
        store.put(identity.tenantId, 'documents', document.id, document);
        store.put(identity.tenantId, 'metadata', 'document-service', { ...next, configurationDigest });
        store.appendAudit({ tenantId: identity.tenantId, actorId: identity.actorId, event: 'document.put', target: document.id, data: { label: document.label, version: next.configurationVersion } });
        return { documentId: document.id, ...next };
      });
    },
    metadata,
    /** @param {any} identity @param {any} action @param {any} context */
    execute(identity, action, { operationId = action.id, expectedVersion, deadlineAt } = {}) {
      identityFor(identity); identifier(operationId);
      // The authenticated resource route supplies a verified single-action grant.
      // These independent checks still run at the final effect boundary.
      positiveInteger(expectedVersion); positiveInteger(deadlineAt);
      const checked = validateProductAction(action);
      const digest = hashCanonical({ actorId: identity.actorId, tenantId: identity.tenantId, action: checked, expectedVersion });
      return store.transaction(() => {
        const prior = store.get(identity.tenantId, 'resource-operations', operationId);
        if (prior) {
          if (prior.digest !== digest) denied('OPERATION_CONFLICT', 409);
          return prior.resultExpiredAt ? { operationId, state: prior.state, resultExpired: true } : structuredClone(prior.result);
        }
        if (deadlineAt <= now()) denied('RESOURCE_GRANT_EXPIRED');
        if (state(identity.tenantId).configurationVersion !== expectedVersion) denied('RESOURCE_VERSION_CHANGED', 409);
        const { document } = current(identity, checked);
        let result;
        if (checked.kind === 'share') {
          if (!recipients.has(checked.recipient) || !document.allowedRecipients.includes(checked.recipient)) denied('RECIPIENT_DENIED');
          const delivery = { operationId, documentId: document.id, recipient: checked.recipient, label: document.label,
            content: document.content, actorId: identity.actorId, committedAt: now() };
          store.put(identity.tenantId, 'deliveries', operationId, delivery);
          result = { kind: 'share', documentId: document.id, recipient: checked.recipient, deliveryId: operationId,
            status: 'committed', channel: 'internal-mailbox' };
        } else result = { kind: 'read', documentId: document.id, label: document.label, content: document.content };
        store.put(identity.tenantId, 'resource-operations', operationId, { digest, actorId: identity.actorId, state: 'succeeded', result, completedAt: now() });
        store.appendAudit({ tenantId: identity.tenantId, actorId: identity.actorId, event: `document.${checked.kind}`, target: operationId,
          data: { documentId: document.id, ...(checked.recipient ? { recipient: checked.recipient } : {}) } });
        return result;
      });
    },
    observe(identity, operationId) {
      identityFor(identity); identifier(operationId);
      const operation = store.get(identity.tenantId, 'resource-operations', operationId);
      if (operation && operation.actorId !== identity.actorId && !identity.roles.includes('operator') && !identity.roles.includes('auditor')) denied('OPERATION_DENIED');
      return operation ? { operationId, state: operation.state, ...(operation.resultExpiredAt ? { resultExpired: true } : { result: operation.result }) } : { operationId, state: 'absent' };
    },
    // Trusted maintenance port. Tombstones retain the unique effect identity;
    // deleting them would make a repeated operation dispatch again.
    pruneResults(tenantId, { before, limit = 50, after = '', now: at = Date.now() }) {
      identifier(tenantId); positiveInteger(before); positiveInteger(at); positiveInteger(limit, 100);
      if (before > at) denied('INVALID_RETENTION_BOUNDARY', 400);
      return store.transaction(() => {
        const page = store.list(tenantId, 'resource-operations', { limit, after }); let pruned = 0;
        for (const { id, value } of page.items) {
          if (value.state === 'succeeded' && value.completedAt <= before && !value.resultExpiredAt) {
            store.put(tenantId, 'resource-operations', id, { ...value, result: null, resultExpiredAt: at }); pruned++;
          }
        }
        return { pruned, next: page.next };
      });
    },
    delivery(identity, deliveryId) {
      identityFor(identity); identifier(deliveryId);
      const delivery = store.get(identity.tenantId, 'deliveries', deliveryId);
      if (!delivery || delivery.recipient !== identity.actorId && !identity.roles.includes('operator')) denied('DELIVERY_DENIED');
      return delivery;
    },
    status(identity) {
      identityFor(identity);
      return { ...state(identity.tenantId), healthy: true, persistence: 'encrypted-sqlite', deliveryChannel: 'internal-mailbox', maxContentBytes };
    },
    async importFile(identity, { relativePath, ...document }) {
      identityFor(identity, ['operator']);
      if (!importRoot || typeof relativePath !== 'string' || isAbsolute(relativePath) || relativePath.includes('..') || relativePath.includes(':')) denied('IMPORT_PATH_DENIED');
      const root = await realpath(importRoot); const candidate = resolve(root, relativePath);
      const actual = await realpath(candidate); const subpath = relative(root, actual);
      if (!subpath || subpath.startsWith('..') || isAbsolute(subpath) || (await lstat(candidate)).isSymbolicLink()) denied('IMPORT_PATH_DENIED');
      const handle = await open(actual, 'r');
      try {
        if (!(await handle.stat()).isFile() || (await handle.stat()).size > maxContentBytes) denied('IMPORT_TOO_LARGE', 413);
        const bytes = Buffer.alloc(maxContentBytes + 1); const { bytesRead } = await handle.read(bytes);
        if (bytesRead > maxContentBytes) denied('IMPORT_TOO_LARGE', 413);
        let content; try { content = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(0, bytesRead)); } catch { denied('IMPORT_INVALID_UTF8', 400); }
        return service.putDocument(identity, { ...document, content });
      } finally { await handle.close(); }
    },
  };
  return Object.freeze(service);
}
