# Runtime operations and client SDKs

This is a single-host encrypted SQLite product profile. Local backup/restore, signed audit verification and terminal result retention have executable checks. Off-site backup storage, deployed alert routing, Linux containment, disaster failover and externally anchored checkpoints remain separate acceptance requirements.

## Start and client identity

Start a configured gateway/resource with `node scripts/start.mjs --config <gateway.json>`. See [product API](product-api.md) and [deployment instructions](../deploy/README.md). Configuration and keys belong to the operator. An agent receives only its short-lived audience/scoped JWT, client certificate/private key and CA certificate; upstream resource keys, issuer keys and operator identity stay outside the agent.

The Node SDK exports `createProductClient` and `createFileProductClient` from `src/product/client.mjs`. It uses the existing fixed-origin HTTPS transport, verifies the CA/hostname, supports TLS over a Unix-domain socket, rejects redirects, bounds response bytes and time, and never automatically retries a mutation. HTTP 202 or a network error may represent an uncertain effect: use the same operation ID and explicit reconciliation, never generate a new action ID to retry blindly. The file client rereads its JWT on every request so an operator can rotate a short-lived token without restarting the agent. TLS certificate/key changes require a new client instance.

```js
import { createFileProductClient } from './src/product/client.mjs';
const client = createFileProductClient({
  origin: 'https://gateway', socketPath: '/run/runtime/gateway.sock',
  caFile: '/run/identity/ca.pem', certFile: '/run/identity/agent-cert.pem',
  keyFile: '/run/identity/agent-key.pem', tokenFile: '/run/identity/agent.jwt'
});
const response = await client.execute('assigned-task', { id: 'stable-operation-id', kind: 'read', documentId: 'guide' });
```

The narrow Compose runner is `scripts/agent-runner.mjs`. Its configured flags match the SDK identity paths. It reads structured JSONL `{ "taskId": "assigned-task", "action": {...} }` from stdin and writes one result per line; free text and arbitrary shell commands are rejected. Input is bounded and output honors backpressure. Compose keeps stdin open; the process is a transport harness for an agent workload, not a model or an agent that independently invents company tasks. The supplied profile gives it no network interface.

Every JSONL response uses `{status,body}` (successful client responses may also include headers). Invalid JSON, task IDs or action schemas return status 400 before any call. A transport failure after a valid invocation returns status 202 with `body.state:'unknown'`, the original `body.operationId` and `retryAutomatically:false`: a lost response may follow a committed effect. Use that same ID for explicit status/reconciliation; the runner never retries execution automatically.

The Python 3.12+ stdlib SDK is `sdk/python/agent_runtime.py`: `RuntimeClient(origin=..., socket_path=..., ca_file=..., cert_file=..., key_file=..., token_file=...)`, then `.execute(task_id, action)` or `.operation(operation_id)`. It verifies TLS/mTLS and hostnames, rereads JWTs, bounds JSON responses, refuses redirects and never retries mutations. UDS uses `AF_UNIX` and is intended for Linux. Trusted fixed origins are operator configuration; this Python SDK is a client for the gateway, not a broker for arbitrary destinations. OS DNS lookup duration is not strictly bounded by Python's socket timeout; use the supported UDS path for the isolated agent.

## Restricted audit exports and independent verification

`GET /v1/evidence` starts a signed ciphertext audit snapshot. Continue with `POST /v1/evidence` and `{ "after": <manifest.next>, "through": <manifest.checkpoint.sequence>, "limit": 100 }` until `manifest.next` is null. Every page authenticates its purpose, tenant, snapshot checkpoint, range and rows digest using the configured Ed25519 signing key. Pages adapt to a 512 KiB row budget. The authenticated evidence response has a larger bounded limit than ordinary resource JSON. These exports contain identifiers, timestamps and encrypted business audit data: restrict access and retention even though they omit decryption and HMAC keys. Do not publish customer exports as anonymous public evidence.

`verifyAuditEvidence(pages, { publicKey, tenantId, expectedCheckpoint })` in `src/product/evidence.mjs` uses only a pinned public key. It checks signatures, every ciphertext hash and predecessor, exact sequence/range continuity, matching page checkpoints, and the complete final snapshot. Alteration, page reordering, missing pages and wrong keys fail. The optional externally retained checkpoint additionally detects substitution of an older otherwise valid signed snapshot. Without that independent checkpoint the library verifies historical snapshot authenticity and completeness, and returns `externallyPinnedCheckpoint:false`; it cannot establish that the snapshot is newest. Signatures do not establish evaluator honesty, kernel integrity, WORM retention, external timestamps or blockchain anchoring.

Ordinary clients default to 64 KiB responses. Auditors requesting large ciphertext evidence must explicitly construct the Node client with `maxBytes:1048576` or Python client with `max_bytes=1048576`; no agent default is enlarged for this export.

The offline export/verification CLI requires explicit operator files, never keys in argv:

```text
node scripts/operations.mjs audit-export --config gateway.json --tenant company --output new-audit.jsonl
node scripts/operations.mjs audit-verify --input new-audit.jsonl --tenant company --public-key pinned-signing-public.pem --checkpoint independently-retained-checkpoint.json
```

Checkpoint JSON has exactly `{ "tenantId": "company", "sequence": 123, "hash": "<64 lowercase hex>" }`. Keep the pinned public key and accepted checkpoint in a separate trust domain. Copying a checkpoint supplied beside an attacker-controlled export does not create rollback protection. The CLI requires a checkpoint; the library permits historical verification explicitly. Export files are created exclusively with owner-only permissions where Unix permissions apply. Windows ACL behavior needs deployment validation.

## Backup, restore and retention

Stop or isolate administration before offline maintenance. The CLI runs with an explicit product config and its storage keys; it is an operator tool, never mounted in the agent with operator keys. All commands return structured summaries and stable error codes without printing key material.

```text
node scripts/operations.mjs backup --config gateway.json --output new-snapshot.db
node scripts/operations.mjs restore --config gateway.json --tenant company --backup new-snapshot.db --destination new-restored.db --expected-sha256 <independently-pinned-64-hex-hash>
node scripts/operations.mjs retention --config gateway.json --tenant company --before <UTC-epoch-milliseconds>
```

Backups use SQLite's consistent serialized snapshot, an exclusive destination, fsync, a size/hash manifest and encrypted database contents. Restore never overwrites an existing target and the CLI requires an externally pinned backup hash. The adjacent manifest alone is only a consistency check. Keep backup encryption keys recoverable in a separate secret manager; losing them makes recovery impossible. Restore verifies the requested tenant's audit chain and reports measured elapsed time. Move encrypted backups and independently trusted manifests to separately administered off-site storage under the customer's retention policy. That automation and off-site recovery are not established by the local command.

Object expiry deletion authenticates a bounded batch before removal. Terminal gateway operation results can be scrubbed after a retention cutoff; the encrypted action metadata, digest, final state, consumed quotas and operation ID remain as permanent idempotency tombstones. Replaying the operation returns its terminal state with `resultExpired:true`, never a second dispatch. A durable encrypted cursor advances bounded retention batches. Active and unknown effects remain for reconciliation; retention does not silently delete or replay them. Company documents and committed internal mailbox deliveries are business records, separately governed by the company's data policy. Resource journal payload retention must likewise retain provider idempotency tombstones. Audit ciphertext is retained for integrity; no audit pruning or cryptographic erasure of every historical backup is claimed. These retained identifiers, unknown outcomes and customer retention decisions require a privacy policy before deployment.

Running the retention CLI with a resource-role config also scrubs up to 50 provider journal results using the provider's tombstone-preserving `pruneResults`. Its `provider.next` cursor can be passed as `--after <cursor>` on the next invocation; no cursor means start of that bounded provider scan. Gateway journal batches persist their cursor internally. The service periodically invokes both role-appropriate maintenance paths. A2A/memory/model caches have their own explicit retention and must be included in the customer's policy; a gateway result cutoff alone does not prove deletion of all copies or backups.

## Containment receipt renewal

Production business execution fails closed when a signed containment receipt expires (maximum accepted age 15 minutes). A real Linux operator/checker must rerun the live acceptance procedure using the current pinned image/profile and renew the receipt. The fixed public diagnostic is only bootstrap evidence of the protected path. It cannot release company documents. The external containment signing private key stays outside gateway, resource and agent; the same receipt/trust public key is supplied to gateway and resource.

The acceptance CLI creates outputs exclusively, so use a new versioned output for each run. Docker Compose file-backed secrets/bind mounts may retain the old inode after an atomic host rename: do not assume replacing a host filename refreshes a running mount. Update the explicitly reviewed mount inputs and recreate the affected services, then verify both report the renewed receipt before admitting work. This repository does not establish automatic live renewal or uninterrupted deployments. Expiry remains a deliberate safe stop if renewal fails.

## Local checks

```text
python scripts/test-pki.py --flat --output artifacts
node --test --test-isolation=none test/product-operations.test.mjs test/product-client.test.mjs
python sdk/python/test_agent_runtime.py
node scripts/operations-check.mjs --out artifacts/new-product-operations.json
node --test --test-isolation=none test/acceptance-product-socket.mjs
```

The operations check records actual encrypted backup size, backup/restore timing, externally pinned hash validation, signed ciphertext-chain verification, tamper rejection and retention/replay checks. It writes only synthetic summary data. Default Node/Python tests exercise actual TCP mTLS. The separate socket acceptance command requires Linux and exits nonzero elsewhere with `SOCKET_ACCEPTANCE_REQUIRES_LINUX`; it is BLOCKED in this Windows environment, outside the passing default test count and never silently skipped. Windows diagnostic access was intermittent: ten native pipe connections were refused with `EPERM`, while a later individual Windows pipe TLS test passed. Neither establishes Linux UDS, permissions, no-network enforcement or containment. Run the actual acceptance successfully on the supported Linux host before deployment. Python Linux UDS acceptance also remains pending. Child process/container launch acceptance is blocked in the current Windows environment and is never silently replaced by an isolated-runner success.
