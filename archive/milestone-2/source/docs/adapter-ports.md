# Resource and Zanii adapter ports

These adapters are backend components. Credentials, trusted endpoints, recipient
registries and TLS trust roots belong in operator configuration and separate
resource/broker processes. Agent callers never receive their values.

## HTTPS transport

`createHttpsTransport({origin,tls,allowPrivateNetworks,allowedPaths,allowedMethods,
timeoutMs,connectTimeoutMs,readTimeoutMs,maxBytes,socketPath})` lives in
`src/adapters/transport.mjs`. `tls` accepts trusted `ca`, `cert`, `key` and optional
`servername`; certificate verification cannot be disabled. `origin` must be one
HTTPS origin without credentials or path. Each transport has its own trust root
and network configuration.

- `request(path,{method,headers,body,deadlineAt})` returns
  `{status,headers,body}` with strictly decoded, bounded JSON. Bodies can be JSON,
  strings or byte arrays; binary callers set the appropriate content type.
- `fetch(url,init)` supplies a bounded `Response` to installed Zanii packages.
- Redirects, compressed bodies, host overrides, hop-by-hop headers, foreign
  origins, known metadata IPs and mapped/transition IPv6 destinations are denied.
- Private addressing is denied by default. `allowPrivateNetworks:true` is an
  operator choice for a fixed internal service; agents cannot select destinations.
  DNS is resolved once into validated socket addresses. Connect, read and total
  deadlines are independent; allocation limits apply before JSON parsing.

This is an outbound client restriction. Linux network namespaces and host firewall
rules must additionally contain code that could bypass the client entirely.

## Persistent document provider

`createDocumentService({store,toolVersion,internalRecipients,maxContentBytes,
importRoot,now})` lives in `src/adapters/documents.mjs`. `store` is the encrypted
SQLite product store; plaintext content is limited to 32 KiB and all rows retain
the store's 64 KiB serialized-value cap. Pathologically escaped JSON can reach
that serialized cap before the plaintext cap and is rejected atomically.

| Method | Contract |
|---|---|
| `putDocument(operator,doc)` | Exact document fields: `id,content,label,allowedRecipients`; optional `allowedPurposes`. Role and registry checks precede persistent writes. |
| `metadata(identity,action)` | Policy-compatible trusted document/tenant/label/tool/purpose/recipient metadata. Never accepts actor-supplied labels. |
| `status(identity)` | `resourceId,configurationVersion,toolVersion,healthy,persistence,deliveryChannel,maxContentBytes`. |
| `execute(identity,action,context)` | Context requires `operationId,expectedVersion,deadlineAt`. Validates current metadata and registered destination immediately before the transaction commits. |
| `observe(identity,operationId)` | `{operationId,state:'succeeded',result}` or local `{operationId,state:'absent'}`. Actor ownership is enforced; tenant operator/auditor may inspect. |
| `delivery(identity,deliveryId)` | Reads the actual durable internal mailbox object for its recipient or tenant operator. |
| `importFile(operator,{relativePath,...doc})` | Optional fixed import root; rejects traversal, absolute/drive paths, outside-root realpaths, final symlinks, oversized and invalid UTF-8 files. |

Read results are `{kind:'read',documentId,label,content}`. Share results are
`{kind:'share',documentId,recipient,deliveryId,status:'committed',channel:'internal-mailbox'}`.
This commits an encrypted mailbox object; it does not claim external email delivery.

Document updates and trusted registry/tool configuration changes advance the
configuration version. Reads and deliveries do not. A transaction atomically
commits the effect, unique resource-operation result and audit entry. The same
operation/digest returns its earlier result after restart; conflicting reuse fails.
Trusted maintenance calls `pruneResults(tenantId,{before,limit,after,now})` to scrub
old completed operation payloads while preserving digest/idempotency tombstones.
It returns `{pruned,next}` for bounded paging. A repeated execution or observation
then returns `{operationId,state:'succeeded',resultExpired:true}` without a new
effect. Source documents and recipient mailbox deliveries remain governed records;
this cache-retention port does not delete them.
The authenticated resource HTTP route remains responsible for verifying a narrow,
signed operation grant before invoking this internal provider port.

## Internal REST connector

`createRestAdapter({transport,credentialProvider,paths})` exposes asynchronous
`metadata`, `status`, `execute` and `observe` ports matching the provider.
`credentialProvider(context)` returns a scoped bearer JWT from trusted server
configuration. It receives identity, action/operation/version/deadline and optional
grant details, plus `scope:resource:<method>`. Credentials never enter a response.

| Method | Fixed default route | Body |
|---|---|---|
| metadata | POST `/v1/resource/metadata` | `{action}` |
| status | GET `/v1/resource/status` | none |
| execute | POST `/v1/resource/execute` | `{action,operationId,expectedVersion,deadlineAt,grant?}` |
| observe | POST `/v1/resource/observe` | `{operationId}` |

Paths are trusted constructor settings. Identity is derived by the authenticated
resource route, never from request JSON. Metadata/result/outcome shapes and tenant,
document and destination bindings are checked. Execution makes exactly one
outbound attempt; uncertain mutations require observation instead of blind retry.

## Actual installed Zanii packages

`src/adapters/zanii.mjs` imports `@zanii/broker@0.1.0`, `@zanii/sdk@0.5.4` and
`@zanii/core@0.5.6`. `zaniiCapabilities({requireRuntime})` reports installed versions.
The optional runtime package is unavailable locally; requiring it raises
`ZANII_RUNTIME_UNAVAILABLE`. No substitute runtime is presented as the upstream
package.
An explicit online install of Runtime 0.4.0 obtained metadata but failed fetching
`https://registry.npmjs.org/@zanii/runtime/-/runtime-0.4.0.tgz` with
`ECONNREFUSED 127.0.0.1:9`; no package bytes or lockfile entry were installed.

`createZaniiLedger({store,transport,tenantId,agentDid,agentPrivateKey|signer,
delegation,apiKey,expectedLogDid,maxPending})` exposes:

- `record(identity,SDKfields)`: signs with the actual SDK, persists the exact signed
  receipt and payload nonce in encrypted tenant outbox storage, then explicitly
  flushes. Before every outgoing batch, each receipt must cryptographically verify
  and match its durable tenant row. Non-2xx responses, short acknowledgements,
  wrong hashes and rejected results fail before company credential injection.
- `recover(operator)`: follows pending receipt `prev` links and submits those exact
  stored receipts to the real `/v1/receipts` protocol. It never replays a company
  action. A restarted writer refuses new records until pending rows reconcile.
- `verifyProof(hash)`: runs the actual SDK receipt/STH/Merkle verifier and pins the
  configured `expectedLogDid`. Returns `included:true,anchored:false`; signed log
  inclusion does not establish an external anchor or business success.
- `status()` and `close()`: bounded serialized writer state and timer shutdown.

SDK 0.5.4 has no public dispose operation. This adapter pins exactly that version,
asserts its queue/timer/options layout, disables normal automatic flushing with a
very long interval and a queue threshold above capacity, and cancels its private
timer after each record/flush/error. An unsupported version fails closed. Durable
recovery owns retries. Run one writer instance per configured DID; distributed
multi-writer failover is outside this single-host port.

`createZaniiBroker({credentials,transport,ledger,identity,gate,validateResponse})`
wraps the installed broker. Requests are copied and frozen before async policy
checks. Credential specs allow only bearer/header injection. The installed broker
records before injecting credentials; this wrapper rejects literal configured
secret reflection in response body or headers and strips common secret headers.
Company adapters should additionally supply an exact response schema. Literal
reflection detection does not promise recognition of every possible secret
encoding; the provider and its response contract must be trusted.

`createConfiguredZaniiLedger({store,config,baseDirectory})` provides the service
startup factory. Exact required configuration keys are `origin,caFile,certFile,
keyFile,tenantId,agentDid,agentPrivateKeyFile,delegationFile,apiKeyFile,expectedLogDid`;
optional keys are `requireRuntime,required,allowPrivateNetworks`. File paths resolve
against the supplied base directory. Files are bounded, regular, non-symlink final
paths with inode checks; private files require restrictive POSIX permissions on
Linux. The signing key accepts a 32-byte seed encoded as 64 hex digits or Ed25519
PKCS8 PEM, and its derived DID must match configuration. Runtime requirements fail
before service startup. `required` is a service readiness setting; this factory
always rejects invalid configured integrations.

## Verification and remaining external validation

Run `node --test --test-isolation=none test/product-adapters.test.mjs test/product-zanii.test.mjs`.
Tests use real local CA/mTLS HTTPS, installed SDK/broker/core signing and a signed
Merkle proof fixture. They verify durable-before-upload ordering, restart recovery,
tenant boundaries, deadline/version denial, internal mailbox persistence, malformed
acknowledgements, receipt outages, secret reflection, foreign log identity and
missing runtime failure. The local log fixture proves protocol behavior, not live
Zanii account acceptance or a production company-system deployment. Those require
operator-owned service endpoints, project API credentials, DIDs and delegations.
