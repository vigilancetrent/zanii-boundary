# Product protocol and companion integrations

The adapters implement protocol handlers and company API clients. Every business action calls the same central executor with an authenticated identity supplied by the HTTP service. Protocol arguments cannot select a tenant, assign a role, supply credentials, introduce an upstream URL or create a task grant.

## MCP

`createMcpAdapter({execute, allowedOrigins, now?, maxSessions?})` from `src/adapters/mcp.mjs` exposes `handle({method,headers,body}, identity)`. The response is `{status,headers?,body?}`. An absent body means an empty response; `notifications/initialized` returns empty HTTP 202.

The supported version is **2025-11-25**, with Streamable HTTP JSON response mode. Clients initialize, retain `Mcp-Session-Id`, send `notifications/initialized`, and supply the negotiated `MCP-Protocol-Version` on subsequent requests. POST requires `Accept: application/json, text/event-stream` and JSON content type. An Origin, when present, must exactly match the configured allowlist. Sessions are short lived, bounded and bound to the authenticated tenant and actor. Restart invalidates sessions; clients initialize again. GET and DELETE return 405. The adapter does not advertise SSE subscriptions, resources, prompts or tool-list changes.

The two tools are `document_read` and `document_share`. Their exact JSON schemas expose task ID, idempotent action ID, document ID, optional version/approval/source references, and a recipient for sharing. The executor receives `execute(identity,{taskId,action})`; denial becomes an MCP tool error with a bounded error code. HTTP authentication runs before this adapter. A session identifier never substitutes for authentication.

Contract references: [MCP lifecycle](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle), [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports), [tools](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).

## A2A

`createA2aAdapter({store,execute,cancel?,readOperation?,publicUrl,now?})` from `src/adapters/a2a.mjs` exposes `handle({method,headers?,body},identity)` and `agentCard()`. Mount the card at `/.well-known/agent-card.json` and JSON-RPC at the configured HTTPS URL. The implementation pins the archived **0.3.0** contract; it does not claim the current protocol version.

Supported methods are `message/send`, `tasks/get`, and `tasks/cancel`. Send a user Message with exactly one structured DataPart:

```json
{"jsonrpc":"2.0","id":"1","method":"message/send","params":{"message":{"kind":"message","role":"user","messageId":"message-1","parts":[{"kind":"data","data":{"taskId":"task-1","action":{"id":"operation-1","kind":"read","documentId":"guide"}}}]}}}
```

Free text and unknown authority fields cannot become actions. Streaming, push notifications, message history, custom metadata and additional message parts are unsupported. History length, when supplied, must be zero. The AgentCard advertises the supported capabilities and the gateway bearer JWT requirement; deployment also enforces sender binding through the gateway.

Tasks are encrypted in the durable store's `a2a` namespace, isolated by tenant and actor. HTTP 202 and unknown/dispatched operations remain `working`. `readOperation(identity,operationId)` may obtain an independently observed completion. Exceptions after starting execution preserve uncertainty. Cancellation needs the injected executor to return `{status:'canceled',dispatched:false}` or `{canceled:true,dispatched:false}`; a Boolean response or an operation already dispatched/committed cannot establish safe cancellation. Task lookup/cancellation use the standard task-not-found and task-not-cancelable errors.

Contract reference: [A2A 0.3.0 specification](https://a2a-protocol.org/v0.3.0/specification/).

## Companion clients

All clients require a fixed operator-configured HTTPS `origin`. Defaults use `createHttpsTransport`, refuse redirects, verify TLS, bound requests/responses and time, and restrict paths. Private networks require explicit trusted deployment configuration. Cookies, CSRF material, viewer access tokens and signing keys come only from operator-provisioned credential providers. They are never accepted in agent tool arguments or returned as response headers. Session expiry denies dispatch before sending a request. No client logs in, bypasses MFA, or reuses an assistant's existing credentials.

`createConfiguredCompanions({agentRoot,register?,passport?,vault?})` from `src/adapters/companions.mjs` assembles the actual clients. Per-service configuration accepts `origin`, optional `caFile`, paired `certificateFile`/`keyFile`, `allowPrivateNetworks`, `tenantId` and `required`. Register/Vault optionally accept `credentialFile`; Passport accepts `viewerCredentialFile` and `workloadCredentialFile`. Unknown configuration fields are rejected. Private TLS keys and session files must stay outside the agent root. The returned bundle exposes the configured clients and `status()`; a required integration stays unready until a route has actually passed live validation.

`credentialFileProvider({path,agentRoot})`, exported by `register.mjs`, reads an explicit bounded credential JSON file outside the agent root and rejects expired credentials. On Unix it requires a regular owner-only file. Mount credentials only into the trusted gateway, never into the agent container. Credential providers may instead read an existing company secrets manager; the callback is part of trusted bootstrap configuration.

| Client | Methods | Actual authentication and meaning |
| --- | --- | --- |
| `createRegisterClient({origin,tls?,allowPrivateNetworks?,tenantId?,credentials?})` | `verifyRegistration({registrationId,recordVersion,canonicalRecordHash,projectionHash?})`, `getRegistration(id)` | Public verification binds the version/hash and checks freshness. Protected GET uses the `register_access` cookie. Assurance is self declared and always returns `dispatchPermit:false`. |
| `createPassportClient({origin,tls?,allowPrivateNetworks?,tenantId?,viewerCredentials?,workloadCredentials?})` | `challenge({audience,requestDigest,expectedPassportId?})`, `verify({tenantId,challengeId,passport})`, `executeDirectoryRead({tenantId,passportId,entryId,operationId,expiresAt})` | Challenge creation uses the provisioned viewer Bearer token. Public verification must return `dispatchPermit:false`. PEP execution uses an EdDSA DPoP JWT bound to method, exact URL, passport and the exact raw request body digest. HTTP 200 requires a committed, independently verified executor outcome; 202 remains pending. |
| `createVaultClient({origin,tls?,allowPrivateNetworks?,tenantId?,credentials})` | `createCase`, `getCase`, `declareUpload`, `putChunk`, `completeUpload`, `uploadEvidence` | Uses `vault_session`; writes require `X-CSRF-Token` and Origin. Upload declares size/provenance/time/acquisition, sends hashed binary chunks, then completes with the final hash. The returned pending scan state is preserved. |

Register/Vault credential callbacks return `{session,expiresAt}`; Vault writes additionally require `csrfToken`. Passport viewer credentials return `{accessToken,expiresAt}` and workload credentials return `{privateKey,publicJwk,expiresAt}`. The workload private key is a Node Ed25519 KeyObject or private JWK; file providers can return private JWKs. Public JWKs must exclude private key material. Viewer DPoP tokens requiring sender binding need an explicitly compatible company credential provider; this initial viewer method supports Bearer tokens accepted by the actual viewer route and fails if that deployment requires another scheme.

The Passport wire proof follows `02-difc-agent-passport/src/server/modules/enforcement/workload.ts`, using the installed JOSE library. It does not claim Mandate SDK integration. Source contracts are `01-difc-ai-agent-register/apps/api/src/projections/{projection.controller,projection.service,projection.types}.ts`, `02-difc-agent-passport/src/server/modules/{verification,enforcement}/`, and `03-difc-evidence-vault/apps/api/src/routes/{cases,evidence}.ts` plus `http.ts`. No companion source is modified.

Vault's convenience upload is bounded to 16 MiB, with 32 KiB maximum chunks. It can retry the same declared upload/chunks with its stable idempotency key, but never silently opens a duplicate case. Source metadata describes observation provenance; it does not assert that an incident is complete or that evidence has passed scanning. Preserve the case ID before uploading so a partial workflow can resume.

## Evidence and external acceptance

`capabilities()` reports configuration and validation status; `validateLive()` without input only reports state. Register can validate a configured verification query, Vault can validate an existing case ID, and Passport can validate an explicitly supplied verification presentation. Passport verification consumes a challenge according to the upstream replay rules, so it is never called automatically as a health probe.

The states are `unconfigured`, `pending`, `failed`, `contract-validated`, and `live-validated`. An injected request implementation is always treated as contract validation. Local fixture runs set `contractOnly:true`; a real HTTPS fixture is still not live companion acceptance. A validated route does not establish every operation or security policy of that companion. Actual deployed identities, configured upstream grants, expiry/revocation negatives and provider audit observation remain deployment acceptance requirements.

Validation observations expire after at most 60 seconds; Register freshness and Passport workload credential expiry can shorten that window. Each protected operation still resolves and checks the current credentials independently. Validation failure or a transport error invalidates the observation. An expired observation returns to `pending` and cannot satisfy a required dependency readiness gate.

`test/product-protocols.test.mjs` exercises lifecycle, version, origin, schemas, tenant/owner isolation, pending recovery and safe cancellation. `test/product-companions.test.mjs` sends actual HTTPS requests to local PKI-backed contract fixtures, verifies a real DPoP signature and request binding, and exercises the real Vault request sequence and byte hashes. These tests do not contact customer systems. Run:

```powershell
node --test --test-isolation=none test/product-protocols.test.mjs test/product-companions.test.mjs
```

The fixture PKI must already exist; generate it with the project's explicit local test PKI command before running on a fresh checkout. No test private keys belong in a release image or public evidence package.
