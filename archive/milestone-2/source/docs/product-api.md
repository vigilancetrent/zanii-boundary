# Product API

Run the supported product binary with `node scripts/start.mjs --config <file>`. It opens HTTPS with TLS 1.3 and mandatory client certificates, using TCP or the configured Unix socket. `SIGTERM`/`SIGINT` stop admission and bound connection draining. Configuration and integration file paths resolve relative to the configuration file. Upstream origins and secret-file paths are operator configuration; API callers cannot supply them.

For a local test, first run `python scripts/test-pki.py --flat --output artifacts`, then start `config/examples/resource.local-test.json` and `config/examples/gateway.local-test.json` in two terminals. Generated PKI expires quickly and is exclusively for tests. The resource trusts the dedicated broker public JWKS; the gateway trusts the independent agent issuer public JWKS. These examples report containment as unverified. The production `.json.example` templates deliberately contain required placeholders and must be provisioned before they validate. Production requires independently provisioned identities, pinned issuer keys, company resources, and a fresh measured containment receipt. The same public receipt and its pinned public verification key must be mounted read-only in both gateway and resource containers; its private evaluator signing key stays outside both.

Every protected request carries a bearer JWT bound through `cnf.x5t#S256` to the SHA-256 DER fingerprint of the presented client certificate. JWT issuer, audience, signing algorithm, issue/expiry time and maximum lifetime are pinned. Claims include `sub`, `tenant_id`, `roles`, `scope`, `iat`, `exp`, `jti`; the trusted issuer assigns authority. Production agents receive only their runtime identity and narrowly scoped task grants. Gateway resource JWTs have a separate audience and issuer configuration; agent runtime JWTs never authorize a resource effect.

All POST bodies are JSON objects with explicit fields. Responses and errors include `x-request-id`; W3C `traceparent` propagates to the resource. Error bodies are `{error:{code,requestId}}`; stack traces, bearer values and downstream error bodies are excluded. Rate/concurrency rejections return 429 with `Retry-After: 1`. Reads and responses are bounded. Metrics expose counters only; request logs exclude content and credentials.

| Route | Scope / role | Request or result |
|---|---|---|
| `GET /health/live` | TLS client certificate | Process liveness only |
| `GET /health/ready` | `runtime:audit`, operator/auditor | 200 ready; 503 missing resource, current containment, required integrations, or valid audit |
| `GET /metrics` | `runtime:audit`, operator/auditor | Prometheus text counters/gauge |
| `POST /v1/tasks` | `runtime:admin`, operator | Task specification; returns 201 |
| `GET /v1/tasks` | `runtime:admin`, operator | Bounded tenant task page |
| `POST /v1/tasks/list` | `runtime:admin`, operator | `{limit?,after?}`; `limit` 1–100, continue with the returned `next` cursor until null |
| `GET /v1/tasks/:id` | `runtime:read`, task owner or observer role | Current task, with root/parent revocation checked |
| `POST /v1/tasks/:id/delegate` | `runtime:invoke`, owning agent/operator | Narrower child specification; returns 201 |
| `POST /v1/tasks/:id/revoke` | `runtime:invoke`, owning agent/operator | `{}`; revokes authority, including descendants |
| `POST /v1/approvals` | `runtime:approve`, separate operator/approver | `{taskId,action,expiresAt}`; trusted provider supplies actual tool version |
| `POST /v1/actions` | `runtime:invoke`, task-owning agent/operator | `{taskId,action}` |
| `GET /v1/operations/:id` | `runtime:invoke`, task owner | Reauthorizes access before returning operation result |
| `POST /v1/operations/:id/reconcile` | Same | `{}`; independently observes an unknown effect without executing again |
| `POST /v1/operations/:id/cancel` | Same | `{}`; revokes task, never claims an in-flight effect was undone |
| `POST /v1/memory` | `runtime:invoke`, agent/operator | `{taskId,entry:{id,text,sourceId,label,expiresAt}}` |
| `POST /v1/memory/read` or `/delete` | Same | `{taskId,id}`; untrusted memory retains source scope and root taint |
| `GET /v1/coverage` | `runtime:audit`, operator/auditor | Current containment evidence status |
| `POST /v1/diagnostic/read` | `containment:probe`, operator/auditor/explicitly granted agent | Exactly `{}`; fixed public canary through the actual backend TLS path |
| `POST /v1/audit` | `runtime:audit`, operator/auditor | `{limit?,after?}`; bounded tenant audit page |
| `GET /v1/evidence` or `POST /v1/evidence` | Same | Signed encrypted audit page; POST `{after?,limit?,through?}`; retain the first checkpoint sequence as `through` for following pages |
| `GET /v1/checkpoint` | Same | Signed historical checkpoint; independently pin its public signing key |
| `GET /v1/integrations/status` | Same | Actual configured capability and validation states |
| `POST /v1/zanii/recover` | `runtime:integrations`, operator | `{}`; submits exact durable receipt outbox only |
| `POST /v1/zanii/proof` | `runtime:audit`, operator/auditor | `{hash:"sha256:<hex>"}`; verifies included log proof, does not claim trusted external anchoring |

A root task requires `id`, `actorId`, `documentIds`, `expiresAt` in UTC epoch milliseconds, `maxActions`, `profile`, and `purpose`. Optional fields are `recipients`, `allowedActions`, `requireApprovalFor`, `allowDelegation`, `maxSensitivity`. Supported profiles and purposes are defined in the governance document. Children cannot widen parent authority, lifetime, sensitivity or aggregate quotas.

An action is `{id,kind:"read"|"share",documentId,recipient?,toolVersion?,approvalId?,sourceRefs?}`. Shares require the exact separate approval when policy says so. Permissions, document labels, allowed purpose and internal-recipient status come from trusted resource metadata. Durable operation IDs bind the exact task/action/policy/version; changing arguments under a used ID returns 409. A successful response is `{status:200,operationId,state:"succeeded",result,warning?}`. A reserved/dispatched/unknown response is 202 and carries no successful result. A timeout after dispatch remains unknown and is never automatically retried. Approval, task/root, identity, provider and coverage deadlines also constrain dispatch after SDK recording awaits. Cached content is reauthorized on replay.

Read results include the bounded detector verdict. It warns and can quarantine suspicious document text for review; it never grants permissions. A partial detector scan explicitly reports `truncated`. The root flow label is committed before releasing content. There is no claim of universal prompt-injection recognition.

Learning routes use `runtime:learn` plus the role enforced by each lifecycle operation: `POST /v1/learning/quarantine`, `/review`, `/train`, `/shadow`, `/candidate`, `/prepare-update`, `/apply-update`, `/detect`, `/delete`. Quarantine accepts `{text,sourceId,sourceKind,id?}`; review `{id,label:"attack"|"benign",split:"train"|"holdout"}`; train `{threshold?}`; shadow/candidate/delete `{id}`; prepare `{id,action?,expiresAt?}`; apply `{jws}`; detect `{text,context?}`. Promotion is signed offline by an independent authorized actor. The service is configured with only the promoter public key. Models, reviewed corpus, holdout metrics, expiry, policy digest and signed update replay are checked. These changes affect detection only.

Operator companion routes require `runtime:integrations`: `POST /v1/integrations/register`, `/passport`, `/vault`, with `{method,input}`. The startup companion configuration requires `runtimeTenantId`; every credential-bearing invocation is bound to that authenticated runtime tenant. Supported methods are Register `verifyRegistration`/`getRegistration`; Passport `challenge`/`verify`/`executeDirectoryRead`; Vault `createCase`/`getCase`/`declareUpload`/`putChunk`/`completeUpload`. Scalar selectors use explicit objects: `{registrationId}`, `{caseId}`, `{caseId,metadata,idempotencyKey}`, `{uploadId,index,base64}`, `{uploadId,sha256}` respectively. Other method inputs match the documented adapter contracts. Credentials/cookies/CSRF/workload keys stay in protected operator files. Verification assurance returns `dispatchPermit:false` and is never a runtime action grant. Required integration validation can expire and blocks ordinary actions until refreshed.

MCP is mounted at `/mcp`, pinned to `2025-11-25`; include Accept `application/json, text/event-stream` and use negotiated sessions/version headers. A2A is mounted at `/a2a`, pinned to `0.3.0`; its authenticated card is `/.well-known/agent-card.json`. Both require `runtime:invoke` and route structured actions through the same executor. Free text cannot become authority or an arbitrary execution request.

The resource role exposes scoped `GET /v1/resource/status`, POST `/metadata`, `/execute`, `/observe`, `/diagnostic`, plus operator `/documents`, `/import`, and recipient/operator `/deliveries`. Execution requires a separately signed action-bound JWT with `task_id`, `policy_digest`, `action_digest`, `operation_id`, `resource_version`, `deadline_at`, sender binding, and `resource:execute`. The backend independently checks exact arguments, epoch, recipient, tenant, deadline, and durable effect idempotency. Document import uses `resource:admin`, reads use `resource:read`, and metadata/status/outcome each have separate scopes. The fixed backend diagnostic contains no selectable company data.

This is a single-host encrypted SQLite service. Bounded maintenance expires TTL objects and prunes old terminal result bodies while retaining operation/effect tombstones and append-only audit events. An expired result returns `resultExpired:true`; the operation is never dispatched again. Unknown effects remain available for independent reconciliation. Maintenance failures degrade readiness. Audit page signatures and complete ciphertext chains are independently verifiable without database decryption keys; detecting rollback/truncation requires an independently retained checkpoint. Live Docker containment, customer identities/systems and remote integration acceptance require their real deployment prerequisites. A local fixture result cannot close those external gates.
