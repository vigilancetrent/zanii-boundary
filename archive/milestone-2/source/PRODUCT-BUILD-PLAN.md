# Company agent protection runtime build plan

## Primary goal

Deliver the researched company-protection runtime: governed agent actions through an externally enforced broker, durable evidence and recovery, protocol/company integrations, controlled adaptive defenses, industry policies, and a reproducible research paper. Every objective in the user's table has an implementation and acceptance requirement; none is silently replaced by another research-only milestone.

**Authorization:** the user explicitly requested planning and building every listed objective. Continue implementation without another routine approval request. Keep the product in `04-agent-runtime`; existing companion projects remain unchanged. Deployment to real customer infrastructure, external publication and claims of first invention require their own evidence and authorization.

**Initial supported profile:** the user selected Linux with Docker/Compose and an internal REST/document service as the first live connector. Use a no-network agent and an authenticated Unix-domain gateway socket. The user selected **zinii ai** as the paper author/organization; preserve that spelling. The paper remains a local draft until publication is explicitly authorized.

**Completion rule:** `implemented`, `locally verified`, `deployment verified`, and `blocked` are distinct states. Missing Docker, credentials or independent review do not become PASS through mocks. Do not mark the full product complete while required external acceptance remains blocked. A paper can be completed as a clearly qualified engineering draft; inventorship or universal industry compatibility cannot be manufactured through code.

## Delivery evidence as of 2026-11-01

Local supported implementation and verification are complete; full deployment acceptance is open. The [requirement register](PRODUCT-REQUIREMENTS.md) distinguishes each objective, and [tasks/todo.md](tasks/todo.md) records local and external completion separately. Phase 2 remains partial for the unavailable upstream Zanii Runtime integration. Phase 3 has working local service/clients/recovery and unaccepted production operations. Phase 4 has a completed local engineering draft and measured evidence, without publication or novelty claims.

Final local verification: 130 Node tests, zero skips; Python TCP/mTLS SDK test; source parsing/basic lint/non-strict checkJs. Canonical product run `a0a30db5-3efb-4436-8bad-7a1a88f7106b` passed 15 cases and 2/2 primary tasks with three expected effects and zero negative/duplicate effects. The finite 512-request load produced 400 successes, 112 admission throttles and 400 unique effects; maximum observed successful throughput was 27.60 requests/s, with no hardware ceiling established. The full readiness gate is **13 PASS / 5 N/A / 29 GAP**; none is signed off.

The compact implementation consolidates planned admin/backup/restore tools into `scripts/operations.mjs`, uses `src/product/client.mjs` plus `sdk/python/`, and keeps current adapter/API/runbook documentation under `docs/product-*` and `docs/adapter-ports.md`. These are implemented replacements for planned file groupings, not silently omitted capabilities. See the linked evidence register for actual files and limits.

## Phase 0 Documentation and capability discovery

**How this serves the primary goal:** select available APIs and identify real infrastructure dependencies before changing the prototype.

- [x] Read the research, current source, original build tracker and readiness gaps.
- [x] Inspect native durability, existing authentication/evidence patterns and current companion contracts.
- [x] Check cached packages, protocol versions and deployment tools without exposing secret values.

### Verified references and allowed APIs

- Node `v24.19.0` and native SQLite `3.53.3`: `DatabaseSync`, `prepare().run/get/all`, `exec`, transactions, UNIQUE/CHECK constraints and rollback were executed. `serialize()` returns a byte array. Product tests subsequently verified disk reopening, rollback, backup/restore and replay tombstones.
- Existing patterns: Passport `src/server/common/oidc.ts:43` uses JOSE issuer/audience/JWKS verification; `modules/enforcement/execution.ts:44` binds operation identity/digest and reserves before dispatch. Register `observability/local-audit-archive.ts:18` uses exclusive writes/fsync and explicitly does not claim WORM. Vault `services/provider-http.ts:43` fixes destinations, refuses redirects and bounds responses/time.
- Pinned cached packages: `jose@6.2.14`, `zod@4.6.7`, `canonicalize@5.1.0`, `@zanii/sdk@0.5.4`, `@zanii/core@0.5.6`, `@zanii/broker@0.1.0` (its nested core is 0.4.0). Install declared dependencies normally, offline with scripts disabled. No runtime imports from sibling `node_modules`.
- Cached broker `createBroker({credentials,record,gate,fetchImpl,stripResponseHeaders}).execute({credential,method,url,headers,body})` records before dispatch. Its default fetch lacks redirect/time/size protection and reads mutable request fields after awaits: wrap a cloned/frozen validated request and hardened transport.
- SDK `record()` queues; `flush()` returns accepted/duplicate/rejected results. A queued record is not durable ledger acceptance. Verify exact current APIs for recovery rather than inventing newer methods.
- `@zanii/runtime@0.4.0` metadata can be read, but the explicit online install attempt (`--offline=false --prefer-online --cache .npm-cache --registry=https://registry.npmjs.org --fetch-timeout=10000 --fetch-retries=0 --ignore-scripts --audit=false`) fails fetching the actual tarball with `ECONNREFUSED 127.0.0.1:9`. No Runtime bytes were installed; root SDK remains pinned at 0.5.4. Its optional integration must fail explicitly when required but unavailable; no fake runtime implementation may claim this integration passed.
- MCP pin: `2025-11-25`; initialization, negotiated-version headers, Origin checks, `tools/list`, `tools/call`, empty 202 notifications and audience-bound authorization. A2A pin: `0.3.0` JSON-RPC `message/send`, `tasks/get`, `tasks/cancel`; do not mix newer `/latest` field/method names.
- Register uses `register_access` cookies. Its public assurance projection is not an execution grant. Passport `/v1/verify` explicitly returns `dispatchPermit:false`; workload PEP execution is separate. Vault uses `vault_session` plus CSRF and multi-step case/upload/chunk/complete ingestion. Use inspected routes, never an invented generic event endpoint.
- Docker/Podman are absent. WSL enumeration is denied. Node child launch returns `EPERM`. Python `cryptography` is installed and can generate ephemeral test PKI; OpenSSL is unusable here. No live container/process containment acceptance is possible in this environment.

## Target architecture and trust boundaries

```text
Authenticated owner / operator
        | task grants, exact approvals, reviewed detector promotions
        v
Gateway / policy + durable journal ----- signed checkpoints / evidence
        |               |                         |
        |               +---- isolated learner ---+ (cannot grant authority)
        | authenticated, fixed-target dispatch
        v
Credential broker / verified provider adapter ----> company resource
        ^                                              |
        |                                   independent authorization/outcome
No-network agent -- narrow authenticated UDS socket ---+
```

The agent never receives upstream keys, a Docker socket, host privileges, control-plane credentials or approval-signing authority. Resource servers independently authenticate the broker and enforce tenant/object/action constraints. An allowed hostname alone is insufficient. All writes reserve durable operation state and authority/quota/approval atomically before network dispatch; unknown effects are reconciled without replay. Host administrators, kernel/sandbox failures and unrestricted provider grants remain explicit trust assumptions, tested where access exists.

Data classes: credentials/key material (never logs/ledger); private business inputs and feedback (encrypted local storage with retention); identifiers and audit metadata (minimised/redacted); public evidence (hashes/versions/outcomes only). Learned content cannot change trusted policy or declare itself public. Root task authority/quotas and taint follow child tasks. Industrial profiles disable physical commands unless a separate safety adapter has been assessed.

## Phase 1 Durable and governed foundation

**How this serves the primary goal:** replace disposable-only state with independently testable product libraries for authority, audit, recovery and controlled decisions.

1. Archive the original prototype source and public evidence before package/source changes. Verify its recorded source digest in the archive.
2. Install only the pinned cached dependencies actually used. Preserve the original tests and experiment as a regression suite.
3. Implement validated product configuration, workload authentication, encrypted SQLite records, atomic reservations/idempotency, approvals/quota consumption, audit chaining/checkpoints, recovery and backup/restore.
4. Implement industry profiles, trusted task/child authority, conservative source/destination flows, explicit memory provenance, bounded injection/task-deviation detection and an independently testable detector learning lifecycle.
5. Write the Linux containment profile, authenticated socket transport, test PKI and static/live acceptance tooling. Static validation is not live isolation evidence.

Files: `archive/milestone-1/` (original source/public evidence); `src/product/{config,auth,store,policy,profiles,detector,learning,memory}.mjs`; `test/product-{store,auth,policy,learning}.test.mjs`; `scripts/{test-pki,doctor}.mjs` or a documented Python PKI helper; `deploy/{Dockerfile,compose.yaml,profile.json,README.md}`; deployment-policy tests; update package/lock only from its designated owner.

Verification: disk reopen/rollback/tamper/restore; cross-tenant object and SQL scoping; hash-bound duplicate behavior; parallel aggregate quota and one-use approval; JWT issuer/audience/expiry/sender binding; child scope/expiry narrowing; no agent declassification; untrusted/poisoned feedback cannot promote models; held-out benign and attack evaluation; no privilege expansion after a detector update; container static rejection of unsafe settings. Live Docker/host tests remain explicit blocked gates until executed.

Guards: no insecure startup defaults, global assistant-provider key reuse, secrets in argv/artifacts, SQLite transaction held over network, arbitrary SQL/paths/URLs, self-approved model updates, hidden fallback to research mode or hand-rolled replacement claimed as Zanii Runtime.

## Phase 2 Real adapters and adaptive lifecycle

**How this serves the primary goal:** connect real resource/protocol boundaries and enable reviewed learning without delegating authority to the model.

1. Implement a configured filesystem/document resource and a fixed-target HTTPS REST adapter with actual reads/shares, object ownership, destination restrictions, provider idempotency and independent outcome queries.
2. Integrate cached Zanii broker/SDK with hardened transport, durable record-before-call behavior and explicit ledger acceptance; implement a version-checked optional Runtime integration with a blocked capability when the required package is absent.
3. Implement Register, Passport and Vault clients against the inspected cookie/CSRF/workload-proof contracts. Their live verification requires provisioned sessions/keys and endpoints; contract fixtures cannot close that gate.
4. Implement pinned MCP and A2A handlers with lifecycle/task persistence, tenant-safe status/cancel, strict tools and no transfer of upstream credentials. A2A cancellation does not promise to undo committed effects.
5. Persist quarantined learning candidates, trusted feedback, holdout results, shadow versions, signed promotion/rollback and policy-digest invariants. Offer optional configured classifier integration; no claim of universal injection recognition.

The central executor/service may be implemented against the declared adapter ports alongside these independent adapters, then joined and hardened in Phase 3. This does not close its end-to-end acceptance before the real adapters are connected.

Files: `src/adapters/{documents,rest,zanii,register,passport,vault,mcp,a2a}.mjs`; protocol/client and adapter tests; `src/product/learning.mjs` lifecycle integration; bounded synthetic attack/benign corpus; `docs/integrations.md` with exact support/version and live-state matrix.

Verification: actual file/document effects in a temporary protected root; symlink/traversal/tenant/destination negatives; HTTPS redirects/DNS/size/deadline and injected-credential scrub; actual installed Zanii package tests; 202 pending/unknown never reported committed; cookie/CSRF workflows; Passport verification never grants dispatch; MCP initialization/notifications/version/Origin/auth tests; A2A send/get/cancel with cross-tenant denial; interrupted upload and callback/recovery tests; detector performance reported only for its declared corpus.

Guards: no invented endpoints or contemporary protocol names from another version, unbounded tool descriptions or provider results, raw customer payloads on the ledger, request mutation after audit, signing attacker-supplied training labels as trusted, or mock-as-live acceptance claims.

## Phase 3 Product service and operational boundaries

**How this serves the primary goal:** make the independent components an executable service that can protect a supported company workflow rather than just demonstrate policies.

1. Implement a fail-fast product server/CLI, secure TLS/mTLS and UDS transports, pinned workload JWT authorization, role-separated administration, rate limits, request deadlines and bounded concurrency.
2. Route task/approval/dispatch/recovery/evidence/learning/MCP/A2A operations through the same authorization and durable execution boundary. Require current coverage/containment evidence for production execution.
3. Add continuous bounded coverage checks, drift invalidation, authenticated health/readiness, structured redacted logs, metrics/traces, retention/deletion, audit/checkpoint export and backup/recovery tools.
4. Supply Node/Python client adapters, deployment and CI configuration, alert/runbook definitions and blocked-live acceptance commands. Never expose an unrestricted generic broker or fail-open if an integration is required.

Resolve containment bootstrapping explicitly: a production process may start its control/health plane while ordinary business execution remains blocked by a missing/invalid containment receipt. An authenticated `containment:probe` diagnostic route may return only a fixed public canary through the real TLS/socket/backend path; it cannot read company documents or grant general dispatch. The live checker can use that narrow positive control to obtain the first real receipt. Never create a fake successful receipt to break the bootstrap cycle.

Files: `src/product/{server,executor,transport,observability,coverage}.mjs`; `scripts/{start,admin,backup,restore,containment-check,product-check}.mjs`; `sdk/python/`; service/end-to-end/restart/concurrency/failure tests; environment/config examples with no real secrets; CI/deploy/monitoring configuration; API/runbook/security documentation.

Verification: real TLS/UDS requests, role and tenant separation, CSRF/OIDC/sender binding where applicable, current provider-side checks after delayed dispatch, safe shutdown, disk failure and dependency isolation, restart-safe result replay and unknown reconciliation, journal tampering, aggregate child budgets and data-flow restrictions, retention deletion and audit integrity, real MCP/A2A client calls through the product service. Container/remote IdP/SaaS/Zanii/companion live prerequisites are mandatory external gates, not skipped successes.

## Phase 4 Full verification and paper

**How this serves the primary goal:** establish repeatable implementation evidence, transparent operational limits and a credible publication artifact for the actual system.

1. Re-run existing research and all new product tests; independent verification, anti-pattern and code-quality/security reviews must pass after fixes.
2. Benchmark the actual product path, authorised utility, attack effects, persistence/recovery, learning holdouts and measured latency/cost under a declared workload; attempt safe saturation and report an unmeasured ceiling honestly.
3. Produce a full fresh 47-row readiness assessment and requirement/evidence matrix. No automatic inherited PASS for changed code and no production clearance while external gates remain unmet.
4. Complete a white-paper draft with actual method, prior-work comparison, reproducibility commands, measured local results, negative controls, limitations and clearly pending external/independent validation. Do not claim invention, guaranteed safety or publication acceptance.

Files: `docs/{product-architecture,product-threat-model,product-api,product-runbook,product-readiness-report,product-status}.md`; `paper/white-paper.md`; reproducibility/evaluation scripts and manifests; updated `PRODUCT-REQUIREMENTS.md`, `README.md` and `tasks/todo.md`.

Verification: all requirement rows cite real code and tests; live-state flags match actual prerequisites; scanners/type/lint and secret checks; backup restoration measured; performance report separates success/denial/uncertain effects; publication contains no fabricated experiment, institutional endorsement, author identity or novelty claim. No commit, push, customer deployment or public publication without explicit instruction.
