# Product production-readiness report

**System:** company agent protection runtime, `04-agent-runtime`  
**Scope:** full product gateway/resource, adapters, durability, learning, clients and deployment artifacts  
**Date:** 2026-11-01  
**Commit:** unavailable; this workspace has no Git repository metadata  
**Prior report:** archived milestone-1 report is historical only; no PASS is inherited  
**Result:** **13 PASS / 5 N/A / 29 GAP**  
**Cleared to ship:** NO  
**Measured capacity ceiling:** not established; configured admission saturation is distinct from a hardware/production ceiling.

This report applies the 47-check production-ready gate to the changed product. PASS identifies evidence within the declared initial profile; it does not mean the whole system is production accepted. Every external or unverified requirement remains GAP. No GAP has been signed off.

## Stage artifacts

| Stage | Artifact | Outcome |
|---|---|---|
| Architecture | product-architecture.md; source store/server/adapter boundaries | Single-host design and failure domains documented; horizontal resilience open. |
| Threat model | product-threat-model.md; PRODUCT-BUILD-PLAN.md | Credential custody, complete mediation and host/evaluator trust assumptions explicit. |
| Implementation | src/product, src/adapters, sdk, scripts, deploy | Implemented locally; upstream Runtime integration unavailable. |
| Tests | Final parent verification: npm test 130/130, zero skips; Python SDK real mTLS 1/1 | Passed locally; isolated-process/Linux socket/container gates separate. |
| Load | product-load.json and product-benchmark.md | Measured 512 issued, 400 successful, 112 throttled, 400 effects across four fresh fixtures; no hardware ceiling. |
| Observability | observability.mjs; monitoring/alerts.yaml and dashboard.json | Counters/correlation and templates only; deployment/complete telemetry open. |
| Security | product-final-secretlint.json; actual ESLint/checkJs/source parsing | Final Secretlint 13.1.0 scan: 114 source/config/test/docs/CI/monitoring files, zero errors/warnings/messages; parsed severity totals verified. Fresh advisory audit remains blocked. |
| Scalability | Single-process local load analysis | No hardware ceiling, agreed customer peak, autoscaling or failover evidence. |
| Readiness | This full report | All 47 evaluated; production clearance withheld. |

## Verification record

Parent verification after source freeze passed **130 Node tests with zero skips** in approximately 9.78 seconds, **72 parsed modules and five narrow source rules**, **51-file ESLint** with zero errors/warnings and **51-file non-strict checkJs** with zero diagnostics. Python's stdlib SDK completed one real TCP/mTLS test in about 0.533 seconds. Development tools were supplied explicitly from a development tooling root; no sibling runtime dependency is imported by the product.

The Linux socket acceptance gate returns nonzero `SOCKET_ACCEPTANCE_REQUIRES_LINUX` on this Windows host. A Windows pipe analogue was intermittent and is not Linux acceptance. The live doctor returns nonzero `PINNED_IMAGE_REQUIRED`; static validation reports `liveVerified:false`. Docker/Podman are absent, WSL enumeration is denied and child launch is restricted. No successful isolation result is inferred.

Current implementation digest: `8478c9ac636aa9cedd40d561dca79c2d48de72a8f334b01741f4a5dc36516a62`. Static deployment profile digest: `bce4d21d0c86880a14c467f8a19b131d28fcc8bccd824d40524c60c1b75618eb`. These identify source/static inputs, not live-host attestation.

A separate explicit whitelist scan of seven public evaluation/recovery artifacts also returned zero messages (`artifacts/product-public-secretlint.json`); it used `--no-gitignore` without including private PKI or databases.

## The 47

All file/test references are relative to this project. Detailed reproduction commands are in product-benchmark.md, product-operations.md and product-api.md.

| # | Requirement | Status | Evidence / remaining work |
|---|---|---|---|
| 1 | Architecture and scalability | GAP | Single-host SQLite, in-memory protocol/rate state and one gateway/resource are documented in product-architecture.md; no instance-loss or shared-store scaling proof. |
| 2 | Authentication | PASS | auth.mjs and product-auth tests pin JOSE signature, issuer, audience, algorithm, lifetime and mTLS thumbprint; real product-service mTLS rejects wrong binding. Authentication is delegated to provisioned machine issuers; no password login is implemented. |
| 3 | Authorization / RBAC | PASS | policy.mjs, executor.mjs and server.mjs enforce roles/scopes plus tenant/task/document/recipient authority. product-service/policy tests deny foreign actors, wrong scopes, direct-resource tokens and cross-tenant companion use. |
| 4 | Session management | N/A | Runtime API is stateless machine-to-machine JWT/mTLS, with no browser login/session cookie. product-auth tests verify short token lifetime/expiry; companion cookies are external provisioned credentials with expiry checks. |
| 5 | API design | PASS | Versioned /v1 routes; shared JSON errors; POST /v1/tasks/list strict bounded cursor pages and 103-task TLS regression. store.list/queryAudit/exportAudit cap page size at 100; protocol handlers use their pinned JSON-RPC contracts. |
| 6 | Rate limiting | PASS | Single-host observability.mjs limits peer and tenant/actor windows plus active concurrency. Example production config: 300 requests/60 seconds and 32 active. Direct limiter verification on 2026-11-01 checked limit+1=429, reset and separate keys; sendJson sets Retry-After:1. Product load measures admission throttling. No distributed-rate claim. |
| 7 | Input validation | PASS | Zod config/auth/adapter schemas and exactObject action/route parsing reject unknown fields; bounded JSON parser and protocol tests cover malformed, oversized and smuggled authority fields. |
| 8 | Output validation | PASS | REST/companion/ledger schemas validate trusted scope and acknowledgement fields; native HTTPS bounds bytes/time and rejects redirects/compression. Product adapter/companion/Zanii tests reject malformed, mismatched and oversized responses. |
| 9 | Secrets management | GAP | Final Secretlint 13.1.0 scan of 114 source/config/test/docs/CI/monitoring files has zero errors/warnings/messages in artifacts/product-final-secretlint.json; severity totals were parsed, and private generated PKI/data were excluded intentionally. No Git history exists and deployed secret manager/rotation/ACL acceptance is unverified. |
| 10 | Encryption | GAP | Real TLS 1.3/mTLS and AES-256-GCM fields/backups are tested. Metadata/WAL/volume protection, managed key lifecycle and production edge/HSTS behavior are not deployment verified. |
| 11 | Database architecture | GAP | store.mjs has STRICT tables, unique keys, indexes, parameterized SQL and schema version checks. No representative EXPLAIN evidence or reversible forward/backward migration rehearsal exists. |
| 12 | Database scalability | N/A | Accepted implementation is explicitly bounded single-host storage: default 128 MiB DB page cap, 64 KiB serialized values and 50,000 rows per tenant/object namespace, with capacity-failure rollback tested. This is not an unlimited-growth service or a sharded-store claim; WAL/temp/backup quota remains operational work. |
| 13 | Caching | N/A | No shared response/performance cache. Authoritative policy and metadata are reloaded. Durable idempotency journals are business state, and every cached result release is reauthorized; protocol/integration state has its own bounded lifecycle. |
| 14 | Queue / background jobs | GAP | Durable receipt outbox/manual recovery and bounded retention exist; no deployed retry worker, exhausted-job/DLQ policy or delivered DLQ alarm has been established. |
| 15 | Distributed locking | N/A | The supported one-host critical state uses SQLite BEGIN IMMEDIATE plus unique constraints; no multi-node worker ownership is claimed. Quota/approval/duplicate races are covered by product-store/executor tests. |
| 16 | Idempotency | PASS | Unique durable operation reservation precedes network/effect; provider journal independently deduplicates. Concurrent duplicate, restart, unknown reconciliation and result-retention tombstone tests prove no second dispatch. |
| 17 | Transaction management | PASS | store.transaction forbids async callbacks; multi-write reservation/approval/quota/audit mutations use BEGIN IMMEDIATE and rollback. Mid-operation disk-capacity and explicit rollback tests pass. |
| 18 | Concurrency control | PASS | Atomic ancestor quota and one-use approval consumption, exact operation digests and provider version checks are covered by concurrent product-store/executor/service tests. |
| 19 | Error handling | PASS | Shared sendError returns stable code/requestId and hides unhandled exceptions; clients receive bounded errors rather than stack/provider secrets. Real HTTP/TLS and adapter failure tests pass. |
| 20 | Logging | GAP | Structured bounded request logs exclude bodies/credentials and carry requestId/traceparent. Complete level/actor correlation, durable collection, sampling and end-to-end operational review remain incomplete. |
| 21 | Audit logging | GAP | Encrypted hash/HMAC chain, signed page export and pinned-checkpoint verification work locally. App-controlled SQLite/signing keys are not an independent append-only/WORM trust domain; exhaustive auth/export/admin-event coverage and deployed retention need review. |
| 22 | Observability | GAP | Actual aggregate counters/gauge and monitoring/dashboard.json exist. No deployed dashboard reading, complete per-endpoint RED histograms or resource USE/business telemetry is established. |
| 23 | Health checks | GAP | Separate live/ready routes and missing-receipt readiness failure are tested. Authenticated mTLS probe identities, startup/load-balancer integration and real dependency-failure probe behavior are not deployment accepted. |
| 24 | Monitoring and alerting | GAP | monitoring/alerts.yaml names thresholds/runbook anchors, but routing, delivered alerts, disk/certificate/exporter coverage and on-call response are not established. |
| 25 | Distributed tracing | GAP | W3C traceparent propagates across gateway/resource HTTP. No complete DB/outbox span trace, tracing backend or verified sampling policy exists. |
| 26 | Performance engineering | GAP | Actual local product latency/throughput/CPU/RSS are measured in product-load.json. Customer SLOs, per-endpoint budgets and representative query/N+1 profiling remain unestablished. |
| 27 | Load testing | GAP | Finite real-TLS synthetic sweep at 1/4/16/64 concurrency is reproducible. No agreed customer peak, representative production data volume, sustained arrival-rate test or hardware breaking point exists. |
| 28 | Autoscaling | GAP | No horizontal autoscaling/shared authoritative store; fixed-capacity production headroom has not been demonstrated at a customer peak. |
| 29 | CDN / edge caching | N/A | This is an internal authenticated JSON/document API with no public static-content origin. JSON responses use no-store; no user-specific content is intentionally CDN cached. |
| 30 | File / object storage | GAP | Bounded protected imports and encrypted persistent host volumes work locally. Cross-instance/object-store durability and customer storage policy are not accepted. |
| 31 | Async communication | GAP | Versioned resource RPC and signed receipt outbox preserve pending/unknown state and reject bad acknowledgements. Deployed delivery/ordering/recovery operations across real services remain unaccepted. |
| 32 | Retry strategy | GAP | Business mutations deliberately have no automatic redispatch; explicit receipt recovery is idempotent. No deployed bounded backoff/jitter worker for safe retryable background work is established. |
| 33 | Circuit breakers | GAP | Ledger failure blocks dispatch and requests are bounded, but a measured circuit-breaker/fallback policy for every external dependency under load is absent. |
| 34 | Timeouts | GAP | Native HTTPS has connect/read/total bounds and dispatch deadlines; provider expiry checks are tested. SQLite busy waits, all companion phases and Python OS DNS are not proven inside a complete end-to-end deadline budget. |
| 35 | Graceful degradation | GAP | Required dependencies fail closed and optional unconfigured features are explicit. No complete optional-dependency fault-under-load acceptance run exists. |
| 36 | High availability | GAP | Single-host gateway/resource/store; no multi-AZ failover or accepted downtime/SLO exemption exists. |
| 37 | Disaster recovery | GAP | A 45,056-byte encrypted backup restored locally in about 5.54 ms with pinned hash, payload/tombstone and audit checks. Automated off-site retention, representative RPO/RTO and failover restore are not established. |
| 38 | Deployment strategy | GAP | Docker/Compose and .github/workflows/product.yml define gates. No executed CI, verified built-image digest, migration/rollback rehearsal or running Linux deployment exists. |
| 39 | Zero / low-downtime deployment | GAP | Server stops admission and bounds drain on shutdown. No rolling/canary deployment under load, accepted maintenance window or schema expand/contract acceptance exists. |
| 40 | Dependency management | GAP | Runtime package-lock pins installed dependencies. Fresh npm advisory audit and Runtime tarball retrieval fail through the proxy; no accepted pinned base image, complete image scan or validated automated update mechanism exists. |
| 41 | Security testing | GAP | Narrow source lint/rules, non-strict checkJs, Secretlint and real auth/tenant/protocol negative tests pass. Fresh dependency/image scanning, deployed DAST and independent penetration/security acceptance remain open. |
| 42 | OWASP protections | PASS | Parameterized scoped SQL; no eval/browser HTML sink; JSON CSP/nosniff/frame denial; fixed-origin DNS-validated HTTPS rejects redirect/metadata/foreign targets. Real transport/auth negatives and Vault CSRF/Origin workflow tests pass within the declared API scope. |
| 43 | Privacy / data protection | GAP | Encrypted local examples/results, redaction, TTL deletion and permanent no-replay tombstones are tested. Documents/mailbox/audit/unknown records and historical backups still require accepted per-category retention/export/deletion policy; no universal PII erasure claim. |
| 44 | Multi-tenancy / data isolation | PASS | Shared store keys/AAD and parameterized repository methods bind tenant/namespace/object; cross-tenant storage, task, provider, protocol and companion-binding tests pass. |
| 45 | Configuration management | PASS | External operator JSON/secret-file config is schema validated at boot, including relative path base, mandatory production sender binding and deployment scope. Bad/incomplete public test/production settings fail; examples contain explicit non-working provisioning placeholders. |
| 46 | Documentation | GAP | Architecture, threat model, API, integrations, deployment, operations, runbook, requirements and paper exist. A fresh operator deployment/incident handoff and real on-call escalation destination remain unverified. |
| 47 | Cost and capacity management | GAP | Local throughput/CPU/RSS are recorded, with no automatic model billing. Monthly deployment/ledger/egress cost, per-request monetary cost, production ceiling and billing alerts remain unestablished. |

## GAPs requiring closure or explicit sign-off

Owner roles below are required responsibilities, not invented named staff. Every decision is **pending**; no risk acceptance is implied.

| # | Missing acceptance | Proposed owner | Decision |
|---|---|---|---|
| 1 | Architecture and scalability: Single-host SQLite, in-memory protocol/rate state and one gateway/resource are documented in product-architecture.md; no instance-loss or shared-store scaling proof. | Deployment/service/security owner, according to subject | Pending |
| 9 | Secrets management: Final Secretlint 13.1.0 scan of 114 source/config/test/docs/CI/monitoring files has zero errors/warnings/messages in artifacts/product-final-secretlint.json; severity totals were parsed, and private generated PKI/data were excluded intentionally. No Git history exists and deployed secret manager/rotation/ACL acceptance is unverified. | Deployment/service/security owner, according to subject | Pending |
| 10 | Encryption: Real TLS 1.3/mTLS and AES-256-GCM fields/backups are tested. Metadata/WAL/volume protection, managed key lifecycle and production edge/HSTS behavior are not deployment verified. | Deployment/service/security owner, according to subject | Pending |
| 11 | Database architecture: store.mjs has STRICT tables, unique keys, indexes, parameterized SQL and schema version checks. No representative EXPLAIN evidence or reversible forward/backward migration rehearsal exists. | Deployment/service/security owner, according to subject | Pending |
| 14 | Queue / background jobs: Durable receipt outbox/manual recovery and bounded retention exist; no deployed retry worker, exhausted-job/DLQ policy or delivered DLQ alarm has been established. | Deployment/service/security owner, according to subject | Pending |
| 20 | Logging: Structured bounded request logs exclude bodies/credentials and carry requestId/traceparent. Complete level/actor correlation, durable collection, sampling and end-to-end operational review remain incomplete. | Deployment/service/security owner, according to subject | Pending |
| 21 | Audit logging: Encrypted hash/HMAC chain, signed page export and pinned-checkpoint verification work locally. App-controlled SQLite/signing keys are not an independent append-only/WORM trust domain; exhaustive auth/export/admin-event coverage and deployed retention need review. | Deployment/service/security owner, according to subject | Pending |
| 22 | Observability: Actual aggregate counters/gauge and monitoring/dashboard.json exist. No deployed dashboard reading, complete per-endpoint RED histograms or resource USE/business telemetry is established. | Deployment/service/security owner, according to subject | Pending |
| 23 | Health checks: Separate live/ready routes and missing-receipt readiness failure are tested. Authenticated mTLS probe identities, startup/load-balancer integration and real dependency-failure probe behavior are not deployment accepted. | Deployment/service/security owner, according to subject | Pending |
| 24 | Monitoring and alerting: monitoring/alerts.yaml names thresholds/runbook anchors, but routing, delivered alerts, disk/certificate/exporter coverage and on-call response are not established. | Deployment/service/security owner, according to subject | Pending |
| 25 | Distributed tracing: W3C traceparent propagates across gateway/resource HTTP. No complete DB/outbox span trace, tracing backend or verified sampling policy exists. | Deployment/service/security owner, according to subject | Pending |
| 26 | Performance engineering: Actual local product latency/throughput/CPU/RSS are measured in product-load.json. Customer SLOs, per-endpoint budgets and representative query/N+1 profiling remain unestablished. | Deployment/service/security owner, according to subject | Pending |
| 27 | Load testing: Finite real-TLS synthetic sweep at 1/4/16/64 concurrency is reproducible. No agreed customer peak, representative production data volume, sustained arrival-rate test or hardware breaking point exists. | Deployment/service/security owner, according to subject | Pending |
| 28 | Autoscaling: No horizontal autoscaling/shared authoritative store; fixed-capacity production headroom has not been demonstrated at a customer peak. | Deployment/service/security owner, according to subject | Pending |
| 30 | File / object storage: Bounded protected imports and encrypted persistent host volumes work locally. Cross-instance/object-store durability and customer storage policy are not accepted. | Deployment/service/security owner, according to subject | Pending |
| 31 | Async communication: Versioned resource RPC and signed receipt outbox preserve pending/unknown state and reject bad acknowledgements. Deployed delivery/ordering/recovery operations across real services remain unaccepted. | Deployment/service/security owner, according to subject | Pending |
| 32 | Retry strategy: Business mutations deliberately have no automatic redispatch; explicit receipt recovery is idempotent. No deployed bounded backoff/jitter worker for safe retryable background work is established. | Deployment/service/security owner, according to subject | Pending |
| 33 | Circuit breakers: Ledger failure blocks dispatch and requests are bounded, but a measured circuit-breaker/fallback policy for every external dependency under load is absent. | Deployment/service/security owner, according to subject | Pending |
| 34 | Timeouts: Native HTTPS has connect/read/total bounds and dispatch deadlines; provider expiry checks are tested. SQLite busy waits, all companion phases and Python OS DNS are not proven inside a complete end-to-end deadline budget. | Deployment/service/security owner, according to subject | Pending |
| 35 | Graceful degradation: Required dependencies fail closed and optional unconfigured features are explicit. No complete optional-dependency fault-under-load acceptance run exists. | Deployment/service/security owner, according to subject | Pending |
| 36 | High availability: Single-host gateway/resource/store; no multi-AZ failover or accepted downtime/SLO exemption exists. | Deployment/service/security owner, according to subject | Pending |
| 37 | Disaster recovery: A 45,056-byte encrypted backup restored locally in about 5.54 ms with pinned hash, payload/tombstone and audit checks. Automated off-site retention, representative RPO/RTO and failover restore are not established. | Deployment/service/security owner, according to subject | Pending |
| 38 | Deployment strategy: Docker/Compose and .github/workflows/product.yml define gates. No executed CI, verified built-image digest, migration/rollback rehearsal or running Linux deployment exists. | Deployment/service/security owner, according to subject | Pending |
| 39 | Zero / low-downtime deployment: Server stops admission and bounds drain on shutdown. No rolling/canary deployment under load, accepted maintenance window or schema expand/contract acceptance exists. | Deployment/service/security owner, according to subject | Pending |
| 40 | Dependency management: Runtime package-lock pins installed dependencies. Fresh npm advisory audit and Runtime tarball retrieval fail through the proxy; no accepted pinned base image, complete image scan or validated automated update mechanism exists. | Deployment/service/security owner, according to subject | Pending |
| 41 | Security testing: Narrow source lint/rules, non-strict checkJs, Secretlint and real auth/tenant/protocol negative tests pass. Fresh dependency/image scanning, deployed DAST and independent penetration/security acceptance remain open. | Deployment/service/security owner, according to subject | Pending |
| 43 | Privacy / data protection: Encrypted local examples/results, redaction, TTL deletion and permanent no-replay tombstones are tested. Documents/mailbox/audit/unknown records and historical backups still require accepted per-category retention/export/deletion policy; no universal PII erasure claim. | Deployment/service/security owner, according to subject | Pending |
| 46 | Documentation: Architecture, threat model, API, integrations, deployment, operations, runbook, requirements and paper exist. A fresh operator deployment/incident handoff and real on-call escalation destination remain unverified. | Deployment/service/security owner, according to subject | Pending |
| 47 | Cost and capacity management: Local throughput/CPU/RSS are recorded, with no automatic model billing. Monthly deployment/ledger/egress cost, per-request monetary cost, production ceiling and billing alerts remain unestablished. | Deployment/service/security owner, according to subject | Pending |

## Measurements and limits

Canonical run a0a30db5-3efb-4436-8bad-7a1a88f7106b passed 15/15 declared cases, 2/2 primary tasks, three expected provider effects, zero negative-case effects and zero duplicate effects. Signature verification and independent outcome/summary recount passed.

The load script issued **512 requests across four fresh fixtures**, recording **400 successful responses**, **112 admission throttles (429)** and **400 provider effects across those fixtures**. Operation IDs are unique per fixture and reused across levels. No effect was duplicated within its fixture; there were no pending/other-denied/error responses or effects without a successful response.

| Concurrent clients | Successful / requested | 429 | Successful requests/s | Successful p50 / p95 / p99, ms |
|---|---:|---:|---:|---:|
| 1 | 128 / 128 | 0 | 27.33 | 34.13 / 52.30 / 65.72 |
| 4 | 128 / 128 | 0 | 27.60 | 137.72 / 174.38 / 190.38 |
| 16 | 128 / 128 | 0 | 23.55 | 675.89 / 719.37 / 728.87 |
| 64 | 16 / 128 | 112 | 12.34 | 1293.14 / 1296.98 / 1296.98 |

The gateway's configured 16-request admission limit was reached. Maximum observed successful throughput was **27.60 requests/s**; a hardware or production capacity ceiling was not established. Post-level combined RSS ranged from approximately 180 MB to 230 MB and includes evaluator plus both service roles. This short closed-loop synthetic workload is not a soak, a customer peak or per-service utilization measurement. Its illustrative 10 requests/s and latency targets are experimental assumptions, not an agreed SLO; p50 exceeded the illustrative 250 ms target at higher concurrency. No monetary billing, autoscaling or sustained production ceiling was measured.

 Local operations evidence is already recorded in `artifacts/product-operations.json`: a 45,056-byte encrypted snapshot backed up in about 2.51 ms and restored in about 5.54 ms. Pinned hash, restored payload/tombstone, signed ciphertext chain, tamper and no-replay retention checks passed. This is a small synthetic local recovery, not a production RPO/RTO.

No deployed cost estimate, hardware breaking point, customer peak, HA event, delivered alert, live external integration or independent reproduction is claimed.

## PASS evidence index

The following paths make the passing rows directly reviewable; they do not close the separate deployment GAPs.

| Check | Source and executable evidence |
|---|---|
| 2 | [JWT verifier](../src/product/auth.mjs), [issuer/audience/expiry/binding tests](../test/product-auth.test.mjs), [real mTLS route tests](../test/product-service.test.mjs). |
| 3 | [Policy](../src/product/policy.mjs), [executor](../src/product/executor.mjs), [object/child/approval tests](../test/product-policy.test.mjs), [companion tenant regression](../test/product-service.test.mjs). |
| 5 | [Versioned server and task paging](../src/product/server.mjs), [103-record cursor regression](../test/product-evaluation.test.mjs). |
| 6 | [Single-host limiter](../src/product/observability.mjs), [429 Retry-After response](../src/http.mjs), [production example limits](../config/examples/gateway.production.json.example), [recorded admission saturation](../artifacts/product-load.json). |
| 7 | [Strict configuration](../src/product/config.mjs), [action/schema boundaries](../src/product/policy.mjs), [malformed input/protocol tests](../test/product-protocols.test.mjs). |
| 8 | [Fixed bounded HTTPS](../src/adapters/transport.mjs), [REST response checks](../src/adapters/rest.mjs), [real TLS malformed/redirect/overflow tests](../test/product-adapters.test.mjs), [receipt acknowledgement tests](../test/product-zanii.test.mjs). |
| 16 | [Atomic operation reservation](../src/product/store.mjs), [duplicate/unknown tests](../test/product-executor.test.mjs), [retention tombstone tests](../test/product-operations.test.mjs). |
| 17 | [Store transactions](../src/product/store.mjs), [rollback/capacity tests](../test/product-store.test.mjs). |
| 18 | [Quota/approval reservation](../src/product/store.mjs), [parallel ancestor/approval tests](../test/product-store.test.mjs), [concurrent duplicate dispatch test](../test/product-executor.test.mjs). |
| 19 | [Shared bounded errors](../src/http.mjs), [real HTTP failure tests](../test/protocol.test.mjs), [real TLS service tests](../test/product-service.test.mjs). |
| 42 | [Parameterized store](../src/product/store.mjs), [HTTPS destination checks](../src/adapters/transport.mjs), [security JSON headers](../src/http.mjs), [Vault CSRF/DPoP contract tests](../test/product-companions.test.mjs). |
| 44 | [Tenant-scoped repository](../src/product/store.mjs), [cross-tenant store tests](../test/product-store.test.mjs), [protocol ownership tests](../test/product-protocols.test.mjs), [companion runtime-tenant test](../test/product-service.test.mjs). |
| 45 | [Config loader](../src/product/config.mjs), [invalid profile/config tests](../test/product-auth.test.mjs), [relative-file-base regression](../test/product-service.test.mjs). |

## Sign-off

Ship approved by: **none**. Accepted GAPs: **none**.

**This system is not cleared to ship until the GAPs above are signed off or closed.**
