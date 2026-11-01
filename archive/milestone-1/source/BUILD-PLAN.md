# Agent runtime research prototype build plan

## Primary goal

Run a reproducible local experiment showing which agent actions are actually blocked, which legitimate tasks succeed, and what happens after credentials or enforcement configuration changes. Produce signed evidence that an independent verifier can check without trusting gateway success messages.

**Authorization:** the user requested “plan and start building” and then explicitly requested a separate project. This plan authorizes the first local research milestone, not deployment, external publication or a production-readiness claim.

**Scope:** a separate Node 24 ESM project in `04-agent-runtime`. The three existing products remain unchanged. Synthetic data only; no paid models, customer credentials, databases, cloud infrastructure or network services exposed beyond loopback. No commits or pushes: this workspace has no Git metadata.

## Phase 0 Documentation discovery

**How this serves the primary goal:** use verified local patterns and the available toolchain rather than inventing APIs or relying on unavailable packages.

- [x] Read the existing research and all three package manifests.
- [x] Inspect at least three applicable implementation/test patterns and available dependencies.
- [x] Check lessons, Git metadata, runtime versions and applicable readiness requirements.

### Findings and allowed APIs

- Stack: Node `v24.19.0`, npm `11.17.0`; Passport and Vault use ESM. Vault already uses `.mjs` scripts and `node:test`.
- HTTP lifecycle: `../01-difc-ai-agent-register/tests/s3-fixture-server.ts:12,49,55` uses `createServer`, loopback `listen(0, '127.0.0.1')`, `closeAllConnections` and awaited `close`. Copy lifecycle, not its permissive fixture authentication.
- Signing: `../01-difc-ai-agent-register/apps/api/src/projections/status-feed.ts:27,36` uses Node Ed25519 `sign(null, bytes, privateKey)` / `verify(null, bytes, publicKey)`.
- Secret comparison: `../02-difc-agent-passport/src/domain/digest.ts:22` hashes credentials and uses length-checked `timingSafeEqual`.
- HTTP boundaries: `../03-difc-evidence-vault/apps/api/src/services/provider-http.ts:43` has fixed configured origins, manual redirects, explicit timeout and bounded reads.
- Process lifecycle: `../03-difc-evidence-vault/apps/api/src/services/worker.ts:197` uses `spawn` with argument arrays, `shell:false`, `windowsHide:true`, an allowlisted environment, bounded outputs and cleanup.
- Offline trust: `../03-difc-evidence-vault/packages/verifier-ts/test/verifier.test.ts:19` tests tampering and externally supplied trust roots.
- `@zanii/runtime`, `broker`, `sdk`, `core`, `policy` and `testing` do not resolve from the existing installation. Only Mandate packages are installed. No runtime import from sibling `node_modules` is allowed.
- Use standard-library crypto for an explicitly experimental exact-byte envelope. It is not a Zanii ledger receipt, JCS interoperability claim, Merkle proof or on-chain anchor. Zanii integration remains a later verified integration.

### Complexity and risk

Complex: multiple trust boundaries, authorization, subprocesses and scientific comparisons. Risks are contained to synthetic loopback fixtures, but security logic needs boundary, integration, concurrency, failure and tamper tests. The 47-row readiness gate applies and must preserve unverified infrastructure/security rows as GAP.

## Proposed architecture and threat model

```text
Trusted experiment controller / evaluator
  | creates fresh credentials, task contract and evaluator key
  | launches resource and broker as separate child processes
  | observes resource state with a separate observer credential
  | signs bounded coverage evidence and final experiment evidence
  v
Untrusted client --> broker: identity + task + coverage checks
                         --> resource: broker-only identity + tenant/object checks
Untrusted direct client --> resource: rejected unless a test deliberately weakens controls
```

The controller, evaluator signing key, fixture resource and its observer endpoint are trusted. The client, request bodies and any agent-supplied authority claims are untrusted. Broker-held resource credentials must not be sent to client processes or included in artifacts. Child-process isolation is process hygiene only; this Windows account is not an adversarial sandbox. Loopback HTTP is a local test transport, not production TLS.

| Threat | Required control / test | Remaining limit |
| --- | --- | --- |
| Forged identity or request | Random ephemeral credentials, hashed/timing-safe comparisons, strict shapes, bounded bodies, expiry and request identifiers | No production IdP integration |
| Cross-tenant or out-of-mission access | Central task authorization; independent provider tenant/object checks | Synthetic resource adapter only |
| Direct access using old credentials | Provider denies legacy credentials by default; actual direct HTTP tests | No OS egress enforcement |
| Stale authorization after drift | Signed record binds resource instance/configuration and task; current-state recheck and resource epoch at dispatch in coverage mode | Real cloud propagation/TOCTOU differs |
| Replay or concurrent overuse | Bounded request IDs, duplicate rejection, atomic admission reservation before awaiting provider calls | Local single broker, no distributed quota claim |
| Tampered evidence / substituted key | Verify signed exact bytes against independently supplied pinned evaluator public key; validate and recompute result summaries | Signature authenticates evaluator statements, not exhaustive protection |
| Downstream failure or timeout | Bounded requests, no mutation retries or direct fallback, classify uncertain outcomes explicitly | No exactly-once external-effect claim |
| Lost enforcement layers | Deliberately enable legacy authority; observe and report successful direct forbidden effects | Invalidating gateway coverage cannot stop direct calls after provider authorization fails |

## Phase 1 Package and trusted boundaries

**How this serves the primary goal:** make the experiment independently runnable and establish a small validated action/evidence contract.

Implement Node 24 ESM with no runtime dependencies. Copy documented HTTP lifecycle, timeout, signing and token-comparison patterns. Use a small research-only task contract: actor, tenant, permitted document IDs, recipients, expiry, revocation and a bounded operation quota. Validate every external object with allowlisted keys and bounded strings/arrays/numbers. Use opaque random identities, not self-asserted roles.

Planned files: `package.json`, `package-lock.json`, `.gitignore`, `README.md`, `src/protocol.mjs`, `src/http.mjs`, `src/policy.mjs`, `test/protocol.test.mjs`, `test/policy.test.mjs`, `docs/architecture.md`, `docs/threat-model.md`, `docs/api.md`, `tasks/todo.md`.

Verification: malformed/unknown/oversized fields; invalid and substituted signatures; independently pinned keys; expiry; exact resource/recipient checks; cross-tenant rejection; no secrets in encoded public records. Syntax check all JavaScript and run meaningful unit tests.

Anti-pattern guards: no fabricated Zanii API, sibling runtime dependency, private key in artifact, client-chosen destination URL, `eval`, shell interpolation or permissive production default.

## Phase 2 Executable broker and resource experiment

**How this serves the primary goal:** exercise real independent HTTP boundaries and inspect actual resource effects.

**Environment adjustment, verified before Phase 2:** Node child-process launch returns `EPERM` here, including `spawnSync(process.execPath, ['--version'])` and the isolated Node test runner. Phase 1's 15 tests pass using the explicitly configured no-child test runner. Implement both a separate-process transport and an explicitly selected `in-process` research transport for this environment. Both use real loopback HTTP. Never silently fall back between them; record transport and lack of process/OS isolation in every result. Separate-process runtime acceptance remains blocked until it can be run in a compatible environment. This is not a reason to weaken service authentication or skip boundary tests.

Implement separate loopback resource and broker processes launched by a trusted harness. Use fixed routes and synthetic documents for two tenants, including a same-tenant document outside the task. Admin fault injection and observer credentials remain controller-only. Process configuration arrives through validated IPC with an allowlisted environment, never credentials in arguments. Ensure bounded startup, requests, outputs and shutdown.

Expose a narrow action endpoint for document read/share; a public health endpoint; authenticated controller operations; and resource observations. The client receives only the broker identity. Separate read-only resource status from resource control. Freeze validated action data and bind any dispatch version to the exact action. Recheck authority for delayed/client-triggered queued work; this milestone need not implement a durable job queue.

Compare three clearly labelled experimental modes using the same task and fixture: `broker-static`, `lease-only`, `coverage-bound`. These are architecture-inspired baselines, not reproductions of published systems. Coverage mode verifies signed scope, freshness and current instance/configuration, and the provider rejects a changed epoch at dispatch. Admission evidence includes actual positive and negative probes. Do not treat an unverified actor-supplied coverage record as authority.

Planned files: `src/resource.mjs`, `src/broker.mjs`, `src/process.mjs`, `src/harness.mjs`, `src/client.mjs`, `test/integration.test.mjs`. Document the timeout distinction: check request deadline before dispatch; once an upstream action may have been sent, a timeout is an uncertain outcome and is never automatically replayed.

Verification: real successful authorized read/share; cross-tenant and wrong-recipient rejection with no effects; wrong/legacy identity; control/observer endpoint separation; replay and parallel quota bounds; changed config/expired coverage; revoked delayed request; provider outage/timeout; graceful child cleanup. Record actual provider events separately from gateway replies.

Anti-pattern guards: no broad proxy, fake production sandbox claim, automatic replay after uncertain mutation, unlimited audit/state arrays, sensitive response logging or disabled authentication on controller routes.

## Phase 3 Reproducible benchmark and offline evidence

**How this serves the primary goal:** turn an architectural claim into an auditable experiment with useful comparisons and honest failures.

Implement a deterministic, model-free client attack corpus and paired legitimate tasks. Record baseline/mode, fixture identity, action IDs, resource outcomes, workload/config versions, local environment and timing. Include cross-tenant and same-tenant mission misuse; direct credential attempts; coverage expiry; tool/config drift; queued-after-revocation; and deliberately weakened resource authorization. The last case must record the resulting forbidden direct effect when the provider allows it. Do not claim prompt-injection detector accuracy without an LLM evaluation.

The independent observer supplies the outcome oracle. Export a signed bounded JSON research bundle and a separately supplied trust key; the verifier requires an explicit pinned key, rejects malformed/tampered data and recomputes summaries. It does not accept an embedded key as its own trust root.

Planned files: `src/evidence.mjs`, `scripts/benchmark.mjs`, `scripts/verify.mjs`, `scripts/load.mjs`, `test/evidence.test.mjs`, `test/benchmark.test.mjs`, `test/load.test.mjs`, `artifacts/` (generated measurements and public evidence only).

Verification: reproducible scenario matrix; expected known failure is reported rather than hidden; negative evidence mutations; unauthorized effect counts are derived from provider outcomes; legitimate completion is reported separately; actual p50/p95/p99 and throughput under stated local load; denied/limited requests are not counted as successful throughput.

Anti-pattern guards: no invented results, first-invention claim, paper-system attribution to our baselines, secrets in outputs or interpretation of empirical evidence as proof of complete mediation.

## Phase 4 Independent verification and handover

**How this serves the primary goal:** provide an experiment another engineer can run and identify what is still required before product or paper claims.

Run fresh independent implementation/security/anti-pattern reviews. Fix findings, rerun affected checks and then the complete new-project suite. Use available lint/type tools where applicable, syntax checks, dependency audit and secret scan. Evaluate all 47 production-readiness rows with artifacts. Run a measured local load experiment, naming any unmeasured breaking point as GAP. Do not modify Git configuration, commit, push, deploy or publish.

Planned files: `docs/runbook.md`, `docs/readiness-report.md`, `docs/research-status.md`; update `README.md`, this plan and `tasks/todo.md` with completed work and measured results.

Verification: `npm test`, `npm run benchmark`, independent `npm run verify -- ...`, local load command, scanner outputs, all local documentation links, no leaked credentials or lingering child processes. Exact commands and results go in the readiness report and review section.

## Deferred beyond this milestone

Production OS sandbox/network enforcement; customer IAM/IdP/cloud/SaaS adapters; actual Zanii runtime/broker/ledger integration; real MCP/A2A adapters; model-based attack generation/detection/learning; persistent queues and audit storage; enterprise deployment/HA/alerts; cross-industry validation; complete white paper results and public publication. These remain explicit next phases, not implied features of a local harness.

## First milestone result

Completed locally on 1 November 2026 (Asia/Dubai), with the frozen experiment recorded in UTC. All new build files are in this project; the first three projects were not modified.

- 43 tests pass; source/script JavaScript checks, basic lint and all 18-module syntax checks pass.
- The 24-case benchmark and offline verifier run successfully. All modes complete their two healthy tasks and expose the deliberately weakened provider's direct-access failure. Coverage-bound mode records no stale broker effects in this corpus.
- The finite load sweep completes 400/400 reads with 400 observed effects. No sustained capacity ceiling or breaking point is established.
- Secretlint reports zero findings across 39 files. The offline audit has zero dependencies/vulnerabilities; no fresh runtime advisory review is claimed.
- Independent implementation, anti-pattern, evidence, metric and final documentation reviews are complete. The [readiness report](docs/readiness-report.md) evaluates all 47 rows: 10 PASS / 13 N/A / 24 GAP, with production clearance withheld.

Use the [README](README.md), [runbook](docs/runbook.md), [research status](docs/research-status.md) and [milestone tracker](tasks/todo.md) to reproduce the experiment and select the next implementation phase. The unverified process transport and production gaps do not invalidate the bounded local results, and those results do not close the production gaps.
