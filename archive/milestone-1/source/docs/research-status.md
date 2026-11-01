# Research milestone status

The first local milestone is implemented: a task-scoped broker, independently authorizing synthetic resource, signed coverage record, three experimental modes, deterministic adversarial client corpus, independently observed resource effects, offline verifier and a finite local load sweep. This is not a deployable company-protection runtime or a completed empirical white paper.

## Frozen recorded evidence

| Item | Recorded result |
| --- | --- |
| Canonical benchmark run | `cd8c6563-91ae-45b6-af3b-ffc6deb20867` |
| Source/script/package digest | `e25385e5f8108076eb560fb47ac0a9a42d133d1b9c65204f219f6a718e4eb819` |
| Environment | Node `v24.19.0`, Windows x64, explicit `in-process` transport, no model |
| Unit/integration/evidence/load tests | 43 passed; 0 failed, skipped or cancelled; `../artifacts/test-output.txt` |
| Benchmark matrix | 8 scenarios × 3 modes = 24 fresh fixtures; `../artifacts/evidence.json` and `../artifacts/benchmark.json` |
| Offline verification | Signature and historical consistency verified using an explicitly supplied evaluator public key; no network required |
| Static checks | 18 JavaScript modules passed syntax checks; limited ESLint and source/script checkJs passed; `../artifacts/static-checks.txt` |
| Dependency audit | Zero installed dependency packages; offline npm audit reports zero vulnerabilities, not a fresh advisory or Node runtime audit |
| Secret scan | Installed Secretlint recommended preset scanned the current project/public artifacts; details in `../artifacts/security-scan.txt` and JSON summary |

The benchmark implementations are architecture-inspired local baselines. They are not reproductions of AgentSpec, ACLE-MCP, FORGE or any other published system. Existing Zanii runtime/broker packages were unavailable locally and are not integrated. The experimental exact-byte envelope is not a Zanii receipt, JCS format, Merkle proof or on-chain anchor.

## Observed comparisons

| Mode | Healthy work | Workload effects | Forbidden effects | Stale broker dispatches | Expired-coverage dispatches | Effects without successful response |
| --- | --- | --- | --- | --- | --- | --- |
| `broker-static` | 2 / 2 | 7 | 1 | 2 | 1 | 1 |
| `lease-only` | 2 / 2 | 6 | 1 | 2 | 0 | 1 |
| `coverage-bound` | 2 / 2 | 4 | 1 | 0 | 0 | 1 |

Admission probes remain in signed traces but are excluded from workload totals. Every forbidden effect above comes from the intentional `broken-resource` case: the provider accepts a legacy identity and performs a same-tenant, out-of-task direct read. This is a demonstrated limit, not a hidden benchmark failure. A normal guide read performed after a tool epoch change counts as stale dispatch rather than automatically becoming a forbidden business read. All three modes report the post-effect timeout as uncertain instead of equating a missing success reply with prevention.

These are single-run deterministic fixture observations, not statistical estimates of detector accuracy, attack generalization or cross-industry efficacy. No model, prompt-injection detector, adaptive learning algorithm or customer agent was tested.

## Local load

The frozen `../artifacts/load.json` contains 100 reads each at concurrency 1, 4, 8 and 16: 400 requested, 400 successful responses, 400 observed effects, zero denials and zero errors. Maximum observed successful throughput was 443.99 requests/second at concurrency 16, with p50 35.38 ms, p95 39.09 ms and p99 41.09 ms. The planning comparison of 25 local requests/second is not a production demand forecast.

This is a brief closed-loop synthetic read sweep excluding fixture startup and final observation. It does not establish sustained arrival-rate capacity, a breaking point, a production ceiling or the first resource bottleneck. There was no predeclared endpoint latency SLO, so measurements do not establish SLO acceptance.

## Conditions for stronger claims

1. Execute and adversarially validate the separate-process profile, then deploy a genuine OS/network containment profile with broker-only resource authority and revoked legacy grants.
2. Implement and validate customer identity/resource adapters, durable authorization/idempotency/audit behavior, controlled recovery and deployed operations.
3. Define workloads, threat assumptions, SLOs, repeated trials, holdout/adaptive cases and fair baselines before comparative research measurements.
4. Obtain independently trusted observation, independent verifier/key distribution and independent reproduction. A signature authenticates an evaluator statement, not its truth or complete route discovery.
5. Reassess novelty against primary work before claiming an original research contribution. No new invention, paper acceptance, regulatory compliance or publication has been established.

The [47-row readiness report](readiness-report.md) distinguishes local evidence from open production requirements. See the [runbook](runbook.md) before rerunning or preserving these artifacts.
