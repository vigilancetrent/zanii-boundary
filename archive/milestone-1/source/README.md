# Agent runtime research prototype

A separate Node 24 project for reproducible experiments on agent authorization under credential and configuration drift. It uses synthetic documents, native HTTP/crypto and Node's test runner, with no runtime dependencies.

Read [the build plan](BUILD-PLAN.md), [architecture](docs/architecture.md), [threat model](docs/threat-model.md) and [API contracts](docs/api.md). Progress is tracked in [tasks/todo.md](tasks/todo.md).

The first local milestone has 43 passing tests, a signed 24-case comparison and 400 successful synthetic load reads. Read [research status](docs/research-status.md) for measured results, [the runbook](docs/runbook.md) before rerunning or archiving artifacts, and [the 47-row readiness report](docs/readiness-report.md) for the unresolved production requirements. These local results do not establish a production capacity ceiling or OS containment.

From this directory:

```powershell
npm test
npm run benchmark
npm run verify -- artifacts/evidence.json artifacts/evaluator-public.pem
npm run load
```

The default runner uses `--test-isolation=none` because this workspace's command sandbox rejects the test runner's child-process launch with `EPERM`. Tests still exercise real loopback HTTP. `npm run test:isolated` retains Node's separate-file process mode for environments that permit it. Neither setting supplies agent OS isolation.

`benchmark` and `load` explicitly select real HTTP with the `in-process` transport. `benchmark:process` and `load:process` select separate processes and fail if that transport is unavailable; they never switch automatically. Neither transport supplies an OS sandbox. The benchmark and load functions default to process transport when called as libraries, so tests must also select in-process mode explicitly.

## Experiments and outputs

The benchmark runs the same eight scenarios against `broker-static`, `lease-only` and `coverage-bound`, creating a fresh fixture for each of its 24 cases. It records real provider reads/deliveries independently of broker replies. These are local architectural baselines, not reproductions of published research systems. No model or prompt-injection detector is evaluated.

- `artifacts/evidence.json`: exact-byte Ed25519-signed experiment envelope, including all provider probe/workload events, attempts and recomputed summary.
- `artifacts/evaluator-public.pem`: generated run evaluator's public key; the private key is never saved.
- `artifacts/benchmark.json`: readable unsigned copy of the experiment payload. Verify the signed envelope, rather than trusting this display copy.
- `artifacts/load.json`: unsigned local closed-loop HTTP load measurements with actual successful effects, request outcomes and latency percentiles. It does not establish a production capacity ceiling.

Running a command again replaces its latest generated public artifacts. Archive a completed run separately before rerunning if it is needed for a paper. The benchmark records Node/platform/architecture/transport and an implementation digest of sorted source, script and package/lock bytes; it fails if these change during the run.

Healthy task completion and forbidden effects are separate metrics. The deliberately broken resource-authority case must record a forbidden direct read in **every** mode. Coverage-bound gateway denial cannot stop a provider that independently accepts an old credential. A successful approved guide read after a tool-version change is counted as stale operational dispatch, not automatically as a forbidden business read. Post-effect response timeouts remain uncertain even when the independent observer sees the committed effect.

Public evidence must contain no credentials or evaluator private keys. Independent verification requires an explicitly supplied pinned public key, never a key trusted merely because it appeared in the same evidence bundle. The example verification command checks a local demonstration under its generated key; an independent reviewer must obtain and pin the intended evaluator key through a separate trusted channel. Colocated files alone establish no trust. Verification checks signature and historical internal consistency, not evaluator honesty, exhaustive coverage, absence of omitted real-world events or first-invention claims. Archived records remain verifiable after their task/lease expiry; live execution has separate freshness checks.

This is a research fixture, not a deployable company protection product. Loopback HTTP is not production TLS. Same-user subprocesses are not a sandbox. No customer IAM, Zanii runtime/broker/ledger integration, learned detector, MCP/A2A integration, persistent audit service or production readiness is implied. The first three projects remain unchanged.
