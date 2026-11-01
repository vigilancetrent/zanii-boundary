# Local research runbook

This is a best-effort synthetic experiment, not a continuously deployed service. Downtime is acceptable for the whole local run: stop a failed run, retain its diagnostics, and start a fresh run. Do not attach company credentials or customer data.

## Prerequisites and execution

Use Node 24 or later; the recorded run used Node `v24.19.0` on Windows x64. There are no installed project dependencies or paid services. From `04-agent-runtime`:

```powershell
npm test
npm run benchmark
npm run verify -- artifacts/evidence.json artifacts/evaluator-public.pem
npm run load
```

The test command explicitly disables per-file process isolation because child creation returns `EPERM` in this command sandbox. The benchmark and load commands explicitly use `in-process` transport with actual loopback HTTP. There is no fallback between transports. On an environment permitting child creation, use `npm run test:isolated`, `npm run benchmark:process` and `npm run load:process`; their acceptance remains unverified here. Same-user child processes still do not supply OS containment.

## Preserve a run before rerunning

Benchmark and load commands replace the latest artifacts. Copy the entire public artifact set to a separately named archive before rerunning: signed `evidence.json`, `evaluator-public.pem`, readable `benchmark.json`, `load.json` and associated check outputs. Preserve the corresponding source tree and lockfile. The signed environment's source digest covers source/scripts and package/lock bytes, not documentation or test files. Never archive runtime credentials, process configuration or evaluator private keys.

The public key beside a bundle is demonstration material, not an independent trust decision. An independent reviewer must obtain and pin the expected evaluator public key through a separate trusted channel. The verifier authenticates that evaluator and historical consistency; it does not establish evaluator honesty or exhaustive event capture.

## Failure diagnosis

| Symptom | Check and response |
| --- | --- |
| `PROCESS_TRANSPORT_UNAVAILABLE` / `EPERM` | Child creation is blocked. Keep the failure explicit. Select in-process mode only as a documented local HTTP experiment; do not report separate-process acceptance. |
| Invalid signature or inconsistent evidence | Retain the original bundle and independently pinned key. Check archive pairing and implementation digest; do not edit the bundle to make verification pass. Re-run a new experiment if needed. |
| `COVERAGE_STALE`, expired coverage, or `CONFIGURATION_CHANGED` | Expected after relevant faults. Do not bypass the gate. A trusted controller may collect fresh positive/negative probes and install new signed coverage. |
| `TASK_REVOKED`, task expiry, quota or replay rejection | Expected protection. A fresh task/run is required; do not reuse admitted action IDs or widen the task silently. |
| `OUTCOME_UNCERTAIN` | A provider effect may already have happened. Consult observer events using the trusted controller. Do not replay the business operation to repair a response. |
| Forbidden event in `broken-resource` | This is an intentional negative control. Every mode should expose one direct legacy-credential effect. Gateway denial cannot repair independently broken provider authorization. |
| Test or downstream timeout | The fixture is local and disposable. Stop it, preserve diagnostics and rerun. Do not disable deadlines or add automatic mutation retries. |
| Load degradation | Record concurrency, successful effects, denials and errors separately. Do not call rejected requests successful throughput or extrapolate a short burst into sustained capacity. |

## Operations and security limits

There is no on-call service, external alert routing, managed secrets store, production IdP, TLS, durable queue/audit store or deployment automation. A controlled process shutdown closes listeners and connections; it is not a zero-downtime drain guarantee. No HTTP listener binds beyond numeric loopback. There is no OS egress policy or protection against hostile code running as this host user.

In the recorded corpus, stored public research fields are fixed synthetic actor/tenant/document/recipient identifiers, opaque request IDs, timestamps, configuration versions, effect metadata, timings, source digest, public key and signatures. No IP addresses, actual emails, customer documents, business credentials or evaluator private keys are intentionally persisted in that corpus. This is not a general input privacy guarantee: bounded identifiers can contain `@` or personal data if callers provide it outside the fixed corpus. Public artifacts are retained locally until their owner archives or deletes them; there is no enforced retention/deletion job or customer privacy service.

Review [readiness](readiness-report.md), [research status](research-status.md), [API](api.md) and [threat model](threat-model.md) before making a claim. There is no production release or rollback target. To undo local work, stop the experiment and restore an archived source/artifact copy; no cloud infrastructure or database is mutated.
