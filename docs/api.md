# Research API contracts

All times below are integer Unix milliseconds. Identifiers are bounded ASCII identifiers. Unknown fields are rejected. Input arrays are bounded and duplicate values are rejected. These contracts apply to the local fixture only.

## Action

```json
{"id":"request-1","kind":"read","documentId":"tenant-a-guide"}
```

`share` additionally requires `recipient`; `read` must not include it. Requests never contain an outbound URL, tenant override, credential, role or approval claim.

## Task

Required fields are `id`, `actorId`, `tenantId`, `documentIds`, `recipients`, `expiresAt` and `maxActions`. `revoked` is optional and defaults to false. The authenticated identity must match the contract. A task grants access only to listed documents and recipients; it does not authorise every action the resource service can perform.

## Coverage record

Required fields are `version: 1`, `resourceId`, positive integer `configurationVersion`, `taskId`, `issuedAt`, `expiresAt` and `checks`. Checks must explicitly be `authorizedRead: true`, `directDenied: true` and `wrongIdentityDenied: true`. A record is scoped to one task/resource configuration, has a bounded lifetime and still requires current-state comparison at dispatch.

## Experimental signed envelope

The envelope has exactly `version`, `purpose`, `payload` and `signature`. Payload and signature use canonical base64url encoding. `payload` holds exact UTF-8 JSON bytes; Ed25519 signs a version/purpose domain separator followed by those bytes. No public key is accepted from the envelope. Verification takes a pinned public key and expected purpose supplied independently.

This is a research transport format, not an interoperability standard. The parser validates signatures and bounded JSON; the receiving service separately validates the payload schema, scope and freshness. A valid signature alone grants no authority.

## HTTP conventions

Listeners bind to `127.0.0.1` on an ephemeral port. Fixed versioned routes are defined by the resource and broker modules. Error bodies have `error.code` and a generated `error.requestId`; exception messages, request credentials and stack traces are omitted. Responses are JSON, non-cacheable and protected by basic content-security headers. Downstream requests use a configured loopback origin, explicit timeouts, bounded reads and no redirects or automatic retries.

## Resource routes

| Method and path | Identity | Contract |
| --- | --- | --- |
| `GET /health/live`, `GET /health/ready` | Public | Bounded `{ok:true}` fixture health |
| `GET /v1/status` | Broker resource identity | Resource ID, configuration/tool versions, declared fixture settings and change time; no credentials |
| `POST /v1/actions` | Broker; legacy only in deliberate fault cases | `{actorId,tenantId,action,expectedConfigurationVersion?,deadlineAt?}` |
| `POST /v1/control` | Controller resource identity | Nonempty exact patch of `brokerOnly`, `legacyEnabled`, `toolVersion`, `delayMs`, `responseDelayMs`; each accepted mutation increments configuration version |
| `GET /v1/observations?after=0&limit=32` | Independent observer identity | At most 32 actual successful resource-effect events plus total count; unknown or duplicate query parameters are rejected |

The resource has three fixed synthetic documents: `tenant-a-guide`, `tenant-a-secret` and `tenant-b-secret`. The task permits only the guide and sharing to `internal-team`. Resource authorization independently rejects foreign-tenant documents and forbidden sharing destinations. The legacy key always represents `agent-a` in `tenant-a`, regardless of submitted identity fields. By default it is disabled and only broker access is permitted.

An observed event has `id`, `actionId`, `kind`, `documentId`, `actorId`, `tenantId`, `via`, `configurationVersion`, `at`, `result` and an optional share `recipient`. It records an actual read or delivery, not a broker denial message. Events and replay IDs are bounded for a single run. Admission probes use an `admission-` action-ID prefix and must not be counted as workload effects.

## Broker routes and modes

| Method and path | Identity | Contract |
| --- | --- | --- |
| `GET /health/live` | Public | Local process health only |
| `GET /health/ready` | Public | Authenticated resource status, valid schema and expected resource identity; failure returns only `{ok:false}` |
| `POST /v1/actions` | Task's opaque client identity | Exact action; tenant and actor come from trusted startup task |
| `GET /v1/control/state` | Broker controller identity | Admission counters/revocation and current coverage, without secrets |
| `POST /v1/control/revoke` | Broker controller identity | Empty object; rejects subsequent action admission |
| `POST /v1/control/coverage` | Broker controller identity | `{envelope}`; requires pinned evaluator signature and correct task/resource scope |

All three modes enforce the same task scope, replay protection and bounded quota. `broker-static` ignores coverage. `lease-only` checks the signed record's scope and expiry. `coverage-bound` additionally compares live resource configuration and supplies that version for the resource to recheck immediately before the effect. These are local architectural baselines, not reproductions of outside systems.

The broker reserves request IDs and quota immediately before dispatch, after any live-status await. Dispatch deadline is the minimum of provider timeout, task expiry and coverage expiry when applicable. The resource checks this deadline and the supplied configuration version after an intentional delay and before the actual effect. HTTP timeouts do not cancel already committed effects: a timeout or malformed response after dispatch returns `OUTCOME_UNCERTAIN` and is not retried. Revocation stops new admission; it does not magically cancel an already sent provider request.

## Trusted harness

`startHarness({mode,transport,maxActions,taskLifetimeMs,coverageLifetimeMs,providerTimeoutMs,maxEvents})` defaults to separate-process transport. Explicit `transport: 'in-process'` retains real loopback HTTP but has no process isolation. Process launch failure returns `PROCESS_TRANSPORT_UNAVAILABLE`; there is no automatic fallback.

The returned controller exposes `client`, `direct`, `observe`, `state`, `mutate`, `revoke`, `refreshCoverage`, `setCoverage`, `coverage`, `closeResource` and `close`, along with mode/transport, public key, task and origins. Its test-only `clientToken` and privileged closures must not be passed to an agent or serialized as evidence. Report writers select specific public fields. `refreshCoverage` performs real positive and negative probes; its optional timestamp overrides are controller-only aging/future-time fault inputs, not a claim that probes occurred at an invented time.

## Experiment evidence and offline verifier

`runBenchmark({transport})` from `scripts/benchmark.mjs` returns a payload without writing artifacts. Its default is process transport; the package command explicitly chooses in-process transport. Each mode runs the fixed `SCENARIOS` corpus: healthy read/share, mission/tenant/recipient misuse, direct legacy access, tool-version drift, expired coverage, post-revocation dispatch, deliberately broken resource authorization and uncertain post-effect response.

The payload has exact fields `version`, `runId`, `startedAt`, `finishedAt`, `environment`, `cases` and `summary`. Environment records Node/platform/architecture, transport, `model: 'none'` and a SHA-256 implementation digest. Digest input is a sorted list of `[relativePath, fileSha256]` pairs for `src/*.mjs`, `scripts/*.mjs`, `package.json` and `package-lock.json`. The runner checks it before and after the experiment. It is a reproducibility identifier, not remote attestation.

Each case contains its mode/scenario, resource identity, initial task, observed final configuration version, accepted coverage version/issuance/expiry, all attempted actions and statuses/timing, all independently observed provider events, observed cardinality and duration. Admission probes remain present and explicitly marked by action-ID prefix; they are excluded from workload metrics. Exact corpus templates, unique identities, action/event association, kind/recipient consistency and cardinality are checked. Successful replies require matching provider effects. Missing cases, duplicate events, substituted operations, unknown fields and inconsistent summary totals are rejected.

`summarizeExperiment(payload)` derives actual forbidden effects from the initial task's identity, document/recipient scope and expiry, plus the declared revocation phase. It separately counts stale broker dispatch against accepted coverage configuration, effects after coverage expiry, useful healthy work, rejection/uncertain replies and latency. A direct effect through a weakened resource remains a forbidden business effect even when the gateway denied its own request.

`verifyEvidence(envelope, pinnedPublicKey)` verifies the `experiment`-purpose Ed25519 signature and returns `{ok,runId,environment,summary}` only after historical consistency checks. It uses no network and no present-time expiry check. `verifyFiles(bundlePath,pinnedKeyPath)` bounds file reads and requires both paths explicitly. An embedded key is never trusted. Signed test statements are not proof of complete mediation or producer honesty; independently trusted collection and reproduction remain necessary.

## Local load measurements

`runLoad({transport,concurrency,requests})` from `scripts/load.mjs` defaults to process transport, concurrency levels `[1,4,8,16]` and 100 requests per level. The package command explicitly selects in-process transport. CLI arguments are `--transport=process|in-process`, `--requests=N` and `--concurrency=1,4,...`; settings are strictly bounded. Measurements pair successful HTTP responses with unique actual resource effects. Rejections and transport failures do not count toward successful throughput. The report states local closed-loop scope and leaves the capacity ceiling unset when no breaking point was measured.
