# Reproducing the product evaluation

These experiments exercise the executable product's gateway and independently authorizing document resource over real TLS 1.3/mTLS and signed, sender-bound workload JWTs. They use encrypted SQLite files, synthetic documents and test identities in a single Node process. They do not demonstrate Linux/container isolation, a live company deployment, paid-model accuracy, or live Register/Passport/Vault/Zanii acceptance.

The original loopback research benchmark remains available as `npm run benchmark` and its archived milestone source/evidence remains under `archive/milestone-1/`. Its numbers describe that implementation. The product measurements below come from separate scripts and are not a new run of a published competitor.

## Commands

Use Node 24.19.0 and Python 3.12 with test-only `cryptography==50.0.0`. Install locked runtime dependencies with `npm ci --ignore-scripts --no-audit --no-fund`, then generate disposable local PKI:

```powershell
python scripts/test-pki.py --flat --output artifacts
npm test
npm run product:check
npm run product:evaluate
npm run product:load
node scripts/product-verify.mjs --evidence artifacts/product-evaluation.signed.json --public-key <independently-pinned-evaluator-public.pem>
```

The evaluator writes `artifacts/product-evaluation.json`, its exact signed representation `product-evaluation.signed.json`, and `product-evaluator-public.pem`. The ephemeral evaluator private key is not written. A public key delivered beside an artifact does not independently establish trust: pin the key through another trusted channel before verifying claims. `product-verify` checks the signed purpose, exact declared cases/statuses, allowed resource-effect associations, recipient/tenant/actor constraints, duplicate effects, primary task completion and independently recomputed totals. It rejects signed fabricated summaries and missing, duplicate or foreign effects. It does not prove that the evaluator or its controlled resource fixture is honest.

The source digest recursively covers package/lock files and supported implementation/configuration files under `src`, `scripts`, `sdk`, `config`, `deploy`, and `fixtures`. It includes the Python client and protocol/industry fixtures, rejects implementation symlinks, and excludes generated PKI, databases, archives, caches and documentation. It identifies source/configuration bytes; it is not deployment attestation. A source mutation during an experiment aborts it. The original archived digest uses its preserved historical implementation.

## Workload and outcome definitions

The fixed 15-case product evaluation includes an authorized read and exactly approved internal-mailbox share, out-of-task and foreign-tenant access, forbidden destination, absent approval/scope, direct resource access using only the agent identity, effect-then-response loss, replay, disk restart, observation-only reconciliation, cached-result revocation and task expiry. Every case asserts both the HTTP outcome and the change in independently queried provider operation records. Three allowed effects are expected: the primary read/share plus the deliberately uncertain read. Replaying or reconciling them must produce no new effect. Internal mailbox commitment does not mean an external email was sent.

The learning study uses the committed, author-authored synthetic corpus: eight explicitly reviewed training examples and eight held-out examples. It runs quarantine, independent review, training, shadow staging and externally signed promotion, checking that the trusted policy digest remains unchanged. Exact normalized training/holdout duplicates are rejected; a deliberately chosen small split does not establish broad generalization, resistance to near-duplicate leakage, novel attacks or production precision/recall.

`product-load.json` records a finite closed-loop read sweep at concurrency 1, 4, 16 and 64, with 128 unique requests per level by default. The gateway admission limit is deliberately 16 concurrent admitted requests; the resource limit is 128. Success, throttling (429), pending/unknown (202), other client denial, server/transport error and actual unique provider effects are counted separately. Effects without a successful response remain visible. No mutation is automatically retried.

Latency p50/p95/p99, successful requests/second, process CPU milliseconds and before/after RSS are measured. CPU/RSS combine the evaluator, gateway and resource in this one process. Per-level throughput excludes fixture setup and observation. An illustrative local target is 10 requests/second with 250/2000/5000 ms p50/p95/p99 targets; these are experimental targets, not an agreed customer SLO. A 429 identifies configured admission saturation. It does not establish hardware failure, sustained arrival-rate capacity, a production capacity ceiling or autoscaling behavior. Monetary billing and an external cost model remain unmeasured.

## Recorded local run

Canonical run `a0a30db5-3efb-4436-8bad-7a1a88f7106b` identifies implementation digest `8478c9ac636aa9cedd40d561dca79c2d48de72a8f334b01741f4a5dc36516a62`. The [measurement manifest](../artifacts/product-manifest.json) inventories 66 implementation/configuration files and the public experiment artifacts. The [evaluation](../artifacts/product-evaluation.json) passed all 15 declared cases, completed 2/2 primary tasks, observed the three expected effects, and observed no negative or duplicate effects. Its [signature and independent recount](../artifacts/product-evaluation.signed.json) verified with the explicitly supplied generated public key; independent trust delivery and independent reproduction remain external requirements.

The [final load run](../artifacts/product-load.json) ran after the parent's full verification finished. It issued 512 requests: 400 succeeded and 112 received 429. It recorded zero pending outcomes, other denials or transport/server errors, exactly 400 unique provider effects, and no effect lacking a successful response.

| Concurrent clients | Successful / issued | 429 | Successful req/s | Successful p50 ms | Successful p95 ms | Successful p99 ms |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 128 / 128 | 0 | 27.3294 | 34.1328 | 52.2972 | 65.7214 |
| 4 | 128 / 128 | 0 | 27.6047 | 137.7179 | 174.3805 | 190.3793 |
| 16 | 128 / 128 | 0 | 23.5520 | 675.8867 | 719.3712 | 728.8701 |
| 64 | 16 / 128 | 112 | 12.3359 | 1293.1388 | 1296.9766 | 1296.9766 |

The configured 16-request admission budget saturated. The hardware and production breaking points remain unestablished; 27.6047 successful requests/second is the maximum observed short-run throughput, not a deployment capacity promise. The synthetic detector holdout produced 4 true positives, 4 true negatives and no false positives/negatives; its limitations remain those described above.

## Quality and deployment gates

`product:check` parses all relevant ES modules through Node's experimental VM module parser and checks five named forbidden-source patterns. It does not claim comprehensive static analysis. `product:lint` and `product:typecheck` run actual ESLint and TypeScript checkJs, respectively. Development tooling must be explicitly installed or supplied through `RUNTIME_TOOLING_ROOT` pointing to a development `node_modules` directory. Type checking is deliberately non-strict (`noImplicitAny:false`, `strictNullChecks:false`); passing it is not a proof of type safety. The offline development-tool install could not resolve the local cache, so no locked development-tool dependency or offline reproducibility claim is made.

The CI template `.github/workflows/product.yml` installs explicitly versioned development tooling (TypeScript 6.0.3, ESLint 9.39.5, Node types 26.6.6, Secretlint 13.1.0 with its recommended preset), runs source parsing/basic lint/checkJs/source secret scanning, the full tests, isolated tests, the explicit Linux socket gate, Python tests, advisory audit and both product experiments. Tooling transitive resolutions and CI execution are not validated here. Runtime dependencies remain locked. Source scanning deliberately excludes generated private PKI, databases and caches; secret-free source examples do not establish data minimization for all customer content or clean repository history.

`npm run product:socket-acceptance` is a separate mandatory Linux Unix-socket TLS test. On Windows it fails explicitly with `SOCKET_ACCEPTANCE_REQUIRES_LINUX`. It is not silently skipped or substituted with TCP. Docker/Podman are unavailable in this environment and process spawning is restricted; passing the in-process suite cannot close those deployment gates. A real Linux stack must run the containment checker with its independently provisioned pinned image and signer. Never fabricate a successful containment receipt from these local measurements.

`monitoring/alerts.yaml` and `monitoring/dashboard.json` are importable example definitions for the actual exported counters and active-request gauge. Thresholds must match the deployed configuration, and a protected metrics scrape identity/transport must be provisioned. No live dashboard, delivered alert, per-endpoint histogram, storage/certificate exporter or on-call routing is established by these files.
