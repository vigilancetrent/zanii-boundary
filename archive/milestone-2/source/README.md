# Company agent protection runtime

A separate Node 24 project for governed company-agent document actions. The gateway checks task, tenant, document, recipient, approval, expiry and data-flow permissions; reserves durable operation state; and calls an independently authorizing resource over mTLS. Agents receive a narrow runtime identity. Upstream credentials stay in the gateway.

The project includes an encrypted SQLite journal, unknown-outcome reconciliation, signed audit export, bounded result retention, Node/Python clients, reviewed adaptive warnings, MCP/A2A handlers, Zanii broker/SDK integration, companion clients and a Linux Docker/Compose profile. **Deployment acceptance is incomplete.** Read the [requirement register](PRODUCT-REQUIREMENTS.md), [current status](docs/product-status.md) and [47-row readiness report](docs/product-readiness-report.md) before using it with company data.

The supported first workflow is an internal REST/document service using the documented resource contract. Sharing commits to an internal mailbox; it does not pretend to send external email. General, finance, healthcare and industrial profiles govern document operations. Additional company systems need a trusted adapter and resource-side authorization; this is not universal plug-and-play industry protection.

## Run local verification

From this directory, with Node 24.19.0 and Python 3.12+:

```text
npm ci --ignore-scripts
python scripts/test-pki.py --flat --output artifacts
npm test
python sdk/python/test_agent_runtime.py
npm run product:check
npm run product:evaluate
npm run product:load
```

The PKI helper requires `cryptography==50.0.0`. It creates short-lived test identities in ignored artifacts; never include their private keys in an image or public evidence bundle. An existing verified inventory can add the separate broker public trust with `--add-broker-trust`.

`npm test` runs real TCP/mTLS and disk-store tests with Node file isolation disabled because this Windows sandbox rejects child launch. It does not provide agent OS isolation. `npm run test:isolated` and `node --test --test-isolation=none test/acceptance-product-socket.mjs` are separate acceptance gates. Passing the default suite cannot close a blocked process, Linux UDS or container gate.

Start the two local-test service roles in separate terminals:

```text
node scripts/start.mjs --config config/examples/resource.local-test.json
node scripts/start.mjs --config config/examples/gateway.local-test.json
```

These examples require explicit signed identities and report containment as unverified. Production templates deliberately contain provisioning placeholders. See [API/configuration](docs/product-api.md), [operations and SDKs](docs/product-operations.md), [deployment](deploy/README.md) and the [product runbook](docs/product-runbook.md).

The final Secretlint 13.1.0 source/config/test/docs/CI/monitoring scan checked 114 files with zero errors, warnings or messages; parsed results are recorded in `artifacts/product-final-secretlint.json`. Generated private PKI and databases are excluded. This does not establish clean Git history or a fresh dependency/image vulnerability scan.

A separate explicit whitelist scan of seven public evaluation/recovery artifacts also returned zero messages (`artifacts/product-public-secretlint.json`); it used `--no-gitignore` without including private PKI or databases.

## Evidence and research

The [engineering white-paper draft](paper/white-paper.md), authored by **zinii ai**, describes the implementation, measured local experiments, prior work and remaining limits. It is a local draft; no publication, first-invention claim or independent reproduction is implied. [Benchmark methodology](docs/product-benchmark.md) describes the current product workload and artifacts.

Product evaluation writes `artifacts/product-evaluation.json`, its signed envelope and a public evaluator key. Independently verify the signed artifact using a separately trusted public key:

```text
node scripts/product-verify.mjs --evidence artifacts/product-evaluation.signed.json --public-key <independently-pinned-evaluator-public.pem>
```

Colocated evidence and a public key do not establish trust. Signatures establish authenticity and declared consistency, not evaluator honesty, complete mediation or exhaustive security. Customer audit exports contain encrypted business audit data and remain access-controlled.

The earlier HTTP research experiment is preserved under `archive/milestone-1/`. Its 43 tests, 24 cases and load measurements are historical evidence for that archived source. Original `benchmark`, `load`, `verify` and research client exports remain available; they do not evaluate the new product path. Current and historical source digests must not be conflated. The first three companion projects were not modified.

## Remaining acceptance

Run the real Linux/container/socket checks with a verified pinned image, provision company/companion/Zanii identities and trust anchors, implement the unavailable upstream Zanii Runtime integration once its package can be obtained, and close or explicitly accept the readiness gaps. No Docker/Podman host, live customer systems, live ledger, external anchoring, off-site recovery, deployed alert routing or production capacity ceiling has been established here.
