# Readiness and evidence

**Not cleared for production.** The repository implements a bounded document-action gateway and local verification tooling. Local fixtures, static configuration checks and signed statements do not establish acceptance on a customer deployment.

This document summarizes the supported scope and remaining gates. It is not a certificate or a claim that a fresh full verification run has passed. Consult the actual command output for the revision being evaluated.

## Acceptance gates

| Area | Evidence still required |
| --- | --- |
| Host containment | Supported rootful userns-remapped Linux Docker host; inspected UID/GID maps, exact private mounts, bounded tmpfs and no agent networking. |
| Resource enforcement | Customer identity and task policy; complete provider credential/route inventory; scoped IAM and revocation of unrestricted legacy access. |
| Database | Real PostgreSQL wire sessions, role/TLS checks, independent concurrency and failover/recovery acceptance. PGlite is not HA evidence. |
| Storage and keys | Genuine object versioning, immutable retention and KMS/provider policies; independent custody, archive checkpoints and recovery trust roots. |
| Recovery | Separate recovery target, authenticated backups, source fencing, privacy reconciliation and a measured restore exercise. |
| Delivery security | Actual built/scanned product image, native scanner execution, producer-bound evidence, provenance and independently trusted CI identity. |
| Operations | Live monitoring receipt checks, accepted human escalation destination, named owners and tested incident/recovery procedures. |
| Capacity and cost | Representative customer workload, accepted latency/throughput targets, dated provider quotes and measured billable usage. |

General, finance, healthcare and industrial profiles require customer review. They are not industry certification. Other company systems require trusted, independently authorizing adapters.

## Performance limits

The recorded Runtime-enabled objective remains unmet: a 5 requests/second warmup reached grant expiry before a 10 requests/second sustained cohort. Expiry guards prevented dispatch after authority expired. A separate lower-rate characterization completed correct effects but exceeded the unchanged median-latency target.

Canonical product evaluation and load profiles remain core-only. Do not present archived prototype results or a reduced-rate run as acceptance of the original Runtime-enabled target. Capacity methods and their limits are described in [capacity measurement](capacity-measurement.md) and [capacity and cost](capacity-cost.md).

## Recorded security observations

Recorded online npm auditing found four moderate affected dependency entries attributable to one minimatch advisory, with no reported high/critical entries. A separate manual Trivy filesystem observation found the same medium advisory and a low mixed-role healthcheck observation. These are historical observations, not a fresh scan of this revision or a built image.

Imported JSON/SARIF alone does not establish that a scanner ran. The security tooling binds evidence to producer identity, source/lock/image inputs and tool output. Do not weaken dependency checks or downgrade tooling to manufacture a green result.

## Reproducible local checks

Use the [README setup commands](../README.md#local-setup). Additional checks include:

```sh
npm run product:delivery-policy
node scripts/security-report.mjs secrets
npm run test:isolated
npm run product:socket-acceptance
node scripts/distributed-acceptance.mjs --static
node scripts/monitoring-acceptance.mjs --static
```

Missing prerequisites intentionally produce nonzero `BLOCKED` results. `liveVerified: false` remains false after a static check. Keep raw scanner output, PKI, local databases, provider credentials and commercial inputs outside public bundles.

## Evidence interpretation

Archives retain historical source and experiment records. Their results do not evaluate the current revision. Some local evidence paths refer to generated `artifacts/` files that are intentionally not published.

The white paper is an engineering draft with attributed prior work, not a published or independently reproduced result. No first-invention, patentability, worldwide priority or superiority claim is established. Signatures authenticate statements under configured keys, not evaluator honesty or full route discovery.

See [architecture and trust](product-architecture.md), [operations](product-operations.md) and the [distributed deployment guide](../deploy/distributed/README.md).
