# Operations

The supported deployment target is Linux Docker/Compose. Do not admit company data until host containment, provider enforcement, recovery and operational ownership are accepted. See [readiness](product-readiness-report.md) and [distributed provisioning](../deploy/distributed/README.md).

## Identity and configuration

Provision separate owner/approver, app, worker, archive, backup, rotator, migrator and independent evaluator identities. Keep provider credentials, decryption/signing keys, administrative tokens, scanner results and commercial inputs outside agent access. The agent receives only its narrow identity, public trust material and permitted relay access.

Use protected operator configuration files based on the repository examples. Pin actual images and provider destinations; never treat placeholder values as a working deployment. Verify issuer, audience, mutual TLS, file permissions, mapped UIDs and scoped egress before starting workloads. Do not reuse assistant-provider credentials.

## Bring-up

Install the locked dependencies and run the [local checks](../README.md#local-setup). Static inspection can identify invalid templates but cannot establish live containment:

```sh
node scripts/doctor.mjs --static
node scripts/distributed-acceptance.mjs --static
node scripts/monitoring-acceptance.mjs --static
```

Run migrations under a dedicated migrator, then verify storage and start each maintenance role with its own private configuration:

```sh
node scripts/migrate.mjs <private-migrator-config.json> up
node scripts/storage-check.mjs <private-role-config.json>
node scripts/worker.mjs <private-worker-config.json>
```

These placeholders are not runnable credentials or sample deployment approval. Validate configuration schemas and command requirements before use. Do not use a down migration to discard active authority, protected audit history or key epochs.

## Monitoring

The bundle under `monitoring/` provides Prometheus, Alertmanager, Grafana, OpenTelemetry Collector, Loki, Tempo, a controlled receipt receiver and fixed probes. Use digest-pinned images, dedicated TLS identities and protected tokens. Dashboard endpoints are not public service endpoints.

Alert annotations depend on the exact headings in [the monitoring runbook](monitoring-runbook.md). Static configuration checks do not demonstrate native component acceptance, deployed dashboards or real alert/log/trace delivery. Human notification destinations require explicit owner authorization; the supplied controlled receiver is not a paging service.

## Incident handling

Reject new protected work when required authority, coverage, maintenance or provider dependencies cannot be established. Preserve operation IDs, request correlations and redacted diagnostic evidence. Never bypass expiry, disable certificate verification or replay a mutation merely to recover availability.

For unknown effects, inspect the durable operation and resource observation using the same operation ID. Reconcile the provider outcome before allowing a new effect. Escalate unresolved conflicts to the designated operator rather than deleting operation state.

## Backup and restore

Verify archive and backup freshness, immutable object versions, catalogue/checkpoint trust and decryption-key retention. The initial logical snapshot limit is 64 MiB per tenant; provision memory and spool capacity explicitly.

Restore into a new empty realm. Keep it quarantined until source fencing and privacy reconciliation are accepted; pre-restore task/approval authority must not resume automatically. Do not activate both the original source and a recovered budget/quota history. Retaining ciphertext does not protect against key deletion.

## Security delivery

The existing GitHub workflow runs local checks and native security gates; its presence does not prove a successful hosted run. Actual image provenance, scanner output and producer trust must be verified for the release revision. Keep generated PKI, database files, raw reports and image archives private. Public summaries must not disclose credentials or customer content.

## Cost and capacity

Use [capacity measurement](capacity-measurement.md) and [cost inputs](capacity-cost.md). An unpriced example must remain an unknown total, not a zero-cost claim. A representative workload and genuine quotes are required before setting production limits or budgets.
