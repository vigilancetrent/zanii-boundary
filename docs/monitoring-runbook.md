# Monitoring runbook

Use private operator access and preserve redacted request/operation identifiers. Do not put tokens, keys or document contents in tickets or public reports. The thresholds come from `monitoring/alerts.yaml`; changing them requires workload review, not an attempt to silence a failing gate.

These headings are stable alert targets and are validated by `src/product/monitoring.mjs`. See [operations](product-operations.md) for deployment prerequisites.

## scrape

Check the target process, configured network destination, mutual TLS certificate chain and the narrow metrics token. Distinguish a scrape failure from a healthy value of zero. Restore the accepted configuration; do not disable TLS verification.

## probes

Inspect liveness, startup and readiness separately. Check fixed probe destinations, dependency health and the reported reason. A live process is not necessarily ready to authorize work; leave admission closed while required checks fail.

## http

Correlate elevated server errors or latency with bounded request traces, admission saturation, database waits and provider deadlines. Check policy/expiry errors separately from infrastructure faults. Do not extend grants or remove authorization checks to improve latency.

## capacity

Inspect admission concurrency, event-loop delay, CPU and memory against the configured workload ceiling. Reduce offered load or drain the affected instance before changing limits. Validate any new ceiling with representative load and database/provider headroom.

## database

Check pool usage/waits, connection/TLS status, query and lock deadlines, migrations and role permissions. Preserve active transaction and operation state. Do not clear leases, drop rows or increase pool sizes without checking server connection capacity.

## storage

Check free bytes and whether the measurement itself is available on the configured data/log filesystem. Preserve protected audit/backup data and unresolved upload intents. Reclaim only data allowed by the retention/cleanup policy; never delete keys or journals to make space.

## maintenance

Inspect required role heartbeats, lease ownership/fences, due-job age and dead letters. Resolve the failing dependency or configuration before retrying supported jobs. Do not reset attempt counters or bypass ownership checks; escalate unresolved work to the operator.

## backup

Compare snapshot capture age and verification age with the configured maximum. Verify the catalogue, immutable chunks, trust pins and key availability. Treat stale or unverified recovery points as unavailable. Exercise recovery in a separate quarantined target, never over the active source.

## archive

Check the independent archive role, immutable segment upload, digest/version/retention verification and checkpoint continuity. Preserve the protected audit prefix and signing-key custody. A copied file without accepted continuity is not a verified archive.

## certificates

Identify the expiring role certificate, issuer, audience bindings and dependent trust configuration. Rotate through the accepted identity procedure and verify mTLS on both ends. Never share administrative identity material with the agent or relax expiry checks.

## containment

Stop admitting protected work when required deployment evidence expires or topology changes. Reinspect actual host UID mappings, private mounts, agent network closure and provider egress. Obtain a fresh independently trusted acceptance receipt; do not extend a stale receipt by editing timestamps.

## dependencies

Identify the fixed dependency whose circuit is open. Check reachability, TLS, scoped credentials and provider errors, then allow the configured bounded recovery path. Do not redirect traffic to an unaccepted endpoint or blindly retry mutations.

## unknown-actions

Keep the original operation ID. Query durable state and independently observe the resource outcome, then use the supported reconciliation route. Do not issue a replacement operation or replay an unknown mutation. Escalate conflicting or unobservable outcomes.

## logs

Check protected log-directory permissions, free space, bounded buffers and write failures. Preserve redaction and retention limits. Dropped events are an observability gap, not evidence that no actions occurred; investigate before resuming normal admission.

## telemetry

Check exporter acknowledgement failures, collector availability, TLS identity and the configured fixed destination. Inspect bounded queues and receipt freshness. Do not export raw credentials or document content to diagnose missing traces.

## monitoring

Check component health, datasource/TLS configuration and controlled receiver rejection reasons. Verify receipt identity and freshness before treating a test as delivered. An accepted controlled receipt does not prove a person was paged; human escalation needs a designated owner and authorized destination.

## budget

If billing evidence is missing, stale or invalid, report spend as unknown. For warning/exceeded thresholds, verify the explicit budget period, currency and measured usage before adjusting workload. Do not substitute forecasts or unpriced examples for actual billing evidence.
