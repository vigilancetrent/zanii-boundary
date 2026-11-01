# Product operator runbook

This runbook covers the initial single-host document runtime. It is not an assertion that the stack, alerts, disaster recovery or Linux containment have been deployed. Before company use, assign a named service owner, security responder, backup custodian and on-call destination, then close the [readiness gaps](product-readiness-report.md).

## Provision and admit work

1. Use the [deployment instructions](../deploy/README.md) to provision separate gateway/resource data paths, issuer and broker public JWKS, role-specific TLS keys and external secret files. Supply verified digest-pinned base/product images. Keep the containment signing private key and detector-promotion private key outside the services and agent.
2. Inventory and revoke legacy credentials, browser sessions, alternate API routes and child-worker identities. The resource must accept only intended broker grants for protected effects. Route company agents through the authenticated socket; do not mount Docker or upstream keys into them.
3. Review purpose, sensitivity, recipient classification, industry profile, expiry, quota and delegation policy. Create grants with an operator identity; obtain independent exact approvals where required.
4. Start the production control plane. Ordinary business actions/readiness remain blocked without a fresh receipt. Provision the agent with only its narrow identity and, if needed, the harmless `containment:probe` scope. Run the actual Linux checker using the fixed public diagnostic to issue the first genuine containment receipt.
5. Mount that receipt and its pinned public key into both gateway and resource. Check authenticated readiness, current coverage, provider version, audit verification and required integration state before admitting tasks. Repeat real acceptance after relevant configuration, credential, image or network changes.

No operator identity is mounted into the agent to solve bootstrap. The diagnostic accepts exactly an empty object and a fixed public canary; it cannot select a company document.

## Runtime unavailable

For an unavailable/readiness alert, inspect `/v1/coverage`, receipt signature/freshness, image/profile pins, both service mounts, provider status, audit integrity and maintenance health. Stop new admissions while a required dependency or boundary is unavailable. Rerun actual host checks; never switch production to local-test or fabricate a receipt. Escalate to the platform/security owner.

A failed audit or maintenance check requires preserving the DB/WAL and latest externally retained checkpoint, isolating affected storage and involving the security/backup custodians. Do not delete a suspicious row to restore readiness.

## Denials and provider failures

| Symptom | Diagnose | Safe action |
|---|---|---|
| Task/expiry/approval/flow denial | Compare task/ancestor grants, purpose, document metadata, destination and exact approval digest. | Keep denial. An authorized independent operator may issue a new narrowed grant/approval after review; never edit encrypted rows to bypass policy. |
| 202 or unknown operation | Inspect its stable operation ID and independently query `/v1/operations/:id/reconcile` or provider observation. | Never redispatch with a fresh ID to guess whether the effect happened. Preserve unknown state if observation is unavailable. |
| Zanii recovery required | Check pinned ledger/log identity, delegation, durable outbox and exact acknowledgement. | Keep dispatch blocked when recording is required. Explicit `/v1/zanii/recover` submits receipts only; it never replays business effects. |
| Required companion unavailable | Inspect runtime-tenant binding, credentials, validated route and observation expiry. | Reprovision/refresh through the companion's real authentication workflow. Public verification remains assurance, not dispatch authority. |
| Suspected leaked credential or rogue agent | Inspect provider audit and alternate paths; revoke affected task roots and provider/issuer credentials. | Isolate the workload, rotate exposed material through its issuer and rerun containment. Revocation does not undo committed effects. |

Escalate repeated unexplained denials, cross-tenant activity or provider observations inconsistent with the journal to the security owner. Retain identifiers/digests and observed outcomes without copying credentials or private content into incident tickets.

## Admission saturation

Compare offered load with configured concurrency/rate limits, resource latency, disk/WAL space and journal growth. Apply backpressure or reduce producer concurrency. Raise limits only after a representative capacity test. Multiple independent SQLite writers do not form a shared quota/approval service.

Alert rules and dashboard templates live under `monitoring/`. Configure their routing and deliver a test alert before treating them as operational monitoring. Aggregate counters are not complete per-route RED/USE telemetry; correlation headers are not a full distributed tracing backend.

## Recovery, retention and key changes

Use the exact CLI/SDK commands in [operations](product-operations.md). Back up to a new exclusive destination, retain expected hashes/checkpoints in a separate trust domain, and restore to a new path with the original encryption/audit keys. Verify the restored tenant audit and application records before redirecting configuration. Unknown operations remain unknown after recovery; never execute them during restore.

Local measured recovery uses a small synthetic database. The deployment owner must choose backup frequency, off-site retention and acceptable RPO/RTO, automate them, and rehearse recovery on representative data. No regional recovery or accepted downtime target is established here. Losing external encryption keys makes encrypted backups unrecoverable.

Maintenance deletes expired authenticated TTL objects and scrubs old terminal operation/provider result bodies in bounded batches. It retains replay tombstones, unknown outcomes and audit ciphertext. Company document/mailbox records, backups and audit retention require explicit company policy; deleting active result bodies does not establish complete PII erasure.

Agent JWT files are reread on each request. TLS key/certificate changes require a new client instance. Update trusted JWKS/issuers through reviewed configuration and restart/revalidate affected roles. Encryption/audit/signing key migration needs a tested migration and retained verification material; an in-place production rotation workflow has not been validated.

Containment receipts expire within 15 minutes. Emit a new versioned file for each measured renewal. File-backed Docker secret mounts can retain an old inode after a host rename: update reviewed mount inputs/recreate affected services and verify both report the renewed receipt. Automatic uninterrupted renewal is not established; expiry deliberately stops admission.

## Rollback and escalation

Drain admission using service shutdown before replacing a pinned image/config. Preserve snapshots and checkpoints, then validate the restored version against the existing schema before reopening. The schema rejects unknown versions; no reversible production migration or zero-downtime rollback rehearsal has been performed. A config/image rollback is not a proven database rollback.

Record UTC time, request/operation IDs, tenant, stable error codes, observed provider outcomes and externally pinned evidence references. Exclude credentials, raw private documents and training examples from chat/log tickets. The deployment owner must provision the real on-call contact and escalation channel; none is invented here.
