# Product implementation status

The separate project now implements the governed document runtime, rather than only the archived authorization experiment. Its gateway and resource use real mTLS, audience/sender-bound JWTs, encrypted durable state and independent effect checks. The [requirement register](../PRODUCT-REQUIREMENTS.md) records each of the twelve objectives.

## Evidence levels

| Level | Current state |
|---|---|
| Implemented | Task/approval/child/data-flow enforcement; broker/resource boundary; bounded injection warnings and reviewed learning; MCP/A2A and company/companion clients; durable journal/evidence/retention/recovery; deployment and operational tooling. |
| Locally verified | TCP/mTLS and disk-store tests, actual installed Zanii broker/SDK against TLS ledger fixtures, companion wire contracts, public-key audit verification and backup restoration. Final aggregate commands and product measurements are recorded in the readiness report. |
| Statically verified | Restrictive Compose configuration, role/mount/image validation, receipt parser and unsafe-setting negatives. |
| Deployment verified | None claimed. Linux UDS/container/network/secret-denial, customer IAM and live external integrations require their actual infrastructure. |
| Unfinished upstream integration | Zanii Runtime package bytes unavailable; optional capability fails closed when Runtime is required. The installed broker/SDK are separate integrations and do not substitute for it. |

The agent runner accepts bounded structured JSONL actions; it supplies no model, autonomous planner or arbitrary command shell. Company agents can use the Node/Python clients or pinned protocols. The first business adapter reads/imports protected documents and commits to an internal mailbox. Existing company services need the resource-side admission contract or an explicitly accepted adapter.

## Recorded local result

Parent verification passed 130 Node tests with zero skips and one Python TCP/mTLS SDK test. Canonical product run 0a30db5-3efb-4436-8bad-7a1a88f7106b passed 15 cases, completed 2/2 primary tasks and observed three expected effects with zero negative-case or duplicate effects. The signed evidence and independent recount verify. The 512-request load produced 400 successes, 112 admission throttles and 400 effects across four fresh fixtures. Maximum observed successful throughput was 27.60 requests/s; the configured 16-request admission limit was reached, with no hardware/production ceiling established.

## Main bypass risk

The runtime protects operations that the company places behind the enforced boundary. Upstream keys and privileged sessions must be removed from agent access, legacy grants revoked, direct resource routes restricted and the workload contained. A valid old provider credential or execution route outside that boundary can still defeat protection. No prompt classifier, signed checkpoint or coverage receipt repairs unrestricted provider IAM by itself.

The local suite checks direct runtime-token rejection, fixed destinations and independent resource authorization. The Linux checker is designed to measure network/metadata/DNS/secret/host/child denial and a fixed public positive control. It cannot run here because Docker/Podman are absent and WSL/child access is restricted. A Windows pipe analogue does not establish Linux permission or isolation behavior.

## Delivery limits

The [white paper](../paper/white-paper.md) is a local engineering draft by **zinii ai**. It reports declared experiments and prior work, without claiming first invention, peer review or universal prompt-injection resistance. The [readiness report](product-readiness-report.md) evaluates every production requirement and withholds clearance while its GAPs remain unresolved.

The original 43-test/24-case research milestone is preserved under `archive/milestone-1/`. Its source digest and results belong to that archived implementation; they are not current product acceptance.
