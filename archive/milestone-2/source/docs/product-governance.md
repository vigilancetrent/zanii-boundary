# Product governance and adaptive warnings

These modules implement governed tasks and tenant-local adaptive warnings using the encrypted SQLite store. They do not establish Linux containment, customer authorization or general prompt-injection immunity by themselves.

## Authority and execution

`createPolicyEngine({store, now?})` exposes `createTask`, `delegate`, `authorize`, `approve`, `revoke`, `recordRead`, `getTask`, `rootContext`, `policyDigest` and `authorityDigest`.

An operator creates a persistent grant containing tenant/actor, reviewed profile and purpose, document IDs, recipients, allowed actions, expiry and operation cap. Delegation requires an explicit grant and narrows scope, purpose, sensitivity, lifetime and quota. Maximum lineage depth is eight. Every authorization reloads ancestors and checks current revocation and scope, rather than trusting the original child grant.

`authorize(identity, taskId, action, metadata)` returns the normalized action, trusted task, root task ID/cap, action and policy digests, effective label, tool version, approval requirement and one unit of work. The executor must authorize immediately before dispatch and call `store.reserveOperation` before any network effect. Map `decision.rootMaxActions` to reservation `maxActions`. The store atomically reserves a unique operation, charges root/ancestor quotas and consumes a one-use matching approval. A duplicate reservation must never cause another dispatch; replay a known result or reconcile an unknown outcome instead.

Approvals bind tenant, task, operation ID, semantic arguments, policy digest, tool version and expiry. The approver must be a different actor from the agent. Approval IDs are proof references excluded from the semantic digest; changing any bound argument invalidates the approval. Revocation prevents new admissions and does not undo a committed or already-sent effect.

Actions allow only `id`, `kind: read|share`, `documentId`, optional share `recipient`, `toolVersion`, `approvalId` and bounded `sourceRefs`. They contain no URL, caller-selected tenant, label override or physical command.

Trusted resource metadata is `{documentId, tenantId, label, toolVersion, allowedRecipients?, allowedPurposes?, recipientIsInternal?}`. The resource/recipient registry must supply it. Do not accept the agent's claim that a destination is internal; missing classification is conservatively external.

## Industry, flow and memory boundaries

Versioned `general`, `finance`, `healthcare` and `industrial` profiles limit purposes, actions, labels, quota, lifetime and approvals. All currently support document reads/shares. Finance and healthcare defaults prohibit external sharing. Industrial defaults prohibit physical commands. These are reviewed starting policies, not regulatory certification, medical authority or industrial safety envelopes.

After an observed read, `recordRead` monotonically raises the root context's sensitivity and records source documents. Children inherit the root flow: summarizing a confidential read or selecting a public output does not remove its restrictions. External sharing must satisfy task, resource and label-release rules simultaneously. This covers the governed document/action path, not perfect semantic or covert-channel tracking through arbitrary software.

`createMemoryService({store, policy, ...})` exposes `remember`, `read` and `remove`. Agent memories always have untrusted provenance, bounded retention and inherited sensitivity. Narrowed children cannot read memories whose recorded source documents or labels exceed their grant. Reads merge flow labels inside the store transaction, retaining them through the root task's expiry rather than shortening retention to a child's lifetime. No memory method creates policy or declassifies content.

## Actual adaptive method

`detectContent(text, context)` emits bounded warning signals for instruction overrides, authority spoofing, credential requests, external disclosure, memory-policy poisoning and task deviation. An optional exemplar component compares token sets against approved attack and benign examples. It never grants authority or claims to read hidden model intent. It is an auditable baseline that can miss unfamiliar languages, encodings and semantic attacks.

`createLearningService({store, trustKey, policyDigest, ...})` implements:

1. `quarantine`: redact common key/token/email patterns, deduplicate normalized observations and enforce tenant/source quotas. Agent observations have no trusted label.
2. `review`: a separately authenticated operator/approver supplies an immutable label and train/holdout split; self-review is denied.
3. `train`: use reviewed training examples and separate holdouts; persist actual precision, recall, false positives and model/corpus/evaluation digests. Failed candidates cannot be promoted.
4. `stage`: evaluate a shadow candidate without changing the active detector.
5. `prepareUpdate` and `applyUpdate`: verify a separately signed EdDSA compact JWS, pinned trust key, independent actor, candidate fitness, exact digests, tenant, expiry, replay ID and unchanged authority-policy digest. Signed rollback selects a previously active retained model.
6. `detect`: use an unexpired active model only under the same authority digest; report expired, missing and policy-mismatched states explicitly while hard permissions remain active.

`signDetectorUpdate` is an owner-side helper. The learner and agent must never receive its private key. The current server binds detector updates to `policy.authorityDigest()`, which covers built-in profiles. It does not bind a candidate to the complete issuer/provider/deployment configuration. The executor independently rechecks its hard authority and coverage controls; learned warnings cannot grant authority. A future full-configuration binding needs an explicit versioned digest and migration, rather than claiming the current profile digest already covers external controls.

The service writes learning namespaces and audit events only. It cannot add issuers, recipients, scopes, budgets or approvals. Warning-driven execution quarantine or temporary tightening requires a separate preauthorized server response policy; suspicious content is not proof of malicious intent.

## Privacy and local evidence

Examples remain local and encrypted with bounded retention. Copied training text in a candidate cannot outlive the earliest source example; deleting a source also invalidates dependent retained models. Redaction cannot guarantee removal of all PII or arbitrary secrets. The server must schedule `store.purgeExpired`. Public update records contain digests/metadata rather than training text. Agent-facing detection omits precise similarity scores and does not expose raw candidate examples. No cross-company training or third-party model request happens automatically.

The synthetic corpus has eight attacks and eight benign examples, divided into eight training and eight held-out examples. Targeted tests measured four true positives and four true negatives under the default candidate. Promotion detects an exemplar-only attack missed by baseline heuristics. This small selected corpus does not establish real-world accuracy, novelty or independent validation.

`test/product-policy.test.mjs` and `test/product-learning.test.mjs` use the actual encrypted SQLite store to test approvals, quotas, lineage changes, memory/flow bounds, poisoned feedback, holdout isolation, signed updates, rollback, replay/key/policy/expiry rejection, retention and unchanged task authority after learning.
